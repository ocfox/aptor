package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

func ParseURIs(content string) []map[string]any {
	var nodes []map[string]any
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if node, err := ParseURI(line); err == nil && node != nil {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

func ParseURI(rawURI string) (map[string]any, error) {
	if strings.HasPrefix(rawURI, "vless://") {
		return parseVlessURI(rawURI)
	}
	if strings.HasPrefix(rawURI, "vmess://") {
		return parseVmessURI(rawURI)
	}
	if strings.HasPrefix(rawURI, "trojan://") {
		return parseTrojanURI(rawURI)
	}
	if strings.HasPrefix(rawURI, "ss://") {
		return parseShadowsocksURI(rawURI)
	}
	if strings.HasPrefix(rawURI, "hysteria2://") || strings.HasPrefix(rawURI, "hy2://") {
		return parseHysteria2URI(rawURI)
	}
	return nil, fmt.Errorf("unsupported uri scheme: %s", rawURI)
}

func parseVlessURI(rawURI string) (map[string]any, error) {
	u, err := url.Parse(rawURI)
	if err != nil {
		return nil, err
	}

	tag := u.Fragment
	if tag == "" {
		tag = u.Host
	}

	host := u.Hostname()
	portStr := u.Port()
	port, err := strconv.Atoi(portStr)
	if err != nil {
		port = 443
	}

	uuid := u.User.Username()
	q := u.Query()

	node := map[string]any{
		"type":            "vless",
		"tag":             tag,
		"server":          host,
		"server_port":     port,
		"uuid":            uuid,
		"packet_encoding": "xudp",
	}

	if flow := q.Get("flow"); flow != "" {
		node["flow"] = flow
	}

	security := q.Get("security")
	tlsEnabled := security == "tls" || security == "reality"
	if tlsEnabled {
		tlsMap := map[string]any{
			"enabled": true,
		}
		if sni := q.Get("sni"); sni != "" {
			tlsMap["server_name"] = sni
		}
		if fp := q.Get("fp"); fp != "" {
			tlsMap["utls"] = map[string]any{
				"enabled":     true,
				"fingerprint": fp,
			}
		}
		if security == "reality" {
			realityMap := map[string]any{
				"enabled": true,
			}
			if pbk := q.Get("pbk"); pbk != "" {
				realityMap["public_key"] = pbk
			}
			if sid := q.Get("sid"); sid != "" {
				realityMap["short_id"] = sid
			}
			tlsMap["reality"] = realityMap
		}
		node["tls"] = tlsMap
	}

	netType := q.Get("type")
	switch netType {
	case "ws":
		wsMap := map[string]any{
			"type": "ws",
			"path": q.Get("path"),
		}
		if hostHdr := q.Get("host"); hostHdr != "" {
			wsMap["headers"] = map[string]any{
				"Host": hostHdr,
			}
		}
		node["transport"] = wsMap
	case "grpc":
		grpcMap := map[string]any{
			"type":         "grpc",
			"service_name": q.Get("serviceName"),
		}
		node["transport"] = grpcMap
	case "http", "h2":
		httpMap := map[string]any{
			"type": "http",
			"path": q.Get("path"),
		}
		if hostHdr := q.Get("host"); hostHdr != "" {
			httpMap["host"] = strings.Split(hostHdr, ",")
		}
		node["transport"] = httpMap
	}

	return node, nil
}

func parseVmessURI(rawURI string) (map[string]any, error) {
	b64 := strings.TrimPrefix(rawURI, "vmess://")
	decoded, err := decodeBase64Flexible(b64)
	if err != nil {
		return nil, err
	}

	var data map[string]any
	if err := json.Unmarshal(decoded, &data); err != nil {
		return nil, err
	}

	tag, _ := data["ps"].(string)
	server, _ := data["add"].(string)
	portVal := data["port"]
	var port int
	switch v := portVal.(type) {
	case float64:
		port = int(v)
	case string:
		port, _ = strconv.Atoi(v)
	}
	if port == 0 {
		port = 443
	}

	uuid, _ := data["id"].(string)
	aidVal := data["aid"]
	var aid int
	switch v := aidVal.(type) {
	case float64:
		aid = int(v)
	case string:
		aid, _ = strconv.Atoi(v)
	}

	security, _ := data["scy"].(string)
	if security == "" {
		security = "auto"
	}

	node := map[string]any{
		"type":            "vmess",
		"tag":             tag,
		"server":          server,
		"server_port":     port,
		"uuid":            uuid,
		"security":        security,
		"alter_id":        aid,
		"packet_encoding": "xudp",
	}

	tlsVal, _ := data["tls"].(string)
	if tlsVal == "tls" {
		tlsMap := map[string]any{
			"enabled": true,
		}
		if sni, _ := data["sni"].(string); sni != "" {
			tlsMap["server_name"] = sni
		} else if host, _ := data["host"].(string); host != "" {
			tlsMap["server_name"] = host
		}
		if fp, _ := data["fp"].(string); fp != "" {
			tlsMap["utls"] = map[string]any{
				"enabled":     true,
				"fingerprint": fp,
			}
		}
		node["tls"] = tlsMap
	}

	netVal, _ := data["net"].(string)
	switch netVal {
	case "ws":
		wsMap := map[string]any{
			"type": "ws",
			"path": data["path"],
		}
		if host, _ := data["host"].(string); host != "" {
			wsMap["headers"] = map[string]any{
				"Host": host,
			}
		}
		node["transport"] = wsMap
	case "grpc":
		grpcMap := map[string]any{
			"type":         "grpc",
			"service_name": data["path"],
		}
		node["transport"] = grpcMap
	case "h2", "http":
		httpMap := map[string]any{
			"type": "http",
			"path": data["path"],
		}
		if host, _ := data["host"].(string); host != "" {
			httpMap["host"] = strings.Split(host, ",")
		}
		node["transport"] = httpMap
	}

	return node, nil
}

func parseTrojanURI(rawURI string) (map[string]any, error) {
	u, err := url.Parse(rawURI)
	if err != nil {
		return nil, err
	}
	tag := u.Fragment
	if tag == "" {
		tag = u.Host
	}
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 443
	}
	password := u.User.Username()
	q := u.Query()

	node := map[string]any{
		"type":        "trojan",
		"tag":         tag,
		"server":      u.Hostname(),
		"server_port": port,
		"password":    password,
		"tls": map[string]any{
			"enabled": true,
		},
	}
	if sni := q.Get("sni"); sni != "" {
		node["tls"].(map[string]any)["server_name"] = sni
	}
	if fp := q.Get("fp"); fp != "" {
		node["tls"].(map[string]any)["utls"] = map[string]any{
			"enabled":     true,
			"fingerprint": fp,
		}
	}
	if netType := q.Get("type"); netType == "ws" {
		node["transport"] = map[string]any{
			"type": "ws",
			"path": q.Get("path"),
		}
	}
	return node, nil
}

func parseHysteria2URI(rawURI string) (map[string]any, error) {
	u, err := url.Parse(rawURI)
	if err != nil {
		return nil, err
	}
	tag := u.Fragment
	if tag == "" {
		tag = u.Host
	}
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 443
	}
	password := u.User.Username()
	q := u.Query()

	node := map[string]any{
		"type":        "hysteria2",
		"tag":         tag,
		"server":      u.Hostname(),
		"server_port": port,
		"password":    password,
		"tls": map[string]any{
			"enabled": true,
		},
	}
	if sni := q.Get("sni"); sni != "" {
		node["tls"].(map[string]any)["server_name"] = sni
	}
	if insecure := q.Get("insecure"); insecure == "1" || insecure == "true" {
		node["tls"].(map[string]any)["insecure"] = true
	}
	if mport := q.Get("mport"); mport != "" {
		node["server_ports"] = strings.Split(mport, ",")
	}
	return node, nil
}

func parseShadowsocksURI(rawURI string) (map[string]any, error) {
	u, err := url.Parse(rawURI)
	if err != nil {
		return nil, err
	}
	tag := u.Fragment
	if tag == "" {
		tag = u.Host
	}

	var method, password string
	if u.User != nil {
		userStr := u.User.String()
		if decoded, err := decodeBase64Flexible(userStr); err == nil && strings.Contains(string(decoded), ":") {
			parts := strings.SplitN(string(decoded), ":", 2)
			method = parts[0]
			password = parts[1]
		} else {
			method = u.User.Username()
			password, _ = u.User.Password()
		}
	}

	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 8388
	}

	return map[string]any{
		"type":        "shadowsocks",
		"tag":         tag,
		"server":      u.Hostname(),
		"server_port": port,
		"method":      method,
		"password":    password,
	}, nil
}

func decodeBase64Flexible(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if r := len(s) % 4; r != 0 {
		s += strings.Repeat("=", 4-r)
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}
