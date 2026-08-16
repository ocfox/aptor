package main

import (
	"fmt"
	"strings"
)

var (
	excludeKeywords = []string{"剩余流量", "下次重置", "到期", "套餐", "官网", "更新", "通知", "群组", "流量"}
	regionPatterns  = [][2]string{
		{"香港", "hk"}, {"hk", "hk"}, {"hongkong", "hk"},
		{"日本", "jp"}, {"jp", "jp"}, {"tokyo", "jp"},
		{"新加坡", "sg"}, {"sg", "sg"}, {"狮城", "sg"},
		{"美国", "us"}, {"us", "us"},
		{"韩国", "kr"}, {"kr", "kr"},
		{"台湾", "tw"}, {"tw", "tw"},
		{"英国", "gb"}, {"gb", "gb"}, {"uk", "gb"},
		{"德国", "de"}, {"法国", "fr"}, {"加拿大", "ca"},
	}
)

func NormalizeNodes(nodes []map[string]any) []map[string]any {
	var clean []map[string]any
	counters := make(map[string]int)

	for _, node := range nodes {
		proto, _ := node["type"].(string)
		tag, _ := node["tag"].(string)
		if tag == "" || !isProxyProto(proto) || containsAny(tag, excludeKeywords) {
			continue
		}

		protoCode := proto
		if proto == "hysteria2" {
			protoCode = "hy2"
		} else if proto == "shadowsocks" {
			protoCode = "ss"
		}

		reg := "node"
		lowerTag := strings.ToLower(tag)
		for _, rp := range regionPatterns {
			if strings.Contains(lowerTag, rp[0]) {
				reg = rp[1]
				break
			}
		}

		key := reg + "-" + protoCode
		counters[key]++
		cleanNode := make(map[string]any, len(node))
		for k, v := range node {
			cleanNode[k] = v
		}
		cleanNode["tag"] = fmt.Sprintf("%s-%02d", key, counters[key])
		clean = append(clean, cleanNode)
	}
	return clean
}

func isProxyProto(t string) bool {
	switch t {
	case "vless", "vmess", "hysteria2", "shadowsocks", "trojan", "tuic", "wireguard", "shadowtls":
		return true
	}
	return false
}

func containsAny(s string, keywords []string) bool {
	lower := strings.ToLower(s)
	for _, kw := range keywords {
		if strings.Contains(lower, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}
