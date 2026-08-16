package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

//go:embed template.json
var defaultTemplate []byte

func Assemble(templatePath, mode string, custom, sub []map[string]any) ([]byte, error) {
	tpl := defaultTemplate
	if templatePath != "" {
		data, err := os.ReadFile(templatePath)
		if err != nil {
			return nil, err
		}
		tpl = data
	}

	var config map[string]any
	if err := json.Unmarshal(tpl, &config); err != nil {
		return nil, err
	}

	// 1. Inbounds
	if strings.ToLower(mode) == "tproxy" {
		config["inbounds"] = []any{
			map[string]any{"type": "mixed", "tag": "mixed-in", "listen": "::", "listen_port": 7890},
			map[string]any{"type": "tproxy", "tag": "tproxy-in", "listen": "::", "listen_port": 7895},
		}
	} else {
		config["inbounds"] = []any{
			map[string]any{"type": "mixed", "tag": "mixed-in", "listen": "::", "listen_port": 7890},
			map[string]any{
				"type":         "tun",
				"tag":          "tun-in",
				"address":      []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
				"mtu":          1500,
				"auto_route":   true,
				"strict_route": true,
				"stack":        "mixed",
			},
		}
	}

	// 2. Nodes & Tags
	isTproxy := strings.ToLower(mode) == "tproxy"
	allNodes := append(custom, NormalizeNodes(sub)...)
	var tags []string
	tagCounts := make(map[string]int)

	for _, node := range allNodes {
		if isTproxy {
			node["routing_mark"] = 255
		}
		tag, _ := node["tag"].(string)
		if tag == "" {
			continue
		}
		if tagCounts[tag] > 0 {
			tag = fmt.Sprintf("%s-%d", tag, tagCounts[tag]+1)
			node["tag"] = tag
		}
		tagCounts[tag]++
		tags = append(tags, tag)
	}

	defNode := "direct"
	for _, t := range tags {
		if t == "light" {
			defNode = "light"
			break
		}
	}
	if defNode == "direct" && len(tags) > 0 {
		defNode = tags[0]
	}

	directOut := map[string]any{"type": "direct", "tag": "direct"}
	if isTproxy {
		directOut["routing_mark"] = 255
	}

	// 3. Outbounds (Proxy -> AI -> Others -> CN -> direct -> block -> nodes)
	config["outbounds"] = append([]any{
		map[string]any{"type": "selector", "tag": "Proxy", "outbounds": append(tags, "direct"), "default": defNode},
		map[string]any{"type": "selector", "tag": "AI", "outbounds": []string{defNode, "Proxy"}, "default": defNode},
		map[string]any{"type": "selector", "tag": "Others", "outbounds": []string{"Proxy", "direct"}},
		map[string]any{"type": "selector", "tag": "CN", "outbounds": []string{"direct", "Proxy"}},
		directOut,
		map[string]any{"type": "block", "tag": "block"},
	}, toAnySlice(allNodes)...)

	return json.MarshalIndent(config, "", "  ")
}

func toAnySlice(nodes []map[string]any) []any {
	res := make([]any, len(nodes))
	for i, n := range nodes {
		res[i] = n
	}
	return res
}
