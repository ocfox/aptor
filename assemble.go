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
	allNodes := append(cloneNodes(custom), NormalizeNodes(sub)...)
	var allTags []string
	groupTags := make(map[string][]string)
	tagCounts := make(map[string]int)

	for _, node := range allNodes {
		if isTproxy {
			node["routing_mark"] = 255
		} else {
			delete(node, "routing_mark")
		}

		var groups []string
		if gList, ok := node["_groups"].([]string); ok && len(gList) > 0 {
			groups = gList
		} else if gAny, ok := node["_groups"].([]any); ok && len(gAny) > 0 {
			for _, g := range gAny {
				if gs, ok := g.(string); ok && gs != "" {
					groups = append(groups, gs)
				}
			}
		} else if gCustom, ok := node["groups"].([]any); ok && len(gCustom) > 0 {
			for _, g := range gCustom {
				if gs, ok := g.(string); ok && gs != "" {
					groups = append(groups, gs)
				}
			}
		}
		if len(groups) == 0 {
			groups = []string{"Proxy"}
		}
		delete(node, "_groups")
		delete(node, "groups")

		tag, _ := node["tag"].(string)
		if tag == "" {
			continue
		}
		if tagCounts[tag] > 0 {
			tag = fmt.Sprintf("%s-%d", tag, tagCounts[tag]+1)
			node["tag"] = tag
		}
		tagCounts[tag]++
		allTags = append(allTags, tag)

		for _, g := range groups {
			groupTags[g] = append(groupTags[g], tag)
		}
	}

	proxyTags := groupTags["Proxy"]
	if len(proxyTags) == 0 {
		proxyTags = allTags
	}

	defNode := "direct"
	for _, t := range proxyTags {
		if t == "light" {
			defNode = "light"
			break
		}
	}
	if defNode == "direct" && len(proxyTags) > 0 {
		defNode = proxyTags[0]
	}

	var aiOutbounds []string
	var aiDef string
	if aiTags := groupTags["AI"]; len(aiTags) > 0 {
		aiOutbounds = append(append([]string{}, aiTags...), "Proxy", "direct")
		aiDef = aiTags[0]
	} else {
		aiOutbounds = []string{defNode, "Proxy"}
		aiDef = defNode
	}

	directOut := map[string]any{"type": "direct", "tag": "direct"}
	if isTproxy {
		directOut["routing_mark"] = 255
	}

	// 3. Outbounds (Proxy -> AI -> Others -> CN -> direct -> block -> nodes)
	config["outbounds"] = append([]any{
		map[string]any{"type": "selector", "tag": "Proxy", "outbounds": append(append([]string{}, proxyTags...), "direct"), "default": defNode},
		map[string]any{"type": "selector", "tag": "AI", "outbounds": aiOutbounds, "default": aiDef},
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

func cloneNodes(nodes []map[string]any) []map[string]any {
	res := make([]map[string]any, len(nodes))
	for i, n := range nodes {
		clone := make(map[string]any, len(n))
		for k, v := range n {
			clone[k] = v
		}
		res[i] = clone
	}
	return res
}
