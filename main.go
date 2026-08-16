package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
)

type Profile struct {
	Name          string           `json:"name,omitempty"`
	SecretKey     string           `json:"secret_key"`
	Subscriptions []string         `json:"subscriptions"`
	CustomNodes   []map[string]any `json:"custom_nodes,omitempty"`
	TemplatePath  string           `json:"template_path,omitempty"`
	InboundMode   string           `json:"inbound_mode,omitempty"`
}

type Config struct {
	Listen        string           `json:"listen,omitempty"`
	TemplatePath  string           `json:"template_path,omitempty"`
	Profiles      []Profile        `json:"profiles,omitempty"`
	SecretKey     string           `json:"secret_key,omitempty"`
	Subscriptions []string         `json:"subscriptions,omitempty"`
	CustomNodes   []map[string]any `json:"custom_nodes,omitempty"`
	InboundMode   string           `json:"inbound_mode,omitempty"`
	Output        string           `json:"output,omitempty"`
}

func (c *Config) Normalize() {
	if len(c.Profiles) == 0 && (c.SecretKey != "" || len(c.Subscriptions) > 0) {
		c.Profiles = append(c.Profiles, Profile{
			Name:          "default",
			SecretKey:     c.SecretKey,
			Subscriptions: c.Subscriptions,
			CustomNodes:   c.CustomNodes,
			TemplatePath:  c.TemplatePath,
			InboundMode:   c.InboundMode,
		})
	}
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	cfg.Normalize()
	return &cfg, nil
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "server" {
		runServer(os.Args[2:])
		return
	}
	runGenerate(os.Args[1:])
}

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	configPath := fs.String("config", "aptor.json", "path to configuration file")
	listenAddr := fs.String("listen", "", "HTTP listen address (e.g. 127.0.0.1:8080)")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: aptor server [--config FILE] [--listen ADDR]\n\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	cfg := &Config{}
	if *configPath != "" {
		if loaded, err := loadConfig(*configPath); err == nil {
			cfg = loaded
		} else {
			log.Fatalf("[fatal] failed to load config %s: %v", *configPath, err)
		}
	}
	if *listenAddr != "" {
		cfg.Listen = *listenAddr
	}

	if err := StartServer(cfg); err != nil {
		log.Fatalf("[fatal] %v", err)
	}
}

func runGenerate(args []string) {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	configPath := fs.String("config", "aptor.json", "path to configuration file")
	profileName := fs.String("profile", "", "profile name to generate")
	outputPath := fs.String("o", "", "output configuration file path")
	subURL := fs.String("sub", "", "subscription URL")
	inboundMode := fs.String("inbound", "tun", "inbound mode: tun or tproxy")
	templatePath := fs.String("template", "", "custom template file path")
	check := fs.Bool("check", false, "run sing-box check on generated config")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: aptor [--config FILE] [--profile NAME] [--sub URL] [--inbound tun|tproxy] [--o FILE] [--check]\n")
		fmt.Fprintf(os.Stderr, "       aptor server [--config FILE] [--listen ADDR]\n\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	cfg := &Config{}
	if *configPath != "" {
		if loaded, err := loadConfig(*configPath); err == nil {
			cfg = loaded
		} else if !os.IsNotExist(err) || *configPath != "aptor.json" {
			log.Fatalf("[fatal] failed to load config %s: %v", *configPath, err)
		}
	}
	cfg.Normalize()

	var profile *Profile
	if *profileName != "" {
		for i := range cfg.Profiles {
			if cfg.Profiles[i].Name == *profileName {
				profile = &cfg.Profiles[i]
				break
			}
		}
		if profile == nil {
			log.Fatalf("[fatal] profile '%s' not found", *profileName)
		}
	} else if len(cfg.Profiles) > 0 {
		profile = &cfg.Profiles[0]
	} else {
		profile = &Profile{Name: "default"}
	}

	if *subURL != "" {
		profile.Subscriptions = []string{*subURL}
	}
	if *templatePath != "" {
		profile.TemplatePath = *templatePath
	}
	if *inboundMode != "" {
		profile.InboundMode = *inboundMode
	}
	if profile.InboundMode == "" {
		profile.InboundMode = "tun"
	}

	if len(profile.Subscriptions) == 0 {
		log.Fatalf("[fatal] no subscription URLs configured. Use --sub or specify in config.")
	}

	tpl := profile.TemplatePath
	if tpl == "" {
		tpl = cfg.TemplatePath
	}

	fmt.Printf("[aptor] [%s] fetching subscriptions...\n", profile.Name)
	nodes, err := FetchAll(profile.Subscriptions)
	if err != nil {
		log.Fatalf("[fatal] fetch failed: %v", err)
	}

	out, err := Assemble(tpl, profile.InboundMode, profile.CustomNodes, nodes)
	if err != nil {
		log.Fatalf("[fatal] assemble failed: %v", err)
	}

	outFile := *outputPath
	if outFile == "" {
		outFile = cfg.Output
	}
	if outFile == "" {
		outFile = "config.json"
	}

	if outFile == "-" {
		os.Stdout.Write(out)
		return
	}

	if err := os.WriteFile(outFile, out, 0644); err != nil {
		log.Fatalf("[fatal] write output failed: %v", err)
	}
	fmt.Printf("[aptor] wrote config to %s\n", outFile)

	if *check {
		cmd := exec.Command("sing-box", "check", "-c", outFile)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Fatalf("[warn] sing-box check failed: %v", err)
		} else {
			fmt.Println("[aptor] sing-box check passed!")
		}
	}
}
