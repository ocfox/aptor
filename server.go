package main

import (
	"crypto/subtle"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

func StartServer(cfg *Config) error {
	cfg.Normalize()
	if len(cfg.Profiles) == 0 {
		return fmt.Errorf("no profiles configured")
	}

	addr := cfg.Listen
	if addr == "" {
		addr = ":8080"
	}

	cache := NewCache(10 * time.Minute)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		path := strings.Trim(r.URL.Path, "/")

		if path == "health" || path == "healthz" {
			_, _ = w.Write([]byte("OK\n"))
			return
		}

		parts := strings.Split(path, "/")
		var mode, key string
		switch len(parts) {
		case 1:
			mode, key = "tun", parts[0]
		case 2:
			if parts[0] == "tun" || parts[0] == "tproxy" {
				mode, key = parts[0], parts[1]
			} else if parts[1] == "tun" || parts[1] == "tproxy" {
				key, mode = parts[0], parts[1]
			} else {
				http.NotFound(w, r)
				return
			}
		default:
			http.NotFound(w, r)
			return
		}

		var profile *Profile
		for i := range cfg.Profiles {
			if subtle.ConstantTimeCompare([]byte(cfg.Profiles[i].SecretKey), []byte(key)) == 1 {
				profile = &cfg.Profiles[i]
				break
			}
		}

		if profile == nil {
			http.NotFound(w, r)
			return
		}

		nodes, err := cache.Get(profile.Subscriptions)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}

		tpl := profile.TemplatePath
		if tpl == "" {
			tpl = cfg.TemplatePath
		}

		out, err := Assemble(tpl, mode, profile.CustomNodes, nodes)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(out)

		log.Printf("[http] %s %s 200 OK (%s) [profile: %s, mode: %s, nodes: %d]",
			r.Method, r.URL.Path, time.Since(start), profile.Name, mode, len(nodes)+len(profile.CustomNodes))
	})

	log.Printf("[aptor] listening on http://%s (routes: /tun/<key>, /tproxy/<key>)", addr)
	return http.ListenAndServe(addr, handler)
}
