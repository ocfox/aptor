package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

var client = &http.Client{Timeout: 15 * time.Second}

func FetchSubscription(url string) ([]map[string]any, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sing-box")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var root map[string]any
	if err := json.Unmarshal(body, &root); err == nil {
		if obs, ok := root["outbounds"].([]any); ok {
			var nodes []map[string]any
			for _, item := range obs {
				if m, ok := item.(map[string]any); ok {
					nodes = append(nodes, m)
				}
			}
			return nodes, nil
		}
	}

	var arr []map[string]any
	if err := json.Unmarshal(body, &arr); err == nil {
		return arr, nil
	}

	// 3. Try Base64 Encoded URI links (e.g. Remnawave, V2Ray subscriptions)
	if decoded, err := decodeBase64Flexible(string(body)); err == nil {
		if nodes := ParseURIs(string(decoded)); len(nodes) > 0 {
			return nodes, nil
		}
	}

	// 4. Try Plain Text URI links (line by line)
	if nodes := ParseURIs(string(body)); len(nodes) > 0 {
		return nodes, nil
	}

	return nil, fmt.Errorf("invalid subscription format from %s", url)
}

func FetchAll(urls []string) ([]map[string]any, error) {
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		nodes   []map[string]any
		lastErr error
	)

	for _, u := range urls {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			n, err := FetchSubscription(url)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				lastErr = err
			} else {
				nodes = append(nodes, n...)
			}
		}(u)
	}
	wg.Wait()

	if len(nodes) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return nodes, nil
}

type Cache struct {
	mu      sync.RWMutex
	ttl     time.Duration
	entries map[string]struct {
		nodes []map[string]any
		exp   time.Time
	}
}

func NewCache(ttl time.Duration) *Cache {
	return &Cache{
		ttl: ttl,
		entries: make(map[string]struct {
			nodes []map[string]any
			exp   time.Time
		}),
	}
}

func (c *Cache) Get(urls []string) ([]map[string]any, error) {
	key := strings.Join(urls, "|")
	c.mu.RLock()
	e, ok := c.entries[key]
	c.mu.RUnlock()

	if ok && time.Now().Before(e.exp) {
		return e.nodes, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if e, ok = c.entries[key]; ok && time.Now().Before(e.exp) {
		return e.nodes, nil
	}

	nodes, err := FetchAll(urls)
	if err != nil {
		if ok && len(e.nodes) > 0 {
			return e.nodes, nil
		}
		return nil, err
	}

	c.entries[key] = struct {
		nodes []map[string]any
		exp   time.Time
	}{nodes: nodes, exp: time.Now().Add(c.ttl)}
	return nodes, nil
}
