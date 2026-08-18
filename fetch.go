package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	defer func() { _ = resp.Body.Close() }()

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

func FetchSubscriptions(subs []Subscription) ([]map[string]any, error) {
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		allNodes []map[string]any
		lastErr  error
	)

	for _, s := range subs {
		wg.Add(1)
		go func(sub Subscription) {
			defer wg.Done()
			rawNodes, err := FetchSubscription(sub.URL)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				lastErr = err
			} else {
				nodes := cloneNodes(rawNodes)
				for _, n := range nodes {
					if sub.TagPrefix != "" {
						if t, ok := n["tag"].(string); ok && t != "" {
							n["tag"] = sub.TagPrefix + t
						}
					}
					if len(sub.Groups) > 0 {
						n["_groups"] = sub.Groups
					} else {
						n["_groups"] = []string{"Proxy"}
					}
				}
				allNodes = append(allNodes, nodes...)
			}
		}(s)
	}
	wg.Wait()

	if len(allNodes) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return allNodes, nil
}

func FetchAll(urls []string) ([]map[string]any, error) {
	subs := make([]Subscription, len(urls))
	for i, u := range urls {
		subs[i] = Subscription{URL: u, Groups: []string{"Proxy"}}
	}
	return FetchSubscriptions(subs)
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

func (c *Cache) Get(subs []Subscription) ([]map[string]any, error) {
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		allNodes []map[string]any
		lastErr  error
	)

	for _, s := range subs {
		wg.Add(1)
		go func(sub Subscription) {
			defer wg.Done()

			c.mu.RLock()
			e, ok := c.entries[sub.URL]
			c.mu.RUnlock()

			var rawNodes []map[string]any
			if ok && time.Now().Before(e.exp) {
				rawNodes = e.nodes
			} else {
				fetched, err := FetchSubscription(sub.URL)
				if err != nil {
					if ok && len(e.nodes) > 0 {
						rawNodes = e.nodes
					} else {
						mu.Lock()
						lastErr = err
						mu.Unlock()
						return
					}
				} else {
					rawNodes = fetched
					c.mu.Lock()
					c.entries[sub.URL] = struct {
						nodes []map[string]any
						exp   time.Time
					}{nodes: fetched, exp: time.Now().Add(c.ttl)}
					c.mu.Unlock()
				}
			}

			nodes := cloneNodes(rawNodes)
			for _, n := range nodes {
				if sub.TagPrefix != "" {
					if t, ok := n["tag"].(string); ok && t != "" {
						n["tag"] = sub.TagPrefix + t
					}
				}
				if len(sub.Groups) > 0 {
					n["_groups"] = sub.Groups
				} else {
					n["_groups"] = []string{"Proxy"}
				}
			}

			mu.Lock()
			allNodes = append(allNodes, nodes...)
			mu.Unlock()
		}(s)
	}
	wg.Wait()

	if len(allNodes) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return allNodes, nil
}
