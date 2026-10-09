// Command 9router-gate is a reverse proxy in front of 9router that restricts
// each client API key to an allowlist of models.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"slices"
	"strings"
)

type client struct {
	Name   string   `json:"name"`
	Models []string `json:"models"` // "*" suffix allowed as prefix match, e.g. "kr/*"
}

type config struct {
	Listen      string            `json:"listen"`
	Upstream    string            `json:"upstream"`
	UpstreamKey string            `json:"upstream_key"`
	Keys        map[string]client `json:"keys"`
}

const maxBody = 32 << 20

func (c client) allows(model string) bool {
	return slices.ContainsFunc(c.Models, func(m string) bool {
		if p, ok := strings.CutSuffix(m, "*"); ok {
			return strings.HasPrefix(model, p)
		}
		return m == model
	})
}

func clientKey(r *http.Request) string {
	if k := r.Header.Get("x-api-key"); k != "" {
		return k
	}
	k, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return k
}

func deny(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"message": msg, "type": "permission_error"}})
}

func newHandler(cfg config) (http.Handler, error) {
	up, err := url.Parse(cfg.Upstream)
	if err != nil {
		return nil, err
	}
	proxy := &httputil.ReverseProxy{
		FlushInterval: -1, // stream SSE immediately
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(up)
			pr.Out.Host = up.Host
			pr.Out.Header.Del("x-api-key")
			pr.Out.Header.Set("Authorization", "Bearer "+cfg.UpstreamKey)
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ponytail: plain map lookup, not constant-time; fine behind LAN/tunnel, add subtle.ConstantTimeCompare loop if exposed publicly.
		c, ok := cfg.Keys[clientKey(r)]
		if !ok {
			deny(w, http.StatusUnauthorized, "invalid api key")
			return
		}

		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/models") {
			data := make([]map[string]string, 0, len(c.Models))
			for _, m := range c.Models {
				data = append(data, map[string]string{"id": m, "object": "model", "owned_by": "9router"})
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": data})
			return
		}

		if r.Method != http.MethodPost {
			deny(w, http.StatusForbidden, "method not allowed")
			return
		}

		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if err != nil {
			deny(w, http.StatusRequestEntityTooLarge, "body too large or unreadable")
			return
		}
		var req struct {
			Model string `json:"model"`
		}
		if json.Unmarshal(body, &req) != nil || req.Model == "" || !c.allows(req.Model) {
			log.Printf("deny %s model=%q path=%s", c.Name, req.Model, r.URL.Path)
			deny(w, http.StatusForbidden, "model not allowed: "+req.Model)
			return
		}

		log.Printf("allow %s model=%s path=%s", c.Name, req.Model, r.URL.Path)
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		proxy.ServeHTTP(w, r)
	}), nil
}

func main() {
	path := flag.String("config", "config.json", "config file")
	flag.Parse()

	raw, err := os.ReadFile(*path)
	if err != nil {
		log.Fatal(err)
	}
	var cfg config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		log.Fatal(err)
	}
	h, err := newHandler(cfg)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("9router-gate on %s -> %s (%d keys)", cfg.Listen, cfg.Upstream, len(cfg.Keys))
	log.Fatal(http.ListenAndServe(cfg.Listen, h))
}
