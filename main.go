// Command 9router-gate is a reverse proxy in front of 9router that restricts
// each client API key to an allowlist of models, with an admin UI at /admin.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
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
	"sync"
	"time"
)

//go:embed admin.html
var adminFS embed.FS

type client struct {
	Name     string   `json:"name"`
	Models   []string `json:"models"` // "*" suffix allowed as prefix match, e.g. "kr/*"
	Disabled bool     `json:"disabled,omitempty"`
}

type config struct {
	Listen        string            `json:"listen"`
	Upstream      string            `json:"upstream"`
	UpstreamKey   string            `json:"upstream_key"`
	AdminPassword string            `json:"admin_password"`
	Keys          map[string]client `json:"keys"`
}

type usage struct {
	Allowed  int            `json:"allowed"`
	Denied   int            `json:"denied"`
	Models   map[string]int `json:"models"`
	LastUsed time.Time      `json:"last_used"`
}

type gate struct {
	mu    sync.RWMutex
	cfg   config
	path  string // empty = do not persist (tests)
	stats map[string]*usage
	up    *url.URL
	proxy *httputil.ReverseProxy
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

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func deny(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": map[string]string{"message": msg, "type": "permission_error"}})
}

func newGate(cfg config, path string) (*gate, error) {
	up, err := url.Parse(cfg.Upstream)
	if err != nil {
		return nil, err
	}
	if cfg.Keys == nil {
		cfg.Keys = map[string]client{}
	}
	g := &gate{cfg: cfg, path: path, stats: map[string]*usage{}, up: up}
	g.proxy = &httputil.ReverseProxy{
		FlushInterval: -1, // stream SSE immediately
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(up)
			pr.Out.Host = up.Host
			pr.Out.Header.Del("x-api-key")
			pr.Out.Header.Set("Authorization", "Bearer "+g.cfg.UpstreamKey)
		},
	}
	return g, nil
}

// save writes the config atomically. Caller must hold g.mu.
func (g *gate) save() error {
	if g.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(g.cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := g.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, g.path)
}

func (g *gate) record(key, model string, ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	u := g.stats[key]
	if u == nil {
		u = &usage{Models: map[string]int{}}
		g.stats[key] = u
	}
	u.LastUsed = time.Now()
	if !ok {
		u.Denied++
		return
	}
	u.Allowed++
	u.Models[model]++
}

func (g *gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/admin" || strings.HasPrefix(r.URL.Path, "/admin/") {
		g.admin(w, r)
		return
	}

	key := clientKey(r)
	g.mu.RLock()
	// ponytail: plain map lookup, not constant-time; fine behind LAN/tunnel, add subtle.ConstantTimeCompare loop if exposed publicly.
	c, ok := g.cfg.Keys[key]
	g.mu.RUnlock()
	if !ok || c.Disabled {
		deny(w, http.StatusUnauthorized, "invalid api key")
		return
	}

	if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/models") {
		data := make([]map[string]string, 0, len(c.Models))
		for _, m := range c.Models {
			data = append(data, map[string]string{"id": m, "object": "model", "owned_by": "9router"})
		}
		writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": data})
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
		g.record(key, req.Model, false)
		deny(w, http.StatusForbidden, "model not allowed: "+req.Model)
		return
	}

	log.Printf("allow %s model=%s path=%s", c.Name, req.Model, r.URL.Path)
	g.record(key, req.Model, true)
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	g.proxy.ServeHTTP(w, r)
}

func (g *gate) admin(w http.ResponseWriter, r *http.Request) {
	g.mu.RLock()
	pw := g.cfg.AdminPassword
	g.mu.RUnlock()
	if pw == "" {
		http.NotFound(w, r)
		return
	}
	_, got, _ := r.BasicAuth()
	if subtle.ConstantTimeCompare([]byte(got), []byte(pw)) != 1 {
		w.Header().Set("WWW-Authenticate", `Basic realm="9router-gate"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// Mutations must be JSON: blocks cross-site form posts (CSRF) since that content type needs a CORS preflight.
	if r.Method != http.MethodGet && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		http.Error(w, "content-type must be application/json", http.StatusUnsupportedMediaType)
		return
	}

	switch {
	case r.URL.Path == "/admin" || r.URL.Path == "/admin/":
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'")
		http.ServeFileFS(w, r, adminFS, "admin.html")
	case r.URL.Path == "/admin/api/state" && r.Method == http.MethodGet:
		g.mu.RLock()
		out := make([]map[string]any, 0, len(g.cfg.Keys))
		for k, c := range g.cfg.Keys {
			out = append(out, map[string]any{"key": k, "client": c, "usage": g.stats[k]})
		}
		g.mu.RUnlock()
		writeJSON(w, http.StatusOK, out)
	case r.URL.Path == "/admin/api/models" && r.Method == http.MethodGet:
		g.upstreamModels(w, r)
	case r.URL.Path == "/admin/api/keys" && r.Method == http.MethodPost:
		g.upsertKey(w, r)
	case r.URL.Path == "/admin/api/keys" && r.Method == http.MethodDelete:
		g.mu.Lock()
		delete(g.cfg.Keys, r.URL.Query().Get("key"))
		delete(g.stats, r.URL.Query().Get("key"))
		err := g.save()
		g.mu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func (g *gate) upsertKey(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Key string `json:"key"`
		client
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}
	models := in.Models[:0]
	for _, m := range in.Models {
		if m = strings.TrimSpace(m); m != "" && !slices.Contains(models, m) {
			models = append(models, m)
		}
	}
	in.Models = models
	if in.Key == "" {
		b := make([]byte, 24)
		_, _ = rand.Read(b)
		in.Key = "sk-gate-" + hex.EncodeToString(b)
	}

	g.mu.Lock()
	g.cfg.Keys[in.Key] = in.client
	err := g.save()
	g.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"key": in.Key})
}

func (g *gate) upstreamModels(w http.ResponseWriter, r *http.Request) {
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, g.up.JoinPath("/v1/models").String(), nil)
	g.mu.RLock()
	req.Header.Set("Authorization", "Bearer "+g.cfg.UpstreamKey)
	g.mu.RUnlock()
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer res.Body.Close()
	var list struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(res.Body).Decode(&list); err != nil {
		http.Error(w, "bad upstream response", http.StatusBadGateway)
		return
	}
	ids := make([]string, 0, len(list.Data))
	for _, m := range list.Data {
		ids = append(ids, m.ID)
	}
	slices.Sort(ids)
	writeJSON(w, http.StatusOK, ids)
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
	g, err := newGate(cfg, *path)
	if err != nil {
		log.Fatal(err)
	}
	if cfg.AdminPassword == "" {
		log.Print("admin_password empty: /admin disabled")
	}
	log.Printf("9router-gate on %s -> %s (%d keys)", cfg.Listen, cfg.Upstream, len(cfg.Keys))
	log.Fatal(http.ListenAndServe(cfg.Listen, g))
}
