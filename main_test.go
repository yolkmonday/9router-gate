package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGate(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer real" {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		b, _ := io.ReadAll(r.Body)
		_, _ = w.Write(b)
	}))
	defer up.Close()

	h, err := newGate(config{
		Upstream:      up.URL,
		UpstreamKey:   "real",
		AdminPassword: "pw",
		Keys: map[string]client{
			"friend": {Name: "f", Models: []string{"kr/claude-sonnet-4.5", "oc/*"}},
			"off":    {Name: "o", Models: []string{"oc/*"}, Disabled: true},
		},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	gate := httptest.NewServer(h)
	defer gate.Close()

	tests := []struct {
		name, key, model string
		want             int
	}{
		{"allowed exact", "friend", "kr/claude-sonnet-4.5", 200},
		{"allowed prefix", "friend", "oc/gpt-5", 200},
		{"blocked model", "friend", "cc/claude-opus-5-5", 403},
		{"missing model", "friend", "", 403},
		{"bad key", "nope", "kr/claude-sonnet-4.5", 401},
		{"disabled key", "off", "oc/gpt-5", 401},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", gate.URL+"/v1/chat/completions", strings.NewReader(`{"model":"`+tc.model+`"}`))
			req.Header.Set("Authorization", "Bearer "+tc.key)
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			res.Body.Close()
			if res.StatusCode != tc.want {
				t.Fatalf("got %d want %d", res.StatusCode, tc.want)
			}
		})
	}

	req, _ := http.NewRequest("GET", gate.URL+"/v1/models", nil)
	req.Header.Set("x-api-key", "friend")
	res, _ := http.DefaultClient.Do(req)
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(b), "kr/claude-sonnet-4.5") || strings.Contains(string(b), "opus") {
		t.Fatalf("models list wrong: %s", b)
	}

	adm := func(method, path, pw, ctype, body string) int {
		req, _ := http.NewRequest(method, gate.URL+path, strings.NewReader(body))
		req.SetBasicAuth("admin", pw)
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if c := adm("GET", "/admin", "wrong", "", ""); c != 401 {
		t.Fatalf("admin wrong pw: %d", c)
	}
	if c := adm("GET", "/admin/", "pw", "", ""); c != 200 {
		t.Fatalf("admin page: %d", c)
	}
	if c := adm("POST", "/admin/api/keys", "pw", "text/plain", `{"name":"x"}`); c != 415 {
		t.Fatalf("csrf guard: %d", c)
	}
	if c := adm("POST", "/admin/api/keys", "pw", "application/json", `{"key":"new","name":"n","models":["oc/*"]}`); c != 200 {
		t.Fatalf("create key: %d", c)
	}
	h.mu.RLock()
	_, created := h.cfg.Keys["new"]
	stats := h.stats["friend"]
	h.mu.RUnlock()
	if !created || stats == nil || stats.Allowed != 2 || stats.Denied != 2 {
		t.Fatalf("created=%v stats=%+v", created, stats)
	}
	if c := adm("DELETE", "/admin/api/keys?key=new", "pw", "application/json", ""); c != 204 {
		t.Fatalf("delete key: %d", c)
	}
}
