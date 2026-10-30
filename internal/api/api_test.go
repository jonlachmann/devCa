package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jonlachmann/devca/internal/ca"
	"github.com/jonlachmann/devca/internal/certs"
	"github.com/jonlachmann/devca/internal/gateway"
	"github.com/jonlachmann/devca/internal/store"
)

func newAPI(t *testing.T) http.Handler {
	dir := t.TempDir()
	c, _ := ca.Create(dir, ca.DefaultSuffixes)
	st, _ := store.Open(filepath.Join(dir, "state.json"))
	m := &certs.Manager{CA: c, Store: st, Dir: dir}
	g := &gateway.Gateway{Store: st, Certs: m}
	a := &API{DataDir: dir, Store: st, Certs: m, Gateway: g, MgmtPort: 7171, ACMEPort: 7443, HTTPPort: 80, HTTPSPort: 443}
	return a.Handler()
}

func TestGuard(t *testing.T) {
	h := newAPI(t)
	cases := []struct {
		name, method, host, body string
		hdr                      map[string]string
		want                     int
	}{
		{"ok", "GET", "127.0.0.1:7171", "", map[string]string{"X-DevCA": "1"}, 200},
		{"localhost ok", "GET", "localhost:7171", "", map[string]string{"X-DevCA": "1"}, 200},
		{"dns rebinding", "GET", "evil.com:7171", "", map[string]string{"X-DevCA": "1"}, 403},
		{"wrong port", "GET", "127.0.0.1:80", "", map[string]string{"X-DevCA": "1"}, 403},
		{"no header", "GET", "127.0.0.1:7171", "", nil, 403},
		{"cross origin", "GET", "127.0.0.1:7171", "", map[string]string{"X-DevCA": "1", "Origin": "http://evil.com"}, 403},
		{"cross site", "GET", "127.0.0.1:7171", "", map[string]string{"X-DevCA": "1", "Sec-Fetch-Site": "cross-site"}, 403},
		{"form post", "POST", "127.0.0.1:7171", `{"hostname":"a.localhost"}`, map[string]string{"X-DevCA": "1", "Content-Type": "text/plain"}, 415},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, "http://"+c.host+"/api/services", strings.NewReader(c.body))
		r.Host = c.host
		for k, v := range c.hdr {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("%s: got %d want %d (%s)", c.name, w.Code, c.want, w.Body)
		}
	}
}

func TestCreateServiceValidation(t *testing.T) {
	h := newAPI(t)
	post := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://127.0.0.1:7171/api/services", strings.NewReader(body))
		r.Header.Set("X-DevCA", "1")
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, body := range []string{
		`{"hostname":"api.localhost","mode":"proxy","target":"169.254.169.254:80"}`,
		`{"hostname":"api.localhost","mode":"proxy","target":"localhost:7171"}`,
		`{"hostname":"google.com","mode":"export"}`,
		`{"hostname":"api.localhost","mode":"export","exportDir":"relative/dir"}`,
		`{"hostname":"api.localhost","mode":"bogus"}`,
	} {
		if w := post(body); w.Code != 400 {
			t.Errorf("%s: got %d %s", body, w.Code, w.Body)
		}
	}
	if w := post(`{"hostname":"API.localhost","mode":"proxy","target":"3000"}`); w.Code != 200 || !strings.Contains(w.Body.String(), `"certificate.pem"`) && !strings.Contains(w.Body.String(), `"status":"valid"`) {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	if w := post(`{"hostname":"api.localhost","mode":"export"}`); w.Code != 409 {
		t.Fatalf("duplicate: %d", w.Code)
	}
}

func TestServiceAddress(t *testing.T) {
	h := newAPI(t)
	do := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://127.0.0.1:7171"+path, strings.NewReader(body))
		r.Header.Set("X-DevCA", "1")
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, body := range []string{
		`{"hostname":"a.localhost","mode":"export","address":"10.0.0.2"}`,
		`{"hostname":"a.localhost","mode":"export","address":"nope"}`,
		`{"hostname":"a.localhost","mode":"proxy","target":"3000","address":"127.0.0.2"}`,
	} {
		if w := do("POST", "/api/services", body); w.Code != 400 {
			t.Errorf("%s: got %d %s", body, w.Code, w.Body)
		}
	}
	if w := do("POST", "/api/services", `{"hostname":"a.localhost","mode":"export","address":"127.0.0.2"}`); w.Code != 200 || !strings.Contains(w.Body.String(), `"address":"127.0.0.2"`) {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	// An update without "address" keeps it; switching to proxy is refused while it's set.
	if w := do("PUT", "/api/services/a.localhost", `{"mode":"export"}`); !strings.Contains(w.Body.String(), `"address":"127.0.0.2"`) {
		t.Fatalf("address lost on update: %s", w.Body)
	}
	if w := do("PUT", "/api/services/a.localhost", `{"mode":"proxy","target":"3000"}`); w.Code != 400 {
		t.Fatalf("proxy with address: %d", w.Code)
	}
	// 127.0.0.1 means the default.
	if w := do("PUT", "/api/services/a.localhost", `{"mode":"export","address":"127.0.0.1"}`); strings.Contains(w.Body.String(), `"address"`) {
		t.Fatalf("127.0.0.1 not normalized: %s", w.Body)
	}
}

func TestServicePassthrough(t *testing.T) {
	h := newAPI(t)
	post := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://127.0.0.1:7171/api/services", strings.NewReader(body))
		r.Header.Set("X-DevCA", "1")
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, body := range []string{
		`{"hostname":"a.localhost","mode":"acme","passthrough":"10.0.0.1:443"}`,
		`{"hostname":"a.localhost","mode":"acme","passthrough":"443"}`,
		`{"hostname":"a.localhost","mode":"acme","passthrough":"8443","address":"127.0.0.2"}`,
	} {
		if w := post(body); w.Code != 400 {
			t.Errorf("%s: got %d %s", body, w.Code, w.Body)
		}
	}
	if w := post(`{"hostname":"a.localhost","mode":"acme","passthrough":"8443"}`); w.Code != 200 ||
		!strings.Contains(w.Body.String(), `"passthrough":"localhost:8443"`) || !strings.Contains(w.Body.String(), `"url":"https://a.localhost"`) {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
}
