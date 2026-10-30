package gateway

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jonlachmann/devca/internal/ca"
	"github.com/jonlachmann/devca/internal/certs"
	"github.com/jonlachmann/devca/internal/store"
)

func TestParseTarget(t *testing.T) {
	ok := map[string]string{
		"3000":                  "http://localhost:3000",
		":3000":                 "http://localhost:3000",
		"localhost:5000":        "http://localhost:5000",
		"http://127.0.0.1:8080": "http://127.0.0.1:8080",
		"https://[::1]:8443/":   "https://[::1]:8443",
	}
	for in, want := range ok {
		if got, err := ParseTarget(in); err != nil || got != want {
			t.Errorf("%q: got %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"example.com:80", "10.0.0.1:80", "http://localhost", "ftp://localhost:21",
		"http://user@localhost:1", "http://localhost:1/path", "169.254.169.254:80", "localhost:7171"} {
		if _, err := ParseTarget(in, 7171); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func newGateway(t *testing.T, upstream string) *Gateway {
	t.Helper()
	dir := t.TempDir()
	c, _ := ca.Create(dir, ca.DefaultSuffixes)
	st, _ := store.Open(filepath.Join(dir, "state.json"))
	m := &certs.Manager{CA: c, Store: st, Dir: dir}
	_ = st.Update(func(s *store.State) error {
		s.Services = append(s.Services, &store.Service{Hostname: "api.localhost", Mode: store.ModeProxy, Target: upstream, Enabled: true})
		return nil
	})
	if err := m.Ensure("api.localhost", false, false); err != nil {
		t.Fatal(err)
	}
	g := &Gateway{Store: st, Certs: m, HTTPSPort: 443}
	g.Reload()
	return g
}

func TestHTTPChallengeRedirectUnknown(t *testing.T) {
	g := newGateway(t, "http://localhost:1")
	g.Publish("api.localhost", "tok", "tok.thumb")
	h := g.HTTPHandler()
	do := func(host, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "http://"+host+path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := do("api.localhost", "/.well-known/acme-challenge/tok"); w.Code != 200 || w.Body.String() != "tok.thumb" {
		t.Fatalf("challenge: %d %q", w.Code, w.Body.String())
	}
	// Challenge path for an unpublished token must not fall through to the redirect.
	if w := do("api.localhost", "/.well-known/acme-challenge/nope"); w.Code != 404 {
		t.Fatalf("missing challenge: %d", w.Code)
	}
	if w := do("api.localhost", "/x?y=1"); w.Code != 308 || w.Header().Get("Location") != "https://api.localhost/x?y=1" {
		t.Fatalf("redirect: %d %s", w.Code, w.Header().Get("Location"))
	}
	if w := do("evil.localhost", "/"); w.Code != http.StatusMisdirectedRequest {
		t.Fatalf("unknown host: %d", w.Code)
	}
}

func TestProxyTLSAndWebSocket(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "websocket" {
			conn, rw, _ := w.(http.Hijacker).Hijack()
			defer conn.Close()
			rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
			rw.Flush()
			line, _ := rw.ReadString('\n')
			rw.WriteString("echo:" + line)
			rw.Flush()
			return
		}
		io.WriteString(w, r.Host+"|"+r.Header.Get("X-Forwarded-Proto")+"|"+r.Header.Get("X-Forwarded-Host"))
	}))
	defer up.Close()
	g := newGateway(t, up.URL)

	srv := httptest.NewUnstartedServer(g.HTTPSHandler())
	srv.TLS = &tls.Config{GetCertificate: g.GetCertificate}
	srv.StartTLS()
	defer srv.Close()
	addr := srv.Listener.Addr().String()
	tlsCfg := &tls.Config{ServerName: "api.localhost", RootCAs: g.Certs.CA.Pool()}

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: tlsCfg,
		DialContext:     func(context.Context, string, string) (net.Conn, error) { return net.Dial("tcp", addr) },
	}}
	resp, err := client.Get("https://api.localhost/")
	if err != nil {
		t.Fatal(err) // also proves SNI selection + chain validity
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "api.localhost|https|api.localhost" {
		t.Fatalf("headers not forwarded: %q", body)
	}

	// Unknown SNI: handshake fails.
	if _, err := tls.Dial("tcp", addr, &tls.Config{ServerName: "other.localhost", RootCAs: g.Certs.CA.Pool()}); err == nil {
		t.Fatal("handshake succeeded for unknown host")
	}

	// WebSocket upgrade passes through.
	conn, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	io.WriteString(conn, "GET /ws HTTP/1.1\r\nHost: api.localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
	br := bufio.NewReader(conn)
	status, _ := br.ReadString('\n')
	if !strings.Contains(status, "101") {
		t.Fatalf("upgrade failed: %q", status)
	}
	for {
		l, _ := br.ReadString('\n')
		if l == "\r\n" {
			break
		}
	}
	io.WriteString(conn, "hello\n")
	if l, _ := br.ReadString('\n'); l != "echo:hello\n" {
		t.Fatalf("ws echo: %q", l)
	}
}

func TestLoopbackListener(t *testing.T) {
	wl, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	ln := loopbackListener{wl}
	defer ln.Close()
	port := wl.Addr().(*net.TCPAddr).Port
	accepted := make(chan net.Addr, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c.RemoteAddr()
			c.Close()
		}
	}()

	// A connection from a non-loopback address of this machine must be dropped.
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		ip, _, _ := net.ParseCIDR(a.String())
		if ip.To4() == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		if c, err := net.Dial("tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port))); err == nil {
			buf := make([]byte, 1)
			if _, err := c.Read(buf); err == nil {
				t.Fatal("non-loopback connection was kept open")
			}
			c.Close()
		}
		break
	}
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if a := <-accepted; !a.(*net.TCPAddr).IP.IsLoopback() {
		t.Fatalf("accepted %v", a)
	}
}
