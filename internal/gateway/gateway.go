// Package gateway runs the loopback :80/:443 listeners: ACME challenge
// serving, HTTP->HTTPS redirects, SNI certificate selection and the reverse
// proxy for proxy-mode services.
package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jonlachmann/devca/internal/certs"
	"github.com/jonlachmann/devca/internal/store"
)

type route struct {
	svc   store.Service
	proxy *httputil.ReverseProxy
	cert  *tls.Certificate
}

type Listener struct {
	Addr  string `json:"addr"`
	Error string `json:"error,omitempty"`
}

type Health struct {
	Up      bool      `json:"up"`
	Error   string    `json:"error,omitempty"`
	Checked time.Time `json:"checked"`
}

type Gateway struct {
	Store     *store.Store
	Certs     *certs.Manager
	HTTPSPort int

	mu        sync.RWMutex
	routes    map[string]*route
	listeners []Listener
	health    map[string]Health

	chal      sync.Map // host + "/" + token -> key authorization
	transport *http.Transport
}

// ParseTarget normalizes a proxy target to scheme://host:port. Only loopback
// destinations are allowed (no SSRF into the LAN or the Internet), and the
// reserved ports (DevCA's own listeners) are refused.
func ParseTarget(s string, reserved ...int) (string, error) {
	s = strings.TrimSpace(s)
	if _, err := strconv.Atoi(s); err == nil {
		s = "localhost:" + s
	}
	if strings.HasPrefix(s, ":") {
		s = "localhost" + s
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return "", fmt.Errorf("target must look like localhost:3000 or http://127.0.0.1:3000")
	}
	host, port := u.Hostname(), u.Port()
	if host != "localhost" {
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.IsLoopback() {
			return "", fmt.Errorf("target must be on this machine (localhost, 127.0.0.1 or ::1), got %q", host)
		}
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return "", errors.New("target needs a port, e.g. localhost:3000")
	}
	for _, r := range reserved {
		if p == r {
			return "", fmt.Errorf("port %d is used by DevCA itself", p)
		}
	}
	return u.Scheme + "://" + net.JoinHostPort(host, port), nil
}

// loopbackOnly is a dialer Control hook: even if "localhost" resolves
// somewhere odd, the proxy never connects off-machine.
func loopbackOnly(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Unmap().IsLoopback() {
		return fmt.Errorf("refusing to proxy to non-loopback address %s", host)
	}
	return nil
}

func (g *Gateway) init() {
	if g.transport != nil {
		return
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	roots.AddCert(g.Certs.CA.Cert)
	g.transport = &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, Control: loopbackOnly}).DialContext,
		TLSClientConfig:       &tls.Config{RootCAs: roots},
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 0, // dev servers may long-poll
	}
	g.health = map[string]Health{}
}

// Reload rebuilds the routing table from the store. Cheap; call after any change.
func (g *Gateway) Reload() {
	g.mu.Lock()
	g.init()
	g.mu.Unlock()
	var svcs []store.Service
	g.Store.View(func(s *store.State) {
		for _, v := range s.Services {
			if v.Enabled && v.Mode == store.ModeProxy {
				svcs = append(svcs, *v)
			}
		}
	})
	routes := map[string]*route{}
	for _, svc := range svcs {
		target, err := url.Parse(svc.Target)
		if err != nil {
			continue
		}
		rt := &route{svc: svc, proxy: g.newProxy(svc.Hostname, target)}
		if c, err := g.Certs.TLSCertificate(svc.Hostname); err == nil {
			rt.cert = c
		}
		routes[svc.Hostname] = rt
	}
	g.mu.Lock()
	g.routes = routes
	g.mu.Unlock()
	go g.checkHealth()
}

func (g *Gateway) newProxy(host string, target *url.URL) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host // keep the original Host, like Caddy/nginx
			pr.SetXForwarded()
		},
		Transport: g.transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Warn("proxy upstream error", "host", host, "target", target.String(), "err", err)
			page(w, http.StatusBadGateway, "Can't reach your app",
				fmt.Sprintf("DevCA could not connect to <code>%s</code> for <code>%s</code>.<br>Is your app running?<br><small>%s</small>",
					html.EscapeString(target.String()), html.EscapeString(host), html.EscapeString(err.Error())))
		},
	}
}

func (g *Gateway) lookup(hostport string) *route {
	host := strings.ToLower(hostport)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.routes[host]
}

// Publish makes a HTTP-01 response available on port 80.
func (g *Gateway) Publish(host, token, body string) { g.chal.Store(host+"/"+token, body) }
func (g *Gateway) Unpublish(host, token string)     { g.chal.Delete(host + "/" + token) }

const chalPrefix = "/.well-known/acme-challenge/"

// HTTPHandler serves port 80: challenges first, then redirects.
func (g *Gateway) HTTPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(r.Host)
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if tok, ok := strings.CutPrefix(r.URL.Path, chalPrefix); ok {
			if v, ok := g.chal.Load(host + "/" + tok); ok {
				w.Header().Set("Content-Type", "text/plain")
				_, _ = w.Write([]byte(v.(string)))
				return
			}
			http.NotFound(w, r)
			return
		}
		if g.lookup(host) == nil {
			unknownHost(w, host)
			return
		}
		target := "https://" + host
		if g.HTTPSPort != 443 {
			target += ":" + strconv.Itoa(g.HTTPSPort)
		}
		http.Redirect(w, r, target+r.URL.RequestURI(), http.StatusPermanentRedirect)
	})
}

// HTTPSHandler proxies known hosts. It never serves DevCA's own API or UI.
func (g *Gateway) HTTPSHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rt := g.lookup(r.Host)
		if rt == nil {
			unknownHost(w, r.Host)
			return
		}
		rt.proxy.ServeHTTP(w, r)
	})
}

// GetCertificate picks the certificate by SNI. It never issues: certificates
// are provisioned when a service is added and by the renewal loop.
func (g *Gateway) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	rt := g.lookup(hello.ServerName)
	if rt == nil || rt.cert == nil {
		return nil, fmt.Errorf("no certificate for %q", hello.ServerName)
	}
	return rt.cert, nil
}

func unknownHost(w http.ResponseWriter, host string) {
	page(w, http.StatusMisdirectedRequest, "Unknown hostname",
		fmt.Sprintf("<code>%s</code> is not a DevCA proxy service. Add it in the DevCA dashboard or with <code>devca proxy add</code>.", html.EscapeString(host)))
}

func page(w http.ResponseWriter, status int, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html><meta charset=utf-8><title>%s</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:40rem;margin:15vh auto;padding:0 1rem;color:#222}
h1{font-size:1.4rem}code{background:#f2f2f2;padding:.1em .3em;border-radius:4px}small{color:#777}
@media(prefers-color-scheme:dark){body{background:#111;color:#ddd}code{background:#222}}</style>
<h1>%s</h1><p>%s</p><p><small>DevCA</small></p>`, html.EscapeString(title), html.EscapeString(title), body)
}

// Serve starts the listeners on loopback and blocks until ctx ends.
// Bind failures are recorded (and shown in the UI) rather than fatal, so the
// management UI stays up to explain the problem.
func (g *Gateway) Serve(ctx context.Context, httpPort, httpsPort int) {
	g.HTTPSPort = httpsPort
	g.Reload()
	tlsCfg := &tls.Config{GetCertificate: g.GetCertificate, MinVersion: tls.VersionTLS12}
	var servers []*http.Server
	var status []Listener
	for _, l := range []struct {
		port int
		h    http.Handler
		tls  bool
	}{{httpPort, g.HTTPHandler(), false}, {httpsPort, g.HTTPSHandler(), true}} {
		lns, st := listen(l.port)
		status = append(status, st...)
		for _, ln := range lns {
			srv := &http.Server{Handler: l.h, ReadHeaderTimeout: 10 * time.Second}
			if l.tls {
				ln = tls.NewListener(ln, tlsCfg)
			}
			servers = append(servers, srv)
			go func() {
				if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
					slog.Error("gateway serve", "addr", ln.Addr(), "err", err)
				}
			}()
		}
	}
	g.mu.Lock()
	g.listeners = status
	g.mu.Unlock()

	go g.healthLoop(ctx)
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(shutdown)
	}
}

// listen binds port on 127.0.0.1 and ::1. macOS only lets unprivileged
// processes bind ports below 1024 on the wildcard address, so on a permission
// error it binds there instead and drops every connection that doesn't come
// from this machine before anything is read or sent.
func listen(port int) ([]net.Listener, []Listener) {
	var lns []net.Listener
	var status []Listener
	for _, ip := range []string{"127.0.0.1", "::1"} {
		addr := net.JoinHostPort(ip, strconv.Itoa(port))
		ln, err := net.Listen("tcp", addr)
		if err != nil && ip == "127.0.0.1" && errors.Is(err, syscall.EACCES) {
			if wl, werr := net.Listen("tcp", ":"+strconv.Itoa(port)); werr == nil {
				slog.Info("binding wildcard address, accepting local connections only", "port", port)
				return []net.Listener{loopbackListener{wl}}, []Listener{{Addr: "*:" + strconv.Itoa(port) + " (local connections only)"}}
			}
		}
		if err != nil {
			status = append(status, Listener{Addr: addr, Error: bindHint(err, port)})
			slog.Error("gateway listen failed", "addr", addr, "err", err)
			continue
		}
		lns = append(lns, ln)
		status = append(status, Listener{Addr: addr})
	}
	return lns, status
}

// loopbackListener closes connections from other machines on accept.
type loopbackListener struct{ net.Listener }

func (l loopbackListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if a, ok := c.RemoteAddr().(*net.TCPAddr); ok && a.IP.IsLoopback() {
			return c, nil
		}
		c.Close()
	}
}

func bindHint(err error, port int) string {
	msg := err.Error()
	switch {
	case errors.Is(err, syscall.EADDRINUSE) || strings.Contains(msg, "address already in use") || strings.Contains(msg, "Only one usage"):
		return fmt.Sprintf("port %d is already in use by another program", port)
	case errors.Is(err, syscall.EACCES) || strings.Contains(msg, "permission denied"):
		return fmt.Sprintf("no permission to use port %d. On Linux run `devca install` (systemd service with CAP_NET_BIND_SERVICE) or `sudo setcap cap_net_bind_service=+ep $(command -v devca)`", port)
	case strings.Contains(msg, "cannot assign requested address"):
		return "address not available (IPv6 disabled?)"
	}
	return msg
}

func (g *Gateway) healthLoop(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		g.checkHealth()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (g *Gateway) checkHealth() {
	g.mu.RLock()
	targets := map[string]string{}
	for h, rt := range g.routes {
		targets[h] = rt.svc.Target
	}
	g.mu.RUnlock()
	res := map[string]Health{}
	for h, t := range targets {
		u, _ := url.Parse(t)
		d := net.Dialer{Timeout: time.Second, Control: loopbackOnly}
		c, err := d.Dial("tcp", u.Host)
		hl := Health{Up: err == nil, Checked: time.Now()}
		if err != nil {
			hl.Error = fmt.Sprintf("nothing is listening on %s", u.Host)
		} else {
			c.Close()
		}
		res[h] = hl
	}
	g.mu.Lock()
	g.health = res
	g.mu.Unlock()
}

// Status returns listener state and upstream health for the UI.
func (g *Gateway) Status() ([]Listener, map[string]Health) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	h := make(map[string]Health, len(g.health))
	for k, v := range g.health {
		h[k] = v
	}
	return append([]Listener(nil), g.listeners...), h
}
