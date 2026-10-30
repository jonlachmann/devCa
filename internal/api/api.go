// Package api serves the loopback management API and the embedded web UI.
package api

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jonlachmann/devca/internal/acme"
	"github.com/jonlachmann/devca/internal/ca"
	"github.com/jonlachmann/devca/internal/certs"
	"github.com/jonlachmann/devca/internal/gateway"
	"github.com/jonlachmann/devca/internal/platform"
	"github.com/jonlachmann/devca/internal/store"
)

type API struct {
	Version  string
	DataDir  string
	Store    *store.Store
	Certs    *certs.Manager
	Gateway  *gateway.Gateway
	SelfTest *acme.SelfTest
	UI       fs.FS
	// Ports actually bound by this process (settings may have changed since).
	MgmtPort, ACMEPort, HTTPPort, HTTPSPort int
	// Running is the settings this process started with; listener and log
	// changes only apply after a restart.
	Running store.Settings
	// ACMELeaf is the ACME listener's certificate, used to check OS trust.
	ACMELeaf func() *x509.Certificate
}

const maxBody = 1 << 20

type httpError struct {
	status int
	msg    string
}

func (e *httpError) Error() string { return e.msg }

func bad(format string, args ...any) error {
	return &httpError{http.StatusBadRequest, fmt.Sprintf(format, args...)}
}

func notFound(what string) error { return &httpError{http.StatusNotFound, what + " not found"} }

// handle adapts func(r) (any, error) to JSON responses.
func handle(fn func(r *http.Request) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v, err := fn(r)
		if err != nil {
			status := http.StatusInternalServerError
			var he *httpError
			if errors.As(err, &he) {
				status = he.status
			}
			writeJSON(w, status, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, v)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return bad("invalid JSON: %v", err)
	}
	return nil
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/status", handle(a.status))
	mux.HandleFunc("GET /api/services", handle(a.listServices))
	mux.HandleFunc("POST /api/services", handle(a.createService))
	mux.HandleFunc("PUT /api/services/{host}", handle(a.updateService))
	mux.HandleFunc("DELETE /api/services/{host}", handle(a.deleteService))
	mux.HandleFunc("POST /api/services/{host}/renew", handle(a.renewService))
	mux.HandleFunc("GET /api/certs", handle(a.listCerts))
	mux.HandleFunc("GET /api/certs/{id}", handle(a.getCert))
	mux.HandleFunc("POST /api/certs/{id}/revoke", handle(a.revokeCert))
	mux.HandleFunc("GET /api/certs/{id}/download", a.downloadCert)
	mux.HandleFunc("GET /api/ca", handle(a.caInfo))
	mux.HandleFunc("GET /api/ca/root.pem", a.downloadRoot)
	mux.HandleFunc("GET /api/acme", handle(a.acmeInfo))
	mux.HandleFunc("GET /api/settings", handle(a.getSettings))
	mux.HandleFunc("PUT /api/settings", handle(a.putSettings))
	mux.HandleFunc("GET /api/events", handle(a.events))
	mux.HandleFunc("POST /api/test/acme", handle(a.testACME))
	mux.HandleFunc("GET /api/hosts", handle(a.hostsInfo))
	if a.UI != nil {
		mux.Handle("GET /", http.FileServerFS(a.UI))
	}
	return a.guard(mux)
}

// guard is the management interface's whole security boundary:
//   - Host must be a loopback name with our port (blocks DNS rebinding).
//   - /api requires the X-DevCA header. Browsers can't send custom headers
//     cross-origin without a CORS preflight, which we never answer, so this
//     doubles as CSRF protection without tokens.
//   - A present Origin must be ours; cross-site fetch metadata is refused.
func (a *API) guard(next http.Handler) http.Handler {
	port := strconv.Itoa(a.MgmtPort)
	allowed := []string{"127.0.0.1:" + port, "localhost:" + port, "[::1]:" + port}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !slices.Contains(allowed, r.Host) {
			http.Error(w, "DevCA: unexpected Host header", http.StatusForbidden)
			return
		}
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if r.Header.Get("X-DevCA") != "1" {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "missing X-DevCA header"})
				return
			}
			if o := r.Header.Get("Origin"); o != "" && !slices.Contains(allowed, strings.TrimPrefix(o, "http://")) {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-origin request refused"})
				return
			}
			if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request refused"})
				return
			}
			if r.Method != http.MethodGet && r.ContentLength != 0 && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "Content-Type must be application/json"})
				return
			}
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// ---- views ----

type certView struct {
	ID          int64     `json:"id"`
	Names       []string  `json:"names"`
	Serial      string    `json:"serial"`
	NotBefore   time.Time `json:"notBefore"`
	NotAfter    time.Time `json:"notAfter"`
	Status      string    `json:"status"` // valid | expiring | expired | revoked
	Owner       string    `json:"owner"`
	OwnerLabel  string    `json:"ownerLabel"`
	KeyType     string    `json:"keyType"`
	Fingerprint string    `json:"fingerprint"`
	Issuer      string    `json:"issuer"`
	Current     bool      `json:"current"`       // the active cert of its service
	HasKey      bool      `json:"hasKey"`        // DevCA holds the private key (service certs)
	PEM         string    `json:"pem,omitempty"` // detail view only
}

func (a *API) certView(s *store.State, c *store.Cert, withPEM bool) certView {
	v := certView{ID: c.ID, Names: c.Names, Serial: c.Serial, NotBefore: c.NotBefore, NotAfter: c.NotAfter,
		Owner: c.Owner, KeyType: c.KeyType, Issuer: a.Certs.CA.Cert.Subject.CommonName}
	if b, _ := pem.Decode([]byte(c.PEM)); b != nil {
		v.Fingerprint = ca.Fingerprint(b.Bytes)
	}
	var renewDays = s.Settings.RenewDays
	switch now := time.Now(); {
	case c.Revoked:
		v.Status = "revoked"
	case now.After(c.NotAfter):
		v.Status = "expired"
	case c.NotAfter.Sub(now) < time.Duration(renewDays)*24*time.Hour:
		v.Status = "expiring"
	default:
		v.Status = "valid"
	}
	switch {
	case c.Owner == store.OwnerTest:
		v.OwnerLabel = "ACME self-test"
	case strings.HasPrefix(c.Owner, "acme:"):
		v.OwnerLabel = "ACME account " + strings.TrimPrefix(c.Owner, "acme:")
	case strings.HasPrefix(c.Owner, "service:"):
		host := strings.TrimPrefix(c.Owner, "service:")
		v.OwnerLabel = "DevCA"
		if svc := s.Service(host); svc != nil {
			v.OwnerLabel = "DevCA (" + svc.Mode + ")"
			v.Current = svc.CertID == c.ID
			v.HasKey = v.Current
		}
	}
	if withPEM {
		v.PEM = c.PEM
	}
	return v
}

type serviceView struct {
	store.Service
	URL      string          `json:"url,omitempty"`
	Cert     *certView       `json:"cert,omitempty"`
	Health   *gateway.Health `json:"health,omitempty"`
	InHosts  bool            `json:"inHosts"`
	CertDir  string          `json:"certDir,omitempty"`
	Resolves string          `json:"resolves"` // "hosts" | "browser" | "missing"
}

func (a *API) serviceViews() []serviceView {
	_, health := a.Gateway.Status()
	inHosts := platform.HostsInFile()
	var out []serviceView
	a.Store.View(func(s *store.State) {
		for _, svc := range s.Services {
			v := serviceView{Service: *svc, InHosts: inHosts[svc.Hostname] == platform.HostsAddr(svc.Address)}
			switch {
			case v.InHosts:
				v.Resolves = "hosts"
			case strings.HasSuffix(svc.Hostname, ".localhost") && svc.Address == "":
				v.Resolves = "browser"
			default:
				v.Resolves = "missing"
			}
			if c := s.Cert(svc.CertID); c != nil {
				cv := a.certView(s, c, false)
				v.Cert = &cv
			}
			if h, ok := health[svc.Hostname]; ok {
				v.Health = &h
			}
			if svc.Mode == store.ModeProxy {
				v.URL = "https://" + svc.Hostname
				if a.HTTPSPort != 443 {
					v.URL += ":" + strconv.Itoa(a.HTTPSPort)
				}
			}
			if svc.Mode != store.ModeACME {
				v.CertDir = a.Certs.CertDir(svc.Hostname)
			}
			out = append(out, v)
		}
	})
	slices.SortFunc(out, func(x, y serviceView) int { return strings.Compare(x.Hostname, y.Hostname) })
	return out
}

// ---- services ----

func (a *API) listServices(*http.Request) (any, error) { return a.serviceViews(), nil }

type serviceInput struct {
	Hostname       string  `json:"hostname"`
	Mode           string  `json:"mode"`
	Target         string  `json:"target"`
	ExportDir      string  `json:"exportDir"`
	ValidationPort int     `json:"validationPort"`
	Address        *string `json:"address"` // nil keeps the current value
	Enabled        *bool   `json:"enabled"`
	AutoRenew      *bool   `json:"autoRenew"`
}

// apply validates in and writes it onto svc.
func (a *API) apply(svc *store.Service, in serviceInput) error {
	switch in.Mode {
	case store.ModeProxy, store.ModeExport, store.ModeACME:
	default:
		return bad("mode must be proxy, export or acme")
	}
	svc.Mode = in.Mode
	svc.Target, svc.ExportDir, svc.ValidationPort = "", "", 0
	switch in.Mode {
	case store.ModeProxy:
		t, err := gateway.ParseTarget(in.Target, a.MgmtPort, a.ACMEPort, a.HTTPPort, a.HTTPSPort)
		if err != nil {
			return bad("%v", err)
		}
		svc.Target = t
	case store.ModeExport:
		if d := strings.TrimSpace(in.ExportDir); d != "" {
			if !filepath.IsAbs(d) {
				return bad("export directory must be an absolute path")
			}
			svc.ExportDir = filepath.Clean(d)
		}
	case store.ModeACME:
		if in.ValidationPort < 0 || in.ValidationPort > 65535 {
			return bad("validation port must be between 1 and 65535")
		}
		svc.ValidationPort = in.ValidationPort
	}
	if in.Address != nil {
		svc.Address = ""
		if s := strings.TrimSpace(*in.Address); s != "" && s != "127.0.0.1" {
			ip, err := netip.ParseAddr(s)
			if err != nil || !ip.IsLoopback() || ip.Zone() != "" || ip.Is4In6() || ip.String() != s {
				return bad("address must be a loopback address such as 127.0.0.2")
			}
			svc.Address = ip.String()
		}
	}
	if svc.Mode == store.ModeProxy && svc.Address != "" {
		return bad("proxy services are reached through the gateway on 127.0.0.1; clear the loopback address first")
	}
	if in.Enabled != nil {
		svc.Enabled = *in.Enabled
	}
	if in.AutoRenew != nil {
		svc.AutoRenew = *in.AutoRenew
	}
	return nil
}

// provision issues/renews as needed and refreshes the gateway.
func (a *API) provision(host string) error {
	var svc store.Service
	a.Store.View(func(s *store.State) {
		if v := s.Service(host); v != nil {
			svc = *v
		}
	})
	var err error
	if svc.Enabled && svc.Mode != store.ModeACME {
		err = a.Certs.Ensure(host, false, false)
	}
	a.Gateway.Reload()
	return err
}

func (a *API) createService(r *http.Request) (any, error) {
	var in serviceInput
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	host := strings.ToLower(strings.TrimSpace(in.Hostname))
	if err := a.Certs.CA.CheckName(host, false); err != nil {
		return nil, bad("%v", err)
	}
	svc := &store.Service{Hostname: host, Enabled: true, AutoRenew: true, Created: time.Now()}
	if err := a.apply(svc, in); err != nil {
		return nil, err
	}
	err := a.Store.Update(func(s *store.State) error {
		if s.Service(host) != nil {
			return &httpError{http.StatusConflict, host + " already exists"}
		}
		s.Services = append(s.Services, svc)
		s.Log("info", "service", "Added %s (%s mode)", host, svc.Mode)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := a.provision(host); err != nil {
		return nil, err
	}
	return a.findService(host)
}

func (a *API) findService(host string) (any, error) {
	for _, v := range a.serviceViews() {
		if v.Hostname == host {
			return v, nil
		}
	}
	return nil, notFound("service")
}

func (a *API) updateService(r *http.Request) (any, error) {
	host := strings.ToLower(r.PathValue("host"))
	var in serviceInput
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	err := a.Store.Update(func(s *store.State) error {
		svc := s.Service(host)
		if svc == nil {
			return notFound("service")
		}
		next := *svc
		if err := a.apply(&next, in); err != nil {
			return err
		}
		*svc = next
		s.Log("info", "service", "Updated %s (%s mode, enabled=%v)", host, svc.Mode, svc.Enabled)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := a.provision(host); err != nil {
		return nil, err
	}
	return a.findService(host)
}

func (a *API) deleteService(r *http.Request) (any, error) {
	host := strings.ToLower(r.PathValue("host"))
	err := a.Store.Update(func(s *store.State) error {
		i := slices.IndexFunc(s.Services, func(v *store.Service) bool { return v.Hostname == host })
		if i < 0 {
			return notFound("service")
		}
		s.Services = slices.Delete(s.Services, i, i+1)
		s.Log("info", "service", "Removed %s", host)
		return nil
	})
	if err != nil {
		return nil, err
	}
	_ = a.Certs.RemoveFiles(host)
	a.Gateway.Reload()
	return map[string]bool{"ok": true}, nil
}

func (a *API) renewService(r *http.Request) (any, error) {
	host := strings.ToLower(r.PathValue("host"))
	if err := a.Certs.Ensure(host, true, false); err != nil {
		return nil, bad("%v", err)
	}
	return a.findService(host)
}

// ---- certificates ----

func (a *API) listCerts(*http.Request) (any, error) {
	var out []certView
	a.Store.View(func(s *store.State) {
		for _, c := range slices.Backward(s.Certs) {
			out = append(out, a.certView(s, c, false))
		}
	})
	return out, nil
}

func pathID(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		return 0, notFound("certificate")
	}
	return id, nil
}

func (a *API) getCert(r *http.Request) (any, error) {
	id, err := pathID(r)
	if err != nil {
		return nil, err
	}
	var v *certView
	a.Store.View(func(s *store.State) {
		if c := s.Cert(id); c != nil {
			cv := a.certView(s, c, true)
			v = &cv
		}
	})
	if v == nil {
		return nil, notFound("certificate")
	}
	return v, nil
}

func (a *API) revokeCert(r *http.Request) (any, error) {
	id, err := pathID(r)
	if err != nil {
		return nil, err
	}
	if err := a.Certs.Revoke(id); err != nil {
		return nil, bad("%v", err)
	}
	a.Gateway.Reload()
	return map[string]bool{"ok": true}, nil
}

// downloadCert serves cert, chain (cert + root), key or bundle. Keys are only
// available for a service's current certificate; ACME clients keep their own.
func (a *API) downloadCert(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var c store.Cert
	var host string
	a.Store.View(func(s *store.State) {
		if x := s.Cert(id); x != nil {
			c = *x
			if svc := s.Service(x.Names[0]); svc != nil && svc.CertID == id && svc.Mode != store.ModeACME {
				host = svc.Hostname
			}
		}
	})
	if c.ID == 0 {
		http.NotFound(w, r)
		return
	}
	part := r.URL.Query().Get("part")
	var data []byte
	switch part {
	case "cert":
		data = []byte(c.PEM)
	case "chain":
		data = append([]byte(c.PEM), a.Certs.CA.CertPEM...)
	case "key", "bundle":
		if host == "" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "DevCA does not hold the private key for this certificate"})
			return
		}
		data, err = os.ReadFile(filepath.Join(a.Certs.CertDir(host), map[string]string{"key": certs.FileKey, "bundle": certs.FileBundle}[part]))
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "key file missing"})
			return
		}
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "part must be cert, chain, key or bundle"})
		return
	}
	name := strings.ReplaceAll(c.Names[0], "*", "_") + "-" + part + ".pem"
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	_, _ = w.Write(data)
}

// ---- CA ----

func (a *API) trust() platform.TrustStatus {
	leaf := a.ACMELeaf()
	if leaf == nil {
		return platform.TrustStatus{Detail: "could not create a test certificate"}
	}
	return platform.TrustCheck(a.Certs.CA.Cert, leaf)
}

func (a *API) caInfo(*http.Request) (any, error) {
	c := a.Certs.CA.Cert
	return map[string]any{
		"subject":     c.Subject.CommonName,
		"fingerprint": a.Certs.CA.Fingerprint(),
		"notBefore":   c.NotBefore,
		"notAfter":    c.NotAfter,
		"keyType":     "ECDSA P-256",
		"suffixes":    a.Certs.CA.Suffixes(),
		"trust":       a.trust(),
		"dataDir":     a.DataDir,
		"certPath":    filepath.Join(a.DataDir, "ca", "root.pem"),
	}, nil
}

func (a *API) downloadRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="devca-root.pem"`)
	_, _ = w.Write(a.Certs.CA.CertPEM)
}

// ---- ACME ----

func (a *API) acmeDirectory() string {
	return fmt.Sprintf("https://localhost:%d/acme/directory", a.ACMEPort)
}

func (a *API) acmeInfo(*http.Request) (any, error) {
	type chal struct {
		Type   string         `json:"type"`
		Status string         `json:"status"`
		Error  *store.Problem `json:"error,omitempty"`
	}
	type authz struct {
		Identifier string `json:"identifier"`
		Status     string `json:"status"`
		Challenges []chal `json:"challenges"`
	}
	type order struct {
		ID          int64          `json:"id"`
		AccountID   int64          `json:"accountId"`
		Status      string         `json:"status"`
		Identifiers []string       `json:"identifiers"`
		Created     time.Time      `json:"created"`
		CertID      int64          `json:"certId,omitempty"`
		Error       *store.Problem `json:"error,omitempty"`
		Authzs      []authz        `json:"authorizations"`
	}
	type account struct {
		ID       int64     `json:"id"`
		Contact  []string  `json:"contact"`
		Status   string    `json:"status"`
		Internal bool      `json:"internal"`
		Created  time.Time `json:"created"`
		Orders   int       `json:"orders"`
	}
	var accounts []account
	var orders []order
	var failures []store.Event
	a.Store.View(func(s *store.State) {
		for _, ac := range s.Accounts {
			n := 0
			for _, o := range s.Orders {
				if o.AccountID == ac.ID {
					n++
				}
			}
			accounts = append(accounts, account{ac.ID, ac.Contact, ac.Status, ac.Internal, ac.Created, n})
		}
		for _, o := range slices.Backward(s.Orders) {
			if len(orders) == 100 {
				break
			}
			ov := order{ID: o.ID, AccountID: o.AccountID, Status: o.Status, Created: o.Created, CertID: o.CertID, Error: o.Error}
			for _, id := range o.Identifiers {
				ov.Identifiers = append(ov.Identifiers, id.Value)
			}
			for _, aid := range o.AuthzIDs {
				if az := s.Authz(aid); az != nil {
					av := authz{Identifier: az.Identifier.Value, Status: az.Status}
					for _, c := range az.Challenges {
						av.Challenges = append(av.Challenges, chal{c.Type, c.Status, c.Error})
					}
					ov.Authzs = append(ov.Authzs, av)
				}
			}
			orders = append(orders, ov)
		}
		for _, e := range slices.Backward(s.Events) {
			if e.Kind == "acme" && e.Level == "error" && len(failures) < 20 {
				failures = append(failures, e)
			}
		}
	})
	return map[string]any{
		"directory":  a.acmeDirectory(),
		"accounts":   accounts,
		"orders":     orders,
		"failures":   failures,
		"challenges": []string{"http-01"},
	}, nil
}

func (a *API) testACME(r *http.Request) (any, error) {
	var in struct {
		Hostname string `json:"hostname"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	host := strings.ToLower(strings.TrimSpace(in.Hostname))
	if err := a.Certs.CA.CheckName(host, false); err != nil {
		return nil, bad("%v", err)
	}
	steps := a.SelfTest.Run(r.Context(), host)
	ok := !slices.ContainsFunc(steps, func(s acme.Step) bool { return !s.OK })
	level := "info"
	if !ok {
		level = "error"
	}
	a.Store.Log(level, "acme", "ACME self-test for %s: %s", host, map[bool]string{true: "passed", false: "failed"}[ok])
	return map[string]any{"ok": ok, "steps": steps}, nil
}

// ---- settings, status, events, hosts ----

func (a *API) needsRestart(s store.Settings) bool {
	r := a.Running
	return r.HTTPPort != s.HTTPPort || r.HTTPSPort != s.HTTPSPort || r.MgmtPort != s.MgmtPort ||
		r.ACMEPort != s.ACMEPort || r.GatewayEnabled != s.GatewayEnabled || r.LogLevel != s.LogLevel
}

func (a *API) getSettings(*http.Request) (any, error) {
	var s store.Settings
	a.Store.View(func(st *store.State) { s = st.Settings })
	return map[string]any{"settings": s, "suffixes": a.Certs.CA.Suffixes(), "dataDir": a.DataDir, "restartRequired": a.needsRestart(s)}, nil
}

func (a *API) putSettings(r *http.Request) (any, error) {
	var in store.Settings
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	ports := []int{in.HTTPPort, in.HTTPSPort, in.MgmtPort, in.ACMEPort}
	for _, p := range ports {
		if p < 1 || p > 65535 {
			return nil, bad("ports must be between 1 and 65535")
		}
	}
	if len(slices.Compact(slices.Sorted(slices.Values(ports)))) != 4 {
		return nil, bad("each listener needs its own port")
	}
	if in.LeafDays < 1 || in.LeafDays > 397 {
		return nil, bad("certificate validity must be 1–397 days")
	}
	if in.RenewDays < 1 || in.RenewDays >= in.LeafDays {
		return nil, bad("renew-before must be at least 1 day and less than the validity")
	}
	if !slices.Contains([]string{"debug", "info", "warn", "error"}, in.LogLevel) {
		return nil, bad("log level must be debug, info, warn or error")
	}
	if !slices.Contains(a.Certs.CA.Suffixes(), in.DefaultSuffix) {
		return nil, bad("default suffix must be one of %v", a.Certs.CA.Suffixes())
	}
	err := a.Store.Update(func(s *store.State) error {
		s.Settings = in
		s.Log("info", "settings", "Settings updated")
		return nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"settings": in, "restartRequired": a.needsRestart(in)}, nil
}

func (a *API) events(*http.Request) (any, error) {
	var ev []store.Event
	a.Store.View(func(s *store.State) { ev = slices.Clone(s.Events) })
	slices.Reverse(ev)
	return ev, nil
}

func (a *API) hostsInfo(*http.Request) (any, error) {
	in := platform.HostsInFile()
	var missing []string
	a.Store.View(func(s *store.State) {
		for _, svc := range s.Services {
			if in[svc.Hostname] != platform.HostsAddr(svc.Address) {
				missing = append(missing, svc.Hostname)
			}
		}
	})
	return map[string]any{"path": platform.HostsPath(), "managed": slices.Sorted(maps.Keys(in)), "missing": missing, "command": "devca hosts apply"}, nil
}

func (a *API) status(*http.Request) (any, error) {
	listeners, health := a.Gateway.Status()
	var gatewayEnabled bool
	var services, active, expiring int
	var expiringCerts []certView
	var recent []store.Event
	acmeFailures := 0
	since := time.Now().Add(-24 * time.Hour)
	a.Store.View(func(s *store.State) {
		gatewayEnabled = s.Settings.GatewayEnabled
		services = len(s.Services)
		for _, c := range s.Certs {
			v := a.certView(s, c, false)
			// Superseded service certs and self-test certs don't count.
			inUse := c.Owner != store.OwnerTest && (v.Current || !strings.HasPrefix(c.Owner, "service:"))
			if inUse && (v.Status == "valid" || v.Status == "expiring") {
				active++
			}
			if inUse && v.Status == "expiring" {
				expiring++
				expiringCerts = append(expiringCerts, v)
			}
		}
		for _, e := range slices.Backward(s.Events) {
			if len(recent) < 15 {
				recent = append(recent, e)
			}
			if e.Kind == "acme" && e.Level == "error" && e.Time.After(since) {
				acmeFailures++
			}
		}
	})
	down := 0
	for _, h := range health {
		if !h.Up {
			down++
		}
	}
	c := a.Certs.CA.Cert
	return map[string]any{
		"version": a.Version,
		"ca": map[string]any{
			"subject":     c.Subject.CommonName,
			"fingerprint": a.Certs.CA.Fingerprint(),
			"notAfter":    c.NotAfter,
			"trust":       a.trust(),
		},
		"gateway": map[string]any{
			"enabled":   gatewayEnabled,
			"listeners": listeners,
			"httpPort":  a.HTTPPort,
			"httpsPort": a.HTTPSPort,
		},
		"counts": map[string]int{
			"services": services, "activeCerts": active, "expiring": expiring,
			"acmeFailures24h": acmeFailures, "upstreamsDown": down, "upstreams": len(health),
		},
		"expiring":      expiringCerts,
		"recent":        recent,
		"acmeDirectory": a.acmeDirectory(),
		"mgmtURL":       "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(a.MgmtPort)),
		"dataDir":       a.DataDir,
	}, nil
}
