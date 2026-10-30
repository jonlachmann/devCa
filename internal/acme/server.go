// Package acme implements the RFC 8555 server subset DevCA needs:
// accounts, orders, HTTP-01, finalize, certificate download, revocation and
// key rollover. Issuance goes through certs.Manager like everything else.
package acme

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jonlachmann/devca/internal/certs"
	"github.com/jonlachmann/devca/internal/store"
)

const (
	errPrefix                = "urn:ietf:params:acme:error:"
	errMalformed             = errPrefix + "malformed"
	errBadNonce              = errPrefix + "badNonce"
	errUnauthorized          = errPrefix + "unauthorized"
	errAccountDoesNotExist   = errPrefix + "accountDoesNotExist"
	errBadSignatureAlgorithm = errPrefix + "badSignatureAlgorithm"
	errRejectedIdentifier    = errPrefix + "rejectedIdentifier"
	errUnsupportedIdentifier = errPrefix + "unsupportedIdentifier"
	errOrderNotReady         = errPrefix + "orderNotReady"
	errBadCSR                = errPrefix + "badCSR"
	errBadPublicKey          = errPrefix + "badPublicKey"
	errAlreadyRevoked        = errPrefix + "alreadyRevoked"
	errBadRevocationReason   = errPrefix + "badRevocationReason"
	errUnsupportedContact    = errPrefix + "unsupportedContact"
	errConnection            = errPrefix + "connection"
	errIncorrectResponse     = errPrefix + "incorrectResponse"
	errDNS                   = errPrefix + "dns"
	errServerInternal        = errPrefix + "serverInternal"
)

const (
	orderLifetime = 24 * time.Hour
	maxBody       = 64 << 10
)

type Server struct {
	Store     *store.Store
	Certs     *certs.Manager
	Validator *Validator
	// GatewayHTTPPort is where DevCA itself serves HTTP-01 responses; the
	// self-test validates there. External clients are validated on port 80
	// unless their service sets a ValidationPort.
	GatewayHTTPPort int

	nonces nonceSet
	wg     sync.WaitGroup // in-flight validations
}

// problem is an error that maps to an RFC 7807 response.
type problem struct {
	status int
	typ    string
	detail string
}

func (p *problem) Error() string { return p.detail }

func prob(status int, typ, format string, args ...any) *problem {
	return &problem{status, typ, fmt.Sprintf(format, args...)}
}

// request is a verified JWS POST.
type request struct {
	r         *http.Request
	hdr       http.Header // response headers (Location, Link)
	base      string      // https://host:port/acme
	url       string      // exact URL signed by the client
	payload   []byte
	postAsGet bool
	acct      *store.Account // nil when signed with jwk
	jwk       json.RawMessage
	pub       crypto.PublicKey
	thumb     string
}

type authMode int

const (
	needKid authMode = iota
	needJWK
	kidOrJWK
)

// Handler returns the ACME HTTP handler, rooted at /acme/.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /acme/directory", s.directory)
	mux.HandleFunc("HEAD /acme/new-nonce", s.newNonce)
	mux.HandleFunc("GET /acme/new-nonce", s.newNonce)
	mux.HandleFunc("POST /acme/new-account", s.post(needJWK, s.newAccount))
	mux.HandleFunc("POST /acme/new-order", s.post(needKid, s.newOrder))
	mux.HandleFunc("POST /acme/revoke-cert", s.post(kidOrJWK, s.revokeCert))
	mux.HandleFunc("POST /acme/key-change", s.post(needKid, s.keyChange))
	mux.HandleFunc("POST /acme/acct/{id}", s.post(needKid, s.account))
	mux.HandleFunc("POST /acme/acct/{id}/orders", s.post(needKid, s.accountOrders))
	mux.HandleFunc("POST /acme/order/{id}", s.post(needKid, s.order))
	mux.HandleFunc("POST /acme/order/{id}/finalize", s.post(needKid, s.finalize))
	mux.HandleFunc("POST /acme/authz/{id}", s.post(needKid, s.authz))
	mux.HandleFunc("POST /acme/chall/{id}", s.post(needKid, s.challenge))
	mux.HandleFunc("POST /acme/cert/{id}", s.post(needKid, s.cert))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !loopbackHost(r.Host) {
			writeProblem(w, prob(http.StatusMisdirectedRequest, errMalformed, "ACME is only served on localhost"))
			return
		}
		w.Header().Set("Replay-Nonce", s.nonces.new())
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Add("Link", fmt.Sprintf(`<%s/directory>;rel="index"`, baseURL(r)))
		mux.ServeHTTP(w, r)
	})
}

// Wait blocks until in-flight validations finish (for shutdown and tests).
func (s *Server) Wait() { s.wg.Wait() }

func loopbackHost(hostport string) bool {
	h, _, err := net.SplitHostPort(hostport)
	if err != nil {
		h = hostport
	}
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

func baseURL(r *http.Request) string { return "https://" + r.Host + "/acme" }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeProblem(w http.ResponseWriter, p *problem) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.status)
	_ = json.NewEncoder(w).Encode(store.Problem{Type: p.typ, Detail: p.detail, Status: p.status})
}

func (s *Server) directory(w http.ResponseWriter, r *http.Request) {
	b := baseURL(r)
	writeJSON(w, 200, map[string]any{
		"newNonce":   b + "/new-nonce",
		"newAccount": b + "/new-account",
		"newOrder":   b + "/new-order",
		"revokeCert": b + "/revoke-cert",
		"keyChange":  b + "/key-change",
		"meta": map[string]any{
			"website":                 "https://localhost",
			"externalAccountRequired": false,
		},
	})
}

func (s *Server) newNonce(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.WriteHeader(http.StatusNoContent)
	}
}

// post wraps a handler with JWS parsing, nonce, URL and signature checks.
func (s *Server) post(mode authMode, h func(*request) (int, any, *problem)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req, p := s.verify(r, mode)
		if p == nil {
			req.hdr = w.Header()
			var status int
			var body any
			status, body, p = h(req)
			if p == nil {
				switch b := body.(type) {
				case rawPEM:
					w.Header().Set("Content-Type", "application/pem-certificate-chain")
					w.WriteHeader(status)
					_, _ = w.Write(b)
				default:
					writeJSON(w, status, body)
				}
				return
			}
		}
		if p.status >= 500 {
			slog.Error("acme", "path", r.URL.Path, "err", p.detail)
		}
		writeProblem(w, p)
	}
}

type rawPEM []byte

func (s *Server) verify(r *http.Request, mode authMode) (*request, *problem) {
	if ct, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";"); ct != "application/jose+json" {
		return nil, prob(http.StatusUnsupportedMediaType, errMalformed, "Content-Type must be application/jose+json")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		return nil, prob(400, errMalformed, "request body too large or unreadable")
	}
	m, h, payload, err := parseJWS(body)
	if err != nil {
		return nil, prob(400, errMalformed, "%v", err)
	}
	switch h.Alg {
	case "ES256", "ES384", "ES512", "RS256", "EdDSA":
	default:
		return nil, prob(400, errBadSignatureAlgorithm, "algorithm %q is not supported", h.Alg)
	}
	req := &request{r: r, base: baseURL(r), payload: payload, postAsGet: m.Payload == ""}
	req.url = "https://" + r.Host + r.URL.Path
	if h.URL != req.url {
		return nil, prob(401, errUnauthorized, "JWS url %q does not match request URL", h.URL)
	}
	if !s.nonces.use(h.Nonce) {
		return nil, prob(400, errBadNonce, "invalid or reused nonce")
	}
	hasJWK, hasKid := len(h.JWK) > 0, h.Kid != ""
	switch {
	case hasJWK == hasKid:
		return nil, prob(400, errMalformed, "exactly one of jwk and kid is required")
	case mode == needJWK && !hasJWK:
		return nil, prob(400, errMalformed, "this request must be signed with jwk")
	case mode == needKid && !hasKid:
		return nil, prob(400, errMalformed, "this request must be signed with kid")
	}
	if hasJWK {
		req.pub, req.thumb, err = parseJWK(h.JWK)
		if err != nil {
			return nil, prob(400, errBadPublicKey, "%v", err)
		}
		req.jwk = h.JWK
	} else {
		id, ok := strings.CutPrefix(h.Kid, req.base+"/acct/")
		n, err := strconv.ParseInt(id, 10, 64)
		if !ok || err != nil {
			return nil, prob(401, errAccountDoesNotExist, "unknown kid")
		}
		s.Store.View(func(st *store.State) {
			if a := st.Account(n); a != nil {
				c := *a
				req.acct = &c
			}
		})
		if req.acct == nil {
			return nil, prob(400, errAccountDoesNotExist, "account does not exist")
		}
		if req.acct.Status != "valid" {
			return nil, prob(401, errUnauthorized, "account is %s", req.acct.Status)
		}
		req.pub, req.thumb, _ = parseJWK(req.acct.JWK)
	}
	if err := verifyJWS(m, h.Alg, req.pub); err != nil {
		if errors.Is(err, errBadAlg) {
			return nil, prob(400, errBadSignatureAlgorithm, "%v", err)
		}
		return nil, prob(401, errMalformed, "%v", err)
	}
	return req, nil
}

func (req *request) decode(v any) *problem {
	if req.postAsGet {
		return prob(400, errMalformed, "this request needs a payload")
	}
	if err := json.Unmarshal(req.payload, v); err != nil {
		return prob(400, errMalformed, "invalid payload: %v", err)
	}
	return nil
}

func (req *request) pathID() (int64, *problem) {
	n, err := strconv.ParseInt(req.r.PathValue("id"), 10, 64)
	if err != nil {
		return 0, prob(404, errMalformed, "not found")
	}
	return n, nil
}

// ---- objects ----

func acctURL(base string, id int64) string { return fmt.Sprintf("%s/acct/%d", base, id) }

func acctJSON(base string, a *store.Account) map[string]any {
	c := a.Contact
	if c == nil {
		c = []string{}
	}
	return map[string]any{"status": a.Status, "contact": c, "orders": acctURL(base, a.ID) + "/orders"}
}

func orderJSON(base string, o *store.Order) map[string]any {
	authzs := make([]string, len(o.AuthzIDs))
	for i, id := range o.AuthzIDs {
		authzs[i] = fmt.Sprintf("%s/authz/%d", base, id)
	}
	m := map[string]any{
		"status":         o.Status,
		"expires":        o.Expires.Format(time.RFC3339),
		"identifiers":    o.Identifiers,
		"authorizations": authzs,
		"finalize":       fmt.Sprintf("%s/order/%d/finalize", base, o.ID),
	}
	if o.CertID != 0 {
		m["certificate"] = fmt.Sprintf("%s/cert/%d", base, o.CertID)
	}
	if o.Error != nil {
		m["error"] = o.Error
	}
	return m
}

func challJSON(base string, c *store.Challenge) map[string]any {
	m := map[string]any{
		"type":   c.Type,
		"url":    fmt.Sprintf("%s/chall/%d", base, c.ID),
		"status": c.Status,
		"token":  c.Token,
	}
	if !c.Validated.IsZero() {
		m["validated"] = c.Validated.Format(time.RFC3339)
	}
	if c.Error != nil {
		m["error"] = c.Error
	}
	return m
}

func authzJSON(base string, a *store.Authz) map[string]any {
	ch := make([]any, len(a.Challenges))
	for i, c := range a.Challenges {
		ch[i] = challJSON(base, c)
	}
	return map[string]any{
		"status":     a.Status,
		"expires":    a.Expires.Format(time.RFC3339),
		"identifier": a.Identifier,
		"challenges": ch,
	}
}

// ---- accounts ----

func (s *Server) newAccount(req *request) (int, any, *problem) {
	var p struct {
		Contact            []string `json:"contact"`
		OnlyReturnExisting bool     `json:"onlyReturnExisting"`
	}
	if pr := req.decode(&p); pr != nil {
		return 0, nil, pr
	}
	for _, c := range p.Contact {
		if !strings.HasPrefix(c, "mailto:") || len(c) > 254 || strings.ContainsAny(c, ",") {
			return 0, nil, prob(400, errUnsupportedContact, "only single mailto: contacts are supported")
		}
	}
	var acct store.Account
	status := http.StatusOK
	err := s.Store.Update(func(st *store.State) error {
		for _, a := range st.Accounts {
			if a.Thumbprint == req.thumb {
				acct = *a
				return nil
			}
		}
		if p.OnlyReturnExisting {
			return prob(400, errAccountDoesNotExist, "no account for this key")
		}
		a := &store.Account{ID: st.ID(), Thumbprint: req.thumb, JWK: req.jwk, Contact: p.Contact, Status: "valid", Created: time.Now()}
		st.Accounts = append(st.Accounts, a)
		st.Log("info", "acme", "New ACME account %d", a.ID)
		acct, status = *a, http.StatusCreated
		return nil
	})
	if err != nil {
		return 0, nil, asProblem(err)
	}
	setLocation(req, acctURL(req.base, acct.ID))
	return status, acctJSON(req.base, &acct), nil
}

func setLocation(req *request, url string) { req.hdr.Set("Location", url) }

func asProblem(err error) *problem {
	var p *problem
	if errors.As(err, &p) {
		return p
	}
	return prob(500, errServerInternal, "%v", err)
}

func (s *Server) account(req *request) (int, any, *problem) {
	id, p := req.pathID()
	if p != nil {
		return 0, nil, p
	}
	if id != req.acct.ID {
		return 0, nil, prob(403, errUnauthorized, "not your account")
	}
	if req.postAsGet {
		return 200, acctJSON(req.base, req.acct), nil
	}
	var upd struct {
		Contact *[]string `json:"contact"`
		Status  string    `json:"status"`
	}
	if p := req.decode(&upd); p != nil {
		return 0, nil, p
	}
	if upd.Status != "" && upd.Status != "deactivated" && upd.Status != "valid" {
		return 0, nil, prob(400, errMalformed, "status may only be set to deactivated")
	}
	var out store.Account
	err := s.Store.Update(func(st *store.State) error {
		a := st.Account(id)
		if upd.Contact != nil {
			a.Contact = *upd.Contact
		}
		if upd.Status == "deactivated" {
			a.Status = "deactivated"
			st.Log("info", "acme", "ACME account %d deactivated", id)
		}
		out = *a
		return nil
	})
	if err != nil {
		return 0, nil, asProblem(err)
	}
	return 200, acctJSON(req.base, &out), nil
}

func (s *Server) accountOrders(req *request) (int, any, *problem) {
	id, p := req.pathID()
	if p != nil {
		return 0, nil, p
	}
	if id != req.acct.ID {
		return 0, nil, prob(403, errUnauthorized, "not your account")
	}
	urls := []string{}
	s.Store.View(func(st *store.State) {
		for _, o := range st.Orders {
			if o.AccountID == id {
				urls = append(urls, fmt.Sprintf("%s/order/%d", req.base, o.ID))
			}
		}
	})
	return 200, map[string]any{"orders": urls}, nil
}

func (s *Server) keyChange(req *request) (int, any, *problem) {
	if req.postAsGet {
		return 0, nil, prob(400, errMalformed, "missing inner JWS")
	}
	m, h, payload, err := parseJWS(req.payload)
	if err != nil {
		return 0, nil, prob(400, errMalformed, "inner JWS: %v", err)
	}
	if len(h.JWK) == 0 || h.Kid != "" || h.Nonce != "" {
		return 0, nil, prob(400, errMalformed, "inner JWS must have jwk and no kid or nonce")
	}
	if h.URL != req.url {
		return 0, nil, prob(400, errMalformed, "inner JWS url mismatch")
	}
	newPub, newThumb, err := parseJWK(h.JWK)
	if err != nil {
		return 0, nil, prob(400, errBadPublicKey, "%v", err)
	}
	if err := verifyJWS(m, h.Alg, newPub); err != nil {
		return 0, nil, prob(400, errMalformed, "inner JWS: %v", err)
	}
	var inner struct {
		Account string          `json:"account"`
		OldKey  json.RawMessage `json:"oldKey"`
	}
	if err := json.Unmarshal(payload, &inner); err != nil {
		return 0, nil, prob(400, errMalformed, "inner payload: %v", err)
	}
	if inner.Account != acctURL(req.base, req.acct.ID) {
		return 0, nil, prob(400, errMalformed, "inner account does not match kid")
	}
	if _, oldThumb, err := parseJWK(inner.OldKey); err != nil || oldThumb != req.thumb {
		return 0, nil, prob(400, errMalformed, "oldKey does not match the current account key")
	}
	var out store.Account
	err = s.Store.Update(func(st *store.State) error {
		for _, a := range st.Accounts {
			if a.Thumbprint == newThumb {
				setLocation(req, acctURL(req.base, a.ID))
				return prob(409, errMalformed, "new key is already in use by another account")
			}
		}
		a := st.Account(req.acct.ID)
		a.JWK, a.Thumbprint = h.JWK, newThumb
		st.Log("info", "acme", "ACME account %d rolled over its key", a.ID)
		out = *a
		return nil
	})
	if err != nil {
		return 0, nil, asProblem(err)
	}
	return 200, acctJSON(req.base, &out), nil
}

// ---- orders ----

func (s *Server) newOrder(req *request) (int, any, *problem) {
	var p struct {
		Identifiers []store.Identifier `json:"identifiers"`
		NotBefore   string             `json:"notBefore"`
		NotAfter    string             `json:"notAfter"`
	}
	if pr := req.decode(&p); pr != nil {
		return 0, nil, pr
	}
	if p.NotBefore != "" || p.NotAfter != "" {
		return 0, nil, prob(400, errMalformed, "notBefore/notAfter are not supported")
	}
	if len(p.Identifiers) == 0 || len(p.Identifiers) > 100 {
		return 0, nil, prob(400, errMalformed, "between 1 and 100 identifiers required")
	}
	var idents []store.Identifier
	for _, id := range p.Identifiers {
		if id.Type != "dns" {
			return 0, nil, prob(400, errUnsupportedIdentifier, "only dns identifiers are supported")
		}
		v := strings.ToLower(id.Value)
		if strings.HasPrefix(v, "*.") {
			return 0, nil, prob(400, errRejectedIdentifier, "%s: wildcards need DNS-01, which DevCA does not support", v)
		}
		if err := s.Certs.CA.CheckName(v, false); err != nil {
			return 0, nil, prob(400, errRejectedIdentifier, "%v", err)
		}
		if !slices.ContainsFunc(idents, func(x store.Identifier) bool { return x.Value == v }) {
			idents = append(idents, store.Identifier{Type: "dns", Value: v})
		}
	}
	var o store.Order
	var authzs []store.Authz
	err := s.Store.Update(func(st *store.State) error {
		// Ownership: one owner per hostname. Validate everything before mutating.
		for _, id := range idents {
			if svc := st.Service(id.Value); svc != nil && svc.Mode != store.ModeACME && !req.acct.Internal {
				return prob(400, errRejectedIdentifier,
					"%s is managed by DevCA (%s mode). Switch it to \"acme\" mode in DevCA to use an external ACME client", id.Value, svc.Mode)
			}
		}
		now := time.Now()
		order := &store.Order{ID: st.ID(), AccountID: req.acct.ID, Status: "pending",
			Expires: now.Add(orderLifetime), Identifiers: idents, Created: now}
		for _, id := range idents {
			if st.Service(id.Value) == nil && !req.acct.Internal {
				st.Services = append(st.Services, &store.Service{Hostname: id.Value, Mode: store.ModeACME, Enabled: true, Created: now})
				st.Log("info", "service", "%s claimed by ACME account %d", id.Value, req.acct.ID)
			}
			a := &store.Authz{ID: st.ID(), AccountID: req.acct.ID, Identifier: id, Status: "pending", Expires: order.Expires,
				Challenges: []*store.Challenge{{ID: st.ID(), Type: "http-01", Token: token(), Status: "pending"}}}
			st.Authzs = append(st.Authzs, a)
			order.AuthzIDs = append(order.AuthzIDs, a.ID)
			authzs = append(authzs, *a)
		}
		st.Orders = append(st.Orders, order)
		o = *order
		return nil
	})
	if err != nil {
		return 0, nil, asProblem(err)
	}
	setLocation(req, fmt.Sprintf("%s/order/%d", req.base, o.ID))
	return http.StatusCreated, orderJSON(req.base, &o), nil
}

func token() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b64.EncodeToString(b)
}

// ownedOrder loads a copy of an order owned by the requesting account,
// expiring it first if needed.
func (s *Server) ownedOrder(req *request) (*store.Order, *problem) {
	id, p := req.pathID()
	if p != nil {
		return nil, p
	}
	var o *store.Order
	_ = s.Store.Update(func(st *store.State) error {
		if x := st.Order(id); x != nil && x.AccountID == req.acct.ID {
			if (x.Status == "pending" || x.Status == "ready") && time.Now().After(x.Expires) {
				x.Status = "invalid"
				x.Error = &store.Problem{Type: errMalformed, Detail: "order expired"}
			}
			c := *x
			o = &c
		}
		return nil
	})
	if o == nil {
		return nil, prob(404, errMalformed, "order not found")
	}
	return o, nil
}

func (s *Server) order(req *request) (int, any, *problem) {
	o, p := s.ownedOrder(req)
	if p != nil {
		return 0, nil, p
	}
	return 200, orderJSON(req.base, o), nil
}

func (s *Server) finalize(req *request) (int, any, *problem) {
	o, p := s.ownedOrder(req)
	if p != nil {
		return 0, nil, p
	}
	var body struct {
		CSR string `json:"csr"`
	}
	if p := req.decode(&body); p != nil {
		return 0, nil, p
	}
	if o.Status != "ready" {
		return 0, nil, prob(403, errOrderNotReady, "order is %s, not ready", o.Status)
	}
	der, err := b64.DecodeString(body.CSR)
	if err != nil {
		return 0, nil, prob(400, errBadCSR, "csr is not base64url")
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil || csr.CheckSignature() != nil {
		return 0, nil, prob(400, errBadCSR, "invalid CSR")
	}
	if len(csr.IPAddresses)+len(csr.EmailAddresses)+len(csr.URIs) > 0 {
		return 0, nil, prob(400, errBadCSR, "CSR may only contain DNS names")
	}
	names := map[string]bool{}
	for _, n := range csr.DNSNames {
		names[strings.ToLower(n)] = true
	}
	if csr.Subject.CommonName != "" {
		names[strings.ToLower(csr.Subject.CommonName)] = true
	}
	want := make([]string, len(o.Identifiers))
	for i, id := range o.Identifiers {
		want[i] = id.Value
	}
	if len(names) != len(want) {
		return 0, nil, prob(400, errBadCSR, "CSR names must exactly match the order identifiers %v", want)
	}
	for _, w := range want {
		if !names[w] {
			return 0, nil, prob(400, errBadCSR, "CSR names must exactly match the order identifiers %v", want)
		}
	}
	if eq, ok := csr.PublicKey.(interface{ Equal(crypto.PublicKey) bool }); ok && eq.Equal(req.pub) {
		return 0, nil, prob(400, errBadCSR, "certificate key must differ from the account key")
	}

	owner := store.OwnerACME(req.acct.ID)
	if req.acct.Internal {
		owner = store.OwnerTest
	}
	_ = s.Store.Update(func(st *store.State) error { st.Order(o.ID).Status = "processing"; return nil })
	c, err := s.Certs.Issue(want, csr.PublicKey, owner)
	err2 := s.Store.Update(func(st *store.State) error {
		x := st.Order(o.ID)
		if err != nil {
			x.Status = "invalid"
			x.Error = &store.Problem{Type: errBadCSR, Detail: err.Error()}
			st.Log("error", "acme", "Order %d failed: %v", o.ID, err)
		} else {
			x.Status, x.CertID = "valid", c.ID
		}
		*o = *x
		return nil
	})
	if err != nil {
		return 0, nil, prob(400, errBadPublicKey, "%v", err)
	}
	if err2 != nil {
		return 0, nil, asProblem(err2)
	}
	setLocation(req, fmt.Sprintf("%s/order/%d", req.base, o.ID))
	return 200, orderJSON(req.base, o), nil
}

// ---- authorizations & challenges ----

func (s *Server) authz(req *request) (int, any, *problem) {
	id, p := req.pathID()
	if p != nil {
		return 0, nil, p
	}
	var deactivate bool
	if !req.postAsGet {
		var body struct {
			Status string `json:"status"`
		}
		if p := req.decode(&body); p != nil {
			return 0, nil, p
		}
		if body.Status != "deactivated" {
			return 0, nil, prob(400, errMalformed, "only status=deactivated may be posted")
		}
		deactivate = true
	}
	var out *store.Authz
	_ = s.Store.Update(func(st *store.State) error {
		a := st.Authz(id)
		if a == nil || a.AccountID != req.acct.ID {
			return nil
		}
		if deactivate {
			a.Status = "deactivated"
		} else if a.Status == "pending" && time.Now().After(a.Expires) {
			a.Status = "expired"
		}
		out = cloneAuthz(a)
		return nil
	})
	if out == nil {
		return 0, nil, prob(404, errMalformed, "authorization not found")
	}
	return 200, authzJSON(req.base, out), nil
}

func cloneAuthz(a *store.Authz) *store.Authz {
	c := *a
	c.Challenges = make([]*store.Challenge, len(a.Challenges))
	for i, ch := range a.Challenges {
		cc := *ch
		c.Challenges[i] = &cc
	}
	return &c
}

func (s *Server) challenge(req *request) (int, any, *problem) {
	id, p := req.pathID()
	if p != nil {
		return 0, nil, p
	}
	var az *store.Authz
	var ch *store.Challenge
	var port int
	start := false
	_ = s.Store.Update(func(st *store.State) error {
		for _, a := range st.Authzs {
			for _, c := range a.Challenges {
				if c.ID == id && a.AccountID == req.acct.ID {
					// Any POST with a JSON body (normally {}) triggers validation.
					if !req.postAsGet && c.Status == "pending" && a.Status == "pending" {
						c.Status = "processing"
						start = true
					}
					az, ch = cloneAuthz(a), nil
					for _, cc := range az.Challenges {
						if cc.ID == id {
							ch = cc
						}
					}
					port = 80
					if req.acct.Internal && s.GatewayHTTPPort != 0 {
						port = s.GatewayHTTPPort
					}
					if svc := st.Service(a.Identifier.Value); svc != nil && svc.Mode == store.ModeACME && svc.ValidationPort != 0 {
						port = svc.ValidationPort
					}
				}
			}
		}
		return nil
	})
	if ch == nil {
		return 0, nil, prob(404, errMalformed, "challenge not found")
	}
	if start {
		keyAuth := ch.Token + "." + req.thumb
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.validate(az.ID, ch.ID, az.Identifier.Value, port, ch.Token, keyAuth)
		}()
	}
	w := challJSON(req.base, ch)
	req.hdr.Add("Link", fmt.Sprintf(`<%s/authz/%d>;rel="up"`, req.base, az.ID))
	return 200, w, nil
}

func (s *Server) validate(authzID, challID int64, host string, port int, tok, keyAuth string) {
	pr := s.Validator.HTTP01(context.Background(), host, port, tok, keyAuth)
	_ = s.Store.Update(func(st *store.State) error {
		a := st.Authz(authzID)
		if a == nil {
			return nil
		}
		for _, c := range a.Challenges {
			if c.ID != challID {
				continue
			}
			if pr == nil {
				c.Status, c.Validated = "valid", time.Now()
				a.Status = "valid"
				st.Log("info", "acme", "HTTP-01 validation succeeded for %s", host)
			} else {
				c.Status, c.Error = "invalid", pr
				a.Status = "invalid"
				st.Log("error", "acme", "HTTP-01 validation failed for %s: %s", host, pr.Detail)
			}
		}
		// Recompute every order that includes this authorization.
		for _, o := range st.Orders {
			if o.Status != "pending" || !slices.Contains(o.AuthzIDs, authzID) {
				continue
			}
			ready := true
			for _, id := range o.AuthzIDs {
				switch x := st.Authz(id); {
				case x == nil || x.Status == "invalid" || x.Status == "deactivated" || x.Status == "expired":
					o.Status = "invalid"
					if x != nil && len(x.Challenges) > 0 && x.Challenges[0].Error != nil {
						o.Error = x.Challenges[0].Error
					}
					ready = false
				case x.Status != "valid":
					ready = false
				}
				if o.Status == "invalid" {
					break
				}
			}
			if ready {
				o.Status = "ready"
			}
		}
		return nil
	})
}

// ---- certificates ----

func (s *Server) cert(req *request) (int, any, *problem) {
	id, p := req.pathID()
	if p != nil {
		return 0, nil, p
	}
	var pemData string
	s.Store.View(func(st *store.State) {
		for _, o := range st.Orders {
			if o.CertID == id && o.AccountID == req.acct.ID {
				if c := st.Cert(id); c != nil {
					pemData = c.PEM
				}
			}
		}
	})
	if pemData == "" {
		return 0, nil, prob(404, errMalformed, "certificate not found")
	}
	return 200, rawPEM(pemData), nil
}

func (s *Server) revokeCert(req *request) (int, any, *problem) {
	var body struct {
		Certificate string `json:"certificate"`
		Reason      *int   `json:"reason"`
	}
	if p := req.decode(&body); p != nil {
		return 0, nil, p
	}
	if body.Reason != nil && (*body.Reason < 0 || *body.Reason > 10 || *body.Reason == 7) {
		return 0, nil, prob(400, errBadRevocationReason, "invalid revocation reason")
	}
	der, err := b64.DecodeString(body.Certificate)
	if err != nil {
		return 0, nil, prob(400, errMalformed, "certificate is not base64url")
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return 0, nil, prob(400, errMalformed, "invalid certificate")
	}
	serial := fmt.Sprintf("%X", leaf.SerialNumber)
	var target *store.Cert
	s.Store.View(func(st *store.State) {
		for _, c := range st.Certs {
			if c.Serial == serial {
				cc := *c
				target = &cc
			}
		}
	})
	if target == nil {
		return 0, nil, prob(404, errMalformed, "certificate was not issued by DevCA")
	}
	authorized := false
	if req.acct != nil {
		authorized = target.Owner == store.OwnerACME(req.acct.ID) || (req.acct.Internal && target.Owner == store.OwnerTest)
	} else if eq, ok := leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool }); ok {
		authorized = eq.Equal(req.pub)
	}
	if !authorized {
		return 0, nil, prob(403, errUnauthorized, "not authorized to revoke this certificate")
	}
	if target.Revoked {
		return 0, nil, prob(400, errAlreadyRevoked, "certificate is already revoked")
	}
	if err := s.Certs.Revoke(target.ID); err != nil {
		return 0, nil, prob(500, errServerInternal, "%v", err)
	}
	return 200, struct{}{}, nil
}

// ---- nonces ----

// ponytail: in-memory, capped FIFO. A restart invalidates nonces; clients
// retry on badNonce as RFC 8555 intends.
type nonceSet struct {
	mu    sync.Mutex
	m     map[string]struct{}
	order []string
}

func (n *nonceSet) new() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	v := b64.EncodeToString(b)
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.m == nil {
		n.m = map[string]struct{}{}
	}
	n.m[v] = struct{}{}
	n.order = append(n.order, v)
	if len(n.order) > 10000 {
		delete(n.m, n.order[0])
		n.order = n.order[1:]
	}
	return v
}

func (n *nonceSet) use(v string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.m[v]; !ok || v == "" {
		return false
	}
	delete(n.m, v)
	return true
}
