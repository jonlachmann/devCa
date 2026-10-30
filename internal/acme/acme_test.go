package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	xacme "golang.org/x/crypto/acme"

	"github.com/jonlachmann/devca/internal/ca"
	"github.com/jonlachmann/devca/internal/certs"
	"github.com/jonlachmann/devca/internal/store"
)

type env struct {
	srv       *Server
	acmeURL   string // https://127.0.0.1:port/acme
	roots     *x509.CertPool
	chalPort  int
	mu        sync.Mutex
	responses map[string]string // token -> key authorization
	dir       string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	c, err := ca.Create(dir, ca.DefaultSuffixes)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	e := &env{roots: c.Pool(), responses: map[string]string{}, dir: dir}
	e.srv = &Server{
		Store: st,
		Certs: &certs.Manager{CA: c, Store: st, Dir: dir},
		Validator: &Validator{Resolve: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}},
	}

	// Challenge responder standing in for a client's port-80 server.
	chal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		defer e.mu.Unlock()
		body, ok := e.responses[strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		io.WriteString(w, body)
	}))
	t.Cleanup(chal.Close)
	_, p, _ := net.SplitHostPort(chal.Listener.Addr().String())
	e.chalPort, _ = strconv.Atoi(p)

	// ACME over TLS with a cert from our own CA.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf, err := c.Issue([]string{"127.0.0.1"}, key.Public(), 24*60*60*1e9)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(e.srv.Handler())
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Raw}, PrivateKey: key}}}
	ts.StartTLS()
	t.Cleanup(func() { ts.Close(); e.srv.Wait() })
	e.acmeURL = ts.URL + "/acme"
	return e
}

// acmeService pre-registers host in acme mode, pointing validation at the test responder.
func (e *env) acmeService(t *testing.T, host string) {
	t.Helper()
	_ = e.srv.Store.Update(func(s *store.State) error {
		s.Services = append(s.Services, &store.Service{Hostname: host, Mode: store.ModeACME, Enabled: true, ValidationPort: e.chalPort})
		return nil
	})
}

func (e *env) client(t *testing.T) *xacme.Client {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &xacme.Client{
		Key:          key,
		DirectoryURL: e.acmeURL + "/directory",
		HTTPClient:   &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: e.roots}}},
	}
}

func TestSelfTest(t *testing.T) {
	e := newEnv(t)
	e.acmeService(t, "api.localhost")
	st := &SelfTest{
		Server: e.srv, DirectoryURL: e.acmeURL + "/directory", Roots: e.roots,
		KeyPath: filepath.Join(e.dir, "acme-test.key"),
		Publish: func(_, tok, body string) { e.mu.Lock(); e.responses[tok] = body; e.mu.Unlock() },
		Unpublish: func(_, tok string) {
			e.mu.Lock()
			delete(e.responses, tok)
			e.mu.Unlock()
		},
	}
	for i := range 2 { // second run reuses the persisted account
		for _, s := range st.Run(context.Background(), "api.localhost") {
			if !s.OK {
				t.Fatalf("run %d: step %q failed: %s (hint: %s)", i, s.Name, s.Detail, s.Hint)
			}
		}
	}
}

func TestExternalClientFlow(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	cl := e.client(t)
	if _, err := cl.Register(ctx, &xacme.Account{Contact: []string{"mailto:dev@example.com"}}, xacme.AcceptTOS); err != nil {
		t.Fatal(err)
	}
	// An unowned host is auto-claimed in acme mode; point validation at the responder.
	o, err := cl.AuthorizeOrder(ctx, xacme.DomainIDs("web.local"))
	if err != nil {
		t.Fatal(err)
	}
	_ = e.srv.Store.Update(func(s *store.State) error {
		svc := s.Service("web.local")
		if svc == nil || svc.Mode != store.ModeACME {
			t.Fatal("host not auto-claimed")
		}
		svc.ValidationPort = e.chalPort
		return nil
	})
	az, _ := cl.GetAuthorization(ctx, o.AuthzURLs[0])
	ch := az.Challenges[0]

	// Wrong response first: validation must fail with a useful error.
	e.responses[ch.Token] = "wrong"
	if _, err := cl.Accept(ctx, ch); err != nil {
		t.Fatal(err)
	}
	if _, err := cl.WaitAuthorization(ctx, az.URI); err == nil || !strings.Contains(err.Error(), "wrong key authorization") {
		t.Fatalf("expected incorrectResponse, got %v", err)
	}

	// Fresh order, correct response.
	o, _ = cl.AuthorizeOrder(ctx, xacme.DomainIDs("web.local"))
	az, _ = cl.GetAuthorization(ctx, o.AuthzURLs[0])
	ch = az.Challenges[0]
	e.responses[ch.Token], _ = cl.HTTP01ChallengeResponse(ch.Token)
	if _, err := cl.Accept(ctx, ch); err != nil {
		t.Fatal(err)
	}
	if _, err := cl.WaitAuthorization(ctx, az.URI); err != nil {
		t.Fatal(err)
	}
	if o, err = cl.WaitOrder(ctx, o.URI); err != nil {
		t.Fatal(err)
	}
	certKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"web.local"}}, certKey)

	// CSR with an extra name must be rejected.
	bad, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"web.local", "other.local"}}, certKey)
	if _, _, err := cl.CreateOrderCert(ctx, o.FinalizeURL, bad, false); err == nil {
		t.Fatal("CSR with extra names accepted")
	}
	der, _, err := cl.CreateOrderCert(ctx, o.FinalizeURL, csr, true)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der[0])
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "web.local", Roots: e.roots}); err != nil {
		t.Fatal(err)
	}

	// Key rollover, then the old key must stop working.
	oldKey := cl.Key
	newKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := cl.AccountKeyRollover(ctx, newKey); err != nil {
		t.Fatal(err)
	}
	old := e.client(t)
	old.Key = oldKey
	if _, err := old.GetReg(ctx, ""); err == nil {
		t.Fatal("old key still valid after rollover")
	}

	// Revoke with the certificate key (jwk-signed).
	if err := cl.RevokeCert(ctx, certKey, der[0], xacme.CRLReasonKeyCompromise); err != nil {
		t.Fatal(err)
	}
	e.srv.Store.View(func(s *store.State) {
		if c := s.Certs[len(s.Certs)-1]; !c.Revoked {
			t.Fatal("certificate not marked revoked")
		}
	})
	// A stranger's account may not revoke it.
	stranger := e.client(t)
	stranger.Register(ctx, &xacme.Account{}, xacme.AcceptTOS)
	if err := stranger.RevokeCert(ctx, nil, der[0], xacme.CRLReasonUnspecified); err == nil || !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("expected unauthorized, got %v", err)
	}
}

func TestOrderOwnershipAndPolicy(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	_ = e.srv.Store.Update(func(s *store.State) error {
		s.Services = append(s.Services, &store.Service{Hostname: "app.localhost", Mode: store.ModeProxy, Enabled: true})
		return nil
	})
	cl := e.client(t)
	if _, err := cl.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"app.localhost", "google.com", "*.x.local"} {
		_, err := cl.AuthorizeOrder(ctx, xacme.DomainIDs(host))
		if err == nil || !strings.Contains(err.Error(), "rejectedIdentifier") {
			t.Errorf("%s: expected rejectedIdentifier, got %v", host, err)
		}
	}
}

// Raw JWS rejection cases that a well-behaved client never produces.
func TestJWSRejections(t *testing.T) {
	e := newEnv(t)
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: e.roots}}}
	nonce := func() string {
		r, err := hc.Head(e.acmeURL + "/new-nonce")
		if err != nil {
			t.Fatal(err)
		}
		return r.Header.Get("Replay-Nonce")
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwkJSON := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`,
		b64.EncodeToString(key.X.FillBytes(make([]byte, 32))), b64.EncodeToString(key.Y.FillBytes(make([]byte, 32))))
	url := e.acmeURL + "/new-account"
	sign := func(hdr map[string]any, payload string, tamper bool) []byte {
		hb, _ := json.Marshal(hdr)
		prot := b64.EncodeToString(hb)
		pl := b64.EncodeToString([]byte(payload))
		h := sha256.Sum256([]byte(prot + "." + pl))
		r, s, _ := ecdsa.Sign(rand.Reader, key, h[:])
		sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
		if tamper {
			sig[0] ^= 1
		}
		b, _ := json.Marshal(map[string]string{"protected": prot, "payload": pl, "signature": b64.EncodeToString(sig)})
		return b
	}
	post := func(body []byte) (int, string) {
		r, err := hc.Post(url, "application/jose+json", strings.NewReader(string(body)))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(r.Body)
		return r.StatusCode, string(b)
	}
	hdr := func(m map[string]any) map[string]any {
		base := map[string]any{"alg": "ES256", "nonce": nonce(), "url": url, "jwk": json.RawMessage(jwkJSON)}
		for k, v := range m {
			if v == nil {
				delete(base, k)
			} else {
				base[k] = v
			}
		}
		return base
	}

	reused := hdr(nil)
	if code, body := post(sign(reused, "{}", false)); code != 201 {
		t.Fatalf("valid request failed: %d %s", code, body)
	}
	cases := []struct {
		name string
		body []byte
		want string
	}{
		{"reused nonce", sign(reused, "{}", false), "badNonce"},
		{"wrong url", sign(hdr(map[string]any{"url": e.acmeURL + "/new-order"}), "{}", false), "unauthorized"},
		{"alg none", sign(hdr(map[string]any{"alg": "none"}), "{}", false), "badSignatureAlgorithm"},
		{"alg mismatch", sign(hdr(map[string]any{"alg": "RS256"}), "{}", false), "badSignatureAlgorithm"},
		{"jwk and kid", sign(hdr(map[string]any{"kid": e.acmeURL + "/acct/1"}), "{}", false), "malformed"},
		{"bad signature", sign(hdr(nil), "{}", true), "signature verification failed"},
		{"no nonce", sign(hdr(map[string]any{"nonce": nil}), "{}", false), "badNonce"},
	}
	for _, c := range cases {
		if code, body := post(c.body); code < 400 || !strings.Contains(body, c.want) {
			t.Errorf("%s: got %d %s, want %s", c.name, code, body, c.want)
		}
	}
}
