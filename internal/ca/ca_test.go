package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func newCA(t *testing.T) *CA {
	t.Helper()
	c, err := Create(t.TempDir(), DefaultSuffixes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCreateLoadNoRegenerate(t *testing.T) {
	dir := t.TempDir()
	c1, err := Create(dir, DefaultSuffixes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Create(dir, DefaultSuffixes); err == nil {
		t.Fatal("Create over existing CA must fail")
	}
	c2, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c1.Fingerprint() != c2.Fingerprint() {
		t.Fatal("reloaded CA differs")
	}
}

func TestCheckName(t *testing.T) {
	c := newCA(t)
	ok := []string{"api.localhost", "a.b.local", "localhost", "127.0.0.1", "::1", "xn--bcher-kva.local"}
	bad := []string{"local", "google.com", "api.local.com", "API.local", "-a.local", "a..local",
		"10.0.0.1", "*.local", "*.localhost", "a_b.local", "api.local.", ""}
	for _, n := range ok {
		if err := c.CheckName(n, false); err != nil {
			t.Errorf("%q rejected: %v", n, err)
		}
	}
	for _, n := range bad {
		if err := c.CheckName(n, true); err == nil {
			t.Errorf("%q accepted", n)
		}
	}
	if c.CheckName("*.api.local", false) == nil || c.CheckName("*.api.local", true) != nil {
		t.Error("wildcard gating broken")
	}
}

func TestIssueVerifies(t *testing.T) {
	c := newCA(t)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf, err := c.Issue([]string{"api.localhost", "127.0.0.1"}, k.Public(), 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "api.localhost", Roots: c.Pool()}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Issue([]string{"evil.com"}, k.Public(), time.Hour); err == nil {
		t.Fatal("issued for public name")
	}
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	if _, err := c.Issue([]string{"a.local"}, small.Public(), time.Hour); err == nil {
		t.Fatal("accepted 1024-bit RSA")
	}
}

// Even with the raw key (bypassing CheckName), the name constraint makes a
// public-name leaf fail verification.
func TestNameConstraintEnforced(t *testing.T) {
	c := newCA(t)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "google.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"google.com"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, k.Public(), c.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "google.com", Roots: c.Pool()}); err == nil {
		t.Fatal("name constraint not enforced")
	}
}
