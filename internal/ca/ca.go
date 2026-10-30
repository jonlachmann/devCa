// Package ca owns the local root CA: creation, loading, name policy and signing.
//
// The root is name-constrained to the allowed suffixes, localhost and loopback
// IPs, so even a stolen root key cannot mint certificates for public names.
package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/jonlachmann/devca/internal/store"
)

// DefaultSuffixes are baked into the root's name constraints at creation.
var DefaultSuffixes = []string{"localhost", "local"}

var loopbackRanges = []*net.IPNet{
	{IP: net.IPv4(127, 0, 0, 0).To4(), Mask: net.CIDRMask(8, 32)},
	{IP: net.IPv6loopback, Mask: net.CIDRMask(128, 128)},
}

type CA struct {
	Cert    *x509.Certificate
	CertPEM []byte
	key     crypto.Signer // never leaves this package
}

func paths(dir string) (certPath, keyPath string) {
	return filepath.Join(dir, "ca", "root.pem"), filepath.Join(dir, "ca", "root.key")
}

// Exists reports whether a root CA is present in dir.
func Exists(dir string) bool {
	c, k := paths(dir)
	_, e1 := os.Stat(c)
	_, e2 := os.Stat(k)
	return e1 == nil || e2 == nil
}

// Load reads the root CA. It never generates one.
func Load(dir string) (*CA, error) {
	certPath, keyPath := paths(dir)
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read CA key: %w", err)
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, errors.New("CA files are not valid PEM; restore from backup (devca ca restore)")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}
	signer, ok := k.(crypto.Signer)
	if !ok || !publicKeysEqual(signer.Public(), cert.PublicKey) {
		return nil, errors.New("CA key does not match CA certificate")
	}
	return &CA{Cert: cert, CertPEM: certPEM, key: signer}, nil
}

// Create generates a new root CA. It refuses if one already exists.
func Create(dir string, suffixes []string) (*CA, error) {
	if Exists(dir) {
		return nil, errors.New("a CA already exists in " + dir)
	}
	for _, s := range suffixes {
		if !validLabel(s) && !validDNS(s) {
			return nil, fmt.Errorf("invalid suffix %q", s)
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	who := "devca"
	if u, err := user.Current(); err == nil {
		who = u.Username
	}
	if h, err := os.Hostname(); err == nil {
		who += "@" + h
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:                randSerial(),
		Subject:                     pkix.Name{CommonName: "DevCA Root (" + who + ")", Organization: []string{"DevCA local development CA"}},
		NotBefore:                   now.Add(-time.Hour),
		NotAfter:                    now.AddDate(10, 0, 0),
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLenZero:              true,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         suffixes,
		PermittedIPRanges:           loopbackRanges,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	certPath, keyPath := paths(dir)
	// Key first: a cert without its key is unusable, the reverse is recoverable.
	if err := store.WriteFileAtomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return nil, err
	}
	if err := store.WriteFileAtomic(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return nil, err
	}
	return Load(dir)
}

// Suffixes returns the DNS suffixes this root may sign for.
func (c *CA) Suffixes() []string { return c.Cert.PermittedDNSDomains }

// Fingerprint is the SHA-256 of the root certificate, colon-separated hex.
func (c *CA) Fingerprint() string { return Fingerprint(c.Cert.Raw) }

func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	var b strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i : i+2])
	}
	return b.String()
}

// Pool returns a cert pool containing only this root.
func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.Cert)
	return p
}

// CheckName validates a hostname (or loopback IP) against the CA policy.
// Names must already be lowercase.
func (c *CA) CheckName(name string, allowWildcard bool) error {
	if ip, err := netip.ParseAddr(name); err == nil {
		if ip.Zone() != "" || ip.Is4In6() || ip.String() != name {
			return fmt.Errorf("%s: write IP addresses in plain form, e.g. 127.0.0.1 or ::1", name)
		}
		if !ip.IsLoopback() {
			return fmt.Errorf("%s: only loopback IP addresses are allowed", name)
		}
		return nil
	}
	if name != strings.ToLower(name) {
		return fmt.Errorf("%s: hostnames must be lowercase", name)
	}
	base := name
	if strings.HasPrefix(name, "*.") {
		if !allowWildcard {
			return fmt.Errorf("%s: wildcards are not allowed here", name)
		}
		base = name[2:]
	}
	if !validDNS(base) {
		return fmt.Errorf("%q is not a valid hostname", name)
	}
	for _, s := range c.Suffixes() {
		if base == s && s == "localhost" && base == name {
			return nil // bare "localhost" is fine; bare "local" is not
		}
		if strings.HasSuffix(base, "."+s) {
			return nil
		}
	}
	return fmt.Errorf("%s: hostname must end in one of %s", name, "."+strings.Join(c.Suffixes(), ", ."))
}

func validDNS(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if !validLabel(l) {
			return false
		}
	}
	return true
}

func validLabel(l string) bool {
	if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for _, r := range l {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

// Issue signs a leaf certificate for names with the given public key.
// Every name is checked against the policy; validity is clamped to the root.
func (c *CA) Issue(names []string, pub crypto.PublicKey, validity time.Duration) (*x509.Certificate, error) {
	if len(names) == 0 {
		return nil, errors.New("no names")
	}
	if err := CheckKey(pub); err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: randSerial(),
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    now.Add(-time.Hour), // tolerate small clock skew
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if _, ok := pub.(*rsa.PublicKey); ok {
		tmpl.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	if tmpl.NotAfter.After(c.Cert.NotAfter) {
		tmpl.NotAfter = c.Cert.NotAfter
	}
	for _, n := range names {
		if err := c.CheckName(n, true); err != nil {
			return nil, err
		}
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, pub, c.key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// CheckKey accepts the key types browsers support for TLS certificates.
func CheckKey(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() {
			return errors.New("unsupported ECDSA curve (use P-256 or P-384)")
		}
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return errors.New("RSA keys must be at least 2048 bits")
		}
	default:
		return errors.New("unsupported key type (use ECDSA or RSA)")
	}
	return nil
}

func randSerial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}
	return n
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	ea, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && ea.Equal(b)
}

// PEM encodes a DER certificate.
func PEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
