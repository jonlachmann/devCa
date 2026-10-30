// Package certs is the single certificate issuance path. Services, the ACME
// server and the self-test all issue through Manager.Issue.
package certs

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jonlachmann/devca/internal/ca"
	"github.com/jonlachmann/devca/internal/store"
)

// Export file names, written into certs/<host>/ and an optional ExportDir.
const (
	FileCert   = "certificate.pem" // leaf certificate
	FileKey    = "private-key.pem"
	FileBundle = "bundle.pem" // private key + certificate in one file (always consistent)
	FileCA     = "ca.pem"
)

type Manager struct {
	CA       *ca.CA
	Store    *store.Store
	Dir      string           // data dir
	OnChange func()           // called after a service cert changes (gateway reload)
	Now      func() time.Time // injectable for tests

	mu sync.Mutex // serializes Ensure so concurrent callers don't double-issue
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Manager) changed() {
	if m.OnChange != nil {
		m.OnChange()
	}
}

// Issue signs names for pub and records the certificate.
func (m *Manager) Issue(names []string, pub crypto.PublicKey, owner string) (*store.Cert, error) {
	var days int
	m.Store.View(func(s *store.State) { days = s.Settings.LeafDays })
	leaf, err := m.CA.Issue(names, pub, time.Duration(days)*24*time.Hour)
	if err != nil {
		return nil, err
	}
	c := &store.Cert{
		Serial:    fmt.Sprintf("%X", leaf.SerialNumber),
		Names:     names,
		NotBefore: leaf.NotBefore,
		NotAfter:  leaf.NotAfter,
		Owner:     owner,
		KeyType:   keyType(pub),
		PEM:       string(ca.PEM(leaf.Raw)),
	}
	err = m.Store.Update(func(s *store.State) error {
		c.ID = s.ID()
		s.Certs = append(s.Certs, c)
		s.Log("info", "cert", "Issued certificate for %s (expires %s)", strings.Join(names, ", "), leaf.NotAfter.Format("2006-01-02"))
		return nil
	})
	return c, err
}

// CertDir is where a service's files live inside the data dir.
func (m *Manager) CertDir(host string) string { return filepath.Join(m.Dir, "certs", host) }

// needsRenewal reports whether c should be replaced for host.
func needsRenewal(c *store.Cert, host string, renewDays int, now time.Time) bool {
	return c == nil || c.Revoked || !slices.Equal(c.Names, []string{host}) ||
		c.NotAfter.Sub(now) < time.Duration(renewDays)*24*time.Hour
}

// Ensure gives a proxy/export service a current certificate. force renews
// regardless of expiry; rekey also replaces the private key.
func (m *Manager) Ensure(host string, force, rekey bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var svc store.Service
	var cur *store.Cert
	var renewDays int
	var found bool
	m.Store.View(func(s *store.State) {
		if v := s.Service(host); v != nil {
			svc, found = *v, true
			if c := s.Cert(v.CertID); c != nil {
				cc := *c
				cur = &cc
			}
		}
		renewDays = s.Settings.RenewDays
	})
	if !found {
		return fmt.Errorf("no service %s", host)
	}
	if svc.Mode == store.ModeACME {
		return fmt.Errorf("%s is managed by an external ACME client", host)
	}
	dir := m.CertDir(host)
	if !force && !needsRenewal(cur, host, renewDays, m.now()) {
		// Cert is current; make sure exports exist (e.g. ExportDir was just set).
		return m.export(svc, dir, cur, false)
	}

	key, err := loadKey(filepath.Join(dir, FileKey))
	if rekey || err != nil {
		if key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			return err
		}
	}
	c, err := m.Issue([]string{host}, key.Public(), store.OwnerService(host))
	if err != nil {
		m.Store.Log("error", "cert", "Issuing %s failed: %v", host, err)
		return err
	}
	if err := writeKey(filepath.Join(dir, FileKey), key); err != nil {
		return err
	}
	if err := m.export(svc, dir, c, true); err != nil {
		return err
	}
	err = m.Store.Update(func(s *store.State) error {
		if v := s.Service(host); v != nil {
			v.CertID = c.ID
		}
		return nil
	})
	m.changed()
	return err
}

// export writes the cert files to dir and to svc.ExportDir.
// Order is key, then bundle, then cert, so an app watching certificate.pem
// always sees a matching key once it changes. Keys are reused across renewals,
// so normally only the certificate changes anyway.
func (m *Manager) export(svc store.Service, dir string, c *store.Cert, overwrite bool) error {
	keyPEM, err := os.ReadFile(filepath.Join(dir, FileKey))
	if err != nil {
		return err
	}
	dirs := []string{dir}
	if svc.ExportDir != "" && svc.Mode == store.ModeExport {
		dirs = append(dirs, svc.ExportDir)
	}
	for _, d := range dirs {
		if !overwrite {
			if _, err := os.Stat(filepath.Join(d, FileCert)); err == nil {
				continue
			}
		}
		files := []struct {
			name string
			data []byte
			perm os.FileMode
		}{
			{FileKey, keyPEM, 0o600},
			{FileCA, m.CA.CertPEM, 0o644},
			{FileBundle, append(append([]byte{}, keyPEM...), c.PEM...), 0o600},
			{FileCert, []byte(c.PEM), 0o644},
		}
		for _, f := range files {
			if err := store.WriteFileAtomic(filepath.Join(d, f.name), f.data, f.perm); err != nil {
				return fmt.Errorf("export %s: %w", d, err)
			}
		}
	}
	return nil
}

// RenewAll ensures every enabled, auto-renewing proxy/export service.
func (m *Manager) RenewAll() {
	var hosts []string
	m.Store.View(func(s *store.State) {
		for _, v := range s.Services {
			if v.Enabled && v.AutoRenew && v.Mode != store.ModeACME {
				hosts = append(hosts, v.Hostname)
			}
		}
	})
	_ = m.Store.Update(func(s *store.State) error { s.Prune(m.now()); return nil })
	for _, h := range hosts {
		if err := m.Ensure(h, false, false); err != nil {
			slog.Error("renewal failed", "host", h, "err", err)
		}
	}
}

// Run renews on startup and then hourly until ctx is done.
func (m *Manager) Run(ctx context.Context) {
	m.RenewAll()
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.RenewAll()
		}
	}
}

// Revoke marks a certificate revoked. If it belongs to an active managed
// service, a replacement with a fresh key is issued immediately.
func (m *Manager) Revoke(id int64) error {
	var host string
	err := m.Store.Update(func(s *store.State) error {
		c := s.Cert(id)
		if c == nil {
			return errors.New("certificate not found")
		}
		if c.Revoked {
			return errors.New("certificate is already revoked")
		}
		c.Revoked, c.RevokedAt = true, m.now()
		s.Log("warn", "cert", "Revoked certificate for %s (serial %s)", strings.Join(c.Names, ", "), c.Serial)
		if v := s.Service(c.Names[0]); v != nil && v.CertID == id && v.Enabled && v.Mode != store.ModeACME {
			host = v.Hostname
		}
		return nil
	})
	if err != nil {
		return err
	}
	m.changed()
	if host != "" {
		return m.Ensure(host, true, true)
	}
	return nil
}

// RemoveFiles deletes the service's files inside the data dir. Files in a
// user-chosen ExportDir are left alone.
func (m *Manager) RemoveFiles(host string) error {
	return os.RemoveAll(m.CertDir(host))
}

// TLSCertificate loads the service's key pair for the gateway.
func (m *Manager) TLSCertificate(host string) (*tls.Certificate, error) {
	dir := m.CertDir(host)
	c, err := tls.LoadX509KeyPair(filepath.Join(dir, FileCert), filepath.Join(dir, FileKey))
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func loadKey(path string) (crypto.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("bad key PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("unsupported key")
	}
	return s, nil
}

func writeKey(path string, k crypto.Signer) error {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return err
	}
	return store.WriteFileAtomic(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
}

func keyType(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", k.N.BitLen())
	}
	return "unknown"
}
