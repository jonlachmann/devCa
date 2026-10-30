package certs

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jonlachmann/devca/internal/ca"
	"github.com/jonlachmann/devca/internal/store"
)

func newManager(t *testing.T) *Manager {
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
	return &Manager{CA: c, Store: st, Dir: dir}
}

func addService(t *testing.T, m *Manager, svc store.Service) {
	t.Helper()
	if err := m.Store.Update(func(s *store.State) error {
		s.Services = append(s.Services, &svc)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func serviceCert(m *Manager, host string) (c store.Cert) {
	m.Store.View(func(s *store.State) { c = *s.Cert(s.Service(host).CertID) })
	return
}

func TestEnsureRenewalAndKeyReuse(t *testing.T) {
	m := newManager(t)
	export := t.TempDir()
	addService(t, m, store.Service{Hostname: "api.localhost", Mode: store.ModeExport, Enabled: true, AutoRenew: true, ExportDir: export})

	if err := m.Ensure("api.localhost", false, false); err != nil {
		t.Fatal(err)
	}
	first := serviceCert(m, "api.localhost")
	key1, _ := os.ReadFile(filepath.Join(export, FileKey))

	// Not due: no new cert.
	m.RenewAll()
	if serviceCert(m, "api.localhost").ID != first.ID {
		t.Fatal("renewed too early")
	}

	// 25 days later (30-day cert, renew at <10 days left): due.
	m.Now = func() time.Time { return time.Now().Add(25 * 24 * time.Hour) }
	m.RenewAll()
	second := serviceCert(m, "api.localhost")
	if second.ID == first.ID {
		t.Fatal("did not renew")
	}
	key2, _ := os.ReadFile(filepath.Join(export, FileKey))
	if string(key1) != string(key2) {
		t.Fatal("key should be reused on renewal")
	}
	if _, err := m.TLSCertificate("api.localhost"); err != nil {
		t.Fatal(err)
	}

	// Revoke rotates the key and re-issues.
	m.Now = nil
	if err := m.Revoke(second.ID); err != nil {
		t.Fatal(err)
	}
	key3, _ := os.ReadFile(filepath.Join(export, FileKey))
	if string(key3) == string(key2) || serviceCert(m, "api.localhost").ID == second.ID {
		t.Fatal("revoke should rekey and re-issue")
	}
}

func TestRevokedKeyNeverReused(t *testing.T) {
	m := newManager(t)
	addService(t, m, store.Service{Hostname: "a.localhost", Mode: store.ModeExport, Enabled: true, AutoRenew: true})
	if err := m.Ensure("a.localhost", false, false); err != nil {
		t.Fatal(err)
	}
	key1, _ := os.ReadFile(filepath.Join(m.CertDir("a.localhost"), FileKey))
	// Disable, revoke, re-enable: the renewal must use a fresh key.
	_ = m.Store.Update(func(s *store.State) error { s.Service("a.localhost").Enabled = false; return nil })
	if err := m.Revoke(serviceCert(m, "a.localhost").ID); err != nil {
		t.Fatal(err)
	}
	_ = m.Store.Update(func(s *store.State) error { s.Service("a.localhost").Enabled = true; return nil })
	m.RenewAll()
	key2, _ := os.ReadFile(filepath.Join(m.CertDir("a.localhost"), FileKey))
	if len(key2) == 0 || string(key1) == string(key2) {
		t.Fatal("revoked key was reused")
	}
}

func TestMissingKeyRecovers(t *testing.T) {
	m := newManager(t)
	addService(t, m, store.Service{Hostname: "a.localhost", Mode: store.ModeProxy, Enabled: true, AutoRenew: true})
	m.Ensure("a.localhost", false, false)
	os.Remove(filepath.Join(m.CertDir("a.localhost"), FileKey))
	if err := m.Ensure("a.localhost", false, false); err != nil {
		t.Fatal(err)
	}
	if _, err := m.TLSCertificate("a.localhost"); err != nil {
		t.Fatal(err)
	}
}

func TestBrokenExportDirDoesNotReissueForever(t *testing.T) {
	m := newManager(t)
	blocker := filepath.Join(t.TempDir(), "file")
	os.WriteFile(blocker, nil, 0o600) // a file where a directory is expected
	addService(t, m, store.Service{Hostname: "a.localhost", Mode: store.ModeExport, Enabled: true, AutoRenew: true, ExportDir: filepath.Join(blocker, "sub")})
	if err := m.Ensure("a.localhost", false, false); err == nil {
		t.Fatal("expected export error")
	}
	first := serviceCert(m, "a.localhost").ID
	m.RenewAll()
	m.RenewAll()
	if serviceCert(m, "a.localhost").ID != first {
		t.Fatal("re-issued because the export directory is broken")
	}
}

func TestEnsureRejectsACMEOwned(t *testing.T) {
	m := newManager(t)
	addService(t, m, store.Service{Hostname: "x.local", Mode: store.ModeACME, Enabled: true})
	if err := m.Ensure("x.local", true, false); err == nil {
		t.Fatal("acme-mode service must not be issued by the manager")
	}
}
