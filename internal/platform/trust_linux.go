package platform

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
)

// Distro trust anchors, first existing directory wins.
var anchors = []struct {
	dir    string
	update []string
}{
	{"/usr/local/share/ca-certificates", []string{"update-ca-certificates"}},           // Debian, Ubuntu, Alpine
	{"/etc/pki/ca-trust/source/anchors", []string{"update-ca-trust", "extract"}},       // Fedora, RHEL
	{"/etc/ca-certificates/trust-source/anchors", []string{"trust", "extract-compat"}}, // Arch
	{"/usr/share/pki/trust/anchors", []string{"update-ca-certificates"}},               // openSUSE
}

const anchorName = "devca-root.crt"

func anchorDir() (string, []string) {
	for _, a := range anchors {
		if st, err := os.Stat(a.dir); err == nil && st.IsDir() {
			return a.dir, a.update
		}
	}
	return "", nil
}

func TrustInstall(root *x509.Certificate, certPath string) error {
	dir, update := anchorDir()
	if dir == "" {
		return errNoAnchors
	}
	if err := RunPrivileged("install", "-m", "0644", certPath, filepath.Join(dir, anchorName)); err != nil {
		return err
	}
	if err := RunPrivileged(update[0], update[1:]...); err != nil {
		return err
	}
	return nssEach(func(db string) error {
		return Run("certutil", "-A", "-d", "sql:"+db, "-t", "C,,", "-n", nssName(root), "-i", certPath)
	})
}

func TrustUninstall(root *x509.Certificate, certPath string) error {
	_ = nssEach(func(db string) error { return Run("certutil", "-D", "-d", "sql:"+db, "-n", nssName(root)) })
	dir, update := anchorDir()
	if dir == "" {
		return nil
	}
	if err := RunPrivileged("rm", "-f", filepath.Join(dir, anchorName)); err != nil {
		return err
	}
	return RunPrivileged(update[0], update[1:]...)
}

// TrustCheck reads the anchor file directly: Go caches the system pool per
// process, so a fresh Verify would miss a trust installed after startup.
func TrustCheck(root, leaf *x509.Certificate) TrustStatus {
	var notes []string
	if len(nssDBs()) > 0 {
		if _, err := exec.LookPath("certutil"); err != nil {
			notes = append(notes, "Firefox and Chrome on Linux use their own NSS store. Install certutil (libnss3-tools / nss-tools) and run `devca trust install` again.")
		} else {
			notes = append(notes, "Firefox/Chrome NSS stores are updated by `devca trust install`.")
		}
	}
	dir, _ := anchorDir()
	if dir == "" {
		return TrustStatus{Detail: errNoAnchors.Error(), Notes: notes}
	}
	b, err := os.ReadFile(filepath.Join(dir, anchorName))
	if err != nil {
		return TrustStatus{Detail: "Not installed in " + dir, Notes: notes}
	}
	blk, _ := pem.Decode(b)
	if blk == nil || !bytes.Equal(blk.Bytes, root.Raw) {
		return TrustStatus{Detail: "A different DevCA root is installed in " + dir + "; run `devca trust install`", Notes: notes}
	}
	return TrustStatus{Trusted: true, Detail: "Installed in " + dir, Notes: notes}
}

// nssDBs lists the user's NSS databases (Chrome and Firefox profiles).
func nssDBs() []string {
	home, _ := os.UserHomeDir()
	var dbs []string
	if _, err := os.Stat(filepath.Join(home, ".pki/nssdb/cert9.db")); err == nil {
		dbs = append(dbs, filepath.Join(home, ".pki/nssdb"))
	}
	for _, pat := range []string{".mozilla/firefox/*", "snap/firefox/common/.mozilla/firefox/*"} {
		m, _ := filepath.Glob(filepath.Join(home, pat, "cert9.db"))
		for _, f := range m {
			dbs = append(dbs, filepath.Dir(f))
		}
	}
	return dbs
}

func nssEach(fn func(db string) error) error {
	if _, err := exec.LookPath("certutil"); err != nil {
		return nil
	}
	for _, db := range nssDBs() {
		if err := fn(db); err != nil {
			return err
		}
	}
	return nil
}

func nssName(root *x509.Certificate) string { return "DevCA " + sha1Hex(root)[:8] }
