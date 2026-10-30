package main

// Commands that work on local files and the OS directly, without the daemon.

import (
	"archive/zip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/jonlachmann/devca/internal/ca"
	"github.com/jonlachmann/devca/internal/platform"
	"github.com/jonlachmann/devca/internal/store"
)

func loadCA(dir string) (*ca.CA, error) {
	if !ca.Exists(dir) {
		return nil, fmt.Errorf("no CA in %s yet; run `devca install` or `devca serve` first", dir)
	}
	return ca.Load(dir)
}

func rootPath(dir string) string { return filepath.Join(dir, "ca", "root.pem") }

func cmdInstall(args []string) error {
	fs, data := flags("install")
	yes := fs.Bool("yes", false, "answer yes to all questions")
	parse(fs, args)
	dir := *data

	st, err := openData(dir)
	if err != nil {
		return err
	}
	root, created, err := loadOrCreateCA(dir, st)
	if err != nil {
		return err
	}
	if created {
		fmt.Println("✓ Created your local certificate authority")
	} else {
		fmt.Println("✓ Using your existing certificate authority")
	}
	fmt.Printf("  Fingerprint (SHA-256): %s\n  Stored in: %s\n\n", root.Fingerprint(), filepath.Join(dir, "ca"))

	if trustStatus(root).Trusted {
		fmt.Println("✓ The root certificate is already trusted by this system")
	} else {
		explainTrust(root)
		if *yes || confirm("Trust the DevCA root certificate now?", false) {
			if err := platform.TrustInstall(root.Cert, rootPath(dir)); err != nil {
				fmt.Println("✗ Trust installation failed:", err)
				fmt.Println("  You can retry later with `devca trust install`.")
			} else {
				fmt.Println("✓ Root certificate trusted")
			}
		} else {
			fmt.Println("  Skipped. Run `devca trust install` when you're ready.")
		}
	}
	fmt.Println()

	exe, err := os.Executable()
	if err == nil {
		exe, _ = filepath.EvalSymlinks(exe)
	}
	if err != nil || strings.Contains(exe, "go-build") {
		fmt.Println("Not installing a background service: run `devca install` from the built binary, not `go run`.")
		return nil
	}
	fmt.Printf("DevCA can start automatically when you log in, as %s.\n", platform.ServiceDescription())
	if *yes || confirm("Run DevCA in the background?", true) {
		if err := platform.ServiceInstall(exe, dir); err != nil {
			return fmt.Errorf("background service: %w (you can still run `devca serve` manually)", err)
		}
		fmt.Println("✓ DevCA is running in the background")
	} else {
		fmt.Println("  Skipped. Start it with `devca serve`.")
	}
	var port int
	st.View(func(s *store.State) { port = s.Settings.MgmtPort })
	fmt.Printf("\nOpen http://127.0.0.1:%d to add your first service, or run:\n  devca proxy add app.localhost 3000\n", port)
	return nil
}

func cmdUninstall(args []string) error {
	fs, data := flags("uninstall")
	parse(fs, args)
	if err := platform.ServiceUninstall(); err != nil {
		return err
	}
	fmt.Println("✓ Background service removed.")
	fmt.Printf(`
Kept, so nothing breaks unexpectedly:
  - your CA, certificates and settings in %s
  - the root certificate in the system trust store  (remove: devca trust uninstall)
  - DevCA's hosts-file entries                      (remove: devca hosts remove)
`, *data)
	return nil
}

func explainTrust(root *ca.CA) {
	fmt.Println(`Trusting the root certificate lets your browsers accept DevCA certificates
without warnings. This is a security-sensitive change: anything signed by this
root will be trusted by this computer. DevCA's root is restricted to these names:`)
	for _, s := range root.Suffixes() {
		fmt.Printf("    *.%s\n", s)
	}
	fmt.Println(`    127.0.0.0/8 and ::1
so it cannot be used to impersonate public websites, even if its key leaked.
Your administrator password may be requested.`)
	fmt.Println()
}

func trustStatus(root *ca.CA) platform.TrustStatus {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf, err := root.Issue([]string{"localhost"}, k.Public(), time.Hour)
	if err != nil {
		return platform.TrustStatus{Detail: err.Error()}
	}
	return platform.TrustCheck(root.Cert, leaf)
}

func cmdTrustInstall(args []string) error {
	fs, data := flags("trust install")
	yes := fs.Bool("yes", false, "don't ask for confirmation")
	parse(fs, args)
	root, err := loadCA(*data)
	if err != nil {
		return err
	}
	explainTrust(root)
	if !*yes && !confirm("Trust the DevCA root certificate?", false) {
		return errors.New("cancelled")
	}
	if err := platform.TrustInstall(root.Cert, rootPath(*data)); err != nil {
		return fmt.Errorf("%w\nYou can import %s manually; see the README", err, rootPath(*data))
	}
	return printTrust(root)
}

func printTrust(root *ca.CA) error {
	s := trustStatus(root)
	mark := "✗"
	if s.Trusted {
		mark = "✓"
	}
	fmt.Printf("%s %s\n", mark, s.Detail)
	for _, n := range s.Notes {
		fmt.Println("  note:", n)
	}
	fmt.Println("  Restart your browser if it was open.")
	return nil
}

func cmdTrustUninstall(args []string) error {
	fs, data := flags("trust uninstall")
	parse(fs, args)
	root, err := loadCA(*data)
	if err != nil {
		return err
	}
	if !confirm("Remove the DevCA root from the system trust store? DevCA certificates will show browser warnings afterwards.", false) {
		return errors.New("cancelled")
	}
	if err := platform.TrustUninstall(root.Cert, rootPath(*data)); err != nil {
		return err
	}
	fmt.Println("✓ Root certificate removed from the system trust store")
	return nil
}

func cmdTrustStatus(args []string) error {
	fs, data := flags("trust status")
	parse(fs, args)
	root, err := loadCA(*data)
	if err != nil {
		return err
	}
	return printTrust(root)
}

func cmdHosts(args []string, action string) error {
	fs, data := flags("hosts " + action)
	yes := fs.Bool("yes", false, "don't ask for confirmation")
	parse(fs, args)
	path := platform.HostsPath()
	cur, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var hosts []string
	if action != "remove" {
		st, err := store.Open(filepath.Join(*data, "state.json"))
		if err != nil {
			return err
		}
		st.View(func(s *store.State) {
			for _, v := range s.Services {
				hosts = append(hosts, v.Hostname)
			}
		})
	}
	next := platform.RenderHosts(string(cur), hosts)
	if next == string(cur) {
		fmt.Printf("%s is up to date.\n", path)
		return nil
	}
	fmt.Printf("Changes to %s (only DevCA's marked block is touched):\n\n%s\n", path, platform.HostsDiff(string(cur), next))
	if action == "plan" {
		fmt.Println("Apply with: devca hosts apply")
		return nil
	}
	if !*yes && !confirm("Apply these changes? Your administrator password may be requested.", false) {
		return errors.New("cancelled")
	}
	if err := platform.WriteHosts(next); err != nil {
		return err
	}
	fmt.Println("✓ Hosts file updated. Undo any time with `devca hosts remove`.")
	return nil
}

func cmdCAInfo(args []string) error {
	fs, data := flags("ca info")
	parse(fs, args)
	root, err := loadCA(*data)
	if err != nil {
		return err
	}
	w := table()
	fmt.Fprintf(w, "Subject\t%s\n", root.Cert.Subject.CommonName)
	fmt.Fprintf(w, "Fingerprint (SHA-256)\t%s\n", root.Fingerprint())
	fmt.Fprintf(w, "Valid\t%s to %s\n", root.Cert.NotBefore.Format(time.DateOnly), root.Cert.NotAfter.Format(time.DateOnly))
	fmt.Fprintf(w, "Allowed names\t.%s, loopback IPs\n", strings.Join(root.Suffixes(), ", ."))
	fmt.Fprintf(w, "Certificate\t%s\n", rootPath(*data))
	fmt.Fprintf(w, "Trust\t%s\n", trustStatus(root).Detail)
	return w.Flush()
}

func cmdCAExport(args []string) error {
	fs, data := flags("ca export")
	out := fs.String("out", "", "write to file instead of stdout")
	parse(fs, args)
	root, err := loadCA(*data)
	if err != nil {
		return err
	}
	if *out == "" {
		_, err = os.Stdout.Write(root.CertPEM)
		return err
	}
	return store.WriteFileAtomic(*out, root.CertPEM, 0o644)
}

// backupFiles are the data-dir paths included in a backup.
var backupFiles = []string{"ca", "certs", "state.json", "acme-test.key"}

func cmdCABackup(args []string) error {
	set, data := flags("ca backup")
	pos := parse(set, args)
	if err := need(pos, 1, "ca backup <file.zip>"); err != nil {
		return err
	}
	f, err := os.OpenFile(pos[0], os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	zw := zip.NewWriter(f)
	for _, name := range backupFiles {
		root := filepath.Join(*data, name)
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			if err != nil || d.IsDir() {
				return err
			}
			rel, _ := filepath.Rel(*data, p)
			w, err := zw.Create(filepath.ToSlash(rel))
			if err != nil {
				return err
			}
			src, err := os.Open(p)
			if err != nil {
				return err
			}
			defer src.Close()
			_, err = io.Copy(w, src)
			return err
		})
		if err != nil {
			f.Close()
			os.Remove(pos[0])
			return err
		}
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Printf("✓ Backup written to %s\n  It contains the CA private key: keep it somewhere safe.\n", pos[0])
	return nil
}

func cmdCARestore(args []string) error {
	fs, data := flags("ca restore")
	force := fs.Bool("force", false, "overwrite an existing CA")
	pos := parse(fs, args)
	if err := need(pos, 1, "ca restore <file.zip> [--force]"); err != nil {
		return err
	}
	if ca.Exists(*data) && !*force {
		return fmt.Errorf("a CA already exists in %s; stop DevCA and pass --force to replace it", *data)
	}
	zr, err := zip.OpenReader(pos[0])
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, zf := range zr.File {
		// Only restore known, relative paths: no zip-slip.
		name := filepath.FromSlash(zf.Name)
		top := strings.SplitN(filepath.ToSlash(name), "/", 2)[0]
		if !filepath.IsLocal(name) || !slices.Contains(backupFiles, top) || zf.FileInfo().IsDir() {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return err
		}
		b, err := io.ReadAll(io.LimitReader(rc, 16<<20))
		rc.Close()
		if err != nil {
			return err
		}
		perm := os.FileMode(0o600)
		if strings.HasSuffix(name, ".pem") && !strings.Contains(name, "key") {
			perm = 0o644
		}
		if err := store.WriteFileAtomic(filepath.Join(*data, name), b, perm); err != nil {
			return err
		}
	}
	root, err := ca.Load(*data)
	if err != nil {
		return fmt.Errorf("restored files are not a valid CA: %w", err)
	}
	fmt.Printf("✓ Restored CA %s\n  Restart DevCA to use it.\n", root.Fingerprint())
	return nil
}
