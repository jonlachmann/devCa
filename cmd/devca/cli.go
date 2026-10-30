package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/jonlachmann/devca/internal/certs"
	"github.com/jonlachmann/devca/internal/store"
)

// client talks to the running daemon's management API.
type client struct{ base string }

func newClient(dataDir string) *client {
	if u := os.Getenv("DEVCA_API"); u != "" {
		return &client{strings.TrimRight(u, "/")}
	}
	port := store.DefaultSettings().MgmtPort
	if st, err := store.Open(filepath.Join(dataDir, "state.json")); err == nil {
		st.View(func(s *store.State) { port = s.Settings.MgmtPort })
	}
	return &client{fmt.Sprintf("http://127.0.0.1:%d", port)}
}

func (c *client) do(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.base+path, body)
	req.Header.Set("X-DevCA", "1")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 90 * time.Second}).Do(req)
	if err != nil {
		return errors.New("DevCA is not running. Start it with `devca serve`, or `devca install` to run it in the background")
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		var e struct{ Error string }
		if json.Unmarshal(b, &e) == nil && e.Error != "" {
			return errors.New(e.Error)
		}
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

// upsert creates a service, or updates an existing one of the same mode.
// Options not given on the command line keep their current values, and a
// service in another mode is never converted behind the user's back.
func (c *client) upsert(host string, body map[string]any) (svcView, error) {
	var v svcView
	err := c.do("POST", "/api/services", body, &v)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		return v, err
	}
	var list []svcView
	if err := c.do("GET", "/api/services", nil, &list); err != nil {
		return v, err
	}
	for _, cur := range list {
		if !strings.EqualFold(cur.Hostname, host) {
			continue
		}
		if cur.Mode != body["mode"] {
			return v, fmt.Errorf("%s is already a %s service; change its mode in the web UI or remove it first", host, cur.Mode)
		}
		if body["exportDir"] == "" {
			body["exportDir"] = cur.ExportDir
		}
		if body["validationPort"] == 0 {
			body["validationPort"] = cur.ValidationPort
		}
		if body["passthrough"] == "" {
			body["passthrough"] = cur.Passthrough
		}
	}
	err = c.do("PUT", "/api/services/"+host, body, &v)
	return v, err
}

func table() *tabwriter.Writer { return tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0) }

type svcView struct {
	Hostname       string
	Address        string
	ExportDir      string
	ValidationPort int
	Passthrough    string
	Mode           string
	Target         string
	Enabled        bool
	URL            string
	CertDir        string
	Resolves       string
	Cert           *struct {
		ID       int64
		Status   string
		NotAfter time.Time
	}
	Health *struct {
		Up    bool
		Error string
	}
}

func cmdStatus(args []string) error {
	fs, data := flags("status")
	parse(fs, args)
	var s struct {
		Version string
		CA      struct {
			Fingerprint string
			NotAfter    time.Time
			Trust       struct {
				Trusted bool
				Detail  string
			}
		}
		Gateway struct {
			Enabled   bool
			Listeners []struct{ Addr, Error string }
		}
		Counts        map[string]int
		ACMEDirectory string
		MgmtURL       string
		DataDir       string
	}
	if err := newClient(*data).do("GET", "/api/status", nil, &s); err != nil {
		return err
	}
	w := table()
	fmt.Fprintf(w, "DevCA\t%s running\n", s.Version)
	fmt.Fprintf(w, "Web UI\t%s\n", s.MgmtURL)
	fmt.Fprintf(w, "ACME directory\t%s\n", s.ACMEDirectory)
	trust := "NOT trusted - run `devca trust install`"
	if s.CA.Trust.Trusted {
		trust = "trusted"
	}
	fmt.Fprintf(w, "Root CA\t%s, expires %s\n", trust, s.CA.NotAfter.Format(time.DateOnly))
	if !s.Gateway.Enabled {
		fmt.Fprintf(w, "Gateway\tdisabled\n")
	}
	for _, l := range s.Gateway.Listeners {
		st := "listening"
		if l.Error != "" {
			st = "FAILED: " + l.Error
		}
		fmt.Fprintf(w, "Gateway %s\t%s\n", l.Addr, st)
	}
	fmt.Fprintf(w, "Services\t%d\n", s.Counts["services"])
	fmt.Fprintf(w, "Active certificates\t%d (%d expiring soon)\n", s.Counts["activeCerts"], s.Counts["expiring"])
	if n := s.Counts["acmeFailures24h"]; n > 0 {
		fmt.Fprintf(w, "ACME failures (24h)\t%d\n", n)
	}
	fmt.Fprintf(w, "Data\t%s\n", s.DataDir)
	return w.Flush()
}

func cmdProxyAdd(args []string) error {
	fs, data := flags("proxy add")
	pos := parse(fs, args)
	if err := need(pos, 2, "proxy add <host> <target>   e.g. devca proxy add api.localhost 3000"); err != nil {
		return err
	}
	var v svcView
	err := newClient(*data).do("POST", "/api/services", map[string]any{"hostname": pos[0], "mode": "proxy", "target": pos[1]}, &v)
	if err != nil {
		return err
	}
	fmt.Printf("%s -> %s\n", v.URL, v.Target)
	printResolveHint(v)
	return nil
}

func printResolveHint(v svcView) {
	switch v.Resolves {
	case "missing":
		fmt.Printf("Note: %s is not in your hosts file yet. Run `devca hosts apply` so it resolves to this machine.\n", v.Hostname)
	case "browser":
		fmt.Printf("Works in Chrome, Firefox and Edge as-is. For Safari and CLI tools run `devca hosts apply`.\n")
	}
}

func cmdServiceList(args []string, mode string) error {
	fs, data := flags("list")
	parse(fs, args)
	var list []svcView
	if err := newClient(*data).do("GET", "/api/services", nil, &list); err != nil {
		return err
	}
	w := table()
	fmt.Fprintln(w, "HOST\tMODE\tTARGET\tCERT EXPIRES\tUPSTREAM")
	for _, v := range list {
		if mode != "" && v.Mode != mode {
			continue
		}
		exp, up := "-", "-"
		if v.Cert != nil {
			exp = v.Cert.NotAfter.Format(time.DateOnly) + " (" + v.Cert.Status + ")"
		}
		if v.Health != nil {
			up = map[bool]string{true: "up", false: "down"}[v.Health.Up]
		}
		if !v.Enabled {
			up = "disabled"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", v.Hostname, v.Mode, or(v.Target, v.CertDir), exp, up)
	}
	return w.Flush()
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func cmdServiceRemove(args []string) error {
	fs, data := flags("remove")
	pos := parse(fs, args)
	if err := need(pos, 1, "proxy remove <host>"); err != nil {
		return err
	}
	if err := newClient(*data).do("DELETE", "/api/services/"+pos[0], nil, nil); err != nil {
		return err
	}
	fmt.Println("Removed", pos[0])
	return nil
}

type certRow struct {
	ID         int64
	Names      []string
	NotAfter   time.Time
	Status     string
	OwnerLabel string
	Serial     string
	Current    bool
}

func cmdCertList(args []string) error {
	fs, data := flags("cert list")
	all := fs.Bool("all", false, "include superseded, revoked and test certificates")
	parse(fs, args)
	var list []certRow
	if err := newClient(*data).do("GET", "/api/certs", nil, &list); err != nil {
		return err
	}
	w := table()
	fmt.Fprintln(w, "ID\tNAMES\tSTATUS\tEXPIRES\tOWNER")
	for _, c := range list {
		if !*all && (c.Status == "revoked" || c.Status == "expired" || c.OwnerLabel == "ACME self-test" ||
			(strings.HasPrefix(c.OwnerLabel, "DevCA") && !c.Current)) {
			continue
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", c.ID, strings.Join(c.Names, ","), c.Status, c.NotAfter.Format(time.DateOnly), c.OwnerLabel)
	}
	return w.Flush()
}

func cmdCertIssue(args []string) error {
	fs, data := flags("cert issue")
	out := fs.String("out", "", "also write the files to this directory (kept up to date on renewal)")
	addr := fs.String("address", "", "loopback address for the hosts file, e.g. 127.0.0.2 (to share a port with another service)")
	forward := fs.String("forward", "", "forward https://<host> on port 443, still encrypted, to your app's own TLS port, e.g. 8443")
	pos := parse(fs, args)
	if err := need(pos, 1, "cert issue <host> [--out dir]"); err != nil {
		return err
	}
	dir := *out
	if dir != "" {
		var err error
		if dir, err = filepath.Abs(dir); err != nil {
			return err
		}
	}
	c := newClient(*data)
	body := map[string]any{"hostname": pos[0], "mode": "export", "exportDir": dir, "passthrough": *forward}
	if *addr != "" {
		body["address"] = *addr
	}
	v, err := c.upsert(pos[0], body)
	if err != nil {
		return err
	}
	fmt.Printf("Certificate for %s, renewed automatically:\n", v.Hostname)
	if v.Address != "" {
		fmt.Printf("Hosts entry: %s %s (bind your app to that address)\n", v.Address, v.Hostname)
	}
	if v.Passthrough != "" {
		fmt.Printf("%s is forwarded, still encrypted, to %s\n", v.URL, v.Passthrough)
	}
	for _, d := range []string{v.CertDir, dir} {
		if d == "" {
			continue
		}
		fmt.Printf("  %s\n  %s\n", filepath.Join(d, certs.FileCert), filepath.Join(d, certs.FileKey))
	}
	fmt.Println("Files are replaced atomically on renewal (same key). Reload your app when certificate.pem changes.")
	printResolveHint(v)
	return nil
}

func cmdCertRenew(args []string) error {
	fs, data := flags("cert renew")
	pos := parse(fs, args)
	if err := need(pos, 1, "cert renew <host>"); err != nil {
		return err
	}
	var v svcView
	if err := newClient(*data).do("POST", "/api/services/"+pos[0]+"/renew", nil, &v); err != nil {
		return err
	}
	fmt.Printf("Renewed %s, valid until %s\n", v.Hostname, v.Cert.NotAfter.Format(time.DateOnly))
	return nil
}

func cmdCertRevoke(args []string) error {
	fs, data := flags("cert revoke")
	pos := parse(fs, args)
	if err := need(pos, 1, "cert revoke <host|id>"); err != nil {
		return err
	}
	c := newClient(*data)
	id, err := strconv.ParseInt(pos[0], 10, 64)
	if err != nil {
		var list []svcView
		if err := c.do("GET", "/api/services", nil, &list); err != nil {
			return err
		}
		for _, v := range list {
			if strings.EqualFold(v.Hostname, pos[0]) && v.Cert != nil {
				id = v.Cert.ID
			}
		}
		if id == 0 {
			return fmt.Errorf("no current certificate for %s (use the certificate ID from `devca cert list --all`)", pos[0])
		}
	}
	if err := c.do("POST", fmt.Sprintf("/api/certs/%d/revoke", id), nil, nil); err != nil {
		return err
	}
	fmt.Printf("Revoked certificate %d. Managed services get a new certificate with a new key immediately.\n", id)
	return nil
}

func cmdCertExport(args []string) error {
	fs, data := flags("cert export")
	out := fs.String("out", "", "destination directory")
	pos := parse(fs, args)
	if err := need(pos, 1, "cert export <host> --out <dir>"); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("--out is required")
	}
	src := filepath.Join(*data, "certs", strings.ToLower(pos[0]))
	for _, f := range []string{certs.FileCert, certs.FileKey, certs.FileBundle, certs.FileCA} {
		b, err := os.ReadFile(filepath.Join(src, f))
		if err != nil {
			return fmt.Errorf("%s has no exported certificate (is it a proxy/export service?): %w", pos[0], err)
		}
		perm := os.FileMode(0o644)
		if f == certs.FileKey || f == certs.FileBundle {
			perm = 0o600
		}
		if err := store.WriteFileAtomic(filepath.Join(*out, f), b, perm); err != nil {
			return err
		}
	}
	fmt.Printf("Wrote %s, %s, %s and %s to %s (one-off copy; use `devca cert issue --out` for automatic updates)\n",
		certs.FileCert, certs.FileKey, certs.FileBundle, certs.FileCA, *out)
	return nil
}

func cmdACMEInfo(args []string) error {
	fs, data := flags("acme info")
	parse(fs, args)
	var info struct {
		Directory string
		Accounts  []struct {
			ID       int64
			Contact  []string
			Status   string
			Internal bool
			Orders   int
		}
		Failures []store.Event
	}
	if err := newClient(*data).do("GET", "/api/acme", nil, &info); err != nil {
		return err
	}
	fmt.Println("Directory:", info.Directory)
	fmt.Println("Challenges: http-01 (validated locally against loopback)")
	fmt.Printf("\nExample: lego --server %s --email you@example.com --domains app.localhost --http run\n\n", info.Directory)
	w := table()
	fmt.Fprintln(w, "ACCOUNT\tSTATUS\tORDERS\tCONTACT")
	for _, a := range info.Accounts {
		contact := strings.Join(a.Contact, ",")
		if a.Internal {
			contact = "(devca self-test)"
		}
		fmt.Fprintf(w, "%d\t%s\t%d\t%s\n", a.ID, a.Status, a.Orders, contact)
	}
	w.Flush()
	for _, f := range info.Failures {
		fmt.Printf("%s  %s\n", f.Time.Format(time.DateTime), f.Message)
	}
	return nil
}

func cmdACMEClaim(args []string) error {
	fs, data := flags("acme claim")
	port := fs.Int("port", 0, "port where your ACME client serves HTTP-01 (if DevCA's gateway holds port 80)")
	addr := fs.String("address", "", "loopback address for the hosts file and HTTP-01 validation, e.g. 127.0.0.2")
	forward := fs.String("forward", "", "forward https://<host> on port 443, still encrypted, to your app's own TLS port, e.g. 8443")
	pos := parse(fs, args)
	if err := need(pos, 1, "acme claim <host> [--port n]"); err != nil {
		return err
	}
	c := newClient(*data)
	body := map[string]any{"hostname": pos[0], "mode": "acme", "validationPort": *port, "passthrough": *forward}
	if *addr != "" {
		body["address"] = *addr
	}
	v, err := c.upsert(pos[0], body)
	if err != nil {
		return err
	}
	fmt.Printf("%s is reserved for an external ACME client. DevCA will not issue or renew it itself.\n", v.Hostname)
	if v.Passthrough != "" {
		fmt.Printf("%s is forwarded, still encrypted, to %s\n", v.URL, v.Passthrough)
	}
	return nil
}

func cmdTestACME(args []string) error {
	fs, data := flags("test acme")
	pos := parse(fs, args)
	if err := need(pos, 1, "test acme <host>"); err != nil {
		return err
	}
	fmt.Printf("Testing ACME issuance for %s against the running DevCA...\n\n", pos[0])
	var res struct {
		OK    bool
		Steps []struct {
			Name, Detail, Hint string
			OK                 bool
			Ms                 int64
		}
	}
	if err := newClient(*data).do("POST", "/api/test/acme", map[string]string{"hostname": pos[0]}, &res); err != nil {
		return err
	}
	for _, s := range res.Steps {
		mark := "✓"
		if !s.OK {
			mark = "✗"
		}
		fmt.Printf("%s %s (%dms)\n", mark, s.Name, s.Ms)
		if s.Detail != "" {
			fmt.Printf("    %s\n", s.Detail)
		}
		if s.Hint != "" {
			fmt.Printf("    hint: %s\n", s.Hint)
		}
	}
	if !res.OK {
		return errors.New("ACME test failed")
	}
	fmt.Println("\nACME workflow OK.")
	return nil
}
