package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/jonlachmann/devca/internal/acme"
	"github.com/jonlachmann/devca/internal/api"
	"github.com/jonlachmann/devca/internal/ca"
	"github.com/jonlachmann/devca/internal/certs"
	"github.com/jonlachmann/devca/internal/gateway"
	"github.com/jonlachmann/devca/internal/platform"
	"github.com/jonlachmann/devca/internal/store"
	"github.com/jonlachmann/devca/web"
)

// loadOrCreateCA never regenerates an existing (even broken) CA.
func loadOrCreateCA(dir string, st *store.Store) (*ca.CA, bool, error) {
	if ca.Exists(dir) {
		c, err := ca.Load(dir)
		return c, false, err
	}
	c, err := ca.Create(dir, ca.DefaultSuffixes)
	if err == nil {
		st.Log("info", "ca", "Created local root CA %s", c.Fingerprint())
	}
	return c, err == nil, err
}

func openData(dir string) (*store.Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return store.Open(filepath.Join(dir, "state.json"))
}

func cmdServe(args []string) error {
	fs, data := flags("serve")
	background := fs.Bool("background", false, "detach from the console and log to devca.log (used by the Windows startup entry)")
	parse(fs, args)
	dir, err := filepath.Abs(*data)
	if err != nil {
		return err
	}

	if *background {
		platform.DetachConsole()
		f, err := os.OpenFile(filepath.Join(dir, "devca.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err == nil {
			os.Stdout, os.Stderr = f, f
		}
	}
	st, err := openData(dir)
	if err != nil {
		return err
	}
	var settings store.Settings
	st.View(func(s *store.State) { settings = s.Settings })
	level := slog.LevelInfo
	_ = level.UnmarshalText([]byte(settings.LogLevel))
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	root, created, err := loadOrCreateCA(dir, st)
	if err != nil {
		return err
	}
	if created {
		slog.Info("created local root CA", "fingerprint", root.Fingerprint())
	}

	mgr := &certs.Manager{CA: root, Store: st, Dir: dir}
	gw := &gateway.Gateway{Store: st, Certs: mgr, HTTPSPort: settings.HTTPSPort}
	mgr.OnChange = gw.Reload
	acmeSrv := &acme.Server{Store: st, Certs: mgr, Validator: &acme.Validator{}, GatewayHTTPPort: settings.HTTPPort}
	acmeSrv.Recover()
	acmeCert := &selfCert{ca: root}

	a := &api.API{
		Version: version, DataDir: dir, Store: st, Certs: mgr, Gateway: gw, UI: web.Dist(),
		MgmtPort: settings.MgmtPort, ACMEPort: settings.ACMEPort,
		HTTPPort: settings.HTTPPort, HTTPSPort: settings.HTTPSPort,
		ACMELeaf: acmeCert.leaf,
		Running:  settings,
		SelfTest: &acme.SelfTest{
			Server:       acmeSrv,
			DirectoryURL: fmt.Sprintf("https://localhost:%d/acme/directory", settings.ACMEPort),
			Roots:        root.Pool(),
			KeyPath:      filepath.Join(dir, "acme-test.key"),
			Publish:      gw.Publish,
			Unpublish:    gw.Unpublish,
		},
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	mgmt := &http.Server{Handler: a.Handler(), ReadHeaderTimeout: 10 * time.Second}
	acmeHTTP := &http.Server{Handler: acmeSrv.Handler(), ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{GetCertificate: acmeCert.get, MinVersion: tls.VersionTLS12}}
	if err := listenLoopback(mgmt, settings.MgmtPort, false, true); err != nil {
		return fmt.Errorf("management port %d: %w (is DevCA already running? check `devca status`)", settings.MgmtPort, err)
	}
	if err := listenLoopback(acmeHTTP, settings.ACMEPort, true, false); err != nil {
		slog.Error("ACME listener failed", "port", settings.ACMEPort, "err", err)
		st.Log("error", "acme", "ACME listener could not start on port %d: %v", settings.ACMEPort, err)
	}

	var wg sync.WaitGroup
	wg.Go(func() { mgr.Run(ctx) })
	if settings.GatewayEnabled {
		wg.Go(func() { gw.Serve(ctx, settings.HTTPPort, settings.HTTPSPort) })
	} else {
		gw.Reload()
	}

	slog.Info("DevCA running",
		"ui", fmt.Sprintf("http://127.0.0.1:%d", settings.MgmtPort),
		"acme", fmt.Sprintf("https://localhost:%d/acme/directory", settings.ACMEPort),
		"data", dir)
	<-ctx.Done()
	slog.Info("shutting down")
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = mgmt.Shutdown(shutdown)
	_ = acmeHTTP.Shutdown(shutdown)
	acmeSrv.Wait()
	wg.Wait()
	return nil
}

// listenLoopback serves srv on 127.0.0.1 and ::1. Only the IPv4 bind is
// required; IPv6 loopback may be disabled on some systems.
func listenLoopback(srv *http.Server, port int, useTLS, required bool) error {
	for i, ip := range []string{"127.0.0.1", "::1"} {
		ln, err := net.Listen("tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
		if err != nil {
			if i == 0 {
				return err
			}
			slog.Warn("IPv6 loopback listen failed", "port", port, "err", err)
			continue
		}
		go func() {
			var err error
			if useTLS {
				err = srv.ServeTLS(ln, "", "")
			} else {
				err = srv.Serve(ln)
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("listener stopped", "addr", ln.Addr(), "err", err)
			}
		}()
	}
	return nil
}

// selfCert is the ACME listener's own certificate (localhost + loopback IPs).
// It is issued straight from the CA and not recorded as a managed cert, and is
// regenerated in memory whenever it gets within 10 days of expiry.
type selfCert struct {
	ca   *ca.CA
	mu   sync.Mutex
	cert *tls.Certificate
}

func (s *selfCert) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cert == nil || time.Until(s.cert.Leaf.NotAfter) < 10*24*time.Hour {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		leaf, err := s.ca.Issue([]string{"localhost", "127.0.0.1", "::1"}, key.Public(), 30*24*time.Hour)
		if err != nil {
			return nil, err
		}
		s.cert = &tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}
	}
	return s.cert, nil
}

func (s *selfCert) leaf() *x509.Certificate {
	c, err := s.get(nil)
	if err != nil {
		return nil
	}
	return c.Leaf
}
