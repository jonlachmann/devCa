package acme

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jonlachmann/devca/internal/store"
)

// Validator performs LOCAL HTTP-01 validation. It only ever connects to
// loopback addresses, so a pass proves the name resolves to this machine and
// the client served the token; it says nothing about public reachability.
type Validator struct {
	// Resolve maps a hostname to addresses. Nil uses DefaultResolve.
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
}

// DefaultResolve treats *.localhost as loopback (RFC 6761) and uses the
// system resolver (which honours the hosts file) for everything else.
func DefaultResolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	for i := range addrs {
		addrs[i] = addrs[i].Unmap()
	}
	return addrs, err
}

func resolveLoopback(ctx context.Context, resolve func(context.Context, string) ([]netip.Addr, error), host string) (netip.Addr, *store.Problem) {
	addrs, err := resolve(ctx, host)
	if err != nil || len(addrs) == 0 {
		return netip.Addr{}, &store.Problem{Type: errDNS, Detail: fmt.Sprintf(
			"%s does not resolve. Add it to the hosts file (devca hosts apply) or use a .localhost name.", host)}
	}
	for _, a := range addrs {
		if !a.IsLoopback() {
			return netip.Addr{}, &store.Problem{Type: errRejectedIdentifier, Detail: fmt.Sprintf(
				"%s resolves to %s, which is not this machine. DevCA only performs local validation against loopback addresses.", host, a)}
		}
	}
	return addrs[0], nil
}

// HTTP01 fetches http://host:port/.well-known/acme-challenge/token and
// compares it to keyAuth. It returns nil on success. A non-empty pin is the
// service's configured loopback address and is used instead of resolving host.
func (v *Validator) HTTP01(ctx context.Context, host, pin string, port int, token, keyAuth string) *store.Problem {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resolve := v.Resolve
	if resolve == nil {
		resolve = DefaultResolve
	}
	if ip, err := netip.ParseAddr(pin); err == nil {
		base := resolve
		resolve = func(ctx context.Context, h string) ([]netip.Addr, error) {
			if h == host {
				return []netip.Addr{ip}, nil
			}
			return base(ctx, h)
		}
	}
	if _, p := resolveLoopback(ctx, resolve, host); p != nil {
		return p
	}
	var dialErr atomic.Pointer[store.Problem]
	tr := &http.Transport{
		Proxy: nil, // never route validation through an HTTP proxy
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			h, p, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ip, prob := resolveLoopback(ctx, resolve, h) // redirects are re-checked here too
			if prob != nil {
				dialErr.Store(prob)
				return nil, errors.New(prob.Detail)
			}
			var d net.Dialer
			return d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), p))
		},
		// RFC 8555 8.3: redirects to https are followed without cert validation.
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
	url := "http://" + net.JoinHostPort(host, strconv.Itoa(port)) + "/.well-known/acme-challenge/" + token
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := client.Do(req)
	if err != nil {
		if p := dialErr.Load(); p != nil {
			return p
		}
		return &store.Problem{Type: errConnection, Detail: fmt.Sprintf(
			"could not fetch %s: %v. Is something listening on port %d?", url, unwrap(err), port)}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return &store.Problem{Type: errIncorrectResponse, Detail: fmt.Sprintf("%s returned HTTP %d", url, resp.StatusCode)}
	}
	if strings.TrimSpace(string(body)) != keyAuth {
		return &store.Problem{Type: errIncorrectResponse, Detail: fmt.Sprintf("%s returned the wrong key authorization", url)}
	}
	return nil
}

func unwrap(err error) error {
	for {
		u := errors.Unwrap(err)
		if u == nil {
			return err
		}
		err = u
	}
}
