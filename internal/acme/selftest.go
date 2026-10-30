package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	xacme "golang.org/x/crypto/acme"

	"github.com/jonlachmann/devca/internal/store"
)

type Step struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
	Hint   string `json:"hint,omitempty"`
	Millis int64  `json:"ms"`
}

// SelfTest runs a full ACME issuance for host with an independent client
// (golang.org/x/crypto/acme) against the real server at directoryURL.
// publish/unpublish place the HTTP-01 response where the validator will
// fetch it (the gateway's port-80 challenge store).
type SelfTest struct {
	Server       *Server
	DirectoryURL string
	Roots        *x509.CertPool
	KeyPath      string // persisted test account key
	Publish      func(host, token, body string)
	Unpublish    func(host, token string)
}

func (t *SelfTest) Run(ctx context.Context, host string) []Step {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var steps []Step
	step := func(name string, fn func() (string, error), hint func(error) string) bool {
		start := time.Now()
		detail, err := fn()
		s := Step{Name: name, OK: err == nil, Detail: detail, Millis: time.Since(start).Milliseconds()}
		if err != nil {
			s.Detail = err.Error()
			if hint != nil {
				s.Hint = hint(err)
			}
		}
		steps = append(steps, s)
		return err == nil
	}

	client := &xacme.Client{
		DirectoryURL: t.DirectoryURL,
		UserAgent:    "devca-selftest",
		HTTPClient: &http.Client{Transport: &http.Transport{
			Proxy:           nil,
			TLSClientConfig: &tls.Config{RootCAs: t.Roots},
		}},
	}
	var order *xacme.Order
	var authz *xacme.Authorization
	var chal *xacme.Challenge
	var der [][]byte
	var certKey crypto.Signer

	ok := step("Create or reuse ACME account", func() (string, error) {
		key, err := t.accountKey()
		if err != nil {
			return "", err
		}
		client.Key = key
		acct, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS)
		if errors.Is(err, xacme.ErrAccountAlreadyExists) {
			acct, err = client.GetReg(ctx, "")
		}
		if err != nil {
			return "", err
		}
		id, err := strconv.ParseInt(acct.URI[strings.LastIndex(acct.URI, "/")+1:], 10, 64)
		if err != nil {
			return "", err
		}
		_ = t.Server.Store.Update(func(s *store.State) error {
			if a := s.Account(id); a != nil {
				a.Internal = true
			}
			return nil
		})
		return acct.URI, nil
	}, func(error) string { return "Is the ACME listener running? Check the ACME port in Settings." })

	ok = ok && step("Create order", func() (string, error) {
		var err error
		order, err = client.AuthorizeOrder(ctx, xacme.DomainIDs(host))
		if err != nil {
			return "", err
		}
		return order.URI, nil
	}, nil)

	ok = ok && step("Publish HTTP-01 challenge", func() (string, error) {
		var err error
		authz, err = client.GetAuthorization(ctx, order.AuthzURLs[0])
		if err != nil {
			return "", err
		}
		for _, c := range authz.Challenges {
			if c.Type == "http-01" {
				chal = c
			}
		}
		if chal == nil {
			return "", errors.New("server offered no http-01 challenge")
		}
		body, err := client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return "", err
		}
		t.Publish(host, chal.Token, body)
		return "http://" + host + client.HTTP01ChallengePath(chal.Token), nil
	}, nil)
	if chal != nil {
		defer t.Unpublish(host, chal.Token)
	}

	ok = ok && step("Validate challenge (local validation)", func() (string, error) {
		if _, err := client.Accept(ctx, chal); err != nil {
			return "", err
		}
		if _, err := client.WaitAuthorization(ctx, authz.URI); err != nil {
			return "", err
		}
		return host + " served the expected token", nil
	}, func(err error) string {
		msg := err.Error()
		switch {
		case strings.Contains(msg, "does not resolve"):
			return "Add the hostname to your hosts file: devca hosts apply"
		case strings.Contains(msg, "port 80"), strings.Contains(msg, "refused"):
			return "DevCA's HTTP listener must be running on port 80. Check the Gateway status on the dashboard."
		}
		return ""
	})

	ok = ok && step("Finalize order", func() (string, error) {
		var err error
		if order, err = client.WaitOrder(ctx, order.URI); err != nil {
			return "", err
		}
		certKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}}, certKey)
		if err != nil {
			return "", err
		}
		der, _, err = client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("received %d certificate(s)", len(der)), nil
	}, nil)

	ok = ok && step("Verify certificate chain", func() (string, error) {
		leaf, err := x509.ParseCertificate(der[0])
		if err != nil {
			return "", err
		}
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: t.Roots}); err != nil {
			return "", err
		}
		return fmt.Sprintf("valid for %s until %s", host, leaf.NotAfter.Format(time.DateOnly)), nil
	}, nil)

	_ = ok && step("Revoke test certificate", func() (string, error) {
		return "the test certificate is not used anywhere", client.RevokeCert(ctx, nil, der[0], xacme.CRLReasonCessationOfOperation)
	}, nil)
	return steps
}

func (t *SelfTest) accountKey() (crypto.Signer, error) {
	if b, err := os.ReadFile(t.KeyPath); err == nil {
		if blk, _ := pem.Decode(b); blk != nil {
			if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
				if s, ok := k.(crypto.Signer); ok {
					return s, nil
				}
			}
		}
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	return k, store.WriteFileAtomic(t.KeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
}
