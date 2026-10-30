// Package store persists all DevCA state in a single JSON file.
//
// Every change rewrites the whole file. That's fine for dozens of services
// and certs; move to SQLite if state ever grows past a few MB.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Service modes.
const (
	ModeProxy  = "proxy"  // DevCA terminates TLS and proxies to Target.
	ModeExport = "export" // DevCA issues/renews, app reads files.
	ModeACME   = "acme"   // An external ACME client owns the lifecycle.
)

type Settings struct {
	HTTPPort       int    `json:"httpPort"`
	HTTPSPort      int    `json:"httpsPort"`
	MgmtPort       int    `json:"mgmtPort"`
	ACMEPort       int    `json:"acmePort"`
	GatewayEnabled bool   `json:"gatewayEnabled"`
	LeafDays       int    `json:"leafDays"`
	RenewDays      int    `json:"renewDays"` // renew when fewer days than this remain
	LogLevel       string `json:"logLevel"`
	DefaultSuffix  string `json:"defaultSuffix"`
}

func DefaultSettings() Settings {
	return Settings{
		HTTPPort: 80, HTTPSPort: 443, MgmtPort: 7171, ACMEPort: 7443,
		GatewayEnabled: true, LeafDays: 30, RenewDays: 10,
		LogLevel: "info", DefaultSuffix: "localhost",
	}
}

type Service struct {
	Hostname       string    `json:"hostname"`
	Mode           string    `json:"mode"`
	Target         string    `json:"target,omitempty"`         // proxy mode
	ExportDir      string    `json:"exportDir,omitempty"`      // extra export location (export mode)
	ValidationPort int       `json:"validationPort,omitempty"` // acme mode: where HTTP-01 is checked
	Address        string    `json:"address,omitempty"`        // loopback IP for the hosts file; "" = 127.0.0.1 and ::1
	Enabled        bool      `json:"enabled"`
	AutoRenew      bool      `json:"autoRenew"`
	CertID         int64     `json:"certId,omitempty"`
	Created        time.Time `json:"created"`
}

// Cert owners.
const (
	OwnerTest = "test"
)

func OwnerService(host string) string { return "service:" + host }
func OwnerACME(acct int64) string     { return fmt.Sprintf("acme:%d", acct) }

type Cert struct {
	ID        int64     `json:"id"`
	Serial    string    `json:"serial"`
	Names     []string  `json:"names"`
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
	Revoked   bool      `json:"revoked"`
	RevokedAt time.Time `json:"revokedAt,omitzero"`
	Owner     string    `json:"owner"`
	KeyType   string    `json:"keyType"`
	PEM       string    `json:"pem"` // leaf only; never contains a private key
}

type Account struct {
	ID         int64           `json:"id"`
	Thumbprint string          `json:"thumbprint"`
	JWK        json.RawMessage `json:"jwk"`
	Contact    []string        `json:"contact,omitempty"`
	Status     string          `json:"status"`
	Internal   bool            `json:"internal,omitempty"` // devca test account
	Created    time.Time       `json:"created"`
}

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Problem struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"status,omitempty"`
}

type Challenge struct {
	ID        int64     `json:"id"`
	Type      string    `json:"type"`
	Token     string    `json:"token"`
	Status    string    `json:"status"`
	Validated time.Time `json:"validated,omitzero"`
	Error     *Problem  `json:"error,omitempty"`
}

type Authz struct {
	ID         int64        `json:"id"`
	AccountID  int64        `json:"accountId"`
	Identifier Identifier   `json:"identifier"`
	Status     string       `json:"status"`
	Expires    time.Time    `json:"expires"`
	Challenges []*Challenge `json:"challenges"`
}

type Order struct {
	ID          int64        `json:"id"`
	AccountID   int64        `json:"accountId"`
	Status      string       `json:"status"`
	Expires     time.Time    `json:"expires"`
	Identifiers []Identifier `json:"identifiers"`
	AuthzIDs    []int64      `json:"authzIds"`
	CertID      int64        `json:"certId,omitempty"`
	Error       *Problem     `json:"error,omitempty"`
	Created     time.Time    `json:"created"`
}

type Event struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"` // info | warn | error
	Kind    string    `json:"kind"`  // cert | acme | service | gateway | ca
	Message string    `json:"message"`
}

type State struct {
	Settings Settings   `json:"settings"`
	Services []*Service `json:"services"`
	Certs    []*Cert    `json:"certs"`
	Accounts []*Account `json:"accounts"`
	Orders   []*Order   `json:"orders"`
	Authzs   []*Authz   `json:"authzs"`
	Events   []Event    `json:"events"`
	NextID   int64      `json:"nextId"`
}

func (s *State) ID() int64 { s.NextID++; return s.NextID }

func (s *State) Service(host string) *Service {
	for _, v := range s.Services {
		if v.Hostname == host {
			return v
		}
	}
	return nil
}

func (s *State) Cert(id int64) *Cert {
	for _, c := range s.Certs {
		if c.ID == id {
			return c
		}
	}
	return nil
}

func (s *State) Account(id int64) *Account {
	for _, a := range s.Accounts {
		if a.ID == id {
			return a
		}
	}
	return nil
}

func (s *State) Order(id int64) *Order {
	for _, o := range s.Orders {
		if o.ID == id {
			return o
		}
	}
	return nil
}

func (s *State) Authz(id int64) *Authz {
	for _, a := range s.Authzs {
		if a.ID == id {
			return a
		}
	}
	return nil
}

const maxEvents = 500

func (s *State) Log(level, kind, format string, args ...any) {
	s.Events = append(s.Events, Event{time.Now(), level, kind, fmt.Sprintf(format, args...)})
	if n := len(s.Events); n > maxEvents {
		s.Events = append([]Event(nil), s.Events[n-maxEvents:]...)
	}
}

// Prune drops finished ACME objects older than 30 days.
func (s *State) Prune(now time.Time) {
	cutoff := now.Add(-30 * 24 * time.Hour)
	keep := map[int64]bool{}
	orders := s.Orders[:0]
	for _, o := range s.Orders {
		if o.Created.After(cutoff) {
			orders = append(orders, o)
			for _, id := range o.AuthzIDs {
				keep[id] = true
			}
		}
	}
	s.Orders = orders
	authzs := s.Authzs[:0]
	for _, a := range s.Authzs {
		if keep[a.ID] || a.Expires.After(now) {
			authzs = append(authzs, a)
		}
	}
	s.Authzs = authzs
}

// Store guards State with a single global mutex. Per-object locking is only
// worth it if this ever gets contended.
type Store struct {
	mu   sync.Mutex
	path string
	st   *State
}

// Open loads path, or starts with defaults if it does not exist yet.
func Open(path string) (*Store, error) {
	s := &Store{path: path, st: &State{Settings: DefaultSettings()}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, s.st); err != nil {
		return nil, fmt.Errorf("%s is corrupt: %w (restore a backup or move it aside)", path, err)
	}
	return s, nil
}

// View runs fn under the lock. fn must not keep references past return.
func (s *Store) View(fn func(*State)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s.st)
}

// Update runs fn under the lock and persists if fn returns nil.
// On error the in-memory state may be partially modified, so callers
// validate before mutating.
func (s *Store) Update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(s.st); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(s.path, b, 0o600)
}

// Log appends an event and persists it.
func (s *Store) Log(level, kind, format string, args ...any) {
	_ = s.Update(func(st *State) error { st.Log(level, kind, format, args...); return nil })
}

// WriteFileAtomic writes via temp file + fsync + rename so readers never see
// a partial file. The temp file lives in the same directory so rename is atomic.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after successful rename
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
