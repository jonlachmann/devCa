// Package platform holds the OS-specific bits: trust store, hosts file,
// background service and privilege escalation.
package platform

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

const (
	hostsBegin = "# BEGIN devca - managed by DevCA, change with `devca hosts`"
	hostsEnd   = "# END devca"
)

func HostsPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("SystemRoot"), "System32", "drivers", "etc", "hosts")
	}
	return "/etc/hosts"
}

// HostEntry maps a hostname to a loopback address. An empty Addr means the
// default: 127.0.0.1 and ::1.
type HostEntry struct{ Name, Addr string }

// HostsAddr is the address a hostname should resolve to.
func HostsAddr(addr string) string {
	if addr == "" {
		return "127.0.0.1"
	}
	return addr
}

// RenderHosts returns current with DevCA's block replaced by entries.
// Default entries get both IPv4 and IPv6 loopback lines (macOS stalls on
// .local names without the ::1 line); a custom address gets only its own
// line, so clients can't reach a different service over ::1.
// Everything outside the block is preserved byte for byte.
// An empty entry list removes the block.
func RenderHosts(current string, entries []HostEntry) (string, error) {
	nl := "\n"
	if strings.Contains(current, "\r\n") {
		nl = "\r\n"
	}
	before, after := current, ""
	if i := strings.Index(current, hostsBegin); i >= 0 {
		before = current[:i]
		j := strings.Index(current[i:], hostsEnd)
		if j < 0 {
			// Guessing where the block ends could delete the user's own lines.
			return "", fmt.Errorf("%q is in %s but %q is missing; fix or remove DevCA's block by hand, then try again", hostsBegin, HostsPath(), hostsEnd)
		}
		after = current[i+j+len(hostsEnd):]
		after = strings.TrimPrefix(strings.TrimPrefix(after, "\r"), "\n")
	}
	if len(entries) == 0 {
		return before + after, nil
	}
	if before != "" && !strings.HasSuffix(before, "\n") {
		before += nl
	}
	entries = slices.Clone(entries)
	slices.SortFunc(entries, func(a, b HostEntry) int { return strings.Compare(a.Name, b.Name) })
	entries = slices.CompactFunc(entries, func(a, b HostEntry) bool { return a.Name == b.Name })
	var b strings.Builder
	b.WriteString(hostsBegin + nl)
	for _, e := range entries {
		if e.Addr == "" {
			fmt.Fprintf(&b, "127.0.0.1 %s%s::1 %s%s", e.Name, nl, e.Name, nl)
		} else {
			fmt.Fprintf(&b, "%s %s%s", e.Addr, e.Name, nl)
		}
	}
	b.WriteString(hostsEnd + nl)
	return before + b.String() + after, nil
}

// HostsInFile maps each hostname in DevCA's block to its first address.
func HostsInFile() map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(HostsPath())
	if err != nil {
		return out
	}
	s := string(b)
	i := strings.Index(s, hostsBegin)
	if i < 0 {
		return out
	}
	s = s[i+len(hostsBegin):]
	j := strings.Index(s, hostsEnd)
	if j < 0 {
		return out // damaged block: don't mistake the user's lines for ours
	}
	s = s[:j]
	for _, line := range strings.Split(s, "\n") {
		if f := strings.Fields(line); len(f) == 2 {
			if _, seen := out[f[1]]; !seen {
				out[f[1]] = f[0]
			}
		}
	}
	return out
}

// HostsDiff renders a human-readable summary of the change.
func HostsDiff(old, new string) string {
	o, n := strings.Split(old, "\n"), strings.Split(new, "\n")
	var b strings.Builder
	for _, l := range o {
		if !slices.Contains(n, l) {
			b.WriteString("- " + strings.TrimRight(l, "\r") + "\n")
		}
	}
	for _, l := range n {
		if !slices.Contains(o, l) {
			b.WriteString("+ " + strings.TrimRight(l, "\r") + "\n")
		}
	}
	return b.String()
}

// WriteHosts replaces the hosts file content, escalating with sudo on Unix.
// It copies in place rather than renaming, so the file keeps its owner, mode
// and (on macOS) any ACLs; the file is tiny, so a torn write is unlikely.
func WriteHosts(content string) error {
	path := HostsPath()
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			if runtime.GOOS == "windows" {
				return fmt.Errorf("%w (run this from an Administrator terminal)", err)
			}
			return err
		}
	} else {
		tmp, err := os.CreateTemp("", "devca-hosts")
		if err != nil {
			return err
		}
		defer os.Remove(tmp.Name())
		if _, err := tmp.WriteString(content); err != nil {
			return err
		}
		tmp.Close()
		if err := RunPrivileged("cp", tmp.Name(), path); err != nil {
			return err
		}
	}
	if runtime.GOOS == "darwin" {
		_ = RunPrivileged("dscacheutil", "-flushcache")
		_ = RunPrivileged("killall", "-HUP", "mDNSResponder")
	}
	return nil
}

// RunPrivileged runs a command as root via sudo (Unix) or directly when
// already privileged or on Windows. Output goes to the terminal so sudo can
// prompt for a password.
func RunPrivileged(name string, args ...string) error {
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		args = append([]string{"--", name}, args...)
		name = "sudo"
	}
	return Run(name, args...)
}

// Run executes a command attached to the terminal.
func Run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}
