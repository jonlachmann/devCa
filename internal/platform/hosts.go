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

// RenderHosts returns current with DevCA's block replaced by entries for
// hosts (both IPv4 and IPv6 loopback; macOS stalls on .local names without
// the ::1 line). Everything outside the block is preserved byte for byte.
// An empty hosts list removes the block.
func RenderHosts(current string, hosts []string) string {
	nl := "\n"
	if strings.Contains(current, "\r\n") {
		nl = "\r\n"
	}
	before, after := current, ""
	if i := strings.Index(current, hostsBegin); i >= 0 {
		before = current[:i]
		if j := strings.Index(current[i:], hostsEnd); j >= 0 {
			after = current[i+j+len(hostsEnd):]
			after = strings.TrimPrefix(strings.TrimPrefix(after, "\r"), "\n")
		}
	}
	if len(hosts) == 0 {
		return before + after
	}
	if before != "" && !strings.HasSuffix(before, "\n") {
		before += nl
	}
	hosts = slices.Clone(hosts)
	slices.Sort(hosts)
	var b strings.Builder
	b.WriteString(hostsBegin + nl)
	for _, h := range slices.Compact(hosts) {
		fmt.Fprintf(&b, "127.0.0.1 %s%s::1 %s%s", h, nl, h, nl)
	}
	b.WriteString(hostsEnd + nl)
	return before + b.String() + after
}

// HostsInFile returns the hostnames currently in DevCA's block.
func HostsInFile() []string {
	b, err := os.ReadFile(HostsPath())
	if err != nil {
		return nil
	}
	s := string(b)
	i := strings.Index(s, hostsBegin)
	if i < 0 {
		return nil
	}
	s = s[i+len(hostsBegin):]
	if j := strings.Index(s, hostsEnd); j >= 0 {
		s = s[:j]
	}
	var out []string
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "127.0.0.1" {
			out = append(out, f[1])
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
// ponytail: in-place copy rather than rename, so the file keeps its owner,
// mode and (on macOS) any ACLs; the file is tiny so a torn write is unlikely.
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
