package platform

import (
	"slices"
	"strings"
	"testing"
)

func render(t *testing.T, current string, e []HostEntry) string {
	t.Helper()
	s, err := RenderHosts(current, e)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRenderHostsMissingEnd(t *testing.T) {
	if _, err := RenderHosts("a\n"+hostsBegin+"\n127.0.0.1 x.local\n10.0.0.5 mine\n", nil); err == nil {
		t.Fatal("damaged block must be refused, not guessed")
	}
}

func TestRenderHosts(t *testing.T) {
	orig := "127.0.0.1 localhost\n# my stuff\n10.0.0.5 nas.lan"
	added := render(t, orig, []HostEntry{{"b.local", ""}, {"a.local", ""}, {"a.local", ""}})
	if !strings.HasPrefix(added, orig+"\n") {
		t.Fatalf("unrelated content changed:\n%s", added)
	}
	if !strings.Contains(added, "127.0.0.1 a.local\n::1 a.local\n127.0.0.1 b.local\n") {
		t.Fatalf("missing entries:\n%s", added)
	}
	if render(t, added, []HostEntry{{"a.local", ""}, {"b.local", ""}}) != added {
		t.Fatal("not idempotent")
	}
	// Block in the middle: replacing it keeps text on both sides.
	mid := render(t, added, []HostEntry{{"c.local", ""}}) + "# trailing\n"
	re := render(t, mid, []HostEntry{{"d.local", ""}})
	if !strings.HasPrefix(re, orig) || !strings.HasSuffix(re, "# trailing\n") || strings.Contains(re, "c.local") {
		t.Fatalf("bad replace:\n%s", re)
	}
	if got := render(t, added, nil); got != orig+"\n" {
		t.Fatalf("removal left %q", got)
	}
	crlf := render(t, "127.0.0.1 localhost\r\n", []HostEntry{{"x.local", ""}})
	if !strings.Contains(crlf, "::1 x.local\r\n") {
		t.Fatal("CRLF not preserved")
	}
}

func TestRenderHostsCustomAddress(t *testing.T) {
	got := render(t, "", []HostEntry{{"b.localhost", "127.0.0.3"}, {"a.localhost", "127.0.0.2"}})
	want := hostsBegin + "\n127.0.0.2 a.localhost\n127.0.0.3 b.localhost\n" + hostsEnd + "\n"
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want) // no ::1 lines: they would reach another service
	}
}

func TestHostsDiff(t *testing.T) {
	d := HostsDiff("a\nb", "a\nc")
	if !slices.Equal(strings.Split(strings.TrimSpace(d), "\n"), []string{"- b", "+ c"}) {
		t.Fatalf("diff: %q", d)
	}
}
