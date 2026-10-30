package platform

import (
	"slices"
	"strings"
	"testing"
)

func TestRenderHosts(t *testing.T) {
	orig := "127.0.0.1 localhost\n# my stuff\n10.0.0.5 nas.lan"
	added := RenderHosts(orig, []string{"b.local", "a.local", "a.local"})
	if !strings.HasPrefix(added, orig+"\n") {
		t.Fatalf("unrelated content changed:\n%s", added)
	}
	if !strings.Contains(added, "127.0.0.1 a.local\n::1 a.local\n127.0.0.1 b.local\n") {
		t.Fatalf("missing entries:\n%s", added)
	}
	if RenderHosts(added, []string{"a.local", "b.local"}) != added {
		t.Fatal("not idempotent")
	}
	// Block in the middle: replacing it keeps text on both sides.
	mid := RenderHosts(added, []string{"c.local"}) + "# trailing\n"
	re := RenderHosts(mid, []string{"d.local"})
	if !strings.HasPrefix(re, orig) || !strings.HasSuffix(re, "# trailing\n") || strings.Contains(re, "c.local") {
		t.Fatalf("bad replace:\n%s", re)
	}
	if got := RenderHosts(added, nil); got != orig+"\n" {
		t.Fatalf("removal left %q", got)
	}
	crlf := RenderHosts("127.0.0.1 localhost\r\n", []string{"x.local"})
	if !strings.Contains(crlf, "::1 x.local\r\n") {
		t.Fatal("CRLF not preserved")
	}
}

func TestHostsDiff(t *testing.T) {
	d := HostsDiff("a\nb", "a\nc")
	if !slices.Equal(strings.Split(strings.TrimSpace(d), "\n"), []string{"- b", "+ c"}) {
		t.Fatalf("diff: %q", d)
	}
}
