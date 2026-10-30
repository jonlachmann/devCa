package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstallBinary(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("LOCALAPPDATA", home)
	exe := filepath.Join(t.TempDir(), "devca-download")
	os.WriteFile(exe, []byte("v1"), 0o755)

	// Fresh machine: copies into the stable location.
	dst, copied, err := installBinary(exe)
	if err != nil || !copied {
		t.Fatalf("first install: %v %v", copied, err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "v1" {
		t.Fatal("not copied")
	}
	if st, _ := os.Stat(dst); st.Mode().Perm()&0o100 == 0 {
		t.Fatal("not executable")
	}

	// Running the installed copy again: nothing to do.
	if _, copied, _ := installBinary(dst); copied {
		t.Fatal("copied onto itself")
	}

	// Upgrade from a new download replaces it.
	os.WriteFile(exe, []byte("v2"), 0o755)
	installBinary(exe)
	if b, _ := os.ReadFile(dst); string(b) != "v2" {
		t.Fatal("not upgraded")
	}

	// Dev setup: a symlink to the running build is left alone.
	os.Remove(dst)
	os.Symlink(exe, dst)
	if _, copied, _ := installBinary(exe); copied {
		t.Fatal("replaced a symlink to the running binary")
	}
	if fi, _ := os.Lstat(dst); fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink was replaced")
	}
}
