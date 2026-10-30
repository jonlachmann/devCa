package platform

import (
	"os"
	"path/filepath"
	"runtime"
)

// BinPath is where `devca install` puts the program: a per-user location, so
// installing needs no admin rights and the service never points at ~/Downloads.
func BinPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs", "devca", "devca.exe")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "bin", "devca")
}
