package platform

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

const runKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

// ServiceInstall registers DevCA in the current user's Run key instead of
// installing a Windows service: per-user autostart needs no admin rights,
// keeps data in the user's profile and needs no extra dependency. It also
// (re)starts DevCA now, detached; DetachConsole hides the console at logon.
func ServiceInstall(exe, dataDir string) error {
	cmdline := fmt.Sprintf(`"%s" serve --background --data "%s"`, exe, dataDir)
	if err := Run("reg", "add", runKey, "/v", "DevCA", "/t", "REG_SZ", "/d", cmdline, "/f"); err != nil {
		return err
	}
	stopRunning() // an upgrade must not leave the old version running
	c := exec.Command(exe, "serve", "--background", "--data", dataDir)
	const detachedProcess, newProcessGroup = 0x00000008, 0x00000200
	c.SysProcAttr = &syscall.SysProcAttr{CreationFlags: detachedProcess | newProcessGroup}
	return c.Start()
}

func ServiceUninstall() error {
	stopRunning()
	_ = quiet("reg", "delete", runKey, "/v", "DevCA", "/f") // fine if it was never added
	return nil
}

// stopRunning ends other devca.exe processes (the background instance).
func stopRunning() {
	_ = quiet("taskkill", "/F", "/IM", "devca.exe", "/FI", fmt.Sprintf("PID ne %d", os.Getpid()))
}

func ServiceDescription() string { return `a per-user startup entry (` + runKey + `)` }

// DetachConsole hides the console window when started at logon.
func DetachConsole() {
	_, _, _ = syscall.NewLazyDLL("kernel32.dll").NewProc("FreeConsole").Call()
}
