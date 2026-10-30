package platform

import (
	"fmt"
	"syscall"
)

// ponytail: a Task Scheduler logon task as the current user instead of a
// Windows service, so data stays in the user's profile and no extra
// dependency is needed. The console is detached at startup (DetachConsole).
func ServiceInstall(exe, dataDir string) error {
	tr := fmt.Sprintf(`"%s" serve --background --data "%s"`, exe, dataDir)
	if err := Run("schtasks", "/Create", "/F", "/SC", "ONLOGON", "/RL", "LIMITED", "/TN", "DevCA", "/TR", tr); err != nil {
		return err
	}
	return Run("schtasks", "/Run", "/TN", "DevCA")
}

func ServiceUninstall() error {
	_ = quiet("schtasks", "/End", "/TN", "DevCA")
	return quiet("schtasks", "/Delete", "/F", "/TN", "DevCA")
}

func ServiceDescription() string { return "a Task Scheduler logon task (DevCA)" }

// DetachConsole hides the console window when started by the logon task.
func DetachConsole() {
	_, _, _ = syscall.NewLazyDLL("kernel32.dll").NewProc("FreeConsole").Call()
}
