package platform

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
)

const unitPath = "/etc/systemd/system/devca.service"

// A system unit running as the current user, with only the capability to
// bind ports 80/443. User units cannot be granted that capability.
func ServiceInstall(exe, dataDir string) error {
	u, err := user.Current()
	if err != nil {
		return err
	}
	unit := fmt.Sprintf(`[Unit]
Description=DevCA local development CA and HTTPS gateway
After=network.target

[Service]
User=%s
ExecStart=%s serve --data %s
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
Restart=on-failure

[Install]
WantedBy=multi-user.target
`, u.Username, systemdQuote(exe), systemdQuote(dataDir))
	tmp, err := os.CreateTemp("", "devca-unit")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	tmp.WriteString(unit)
	tmp.Close()
	if err := RunPrivileged("install", "-m", "0644", tmp.Name(), unitPath); err != nil {
		return err
	}
	if err := RunPrivileged("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := RunPrivileged("systemctl", "enable", "devca"); err != nil {
		return err
	}
	return RunPrivileged("systemctl", "restart", "devca") // also picks up a replaced binary
}

// systemdQuote quotes a path for ExecStart; % starts a systemd specifier.
func systemdQuote(s string) string {
	return strings.ReplaceAll(strconv.Quote(s), "%", "%%")
}

func ServiceUninstall() error {
	if _, err := os.Stat(unitPath); os.IsNotExist(err) {
		return nil
	}
	_ = RunPrivileged("systemctl", "disable", "--now", "devca")
	if err := RunPrivileged("rm", "-f", unitPath); err != nil {
		return err
	}
	return RunPrivileged("systemctl", "daemon-reload")
}

func ServiceDescription() string { return "a systemd service (" + unitPath + ")" }
