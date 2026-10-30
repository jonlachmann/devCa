package platform

import (
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strconv"
)

const launchLabel = "dev.devca"

func plistPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", launchLabel+".plist")
}

func ServiceInstall(exe, dataDir string) error {
	esc := html.EscapeString
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key><array><string>%s</string><string>serve</string><string>--data</string><string>%s</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>%s</string>
  <key>StandardErrorPath</key><string>%s</string>
</dict></plist>
`, launchLabel, esc(exe), esc(dataDir), esc(filepath.Join(dataDir, "devca.log")), esc(filepath.Join(dataDir, "devca.log")))
	if err := os.MkdirAll(filepath.Dir(plistPath()), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(plistPath(), []byte(plist), 0o644); err != nil {
		return err
	}
	domain := "gui/" + strconv.Itoa(os.Getuid())
	_ = quiet("launchctl", "bootout", domain, plistPath()) // reinstall: ignore "not loaded"
	return Run("launchctl", "bootstrap", domain, plistPath())
}

func ServiceUninstall() error {
	_ = quiet("launchctl", "bootout", "gui/"+strconv.Itoa(os.Getuid()), plistPath())
	err := os.Remove(plistPath())
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func ServiceDescription() string { return "a launchd agent (" + plistPath() + ")" }
