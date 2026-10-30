// Command devca is a local development CA, ACME server and HTTPS gateway.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var version = "dev"

const usage = `DevCA - local HTTPS for development

Setup:
  devca install                      create the CA, offer to trust it, run in background
  devca uninstall                    remove the background service (keeps CA, data and trust)
  devca serve                        run in the foreground
  devca status                       show what is running

Services:
  devca proxy add <host> <target>    HTTPS proxy, e.g. devca proxy add api.localhost 3000
  devca proxy list
  devca proxy remove <host>
  devca cert issue <host> [--out dir]  certificate files for an app that does its own TLS
  devca cert list
  devca cert renew <host>
  devca cert revoke <host|id>
  devca cert export <host> --out dir
  devca acme info                    ACME directory URL and accounts
  devca acme claim <host> [--port n] reserve a host for an external ACME client
  devca test acme <host>             run a full ACME issuance against DevCA

CA and system:
  devca ca info | export [--out file] | backup <file.zip> | restore <file.zip> [--force]
  devca trust install | uninstall | status
  devca hosts plan | apply | remove

Every command accepts --data <dir> (default: %s, or $DEVCA_HOME).
`

func main() {
	args := os.Args[1:]
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Printf(usage, defaultDataDir())
		return
	}
	cmd, rest := args[0], args[1:]
	sub := ""
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		sub = rest[0]
	}
	var err error
	switch cmd + " " + sub {
	case "version ":
		fmt.Println("devca", version)
	case "serve ":
		err = cmdServe(rest)
	case "install ":
		err = cmdInstall(rest)
	case "uninstall ":
		err = cmdUninstall(rest)
	case "status ":
		err = cmdStatus(rest)
	case "proxy add":
		err = cmdProxyAdd(rest[1:])
	case "proxy list":
		err = cmdServiceList(rest[1:], "proxy")
	case "proxy remove":
		err = cmdServiceRemove(rest[1:])
	case "cert list":
		err = cmdCertList(rest[1:])
	case "cert issue":
		err = cmdCertIssue(rest[1:])
	case "cert renew":
		err = cmdCertRenew(rest[1:])
	case "cert revoke":
		err = cmdCertRevoke(rest[1:])
	case "cert export":
		err = cmdCertExport(rest[1:])
	case "acme info":
		err = cmdACMEInfo(rest[1:])
	case "acme claim":
		err = cmdACMEClaim(rest[1:])
	case "test acme":
		err = cmdTestACME(rest[1:])
	case "ca info":
		err = cmdCAInfo(rest[1:])
	case "ca export":
		err = cmdCAExport(rest[1:])
	case "ca backup":
		err = cmdCABackup(rest[1:])
	case "ca restore":
		err = cmdCARestore(rest[1:])
	case "trust install":
		err = cmdTrustInstall(rest[1:])
	case "trust uninstall":
		err = cmdTrustUninstall(rest[1:])
	case "trust status":
		err = cmdTrustStatus(rest[1:])
	case "hosts plan":
		err = cmdHosts(rest[1:], "plan")
	case "hosts apply":
		err = cmdHosts(rest[1:], "apply")
	case "hosts remove":
		err = cmdHosts(rest[1:], "remove")
	default:
		fmt.Fprintf(os.Stderr, "unknown command: devca %s\n\n", strings.Join(args, " "))
		fmt.Fprintf(os.Stderr, usage, defaultDataDir())
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func defaultDataDir() string {
	if d := os.Getenv("DEVCA_HOME"); d != "" {
		return d
	}
	base, err := os.UserConfigDir()
	if err != nil {
		base = "."
	}
	return filepath.Join(base, "devca")
}

// flags creates a FlagSet with the shared --data flag.
func flags(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	data := fs.String("data", defaultDataDir(), "data directory")
	return fs, data
}

// parse parses args allowing flags after positional arguments
// (devca cert issue api.localhost --out ./certs).
func parse(fs *flag.FlagSet, args []string) []string {
	var pos []string
	for {
		_ = fs.Parse(args)
		if fs.NArg() == 0 {
			return pos
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func confirm(question string, defaultYes bool) bool {
	hint := " [y/N] "
	if defaultYes {
		hint = " [Y/n] "
	}
	fmt.Print(question + hint)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	case "":
		return defaultYes
	}
	return false
}

func need(pos []string, n int, usage string) error {
	if len(pos) != n {
		return fmt.Errorf("usage: devca %s", usage)
	}
	return nil
}
