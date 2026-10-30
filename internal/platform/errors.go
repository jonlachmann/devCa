package platform

import (
	"errors"
	"os/exec"
)

var errNoAnchors = errors.New("no known system trust directory found; import ca.pem manually (see README)")

// quiet runs a command, discarding its output.
func quiet(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}
