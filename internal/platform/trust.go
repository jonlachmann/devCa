package platform

import (
	"crypto/sha1"
	"crypto/x509"
	"fmt"
	"strings"
)

// TrustStatus describes whether the OS trusts the DevCA root.
type TrustStatus struct {
	Trusted bool     `json:"trusted"`
	Detail  string   `json:"detail"`
	Notes   []string `json:"notes,omitempty"` // browser-specific caveats
}

// verifyWithPlatform asks the OS verifier (macOS/Windows) about leaf.
func verifyWithPlatform(leaf *x509.Certificate) error {
	_, err := leaf.Verify(x509.VerifyOptions{DNSName: "localhost"})
	return err
}

func sha1Hex(c *x509.Certificate) string {
	return strings.ToUpper(fmt.Sprintf("%x", sha1.Sum(c.Raw)))
}
