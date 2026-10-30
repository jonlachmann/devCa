package platform

import (
	"crypto/x509"
	"fmt"
)

// The current-user Root store needs no admin rights; Windows itself shows a
// confirmation dialog, which doubles as the explicit approval.
func TrustInstall(root *x509.Certificate, certPath string) error {
	return Run("certutil", "-user", "-addstore", "Root", certPath)
}

func TrustUninstall(root *x509.Certificate, certPath string) error {
	return Run("certutil", "-user", "-delstore", "Root", fmt.Sprintf("%X", root.SerialNumber))
}

func TrustCheck(root, leaf *x509.Certificate) TrustStatus {
	notes := []string{"Chrome, Edge and Firefox (enterprise roots enabled by default) use the Windows certificate store."}
	if err := verifyWithPlatform(leaf); err != nil {
		return TrustStatus{Detail: "Not trusted by Windows yet", Notes: notes}
	}
	return TrustStatus{Trusted: true, Detail: "Trusted in the current user's Root store", Notes: notes}
}
