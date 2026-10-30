package platform

import "crypto/x509"

const systemKeychain = "/Library/Keychains/System.keychain"

func TrustInstall(root *x509.Certificate, certPath string) error {
	return RunPrivileged("security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", systemKeychain, certPath)
}

func TrustUninstall(root *x509.Certificate, certPath string) error {
	_ = RunPrivileged("security", "remove-trusted-cert", "-d", certPath)
	return RunPrivileged("security", "delete-certificate", "-Z", sha1Hex(root), systemKeychain)
}

// TrustCheck verifies a leaf for "localhost" with the macOS verifier.
func TrustCheck(root, leaf *x509.Certificate) TrustStatus {
	notes := []string{"Safari, Chrome, Edge and Firefox (with its default enterprise-roots setting) use the macOS keychain."}
	if err := verifyWithPlatform(leaf); err != nil {
		return TrustStatus{Detail: "Not trusted by macOS yet", Notes: notes}
	}
	return TrustStatus{Trusted: true, Detail: "Trusted in the macOS System keychain", Notes: notes}
}
