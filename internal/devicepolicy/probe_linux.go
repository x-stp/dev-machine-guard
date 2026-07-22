//go:build linux

package devicepolicy

// linuxPolicyFilePath is VS Code's managed-policy file on Linux, read by its
// FilePolicyService. World-readable when an MDM/admin creates it, so the probe
// needs no elevation.
const linuxPolicyFilePath = "/etc/vscode/policy.json"

// ProbeManagedPolicy reports whether an AllowedExtensions or
// ExtensionGalleryServiceUrl policy exists in the Linux policy file.
func ProbeManagedPolicy() (bool, string) {
	return probeLinuxPolicyFile(linuxPolicyFilePath)
}

// probeLinuxPolicyFile is ProbeManagedPolicy parameterized over the policy-file
// path so tests can stage a fixture instead of touching /etc.
func probeLinuxPolicyFile(path string) (bool, string) {
	for _, name := range managedPolicyNames() {
		if jsonFileHasKey(path, name) {
			return true, path + " [" + name + "]"
		}
	}
	return false, ""
}
