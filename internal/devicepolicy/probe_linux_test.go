//go:build linux

package devicepolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestProbeLinuxEitherKey stages a fake /etc/vscode/policy.json and confirms
// the probe yields on AllowedExtensions OR ExtensionGalleryServiceUrl.
func TestProbeLinuxEitherKey(t *testing.T) {
	cases := []struct {
		name    string
		content string // empty → no file
		want    bool
		detail  string
	}{
		{"allowlist only", `{"AllowedExtensions":{"*":false}}`, true, allowedExtensionsName},
		{"gallery only", `{"ExtensionGalleryServiceUrl":"https://mkt.example/api/v1"}`, true, galleryServiceURLName},
		{"both (allowlist preferred)", `{"AllowedExtensions":{},"ExtensionGalleryServiceUrl":"x"}`, true, allowedExtensionsName},
		{"neither", `{"Other":1}`, false, ""},
		{"missing file", "", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.json")
			if tc.content != "" {
				if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			managed, detail := probeLinuxPolicyFile(path)
			if managed != tc.want {
				t.Fatalf("managed = %v, want %v (detail %q)", managed, tc.want, detail)
			}
			if tc.want && !strings.Contains(detail, tc.detail) {
				t.Fatalf("detail = %q, want to contain %q", detail, tc.detail)
			}
		})
	}
}
