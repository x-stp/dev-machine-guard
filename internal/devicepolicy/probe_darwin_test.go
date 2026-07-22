//go:build darwin

package devicepolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestProbeDarwinEitherKey stages a fake managed-preferences plist and confirms
// the probe yields on AllowedExtensions OR ExtensionGalleryServiceUrl (the key
// names appear as plain ASCII runs, matching real binary plists).
func TestProbeDarwinEitherKey(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    bool
		detail  string
	}{
		{"allowlist only", "bplist00\x00AllowedExtensions\x00", true, allowedExtensionsName},
		{"gallery only", "bplist00\x00ExtensionGalleryServiceUrl\x00", true, galleryServiceURLName},
		{"both (allowlist preferred in detail)", "bplist00\x00AllowedExtensions\x00ExtensionGalleryServiceUrl\x00", true, allowedExtensionsName},
		{"neither", "bplist00\x00SomethingElse\x00", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			p := filepath.Join(root, darwinVSCodePlistName)
			if err := os.WriteFile(p, []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}
			managed, detail := probeDarwinManagedPrefs(root)
			if managed != tc.want {
				t.Fatalf("managed = %v, want %v (detail %q)", managed, tc.want, detail)
			}
			if tc.want && !strings.Contains(detail, tc.detail) {
				t.Fatalf("detail = %q, want to contain %q", detail, tc.detail)
			}
		})
	}
}

// TestProbeDarwinPerUserGalleryKey confirms the per-user glob path also detects
// the gallery key (an MDM may materialize the plist under a <user> subdir).
func TestProbeDarwinPerUserGalleryKey(t *testing.T) {
	root := t.TempDir()
	userDir := filepath.Join(root, "alice")
	if err := os.MkdirAll(userDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(userDir, darwinVSCodePlistName),
		[]byte("bplist00\x00ExtensionGalleryServiceUrl\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	managed, detail := probeDarwinManagedPrefs(root)
	if !managed || !strings.Contains(detail, galleryServiceURLName) {
		t.Fatalf("per-user gallery key: want managed=true with gallery detail, got (%v, %q)", managed, detail)
	}
}
