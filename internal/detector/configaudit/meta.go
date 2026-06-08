package configaudit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// ownerInfo carries the resolved owning user / group for a file. OK is false
// on Windows (we don't resolve SIDs) or when the file doesn't exist; callers
// treat that as "owner unknown" and leave the corresponding model fields empty.
//
// Tests substitute a deterministic ownerLookup hook on each detector so they
// never invoke statOwner.
type ownerInfo struct {
	UID       int
	GID       int
	OwnerName string
	GroupName string
	OK        bool
}

// defaultInGitRepo walks parent directories looking for a `.git` entry
// (directory for a regular repo, file for a git worktree). Stops at the
// filesystem root. Used by every rc/config detector to decide whether the
// discovered file lives inside a repository — which is the prerequisite for
// the more expensive `git ls-files` tracked check.
func defaultInGitRepo(path string) bool {
	dir := filepath.Dir(path)
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}

// gitTrackedViaExec shells out to git to check whether path is tracked by the
// repo that contains it. Returns false on any error (git not installed, not
// in a repo, untracked) — the caller has already established via
// defaultInGitRepo that this is even worth asking.
func gitTrackedViaExec(ctx context.Context, exec executor.Executor, path string) bool {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	_, _, exit, err := exec.RunWithTimeout(ctx, 5*time.Second, "git", "-C", dir, "ls-files", "--error-unmatch", base)
	return err == nil && exit == 0
}

// sha256Hex returns the hex SHA-256 of a string. Used to fingerprint env-var
// values and other small inputs without exposing them.
func sha256Hex(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
