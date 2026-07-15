//go:build darwin

package detector

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

// tccAccessRecorder wraps the mock executor and records every path handed to a
// filesystem call that stats/reads on a real machine — the calls that fire a
// macOS TCC prompt. Tests assert none of them touched a protected tree, which
// proves the guard runs BEFORE any access: an outcome-only check (skill absent)
// would still pass if a guard were moved AFTER the stat, but the prompt would
// already have fired. Embeds *executor.Mock so all other methods pass through.
// (Distinct from skills_test.go's recordingExec, which records only ReadFile.)
type tccAccessRecorder struct {
	*executor.Mock
	mu       sync.Mutex
	accessed []string
}

func (r *tccAccessRecorder) note(path string) {
	r.mu.Lock()
	r.accessed = append(r.accessed, path)
	r.mu.Unlock()
}

func (r *tccAccessRecorder) Stat(p string) (os.FileInfo, error) { r.note(p); return r.Mock.Stat(p) }
func (r *tccAccessRecorder) DirExists(p string) bool            { r.note(p); return r.Mock.DirExists(p) }
func (r *tccAccessRecorder) ReadDir(p string) ([]os.DirEntry, error) {
	r.note(p)
	return r.Mock.ReadDir(p)
}
func (r *tccAccessRecorder) EvalSymlinks(p string) (string, error) {
	r.note(p)
	return r.Mock.EvalSymlinks(p)
}
func (r *tccAccessRecorder) ReadFile(p string) ([]byte, error) { r.note(p); return r.Mock.ReadFile(p) }

// accessedUnder returns the recorded paths that equal prefix or are nested
// under it at a "/" boundary.
func (r *tccAccessRecorder) accessedUnder(prefix string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var hits []string
	for _, p := range r.accessed {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			hits = append(hits, p)
		}
	}
	return hits
}

// runSkillsUnderProtected seeds a fully-discoverable skill inside ~/Documents (a
// TCC-protected tree) and registers its project in ~/.claude.json, then runs
// Detect with the given skipper through an access recorder. Because the whole
// tree is seeded, the skill is reachable if — and only if — the detector stats
// into ~/Documents; the recorder then lets tests assert directly on access.
// Darwin-tagged because tcc.New only builds home-anchored protected paths on
// macOS.
func runSkillsUnderProtected(t *testing.T, skipper *tcc.Skipper) ([]model.AgentSkill, *model.AgentSkillScanInfo, *tccAccessRecorder) {
	t.Helper()
	m, fs := newSkillsMock() // mock home defaults to testHome
	fs.addSkill(testHome+"/Documents/proj/.claude/skills/demo", "SKILL.md", validFrontmatter("demo", "d"), nil)
	fs.addFile(testHome+"/.claude.json", `{"projects":{"`+testHome+`/Documents/proj":{}}}`)
	fs.commit()
	rec := &tccAccessRecorder{Mock: m}
	records, info := NewSkillsDetector(rec).WithSkipper(skipper).Detect(context.Background(), nil)
	return records, info, rec
}

// TestDetect_SkipsProjectUnderProtectedDir is the primary-fix regression: a
// ~/.claude.json project inside ~/Documents must be dropped before any stat, so
// the skill is never discovered and no prompt fires.
func TestDetect_SkipsProjectUnderProtectedDir(t *testing.T) {
	records, info, rec := runSkillsUnderProtected(t, tcc.New(testHome))

	if s := findSkill(records, "claude_project", "demo"); s != nil {
		t.Errorf("skill under ~/Documents must not be discovered (statting it would fire a TCC prompt), got %+v", s)
	}
	if info.ProjectsScanned != 0 {
		t.Errorf("project under ~/Documents must be dropped before probing, ProjectsScanned = %d, want 0", info.ProjectsScanned)
	}
	protected := testHome + "/Documents"
	for _, r := range info.RootsScanned {
		if r == protected || strings.HasPrefix(r, protected+"/") {
			t.Errorf("no root under a protected dir may be scanned, got %q in RootsScanned", r)
		}
	}
	// The core guarantee: the guard runs BEFORE any filesystem access, so nothing
	// under ~/Documents is ever statted or read (that stat is what pops the
	// dialog). This is what the outcome assertions above cannot prove on their own.
	if hits := rec.accessedUnder(protected); len(hits) > 0 {
		t.Errorf("no filesystem access may occur under %q (would fire a TCC prompt), got: %v", protected, hits)
	}
}

// TestDetect_ScansProtectedDirWhenSkipperNil is the opt-in counterpart: with
// --include-tcc-protected the caller passes a nil skipper, WithinProtected is a
// no-op, and the same ~/Documents skill IS scanned (FDA is assumed granted, so
// no prompt). This also proves the skill is genuinely reachable, so the skip
// assertions above are meaningful rather than vacuously true.
func TestDetect_ScansProtectedDirWhenSkipperNil(t *testing.T) {
	records, _, _ := runSkillsUnderProtected(t, nil)

	if findSkill(records, "claude_project", "demo") == nil {
		t.Error("with a nil skipper (--include-tcc-protected) the ~/Documents skill must be scanned")
	}
}

// TestApplyLocks_SkipsXDGLockUnderProtectedDir covers the lock-path vector: when
// XDG_STATE_HOME points under a protected tree (e.g. ~/Library), the global
// skills.sh lock resolves there and loadLock's Stat would fire a prompt. With a
// skipper the lock must be skipped before any access; with a nil skipper it is
// read and parsed.
func TestApplyLocks_SkipsXDGLockUnderProtectedDir(t *testing.T) {
	xdgState := testHome + "/Library/state"
	lockPath := xdgState + "/skills/.skill-lock.json"

	run := func(skipper *tcc.Skipper) (*model.AgentSkillScanInfo, *tccAccessRecorder) {
		m, fs := newSkillsMock()
		m.SetEnv("XDG_STATE_HOME", xdgState)
		fs.addFileBytes(lockPath, []byte(`{"skills":{}}`))
		fs.commit()
		rec := &tccAccessRecorder{Mock: m}
		info := &model.AgentSkillScanInfo{}
		NewSkillsDetector(rec).WithSkipper(skipper).applyLocks(nil, nil, info)
		return info, rec
	}

	// Skipper ON: the XDG lock under ~/Library is never parsed or even accessed.
	info, rec := run(tcc.New(testHome))
	if info.LockFilesParsed != 0 {
		t.Errorf("XDG lock under ~/Library must not be parsed, LockFilesParsed = %d, want 0", info.LockFilesParsed)
	}
	if hits := rec.accessedUnder(testHome + "/Library"); len(hits) > 0 {
		t.Errorf("no filesystem access may occur under ~/Library (would fire a TCC prompt), got: %v", hits)
	}

	// Skipper nil (--include-tcc-protected): the same lock IS read and parsed.
	info, _ = run(nil)
	if info.LockFilesParsed != 1 {
		t.Errorf("with a nil skipper the XDG lock must be parsed, LockFilesParsed = %d, want 1", info.LockFilesParsed)
	}
}
