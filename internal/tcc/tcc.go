// Package tcc identifies macOS TCC (Transparency, Consent, and Control)
// protected directories so filesystem walks can skip them and avoid
// triggering system permission prompts on a user's machine.
//
// On non-darwin builds the Skipper is a no-op: ShouldSkip always returns
// false and Candidates returns nil, so callers can wire it unconditionally.
package tcc

import (
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Skipper matches TCC-protected directories. Build one per scan via New;
// share across detectors. Hits are tracked so callers can prove from logs
// which protected paths were actually encountered during the walks.
type Skipper struct {
	paths    map[string]struct{}
	prefixes []string

	mu   sync.Mutex
	hits map[string]int
}

// New builds a Skipper anchored at home. home == "" produces a degraded
// Skipper that only matches absolute-prefix entries (e.g. Time Machine
// snapshot mounts) — useful when the agent runs without a console user.
func New(home string) *Skipper {
	return &Skipper{
		paths:    buildProtectedPaths(home),
		prefixes: protectedPrefixes(),
	}
}

// ShouldSkip reports whether path is a TCC-protected directory whose walk
// should be short-circuited. When path equals walkRoot the result is always
// false: passing --search-dirs ~/Documents is an explicit opt-in, and the
// walk root must be entered for anything to happen.
//
// Safe to call on a nil receiver (returns false), which is what callers
// pass when --include-tcc-protected is set.
func (s *Skipper) ShouldSkip(path, walkRoot string) bool {
	if s == nil {
		return false
	}
	cleaned := filepath.Clean(path)
	if filepath.Clean(walkRoot) == cleaned {
		return false
	}
	if _, ok := s.paths[cleaned]; ok {
		s.recordHit(cleaned)
		return true
	}
	for _, p := range s.prefixes {
		if strings.HasPrefix(cleaned, p) {
			s.recordHit(cleaned)
			return true
		}
	}
	return false
}

func (s *Skipper) recordHit(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hits == nil {
		s.hits = make(map[string]int)
	}
	s.hits[path]++
}

// Hits returns the set of TCC-protected paths that were encountered during
// walks, with the count of times each was matched. Returns nil if nothing
// was skipped (or on a nil receiver). Safe to call concurrently with
// ShouldSkip, though callers typically only read after walks complete.
func (s *Skipper) Hits() map[string]int {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.hits) == 0 {
		return nil
	}
	out := make(map[string]int, len(s.hits))
	for k, v := range s.hits {
		out[k] = v
	}
	return out
}

// Candidates returns the exact-match protected paths the Skipper would
// skip, sorted lexicographically. Useful for surfacing in logs. Returns nil
// on a nil receiver or on non-darwin builds.
func (s *Skipper) Candidates() []string {
	if s == nil || len(s.paths) == 0 {
		return nil
	}
	out := make([]string, 0, len(s.paths))
	for p := range s.paths {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
