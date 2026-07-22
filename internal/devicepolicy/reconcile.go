package devicepolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Reconciler converges the user-scope VS Code settings.json to the backend's
// effective policy for one device, once per scheduled cycle. It is OS-agnostic:
// the settings Writer, the managed-policy Probe, the policy Fetcher, and the
// compliance Reporter are all injected, so the whole flow is fake-testable
// with no real I/O.
type Reconciler struct {
	Fetcher  Fetcher
	Reporter Reporter
	// Writer is the settings.json writer, or nil when the platform has no
	// resolvable settings path. A nil Writer makes Reconcile a no-op.
	Writer Writer

	CustomerID string
	DeviceID   string
	Platform   string // reported in compliance; e.g. "windows", "linux", "darwin"
	Category   string // defaults to ide_extension
	Target     string // defaults to vscode

	// Probe reports whether a real MDM/admin-managed AllowedExtensions policy
	// exists at this OS's policy location (registry / policy.json / managed
	// preferences). Such a policy outranks user settings inside VS Code, so the
	// agent yields (mdm_managed) instead of writing a value VS Code would
	// ignore. nil → ProbeManagedPolicy (the per-OS implementation); tests
	// inject a stub so results never depend on the host machine.
	Probe func() (managed bool, detail string)

	// Now and Logf are optional seams. Now defaults to time.Now().UTC; Logf to a
	// no-op.
	Now  func() time.Time
	Logf func(format string, args ...any)

	// writeState and clearState are test seams over the ownership store
	// (WriteAppliedState / ClearAppliedState). nil → the real implementation.
	writeState func(category, target string, s AppliedTargetState) error
	clearState func(category, target string) error
}

func (r *Reconciler) persistState(cat, tgt string, s AppliedTargetState) error {
	if r.writeState != nil {
		return r.writeState(cat, tgt, s)
	}
	return WriteAppliedState(cat, tgt, s)
}

func (r *Reconciler) dropState(cat, tgt string) error {
	if r.clearState != nil {
		return r.clearState(cat, tgt)
	}
	return ClearAppliedState(cat, tgt)
}

func (r *Reconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now().UTC()
}

func (r *Reconciler) logf(format string, args ...any) {
	if r.Logf != nil {
		r.Logf(format, args...)
	}
}

func (r *Reconciler) category() string {
	if r.Category != "" {
		return r.Category
	}
	return CategoryIDEExtension
}

func (r *Reconciler) target() string {
	if r.Target != "" {
		return r.Target
	}
	return TargetVSCode
}

func (r *Reconciler) probe() (bool, string) {
	if r.Probe != nil {
		return r.Probe()
	}
	return ProbeManagedPolicy()
}

// Reconcile runs one enforcement cycle. It NEVER panics into the caller's hot
// path; failures are returned for logging. The contract:
//
//   - fetch error (transport / non-200 / malformed) → NO-OP, error returned.
//     Enforcement on disk is never wiped on a transient or malformed response.
//   - platform not enforceable (nil Writer) → silent no-op.
//   - absent policy (run-config carried no `policy` directive for this
//     category/target) → silent no-op; the on-disk value and ownership record
//     stand. This is NOT a clear — removal happens only on an explicit clear.
//   - clear result → remove ONLY the agent-owned settings key; a value the
//     agent has no record of writing is left untouched. No compliance report
//     (an unassigned device is backend-derived).
//   - policy result → probe → ownership/drift-checked write + readback +
//     verify + report (handleEnforce).
func (r *Reconciler) Reconcile(ctx context.Context) error {
	if r.Fetcher == nil {
		return errors.New("devicepolicy: nil fetcher")
	}
	cat := r.category()
	tgt := r.target()

	ep, err := r.Fetcher.Fetch(ctx, r.CustomerID, r.DeviceID, cat, tgt)
	if err != nil {
		// Malformed/transient: do nothing. The on-disk policy (if any) stands.
		return fmt.Errorf("devicepolicy: fetch: %w", err)
	}

	if r.Writer == nil {
		r.logf("devicepolicy: no settings path on this platform; skipping (category=%s target=%s)", cat, tgt)
		return nil
	}

	if !ep.present() {
		// Run-config carried no policy directive for this category/target — no value
		// to enforce and no explicit clear. Leave the on-disk value and ownership
		// record untouched; a transient drop must never wipe enforcement.
		r.logf("devicepolicy: run-config carried no policy for %s/%s; leaving on-disk state untouched", cat, tgt)
		return nil
	}

	if ep.Clear {
		return r.handleClear(cat, tgt)
	}
	return r.handleEnforce(ctx, cat, tgt, ep)
}

// handleClear removes the agent-owned settings on unassignment, then drops the
// ownership record. It dispatches on the Writer: a managed multi-key writer
// clears each owned key independently (clearManaged); any other Writer keeps
// the single-key path (clearSingle). Both are ownership-gated: a value the
// agent has no record of writing is left intact.
func (r *Reconciler) handleClear(cat, tgt string) error {
	prev, hadPrev := ReadAppliedState(cat, tgt)
	if mw, ok := r.Writer.(managedSettingsWriter); ok {
		return r.clearManaged(cat, tgt, prev, hadPrev, mw)
	}
	return r.clearSingle(cat, tgt, prev, hadPrev)
}

// clearSingle is the single-key unassignment path. It clears the on-disk value
// ONLY when it still equals what the agent last wrote (ownership); a value the
// agent has no record of writing — the user's own extensions.allowed predates
// enforcement, or the record was lost — is left intact.
func (r *Reconciler) clearSingle(cat, tgt string, prev AppliedTargetState, hadPrev bool) error {
	onDisk, present, err := r.Writer.Read()
	if err != nil {
		return fmt.Errorf("devicepolicy: clear: read %s: %w", r.Writer.Location(), err)
	}

	owns := present && prev.WrittenValue != "" && onDisk == prev.WrittenValue
	switch {
	case owns:
		if err := r.Writer.Clear(); err != nil {
			return fmt.Errorf("devicepolicy: clear %s: %w", r.Writer.Location(), err)
		}
		r.logf("devicepolicy: cleared agent-owned policy at %s", r.Writer.Location())
	case present:
		// A value the agent did not write — leave it to whoever set it.
		r.logf("devicepolicy: clear requested but %s holds a value the agent did not write; leaving it", r.Writer.Location())
	}

	return r.dropClearedState(cat, tgt, hadPrev)
}

// clearManaged is the managed multi-key unassignment path. It removes each
// managed key INDEPENDENTLY, and only when its on-disk value still equals what
// the agent wrote (per-key ownership); a foreign-valued or absent key is
// preserved. One atomic write carries only the owned-key removes.
func (r *Reconciler) clearManaged(cat, tgt string, prev AppliedTargetState, hadPrev bool, mw managedSettingsWriter) error {
	keys := managedKeys()
	cur, err := mw.ReadManaged(keys)
	if err != nil {
		return fmt.Errorf("devicepolicy: clear: read %s: %w", r.Writer.Location(), err)
	}
	owned := ownedKeys(prev, hadPrev)
	var ops []settingOp
	for _, key := range keys { // fixed order → deterministic write
		ov := owned[key]
		if ov != "" && cur[key].Present && cur[key].Raw == ov {
			ops = append(ops, settingOp{Key: key, Remove: true})
		}
	}
	if len(ops) > 0 {
		if _, err := mw.ApplyManaged(ops); err != nil {
			return fmt.Errorf("devicepolicy: clear %s: %w", r.Writer.Location(), err)
		}
		r.logf("devicepolicy: cleared %d agent-owned key(s) at %s", len(ops), r.Writer.Location())
	} else {
		r.logf("devicepolicy: clear requested but %s holds no agent-owned value; leaving it", r.Writer.Location())
	}

	return r.dropClearedState(cat, tgt, hadPrev)
}

// dropClearedState drops the ownership record whenever an entry exists for this
// (category, target). Beyond the obvious case (we owned a value), this reclaims
// an empty record a preflight may have left after its settings write later
// failed. An absent entry → no-op (idempotent).
func (r *Reconciler) dropClearedState(cat, tgt string, hadPrev bool) error {
	if hadPrev {
		if err := r.dropState(cat, tgt); err != nil {
			return fmt.Errorf("devicepolicy: clear: update state: %w", err)
		}
	}
	return nil
}

// handleEnforce converges settings.json to the compiled policy and reports. It
// runs the shared head of the ladder (compact the allowlist, then the
// managed-policy probe), then dispatches on the Writer: a managed multi-key
// writer converges the full SET of managed keys (enforceManaged); any other
// Writer keeps the single-key path (enforceSingle).
//
//	probe (managed policy exists → mdm_managed, never write)
//	→ read current value(s)
//	→ idempotency (hash unchanged ∧ every managed key converged → report, no write)
//	→ preflight ownership-store writability
//	→ drift detection (an OWNED key diverged from its recorded written value)
//	→ merge-write + readback
//	→ persist ownership on every successful write (rollback if that fails)
//	→ Verify → report (drift upgrades a would-be compliant to drift_detected)
func (r *Reconciler) handleEnforce(ctx context.Context, cat, tgt string, ep EffectivePolicy) error {
	// The compiled allowlist compacted: the canonical comparison form for
	// readback, idempotency, and ownership. (The backend's hash still travels
	// verbatim; only the value bytes are normalized for comparison.)
	newValue, err := compactJSON(ep.Policy)
	if err != nil {
		// Defensive: the fetcher already validated object shape, so this is a
		// malformed-payload class failure → no-op, never write.
		return fmt.Errorf("devicepolicy: enforce: compact policy: %w", err)
	}

	// Managed-policy probe. A policy at the OS policy location outranks user
	// settings inside VS Code — writing would be ineffective at best and fight
	// the MDM at worst. Yield and report. (Presence of EITHER managed policy
	// key yields; see the probe.)
	if managed, detail := r.probe(); managed {
		r.logf("devicepolicy: managed policy present at %s → mdm_managed (yielding)", detail)
		return r.report(ctx, cat, tgt, StateMDMManaged, "")
	}

	if mw, ok := r.Writer.(managedSettingsWriter); ok {
		return r.enforceManaged(ctx, cat, tgt, ep, newValue, mw)
	}
	return r.enforceSingle(ctx, cat, tgt, ep, newValue)
}

// enforceSingle is the single-key convergence path (any Writer without the
// managed multi-key API). It is unchanged from the original enforce: it manages
// exactly the extensions.allowed key.
func (r *Reconciler) enforceSingle(ctx context.Context, cat, tgt string, ep EffectivePolicy, newValue string) error {
	// Read the current settings value.
	prev, hadPrev := ReadAppliedState(cat, tgt)
	onDisk, present, err := r.Writer.Read()
	if err != nil {
		// Couldn't read to decide idempotency/drift → verification_failed.
		// This includes an unsalvageable settings.json (not valid JSONC), which
		// the writer refuses to touch.
		_ = r.report(ctx, cat, tgt, StateVerificationFailed, "")
		return fmt.Errorf("devicepolicy: enforce: read %s: %w", r.Writer.Location(), err)
	}

	// Idempotency: the desired policy is already in place and unchanged. No
	// write — but still report so the backend sees a fresh evaluation.
	if present && onDisk == newValue && prev.AppliedHash == ep.Hash {
		r.logf("devicepolicy: policy already applied (hash unchanged) — no write")
		return r.report(ctx, cat, tgt, StateCompliant, ep.Hash)
	}

	// Drift: the agent wrote a value before, and what is on disk now is not it
	// (edited or removed — typically the user hand-editing settings.json).
	// Enforcement means converging it back; the distinct state lets the backend
	// surface that it happened.
	drifted := hadPrev && prev.WrittenValue != "" && (!present || onDisk != prev.WrittenValue)
	if drifted {
		r.logf("devicepolicy: %s diverged from the recorded written value → re-applying (drift)", r.Writer.Location())
	}

	// Preflight: prove the ownership store is writable BEFORE mutating the
	// settings file. An enforced value with no ownership record is orphaned — a
	// later clear refuses to remove it. Re-persisting the current state is a
	// meaning-preserving writability probe.
	probe := prev
	if !hadPrev {
		probe = AppliedTargetState{FetchedAt: r.now()}
	}
	if perr := r.persistState(cat, tgt, probe); perr != nil {
		_ = r.report(ctx, cat, tgt, StateWriteFailed, "")
		return fmt.Errorf("devicepolicy: enforce: ownership state not writable, refusing to write policy: %w", perr)
	}

	// Merge-write + readback.
	rb, werr := r.Writer.Write(newValue)
	if werr != nil {
		_ = r.report(ctx, cat, tgt, StateWriteFailed, "")
		return fmt.Errorf("devicepolicy: enforce: write %s: %w", r.Writer.Location(), werr)
	}
	readbackMatch := rb == newValue

	// Ownership is recorded on EVERY successful write — it means "what the agent
	// wrote", not "what it verified". On a readback mismatch the write may still
	// have landed; without a record the next cycle would classify the agent's
	// own value as drift forever. Value-based ownership self-corrects: the
	// record only takes effect when the on-disk value actually equals it.
	if err := r.persistState(cat, tgt, AppliedTargetState{
		AppliedHash:  ep.Hash,
		WrittenValue: newValue,
		FetchedAt:    r.now(),
	}); err != nil {
		// The write happened but ownership couldn't be recorded — undo it so no
		// unrecorded value is left behind, and report a failed write.
		r.rollbackWrite(onDisk, present)
		_ = r.report(ctx, cat, tgt, StateWriteFailed, "")
		return fmt.Errorf("devicepolicy: enforce: update state: %w", err)
	}
	r.logf("devicepolicy: wrote policy to %s (readback_match=%v)", r.Writer.Location(), readbackMatch)

	state := Verify(VerifyInput{WriteOK: true, ReadbackMatch: readbackMatch})
	if drifted && state == StateCompliant {
		state = StateDriftDetected
	}

	// applied_hash is echoed only when we are confident the policy is applied
	// (readback-confirmed) — compliant, or drift_detected (drift that was
	// successfully re-applied). It is the backend's hash verbatim — never
	// recomputed — so the backend's byte-exact applied==desired check gates
	// `compliant`.
	appliedHash := ""
	if state == StateCompliant || state == StateDriftDetected {
		appliedHash = ep.Hash
	}
	return r.report(ctx, cat, tgt, state, appliedHash)
}

// enforceManaged is the managed multi-key convergence path. The allowlist is
// always authoritative (Set); the gallery URL is Set when the policy carries
// one, else an ownership-gated Remove (only a value the agent itself wrote),
// else preserved (a foreign or absent value is never deleted).
func (r *Reconciler) enforceManaged(ctx context.Context, cat, tgt string, ep EffectivePolicy, newValue string, mw managedSettingsWriter) error {
	prev, hadPrev := ReadAppliedState(cat, tgt)
	owned := ownedKeys(prev, hadPrev)

	// 1. Read the managed keys up front.
	keys := managedKeys()
	cur, err := mw.ReadManaged(keys)
	if err != nil {
		_ = r.report(ctx, cat, tgt, StateVerificationFailed, "")
		return fmt.Errorf("devicepolicy: enforce: read %s: %w", r.Writer.Location(), err)
	}

	// 2. Build the desired end-state ops. Allowlist is ALWAYS Set. The gallery
	// op is decided from the policy URL and per-key ownership.
	galValue, err := managedGalleryValue(ep.GalleryServiceURL)
	if err != nil {
		// Defensive: encoding a validated URL string cannot fail in practice.
		// If it ever did, nothing has been written — report verification_failed
		// symmetrically with the ReadManaged-error path above.
		_ = r.report(ctx, cat, tgt, StateVerificationFailed, "")
		return fmt.Errorf("devicepolicy: enforce: encode gallery url: %w", err)
	}
	desired := []settingOp{{Key: allowedExtensionsSettingKey, Set: true, Value: json.RawMessage(newValue)}}

	galKey := galleryServiceURLSettingKey
	var galleryOp settingOp
	switch {
	case ep.GalleryServiceURL != "":
		// Authoritative: set the gallery key to the policy's URL.
		galleryOp = settingOp{Key: galKey, Set: true, Value: json.RawMessage(galValue)}
	case owned[galKey] != "" && cur[galKey].Present && cur[galKey].Raw == owned[galKey]:
		// No URL and the on-disk value is the one the agent wrote → remove it
		// (ownership-gated).
		galleryOp = settingOp{Key: galKey, Remove: true}
	default:
		// No URL and either no ownership record or a foreign value on disk →
		// preserve (never delete a value the agent did not write).
		galleryOp = settingOp{Key: galKey}
	}
	desired = append(desired, galleryOp)

	// 3. Convergence over the FULL desired end-state, computed BEFORE the
	// idempotency short-circuit. It covers every managed key, so gallery-only
	// drift with an unchanged hash re-applies rather than short-circuiting to
	// compliant.
	converged := true
	for _, op := range desired {
		if !opConverged(op, cur) {
			converged = false
			break
		}
	}
	if converged && prev.AppliedHash == ep.Hash {
		r.logf("devicepolicy: policy already applied (hash unchanged) — no write")
		return r.report(ctx, cat, tgt, StateCompliant, ep.Hash)
	}

	// 4. Drift: an OWNED key diverged from its recorded written value (edited or
	// removed). Only owned keys count — a foreign value is not the agent's drift.
	drifted := false
	for key, ov := range owned {
		if !cur[key].Present || cur[key].Raw != ov {
			drifted = true
			break
		}
	}
	if drifted {
		r.logf("devicepolicy: %s diverged from a recorded written value → re-applying (drift)", r.Writer.Location())
	}

	// 5. Snapshot the full pre-write state for an atomic multi-key rollback.
	snapshot := make(map[string]settingValue, len(cur))
	for k, sv := range cur {
		snapshot[k] = sv
	}

	// 6. Preflight: prove the ownership store is writable BEFORE mutating the
	// settings file (same rationale as the single-key path).
	probe := prev
	if !hadPrev {
		probe = AppliedTargetState{FetchedAt: r.now()}
	}
	if perr := r.persistState(cat, tgt, probe); perr != nil {
		_ = r.report(ctx, cat, tgt, StateWriteFailed, "")
		return fmt.Errorf("devicepolicy: enforce: ownership state not writable, refusing to write policy: %w", perr)
	}

	// 7. Write the mutating ops in one atomic patch; a preserve contributes
	// nothing.
	writeOps := make([]settingOp, 0, len(desired))
	for _, op := range desired {
		if op.Set || op.Remove {
			writeOps = append(writeOps, op)
		}
	}
	readback, werr := mw.ApplyManaged(writeOps)
	if werr != nil {
		_ = r.report(ctx, cat, tgt, StateWriteFailed, "")
		return fmt.Errorf("devicepolicy: enforce: write %s: %w", r.Writer.Location(), werr)
	}

	// 8. Readback over every mutating op — value + presence prove the requested
	// mutation (a bare string cannot distinguish absent from present-empty).
	readbackMatch := true
	for _, op := range writeOps {
		if !opConverged(op, readback) {
			readbackMatch = false
			break
		}
	}

	// 9. Persist ownership: every managed key the agent now OWNS, keyed by setting
	// id. The allowlist is always owned (authoritative Set); a Remove or preserve
	// key asserts no ownership this cycle (omitted). WrittenValue is the single-key
	// path's field and is left untouched here.
	ownedAfter := map[string]string{allowedExtensionsSettingKey: newValue}
	if galleryOp.Set {
		ownedAfter[galKey] = galValue
	}
	if err := r.persistState(cat, tgt, AppliedTargetState{
		AppliedHash:     ep.Hash,
		WrittenSettings: ownedAfter,
		FetchedAt:       r.now(),
	}); err != nil {
		// The write happened but ownership couldn't be recorded — roll back ALL
		// keys atomically so no unrecorded value is left behind. A clean undo →
		// write_failed; a failed restore leaves the on-disk state uncertain →
		// verification_failed.
		if rerr := mw.RestoreManaged(snapshot); rerr != nil {
			r.logf("devicepolicy: rollback at %s failed: %v", r.Writer.Location(), rerr)
			_ = r.report(ctx, cat, tgt, StateVerificationFailed, "")
			return fmt.Errorf("devicepolicy: enforce: update state (rollback failed: %v): %w", rerr, err)
		}
		_ = r.report(ctx, cat, tgt, StateWriteFailed, "")
		return fmt.Errorf("devicepolicy: enforce: update state: %w", err)
	}
	r.logf("devicepolicy: wrote policy to %s (readback_match=%v)", r.Writer.Location(), readbackMatch)

	state := Verify(VerifyInput{WriteOK: true, ReadbackMatch: readbackMatch})
	if drifted && state == StateCompliant {
		state = StateDriftDetected
	}

	// applied_hash is echoed only when readback-confirmed (compliant or
	// drift_detected). It is the backend's hash verbatim — never recomputed — so
	// the backend's byte-exact applied==desired check gates `compliant`.
	appliedHash := ""
	if state == StateCompliant || state == StateDriftDetected {
		appliedHash = ep.Hash
	}
	return r.report(ctx, cat, tgt, state, appliedHash)
}

// managedKeys is the fixed, ordered set of VS Code settings.json keys the IDE
// reconciler manages. The order is stable so reads, convergence, and writes are
// deterministic.
func managedKeys() []string {
	return []string{allowedExtensionsSettingKey, galleryServiceURLSettingKey}
}

// opConverged reports whether on-disk state m already satisfies op: a Set
// converges when the key is present with the exact value; a Remove when the key
// is absent; a preserve (neither Set nor Remove) is always satisfied.
func opConverged(op settingOp, m map[string]settingValue) bool {
	sv := m[op.Key]
	switch {
	case op.Set:
		return sv.Present && sv.Raw == string(op.Value)
	case op.Remove:
		return !sv.Present
	default:
		return true
	}
}

// ownedKeys folds an ownership record into a flat map of setting id → the exact
// value the agent last wrote, skipping empty entries. Every managed key — the
// allowlist included — lives in WrittenSettings. Drift detection and
// ownership-gated removal act only on keys the agent actually wrote.
func ownedKeys(prev AppliedTargetState, hadPrev bool) map[string]string {
	owned := map[string]string{}
	if !hadPrev {
		return owned
	}
	for k, v := range prev.WrittenSettings {
		if v != "" {
			owned[k] = v
		}
	}
	return owned
}

// managedGalleryValue returns the compacted JSON-string encoding of a gallery
// URL — the exact bytes written to settings.json AND recorded as owned, so the
// readback and the next-cycle ownership comparison are canonical against what
// ReadManaged returns. HTML escaping is disabled so the value round-trips
// byte-stably (json.Compact does not escape, and the JSONC writer preserves the
// literal string token). An empty URL yields "" (no value).
func managedGalleryValue(url string) (string, error) {
	if url == "" {
		return "", nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(url); err != nil {
		return "", fmt.Errorf("devicepolicy: encode gallery url: %w", err)
	}
	// Encode appends a newline; compact strips it (a JSON string has no other
	// insignificant whitespace).
	return compactJSON(buf.Bytes())
}

// rollbackWrite restores the settings key to its pre-cycle condition after the
// post-write ownership persist failed. WriteAppliedState is atomic
// (temp+rename), so the failed persist left the previous state file intact —
// restoring the previous on-disk value keeps record and disk consistent.
// Best-effort: a rollback failure is logged, and the divergence surfaces as
// drift on the next cycle.
func (r *Reconciler) rollbackWrite(prevOnDisk string, prevPresent bool) {
	var err error
	if prevPresent {
		_, err = r.Writer.Write(prevOnDisk)
	} else {
		err = r.Writer.Clear()
	}
	if err != nil {
		r.logf("devicepolicy: rollback at %s failed: %v", r.Writer.Location(), err)
	}
}

func (r *Reconciler) report(ctx context.Context, cat, tgt, state, appliedHash string) error {
	r.logf("devicepolicy: reporting state=%s category=%s target=%s", state, cat, tgt)
	if r.Reporter == nil {
		return nil
	}
	rep := ComplianceReport{
		Category:     cat,
		Target:       tgt,
		State:        state,
		AppliedHash:  appliedHash,
		AgentVersion: AgentVersion(),
		Platform:     r.Platform,
	}
	if err := r.Reporter.Report(ctx, r.CustomerID, r.DeviceID, rep); err != nil {
		return fmt.Errorf("devicepolicy: report %s: %w", state, err)
	}
	return nil
}
