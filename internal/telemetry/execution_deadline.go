package telemetry

import (
	"os"
	"time"
)

// defaultExecutionDeadline is the hard wall on whole-process runtime.
// Sits ABOVE the scan deadline (STEPSEC_MAX_SCAN_DURATION, 60min default):
// scan-deadline cancels the scan body but leaves heartbeat, phase-post,
// and final upload running on runCtx. If any of those goroutines wedges
// — a hung S3 PUT, an HTTP socket stuck in close-wait, an unreaped
// grandchild that slipped past the PR-122 process-group fix — the
// process can otherwise run indefinitely. Four hours gives normal scans
// (which finish in under an hour) plus retry budget room, while still
// bounding pathological cases to a single daily launchd/schtasks tick.
const defaultExecutionDeadline = 4 * time.Hour

// ExecutionDeadlineFromEnv resolves STEPSEC_MAX_EXECUTION_DURATION using
// the same contract as scanDeadlineFromEnv (scan_deadline.go):
//   - unset / empty: returns defaultExecutionDeadline (4h)
//   - "0" / "off": returns 0 (watchdog disabled; main.go skips arming)
//   - any Go time.ParseDuration string ("2h", "30m", "45m30s"): that
//     duration when positive
//   - anything else: returns defaultExecutionDeadline (silent fallback —
//     telemetry runs from unattended launchd/schtasks/systemd contexts
//     where a typo in the env var should not be fatal to the scan)
func ExecutionDeadlineFromEnv() time.Duration {
	v := os.Getenv("STEPSEC_MAX_EXECUTION_DURATION")
	if v == "" {
		return defaultExecutionDeadline
	}
	if v == "0" || v == "off" {
		return 0
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return defaultExecutionDeadline
	}
	return d
}
