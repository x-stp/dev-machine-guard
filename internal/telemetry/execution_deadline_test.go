package telemetry

import (
	"testing"
	"time"
)

func TestExecutionDeadlineFromEnv(t *testing.T) {
	cases := []struct {
		name string
		env  string
		set  bool
		want time.Duration
	}{
		{"unset", "", false, 4 * time.Hour},
		{"empty", "", true, 4 * time.Hour},
		{"zero disables", "0", true, 0},
		{"off disables", "off", true, 0},
		{"valid duration 2h", "2h", true, 2 * time.Hour},
		{"valid duration 30m", "30m", true, 30 * time.Minute},
		{"valid duration 45m30s", "45m30s", true, 45*time.Minute + 30*time.Second},
		{"invalid string falls back", "junk", true, 4 * time.Hour},
		{"negative falls back", "-5m", true, 4 * time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv("STEPSEC_MAX_EXECUTION_DURATION", tc.env)
			} else {
				// Belt-and-braces: t.Setenv resets at test exit, but
				// nothing in this package mutates the env at init.
				_ = tc.env
			}
			got := ExecutionDeadlineFromEnv()
			if got != tc.want {
				t.Errorf("ExecutionDeadlineFromEnv() = %v, want %v", got, tc.want)
			}
		})
	}
}
