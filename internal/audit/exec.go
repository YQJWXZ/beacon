package audit

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Runner executes host commands so parsers can be fed fixtures in tests.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// ExecRunner runs real commands.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return out, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(ee.Stderr)))
		}
		return out, err
	}
	return out, nil
}

// Event is an audit finding that is too rich for a metric label.
type Event struct {
	Time     time.Time      `json:"time"`
	Host     string         `json:"host"`
	Type     string         `json:"type"`
	Severity string         `json:"severity"`
	Data     map[string]any `json:"data"`
}

// Sink receives events from collectors.
type Sink interface {
	Emit(Event)
}

// NopSink drops events; used by the CLI and by tests.
type NopSink struct{}

func (NopSink) Emit(Event) {}
