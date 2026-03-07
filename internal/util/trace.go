package util

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	traceMu      sync.Mutex
	traceEnabled bool
)

// SetTrace enables/disables live trace logs for command execution.
func SetTrace(enabled bool) {
	traceMu.Lock()
	traceEnabled = enabled
	traceMu.Unlock()
}

func tracef(format string, args ...any) {
	traceMu.Lock()
	enabled := traceEnabled
	traceMu.Unlock()
	if !enabled {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintln(os.Stdout, "[trace] "+msg)
}

func traceCommandStart(name string, args []string, timeout time.Duration, withInput bool) time.Time {
	cmd := name
	if len(args) > 0 {
		cmd += " " + strings.Join(args, " ")
	}
	inputTag := ""
	if withInput {
		inputTag = " stdin=yes"
	}
	if timeout > 0 {
		tracef("cmd start timeout=%s%s: %s", timeout.Round(time.Millisecond), inputTag, cmd)
	} else {
		tracef("cmd start%s: %s", inputTag, cmd)
	}
	return time.Now()
}

func traceCommandEnd(start time.Time, name string, err error, stdout string, stderr string) {
	d := time.Since(start).Round(time.Millisecond)
	if err != nil {
		tracef("cmd fail %s in %s: %v", name, d, err)
	} else {
		tracef("cmd done %s in %s", name, d)
	}
	if strings.TrimSpace(stderr) != "" {
		trimmed := strings.TrimSpace(stderr)
		if len(trimmed) > 220 {
			trimmed = trimmed[:220] + "..."
		}
		tracef("cmd stderr %s: %s", name, trimmed)
	}
	if strings.TrimSpace(stdout) != "" {
		lines := strings.Count(stdout, "\n") + 1
		tracef("cmd stdout %s: %d line(s)", name, lines)
	}
}
