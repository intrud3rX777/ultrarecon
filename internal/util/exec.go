package util

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

var ErrToolMissing = errors.New("tool missing")

type CmdResult struct {
	Stdout string
	Stderr string
	Err    error
}

func HaveCommand(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func RunCommand(ctx context.Context, timeout time.Duration, name string, args ...string) CmdResult {
	if _, err := exec.LookPath(name); err != nil {
		tracef("cmd missing: %s", name)
		return CmdResult{
			Err: fmt.Errorf("%w: %s", ErrToolMissing, name),
		}
	}
	started := traceCommandStart(name, args, timeout, false)

	runCtx := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(runCtx, name, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	out := strings.TrimSpace(stdout.String())
	errOut := strings.TrimSpace(stderr.String())
	traceCommandEnd(started, name, err, out, errOut)

	return CmdResult{
		Stdout: out,
		Stderr: errOut,
		Err:    err,
	}
}

func RunCommandInput(ctx context.Context, timeout time.Duration, stdin string, name string, args ...string) CmdResult {
	if _, err := exec.LookPath(name); err != nil {
		tracef("cmd missing: %s", name)
		return CmdResult{
			Err: fmt.Errorf("%w: %s", ErrToolMissing, name),
		}
	}
	started := traceCommandStart(name, args, timeout, true)

	runCtx := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(runCtx, name, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	in, err := cmd.StdinPipe()
	if err != nil {
		return CmdResult{Err: err}
	}
	if err := cmd.Start(); err != nil {
		return CmdResult{Err: err}
	}
	if stdin != "" {
		_, _ = io.WriteString(in, stdin)
	}
	_ = in.Close()
	err = cmd.Wait()
	out := strings.TrimSpace(stdout.String())
	errOut := strings.TrimSpace(stderr.String())
	traceCommandEnd(started, name, err, out, errOut)

	return CmdResult{
		Stdout: out,
		Stderr: errOut,
		Err:    err,
	}
}
