package pipeline

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ultrarecon/internal/util"
)

func runAmassPassive(ctx context.Context, timeout time.Duration, domain, outputDir string) ([]string, error) {
	workRoot := filepath.Join(outputDir, ".ultrarecon", "amass")
	if err := os.MkdirAll(workRoot, 0o755); err != nil {
		return nil, fmt.Errorf("prepare amass work dir: %w", err)
	}
	workDir, err := os.MkdirTemp(workRoot, "run-*")
	if err != nil {
		return nil, fmt.Errorf("create amass temp dir: %w", err)
	}
	defer os.RemoveAll(workDir)

	variants := [][]string{
		{"enum", "-passive", "-norecursive", "-noalts", "-dir", workDir, "-d", domain},
		{"enum", "-passive", "-norecursive", "-dir", workDir, "-d", domain},
		{"enum", "-passive", "-dir", workDir, "-d", domain},
	}

	var last util.CmdResult
	for _, args := range variants {
		res := util.RunCommand(ctx, timeout, "amass", args...)
		if res.Err == nil {
			return splitLines(res.Stdout), nil
		}
		last = res
		if !shouldRetryAmass(res) {
			break
		}
	}
	return nil, explainAmassFailure(last)
}

func shouldRetryAmass(res util.CmdResult) bool {
	if res.Err == nil {
		return false
	}
	low := strings.ToLower(strings.TrimSpace(res.Stderr + "\n" + res.Err.Error()))
	return strings.Contains(low, "unknown flag") ||
		strings.Contains(low, "flag provided but not defined") ||
		strings.Contains(low, "usage:") ||
		strings.Contains(low, "help")
}

func explainAmassFailure(res util.CmdResult) error {
	if res.Err == nil {
		return nil
	}
	low := strings.ToLower(strings.TrimSpace(res.Stderr + "\n" + res.Err.Error()))
	switch {
	case strings.Contains(low, "flag provided but not defined") || strings.Contains(low, "unknown flag"):
		return fmt.Errorf("amass CLI compatibility failure: %s", firstMeaningfulLine(res.Stderr, res.Err.Error()))
	case strings.Contains(low, "lock") || strings.Contains(low, "database"):
		return fmt.Errorf("amass workspace lock failure: %s", firstMeaningfulLine(res.Stderr, res.Err.Error()))
	case strings.Contains(low, "config") && strings.Contains(low, "data source"):
		return fmt.Errorf("amass data source configuration failure: %s", firstMeaningfulLine(res.Stderr, res.Err.Error()))
	default:
		return fmt.Errorf("amass failed: %s", firstMeaningfulLine(res.Stderr, res.Err.Error()))
	}
}

func firstMeaningfulLine(parts ...string) string {
	for _, part := range parts {
		for _, line := range strings.Split(strings.ReplaceAll(part, "\r", ""), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if strings.HasPrefix(line, ".++") || strings.HasPrefix(line, "+W") || strings.HasPrefix(line, "&@") || strings.HasPrefix(line, "/ /") {
				continue
			}
			return line
		}
	}
	return "exit status 1"
}
