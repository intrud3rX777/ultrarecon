package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"ultrarecon/internal/config"
	"ultrarecon/internal/util"
)

func runSecurityChecks(
	ctx context.Context,
	cfg config.Config,
	store *SafeStore,
	surfaceRows []SurfaceRow,
	contentRows []ContentRow,
	toolErrs *[]ToolError,
	logf func(string, ...any),
) []SecurityFinding {
	if !cfg.EnableSecurityChecks {
		return nil
	}

	targets := collectSecurityTargets(store, surfaceRows, contentRows, cfg.MaxSecurityTargets)
	if len(targets) == 0 {
		logf("[security] targets=0")
		return nil
	}
	if !util.HaveCommand("nuclei") {
		*toolErrs = append(*toolErrs, ToolError{Stage: "security_checks", Tool: "nuclei", Error: "tool missing: nuclei"})
		logf("[security] nuclei missing targets=%d", len(targets))
		return nil
	}

	logf("[security] running nuclei targets=%d", len(targets))
	findings, runErr := runNucleiChecks(ctx, cfg, targets, logf)
	if runErr != nil {
		*toolErrs = append(*toolErrs, ToolError{Stage: "security_checks", Tool: "nuclei", Error: runErr.Error()})
		logf("[security] nuclei failed: %v", runErr)
	}
	findings = dedupeFindings(findings, cfg.MaxSecurityFindings)
	for _, f := range findings {
		h := findingHost(f.Target)
		if h == "" {
			h = findingHost(f.MatchedAt)
		}
		if h != "" && (f.Severity == "high" || f.Severity == "critical") {
			store.AddNote(h, "security:"+f.TemplateID+":"+f.Severity)
		}
	}
	logf("[security] targets=%d findings=%d", len(targets), len(findings))
	return findings
}

func runNucleiChecks(ctx context.Context, cfg config.Config, targets []string, logf func(string, ...any)) ([]SecurityFinding, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	batchSize := minInt(cfg.SecurityBatchSize, len(targets))
	if batchSize < 1 {
		batchSize = len(targets)
	}
	return runNucleiBatches(ctx, cfg, targets, batchSize, logf)
}

func runNucleiBatches(ctx context.Context, cfg config.Config, targets []string, batchSize int, logf func(string, ...any)) ([]SecurityFinding, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	if batchSize < 1 {
		batchSize = len(targets)
	}
	totalBatches := (len(targets) + batchSize - 1) / batchSize
	allFindings := make([]SecurityFinding, 0, minInt(len(targets), cfg.MaxSecurityFindings))
	var lastErr error
	for start := 0; start < len(targets); start += batchSize {
		end := minInt(start+batchSize, len(targets))
		batch := append([]string(nil), targets[start:end]...)
		if totalBatches > 1 {
			logf("[security] batch=%d/%d size=%d", (start/batchSize)+1, totalBatches, len(batch))
		}
		findings, err := runNucleiBatch(ctx, cfg, batch, logf)
		if isKilledProcessError(err) && len(batch) > 15 {
			nextBatchSize := maxInt(10, len(batch)/2)
			logf("[security] batch split size=%d -> %d", len(batch), nextBatchSize)
			findings, err = runNucleiBatches(ctx, cfg, batch, nextBatchSize, logf)
		}
		allFindings = append(allFindings, findings...)
		if err != nil {
			lastErr = err
		}
		if cfg.MaxSecurityFindings > 0 && len(allFindings) >= cfg.MaxSecurityFindings {
			return dedupeFindings(allFindings, cfg.MaxSecurityFindings), lastErr
		}
	}
	return dedupeFindings(allFindings, cfg.MaxSecurityFindings), lastErr
}

func runNucleiBatch(ctx context.Context, cfg config.Config, batch []string, logf func(string, ...any)) ([]SecurityFinding, error) {
	targetFile, cleanupTargets, err := writeTempList(cfg.OutputDir, "security-targets-*.txt", batch)
	if err != nil {
		return nil, err
	}
	defer cleanupTargets()

	timeout := cfg.SecurityTimeout
	if timeout <= 0 {
		timeout = 12 * time.Minute
	}
	concurrency := minInt(maxInt(8, cfg.HTTPThreads/10), 20)
	rate := minInt(maxInt(20, cfg.ContentRate/2), 60)
	bulkSize := minInt(maxInt(8, concurrency/2), 16)
	attempts := [][]string{
		{
			"-l", targetFile,
			"-silent",
			"-jsonl",
			"-duc",
			"-severity", "medium,high,critical",
			"-tags", "takeover,cors,misconfig,exposure,panel,default-login,redirect,token,secret",
			"-rate-limit", strconvI(rate),
			"-c", strconvI(concurrency),
			"-bs", strconvI(bulkSize),
		},
		{
			"-l", targetFile,
			"-silent",
			"-jsonl",
			"-duc",
			"-severity", "medium,high,critical",
			"-rate-limit", strconvI(rate),
			"-c", strconvI(concurrency),
		},
		{
			"-l", targetFile,
			"-silent",
			"-jsonl",
			"-duc",
			"-c", strconvI(concurrency),
		},
		{
			"-l", targetFile,
			"-silent",
			"-jsonl",
			"-c", strconvI(concurrency),
		},
	}

	var (
		findings []SecurityFinding
		lastErr  error
		prepared bool
	)
	for _, args := range attempts {
		subCtx, cancel := context.WithTimeout(ctx, timeout)
		res := util.RunCommand(subCtx, timeout, "nuclei", args...)
		cancel()
		if nucleiNeedsTemplates(res.Stdout, res.Stderr) && !prepared {
			prepared = true
			if prepErr := ensureNucleiTemplates(ctx, cfg, logf); prepErr != nil {
				lastErr = prepErr
			}
			continue
		}
		if strings.TrimSpace(res.Stdout) != "" {
			findings = append(findings, parseNucleiFindings(res.Stdout, cfg.MaxSecurityFindings)...)
		}
		if res.Err == nil && !flagError(res.Stderr) {
			return findings, lastErr
		}
		if res.Err != nil {
			lastErr = summarizeToolFailure(res.Err, res.Stderr)
		}
		if !flagError(res.Stderr) && strings.TrimSpace(res.Stdout) != "" {
			return findings, lastErr
		}
	}
	if len(findings) > 0 {
		return findings, lastErr
	}
	return findings, lastErr
}

func ensureNucleiTemplates(ctx context.Context, cfg config.Config, logf func(string, ...any)) error {
	logf("[security] initializing nuclei templates")
	timeout := minDuration(cfg.SecurityTimeout, 8*time.Minute)
	if timeout < 2*time.Minute {
		timeout = 2 * time.Minute
	}
	attempts := [][]string{
		{"-ut", "-duc"},
		{"-update-templates", "-duc"},
		{"-ut"},
		{"-update-templates"},
	}
	var lastErr error
	for _, args := range attempts {
		subCtx, cancel := context.WithTimeout(ctx, timeout)
		res := util.RunCommand(subCtx, timeout, "nuclei", args...)
		cancel()
		if res.Err == nil {
			logf("[security] nuclei templates ready")
			return nil
		}
		if flagError(res.Stderr) {
			continue
		}
		lastErr = summarizeToolFailure(res.Err, res.Stderr)
	}
	if lastErr != nil {
		logf("[security] nuclei template initialization failed: %v", lastErr)
	}
	return lastErr
}

func nucleiNeedsTemplates(stdout, stderr string) bool {
	low := strings.ToLower(strings.TrimSpace(stdout + "\n" + stderr))
	return strings.Contains(low, "no templates found") ||
		strings.Contains(low, "no templates provided") ||
		strings.Contains(low, "could not find template") ||
		strings.Contains(low, "templates are not installed") ||
		strings.Contains(low, "nuclei-templates are not installed")
}

func summarizeToolFailure(err error, stderr string) error {
	if msg := strings.TrimSpace(stderr); msg != "" {
		return errors.New(msg)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("timeout exceeded")
	}
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "deadline exceeded") {
		return fmt.Errorf("timeout exceeded")
	}
	return err
}

func isKilledProcessError(err error) bool {
	if err == nil {
		return false
	}
	low := strings.ToLower(err.Error())
	return strings.Contains(low, "signal: killed") || strings.Contains(low, "killed")
}

func collectSecurityTargets(store *SafeStore, surface []SurfaceRow, content []ContentRow, limit int) []string {
	if limit <= 0 {
		return nil
	}
	out := make([]string, 0, limit)
	seen := make(map[string]struct{}, limit)
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}

	for _, r := range content {
		add(r.URL)
		if len(out) >= limit {
			return out
		}
	}
	for _, r := range surface {
		if r.Category == "admin" || r.Category == "auth" || r.Category == "upload" || r.HasParams {
			add(r.URL)
			if len(out) >= limit {
				return out
			}
		}
	}
	for _, c := range store.Snapshot() {
		if !c.Resolved || c.Wildcard {
			continue
		}
		for _, u := range c.LiveURLs {
			add(u)
			if len(out) >= limit {
				return out
			}
		}
		if len(c.LiveURLs) == 0 {
			add("https://" + c.Name)
		}
		if len(out) >= limit {
			return out
		}
	}
	return out
}

func parseNucleiFindings(blob string, limit int) []SecurityFinding {
	if strings.TrimSpace(blob) == "" || limit <= 0 {
		return nil
	}
	lines := splitLines(blob)
	out := make([]SecurityFinding, 0, minInt(len(lines), limit))
	for _, line := range lines {
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			continue
		}
		f := SecurityFinding{
			Target:     stringAny(obj["host"]),
			MatchedAt:  stringAny(obj["matched-at"]),
			TemplateID: stringAny(obj["template-id"]),
			Type:       stringAny(obj["type"]),
			Source:     "nuclei",
		}
		if f.Target == "" {
			f.Target = stringAny(obj["url"])
		}
		if info, ok := obj["info"].(map[string]any); ok {
			if f.Name == "" {
				f.Name = stringAny(info["name"])
			}
			f.Severity = strings.ToLower(strings.TrimSpace(stringAny(info["severity"])))
		}
		if f.Severity == "" {
			f.Severity = strings.ToLower(strings.TrimSpace(stringAny(obj["severity"])))
		}
		if f.TemplateID == "" && f.Target == "" && f.MatchedAt == "" {
			continue
		}
		out = append(out, f)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func dedupeFindings(rows []SecurityFinding, limit int) []SecurityFinding {
	if len(rows) == 0 {
		return nil
	}
	out := make([]SecurityFinding, 0, minInt(len(rows), limit))
	seen := make(map[string]struct{}, len(rows))
	for _, r := range rows {
		k := r.TemplateID + "|" + r.Target + "|" + r.MatchedAt + "|" + r.Severity
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, r)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity == out[j].Severity {
			if out[i].Target == out[j].Target {
				return out[i].TemplateID < out[j].TemplateID
			}
			return out[i].Target < out[j].Target
		}
		return severityRank(out[i].Severity) > severityRank(out[j].Severity)
	})
	return out
}

func severityRank(v string) int {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func findingHost(v string) string {
	u, err := url.Parse(strings.TrimSpace(v))
	if err == nil && strings.TrimSpace(u.Host) != "" {
		return strings.ToLower(strings.TrimSpace(u.Hostname()))
	}
	s := strings.TrimSpace(v)
	if strings.Contains(s, "://") {
		return ""
	}
	if strings.Contains(s, ":") {
		if h, _, ok := strings.Cut(s, ":"); ok {
			return strings.ToLower(strings.TrimSpace(h))
		}
	}
	return strings.ToLower(s)
}

func stringAny(v any) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprintf("%v", v))
}
