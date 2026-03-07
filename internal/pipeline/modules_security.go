package pipeline

import (
	"context"
	"encoding/json"
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
		return nil
	}
	if !util.HaveCommand("nuclei") {
		*toolErrs = append(*toolErrs, ToolError{Stage: "security_checks", Tool: "nuclei", Error: "tool missing: nuclei"})
		logf("[security] nuclei missing targets=%d", len(targets))
		return nil
	}

	targetFile, cleanupTargets, err := writeTempList(cfg.OutputDir, "security-targets-*.txt", targets)
	if err != nil {
		*toolErrs = append(*toolErrs, ToolError{Stage: "security_checks", Tool: "internal", Error: err.Error()})
		return nil
	}
	defer cleanupTargets()

	attempts := [][]string{
		{
			"-l", targetFile,
			"-silent",
			"-jsonl",
			"-severity", "medium,high,critical",
			"-tags", "takeover,cors,misconfig,exposure,panel,default-login,redirect,token,secret",
			"-rate-limit", strconvI(maxInt(30, cfg.ContentRate)),
			"-c", strconvI(minInt(cfg.HTTPThreads, 80)),
		},
		{
			"-l", targetFile,
			"-silent",
			"-jsonl",
			"-severity", "medium,high,critical",
			"-rate-limit", strconvI(maxInt(30, cfg.ContentRate)),
			"-c", strconvI(minInt(cfg.HTTPThreads, 80)),
		},
		{
			"-l", targetFile,
			"-silent",
			"-jsonl",
		},
	}

	var findings []SecurityFinding
	runToolAttempts(ctx, minDuration(cfg.BruteTimeout, 6*time.Minute), "nuclei", attempts, "security_checks", toolErrs, func(stdout string) {
		parsed := parseNucleiFindings(stdout, cfg.MaxSecurityFindings)
		findings = append(findings, parsed...)
	})

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
