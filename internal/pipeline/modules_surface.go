package pipeline

import (
	"context"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"ultrarecon/internal/config"
	"ultrarecon/internal/util"
)

var urlRegex = regexp.MustCompile(`(?i)https?://[^\s"'<>]+`)

func runSurfaceMapping(
	ctx context.Context,
	cfg config.Config,
	store *SafeStore,
	toolErrs *[]ToolError,
	logf func(string, ...any),
) []SurfaceRow {
	if !cfg.EnableSurfaceMapping {
		return nil
	}

	inputs := collectSurfaceInputs(store, cfg.MaxSurfaceInputs)
	if len(inputs) == 0 {
		return nil
	}

	results := make([]SurfaceRow, 0, minInt(cfg.MaxSurfaceRows, cfg.MaxSurfaceURLs))
	seen := make(map[string]struct{}, cfg.MaxSurfaceRows)
	addRow := func(raw, source string) {
		row, ok := normalizeSurfaceURL(raw, cfg.Domain, source)
		if !ok {
			return
		}
		if len(seen) >= cfg.MaxSurfaceRows || len(seen) >= cfg.MaxSurfaceURLs {
			return
		}
		if _, exists := seen[row.URL]; exists {
			return
		}
		seen[row.URL] = struct{}{}
		results = append(results, row)
	}

	for _, in := range inputs {
		addRow(in, "seed")
	}

	inputFile, cleanupInputs, err := writeTempList(cfg.OutputDir, "surface-inputs-*.txt", inputs)
	if err != nil {
		*toolErrs = append(*toolErrs, ToolError{Stage: "surface_mapping", Tool: "internal", Error: err.Error()})
		return results
	}
	defer cleanupInputs()

	appendOutput := func(blob, source string) {
		if strings.TrimSpace(blob) == "" {
			return
		}
		lines := splitLines(blob)
		for _, line := range lines {
			// Most collectors return URL lines; also extract embedded URLs as fallback.
			addRow(line, source)
			for _, u := range extractURLsFromBlob(line) {
				addRow(u, source)
			}
			if len(results) >= cfg.MaxSurfaceRows || len(results) >= cfg.MaxSurfaceURLs {
				return
			}
		}
	}

	if util.HaveCommand("katana") {
		attempts := [][]string{
			{"-list", inputFile, "-silent", "-d", strconvI(cfg.ScrapeDepth), "-c", strconvI(minInt(cfg.HTTPThreads, 100))},
			{"-list", inputFile, "-silent", "-d", "1"},
			{"-list", inputFile, "-silent"},
		}
		runToolAttempts(ctx, cfg.BruteTimeout, "katana", attempts, "surface_mapping", toolErrs, func(stdout string) {
			appendOutput(stdout, "katana")
		})
	}

	if util.HaveCommand("gau") {
		attempts := [][]string{
			{"--subs", cfg.Domain},
			{cfg.Domain},
		}
		runToolAttempts(ctx, cfg.BruteTimeout, "gau", attempts, "surface_mapping", toolErrs, func(stdout string) {
			appendOutput(stdout, "gau")
		})
	}

	if util.HaveCommand("waybackurls") {
		attempts := [][]string{
			{cfg.Domain},
		}
		runToolAttempts(ctx, cfg.BruteTimeout, "waybackurls", attempts, "surface_mapping", toolErrs, func(stdout string) {
			appendOutput(stdout, "waybackurls")
		})
	}

	if util.HaveCommand("urlfinder") {
		attempts := [][]string{
			{"-d", cfg.Domain, "-all"},
			{"-d", cfg.Domain},
		}
		runToolAttempts(ctx, cfg.BruteTimeout, "urlfinder", attempts, "surface_mapping", toolErrs, func(stdout string) {
			appendOutput(stdout, "urlfinder")
		})
	}

	results = dedupeSurfaceRows(results, cfg.MaxSurfaceRows)
	logf("[surface] inputs=%d rows=%d", len(inputs), len(results))
	return results
}

func collectSurfaceInputs(store *SafeStore, limit int) []string {
	if limit <= 0 {
		return nil
	}
	snap := store.Snapshot()
	out := make([]string, 0, limit)
	seen := make(map[string]struct{}, limit)

	for _, c := range snap {
		if !c.Resolved || c.Wildcard {
			continue
		}
		for _, u := range c.LiveURLs {
			u = strings.TrimSpace(u)
			if u == "" {
				continue
			}
			if _, ok := seen[u]; ok {
				continue
			}
			seen[u] = struct{}{}
			out = append(out, u)
			if len(out) >= limit {
				return out
			}
		}
	}

	for _, c := range snap {
		if !c.Resolved || c.Wildcard {
			continue
		}
		u := "https://" + c.Name
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		out = append(out, u)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func normalizeSurfaceURL(raw, domain, source string) (SurfaceRow, bool) {
	var row SurfaceRow
	s := strings.TrimSpace(raw)
	if s == "" {
		return row, false
	}
	if !strings.Contains(s, "://") {
		if h, ok := util.NormalizeCandidate(s, domain); ok {
			s = "https://" + h
		} else {
			return row, false
		}
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return row, false
	}
	host, ok := util.NormalizeCandidate(u.Host, domain)
	if !ok {
		return row, false
	}
	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	if scheme != "http" && scheme != "https" {
		return row, false
	}
	u.Scheme = scheme
	u.Host = host
	u.Fragment = ""
	if strings.TrimSpace(u.Path) == "" {
		u.Path = "/"
	}
	keys := make([]string, 0, len(u.Query()))
	for k := range u.Query() {
		k = strings.TrimSpace(strings.ToLower(k))
		if k != "" {
			keys = append(keys, k)
		}
	}
	keys = util.UniqueSorted(keys)
	row = SurfaceRow{
		URL:       u.String(),
		Host:      host,
		Path:      u.EscapedPath(),
		Category:  classifyEndpoint(host, u.EscapedPath(), keys),
		ParamKeys: keys,
		HasParams: len(keys) > 0,
		Source:    source,
	}
	if row.Path == "" {
		row.Path = "/"
	}
	return row, true
}

func classifyEndpoint(host, path string, params []string) string {
	v := strings.ToLower(host + " " + path + " " + strings.Join(params, " "))
	switch {
	case strings.Contains(v, "graphql"):
		return "graphql"
	case strings.Contains(v, "/api") || strings.HasPrefix(strings.TrimSpace(path), "/v1") || strings.HasPrefix(strings.TrimSpace(path), "/v2"):
		return "api"
	case strings.Contains(v, "login") || strings.Contains(v, "auth") || strings.Contains(v, "signin") || strings.Contains(v, "sso"):
		return "auth"
	case strings.Contains(v, "admin") || strings.Contains(v, "dashboard") || strings.Contains(v, "panel"):
		return "admin"
	case strings.Contains(v, "upload") || strings.Contains(v, "file") || strings.Contains(v, "import"):
		return "upload"
	case strings.Contains(v, ".js") || strings.Contains(v, ".css") || strings.Contains(v, "/static") || strings.Contains(v, "/assets"):
		return "static"
	case strings.Contains(v, "ws") || strings.Contains(v, "socket"):
		return "websocket"
	default:
		return "other"
	}
}

func extractURLsFromBlob(blob string) []string {
	if strings.TrimSpace(blob) == "" {
		return nil
	}
	return util.UniqueSorted(urlRegex.FindAllString(blob, -1))
}

func dedupeSurfaceRows(rows []SurfaceRow, limit int) []SurfaceRow {
	if len(rows) == 0 {
		return nil
	}
	out := make([]SurfaceRow, 0, minInt(len(rows), limit))
	seen := make(map[string]struct{}, len(rows))
	for _, r := range rows {
		k := r.URL
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
		if out[i].Host == out[j].Host {
			return out[i].URL < out[j].URL
		}
		return out[i].Host < out[j].Host
	})
	return out
}

func urlsFromSurfaceRows(rows []SurfaceRow) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		if strings.TrimSpace(r.URL) != "" {
			out = append(out, r.URL)
		}
	}
	return util.UniqueSorted(out)
}

func countSurfacePaths(rows []SurfaceRow) int {
	seen := make(map[string]struct{}, len(rows))
	for _, r := range rows {
		if strings.TrimSpace(r.Path) == "" {
			continue
		}
		key := r.Host + r.Path
		seen[key] = struct{}{}
	}
	return len(seen)
}

func runToolAttempts(
	ctx context.Context,
	timeout time.Duration,
	tool string,
	attempts [][]string,
	stage string,
	toolErrs *[]ToolError,
	onSuccess func(stdout string),
) {
	var lastErr error
	for _, args := range attempts {
		subCtx, cancel := context.WithTimeout(ctx, timeout)
		res := util.RunCommand(subCtx, timeout, tool, args...)
		cancel()
		if strings.TrimSpace(res.Stdout) != "" {
			onSuccess(res.Stdout)
		}
		if res.Err == nil {
			return
		}
		lastErr = res.Err
		if !flagError(res.Stderr) {
			if strings.TrimSpace(res.Stdout) != "" {
				return
			}
		}
	}
	if lastErr != nil {
		*toolErrs = append(*toolErrs, ToolError{Stage: stage, Tool: tool, Error: lastErr.Error()})
	}
}

func strconvI(v int) string {
	return strconv.Itoa(v)
}
