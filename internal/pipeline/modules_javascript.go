package pipeline

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ultrarecon/internal/config"
	"ultrarecon/internal/util"
)

var (
	jsQuotedPathRegex    = regexp.MustCompile("[\"'`]((?:/|\\./|\\.\\./)[A-Za-z0-9_./?&=%#:@~,+-]{2,})[\"'`]")
	jsProtoRelativeRegex = regexp.MustCompile("[\"'`](//[A-Za-z0-9.-]+(?:/[A-Za-z0-9_./?&=%#:@~,+-]*)?)[\"'`]")
	jsLoosePathRegex     = regexp.MustCompile("[\"'`]((?:api|graphql|graph|rest|auth|admin|oauth|v[0-9]+|assets|static|content|services?|uploads?|_next|wp-json)(?:/[A-Za-z0-9_./?&=%#:@~,+-]*)?)[\"'`]")
	jsSourceMapRegex     = regexp.MustCompile(`(?m)sourceMappingURL=([^\s*]+)`)
)

type jsAnalysisResult struct {
	row        JSAnalysisRow
	discovered []SurfaceRow
}

func runJSAnalysis(
	ctx context.Context,
	cfg config.Config,
	surfaceRows []SurfaceRow,
	toolErrs *[]ToolError,
	logf func(string, ...any),
) ([]JSAnalysisRow, []SurfaceRow) {
	if !cfg.EnableJSAnalysis {
		return nil, nil
	}
	targets := collectJSURLs(surfaceRows, cfg.MaxJSFiles)
	if len(targets) == 0 {
		logf("[js] files=0 extracted=0")
		return nil, nil
	}

	timeout := cfg.HTTPTimeout * 2
	if timeout < 12*time.Second {
		timeout = 12 * time.Second
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			MaxIdleConns:        32,
			MaxIdleConnsPerHost: 4,
			TLSHandshakeTimeout: 5 * time.Second,
			IdleConnTimeout:     30 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	workers := minInt(maxInt(2, cfg.HTTPThreads/20), 12)
	if workers > len(targets) {
		workers = len(targets)
	}
	tasks := make(chan string, len(targets))
	results := make(chan jsAnalysisResult, len(targets))
	for _, target := range targets {
		tasks <- target
	}
	close(tasks)

	var processed int64
	progressDone := make(chan struct{})
	go reportJSProgress(progressDone, len(targets), &processed, logf)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range tasks {
				row, discovered := analyzeJSFile(ctx, client, cfg, target)
				atomic.AddInt64(&processed, 1)
				results <- jsAnalysisResult{row: row, discovered: discovered}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(progressDone)
		close(results)
	}()

	jsRows := make([]JSAnalysisRow, 0, len(targets))
	discovered := make([]SurfaceRow, 0, minInt(cfg.MaxJSDiscoveries, len(targets)*4))
	for result := range results {
		jsRows = append(jsRows, result.row)
		for _, row := range result.discovered {
			discovered = append(discovered, row)
			if len(discovered) >= cfg.MaxJSDiscoveries {
				break
			}
		}
		if len(discovered) >= cfg.MaxJSDiscoveries {
			continue
		}
	}

	sort.Slice(jsRows, func(i, j int) bool {
		if jsRows[i].Host == jsRows[j].Host {
			return jsRows[i].URL < jsRows[j].URL
		}
		return jsRows[i].Host < jsRows[j].Host
	})
	discovered = dedupeSurfaceRows(discovered, cfg.MaxJSDiscoveries)
	logf("[js] files=%d extracted=%d", len(jsRows), len(discovered))
	return jsRows, discovered
}

func collectJSURLs(rows []SurfaceRow, limit int) []string {
	if limit <= 0 {
		return nil
	}
	type candidate struct {
		URL   string
		Score int
	}
	candidates := make([]candidate, 0, minInt(limit, len(rows)))
	seen := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		if !isJavaScriptURL(row.URL, row.Path) {
			continue
		}
		if _, ok := seen[row.URL]; ok {
			continue
		}
		seen[row.URL] = struct{}{}
		candidates = append(candidates, candidate{URL: row.URL, Score: jsURLScore(row.URL, row.Path)})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Score == candidates[j].Score {
			return candidates[i].URL < candidates[j].URL
		}
		return candidates[i].Score > candidates[j].Score
	})
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	out := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		out = append(out, candidate.URL)
	}
	return out
}

func isJavaScriptURL(rawURL, path string) bool {
	rawURL = strings.ToLower(strings.TrimSpace(rawURL))
	path = strings.ToLower(strings.TrimSpace(path))
	return strings.Contains(rawURL, ".js") || strings.HasSuffix(path, ".js")
}

func analyzeJSFile(ctx context.Context, client *http.Client, cfg config.Config, target string) (JSAnalysisRow, []SurfaceRow) {
	row := JSAnalysisRow{
		URL:    target,
		Source: "javascript",
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		row.Error = err.Error()
		return row, nil
	}
	req.Header.Set("User-Agent", "UltraRecon/1.0")
	resp, err := client.Do(req)
	if err != nil {
		row.Error = err.Error()
		return row, nil
	}
	defer resp.Body.Close()
	row.StatusCode = resp.StatusCode
	if u, err := url.Parse(target); err == nil {
		row.Host = strings.ToLower(strings.TrimSpace(u.Hostname()))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		row.Error = err.Error()
		return row, nil
	}
	blob := normalizeJSBlob(string(body))
	if sourceMapBlob, ok := fetchSourceMapBlob(ctx, client, target, blob); ok {
		blob += "\n" + normalizeJSBlob(sourceMapBlob)
	}
	absURLs := util.UniqueSorted(extractURLsFromBlob(blob))
	pathURLs := extractJSRelativeURLs(target, blob)
	inScopeHosts := extractJSHosts(blob, cfg.Domain)

	discovered := make([]SurfaceRow, 0, minInt(cfg.MaxJSDiscoveries, len(absURLs)+len(pathURLs)+len(inScopeHosts)))
	addDiscovered := func(raw string) {
		surface, ok := normalizeSurfaceURL(raw, cfg.Domain, "js")
		if !ok {
			return
		}
		discovered = append(discovered, surface)
	}
	for _, raw := range absURLs {
		addDiscovered(raw)
	}
	for _, raw := range pathURLs {
		addDiscovered(raw)
	}
	for _, host := range inScopeHosts {
		addDiscovered("https://" + host)
	}
	discovered = dedupeSurfaceRows(discovered, cfg.MaxJSDiscoveries)

	row.ExtractedURLs = surfaceURLsFromRows(discovered, 25)
	row.ExtractedHosts = limitStrings(inScopeHosts, 25)
	row.ExtractedPaths = limitStrings(relativePathsFromBlob(blob), 25)
	return row, discovered
}

func extractJSRelativeURLs(baseURL string, blob string) []string {
	base, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return nil
	}
	out := make([]string, 0, 32)
	seen := make(map[string]struct{}, 32)
	addResolved := func(raw string, forceRoot bool) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		switch {
		case strings.HasPrefix(raw, "//"):
			raw = base.Scheme + ":" + raw
		case forceRoot:
			raw = "/" + strings.TrimLeft(raw, "/")
		}
		ref, err := url.Parse(raw)
		if err != nil {
			return
		}
		u := base.ResolveReference(ref)
		if _, ok := seen[u.String()]; ok {
			return
		}
		seen[u.String()] = struct{}{}
		out = append(out, u.String())
	}
	for _, m := range jsQuotedPathRegex.FindAllStringSubmatch(blob, -1) {
		if len(m) >= 2 {
			addResolved(m[1], false)
		}
	}
	for _, m := range jsProtoRelativeRegex.FindAllStringSubmatch(blob, -1) {
		if len(m) >= 2 {
			addResolved(m[1], false)
		}
	}
	for _, m := range jsLoosePathRegex.FindAllStringSubmatch(blob, -1) {
		if len(m) >= 2 {
			addResolved(m[1], true)
		}
	}
	sort.Strings(out)
	return out
}

func extractJSHosts(blob string, domain string) []string {
	pat := `(?i)\b[a-z0-9][a-z0-9.-]*\.` + regexp.QuoteMeta(strings.ToLower(strings.TrimSpace(domain))) + `\b`
	re, err := regexp.Compile(pat)
	if err != nil {
		return nil
	}
	matches := re.FindAllString(blob, -1)
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		if host, ok := util.NormalizeCandidate(match, domain); ok {
			out = append(out, host)
		}
	}
	return util.UniqueSorted(out)
}

func relativePathsFromBlob(blob string) []string {
	out := make([]string, 0, 32)
	seen := make(map[string]struct{}, 32)
	addPath := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		out = append(out, path)
	}
	for _, m := range jsQuotedPathRegex.FindAllStringSubmatch(blob, -1) {
		if len(m) >= 2 {
			addPath(m[1])
		}
	}
	for _, m := range jsLoosePathRegex.FindAllStringSubmatch(blob, -1) {
		if len(m) >= 2 {
			addPath(m[1])
		}
	}
	sort.Strings(out)
	return out
}

func normalizeJSBlob(blob string) string {
	blob = strings.ReplaceAll(blob, `\/`, `/`)
	blob = strings.ReplaceAll(blob, `\u002f`, `/`)
	blob = strings.ReplaceAll(blob, `\x2f`, `/`)
	return blob
}

func jsURLScore(rawURL, path string) int {
	score := 0
	v := strings.ToLower(strings.TrimSpace(rawURL + " " + path))
	positive := []string{"app", "main", "index", "bundle", "chunk", "runtime", "client", "_next", "webpack", "api", "graphql", "auth"}
	negative := []string{"jquery", "bootstrap", "polyfill", "analytics", "gtm", "google", "cookie", "consent", "ads", "vendor"}
	for _, token := range positive {
		if strings.Contains(v, token) {
			score += 3
		}
	}
	for _, token := range negative {
		if strings.Contains(v, token) {
			score -= 2
		}
	}
	if strings.Contains(v, ".min.js") {
		score--
	}
	if strings.Contains(v, ".js") {
		score++
	}
	return score
}

func fetchSourceMapBlob(ctx context.Context, client *http.Client, baseURL, blob string) (string, bool) {
	m := jsSourceMapRegex.FindStringSubmatch(blob)
	if len(m) < 2 {
		return "", false
	}
	ref := strings.TrimSpace(m[1])
	if ref == "" || strings.HasPrefix(ref, "data:") {
		return "", false
	}
	base, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", false
	}
	u, err := url.Parse(ref)
	if err != nil {
		return "", false
	}
	sourceMapURL := base.ResolveReference(u).String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceMapURL, nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("User-Agent", "UltraRecon/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return "", false
	}
	var obj struct {
		SourcesContent []string `json:"sourcesContent"`
	}
	if err := json.Unmarshal(body, &obj); err != nil {
		return "", false
	}
	if len(obj.SourcesContent) == 0 {
		return "", false
	}
	var b strings.Builder
	for _, content := range obj.SourcesContent {
		content = strings.TrimSpace(content)
		if content == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(content)
	}
	if b.Len() == 0 {
		return "", false
	}
	return b.String(), true
}

func surfaceURLsFromRows(rows []SurfaceRow, limit int) []string {
	out := make([]string, 0, minInt(limit, len(rows)))
	seen := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		if _, ok := seen[row.URL]; ok {
			continue
		}
		seen[row.URL] = struct{}{}
		out = append(out, row.URL)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func limitStrings(values []string, limit int) []string {
	if len(values) == 0 || limit <= 0 {
		return nil
	}
	if len(values) > limit {
		values = values[:limit]
	}
	out := make([]string, len(values))
	copy(out, values)
	return out
}

func countJSExtractedURLs(rows []JSAnalysisRow) int {
	seen := make(map[string]struct{}, len(rows)*4)
	for _, row := range rows {
		for _, raw := range row.ExtractedURLs {
			seen[raw] = struct{}{}
		}
	}
	return len(seen)
}

func reportJSProgress(done <-chan struct{}, total int, processed *int64, logf func(string, ...any)) {
	if total <= 0 {
		return
	}
	ticker := time.NewTicker(4 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			p := int(atomic.LoadInt64(processed))
			if p == 0 || p >= total {
				continue
			}
			logf("[js] progress=%d/%d", p, total)
		}
	}
}
