package pipeline

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"ultrarecon/internal/config"
	"ultrarecon/internal/util"
)

func runBruteforceCollection(
	ctx context.Context,
	cfg config.Config,
	resolvers []dnsResolver,
	toolErrs *[]ToolError,
	logf func(string, ...any),
) []string {
	if !cfg.EnableBruteforce {
		return nil
	}

	words := loadBruteforceWordlist(cfg)
	if len(words) == 0 {
		return nil
	}
	if len(words) > cfg.MaxBruteforceWords {
		words = words[:cfg.MaxBruteforceWords]
	}

	wordsFile, cleanupWords, err := writeTempList(cfg.OutputDir, "brutewords-*.txt", words)
	if err != nil {
		*toolErrs = append(*toolErrs, ToolError{Stage: "bruteforce", Tool: "internal", Error: err.Error()})
		return nil
	}
	defer cleanupWords()

	resolverLines := make([]string, 0, len(resolvers))
	for _, r := range resolvers {
		resolverLines = append(resolverLines, r.Addr)
	}
	resolverFile, cleanupRes, err := writeTempList(cfg.OutputDir, "resolvers-*.txt", resolverLines)
	if err != nil {
		*toolErrs = append(*toolErrs, ToolError{Stage: "bruteforce", Tool: "internal", Error: err.Error()})
		return nil
	}
	defer cleanupRes()

	// Fast path: shuffledns bruteforce
	if util.HaveCommand("shuffledns") {
		subCtx, cancel := context.WithTimeout(ctx, cfg.BruteTimeout)
		defer cancel()
		res := util.RunCommand(
			subCtx,
			cfg.BruteTimeout,
			"shuffledns",
			"-d", cfg.Domain,
			"-w", wordsFile,
			"-r", resolverFile,
			"-mode", "bruteforce",
			"-silent",
		)
		if res.Err == nil {
			hosts := normalizeCandidates(splitLines(res.Stdout), cfg.Domain)
			logf("[brute] shuffledns candidates=%d", len(hosts))
			return hosts
		}
		*toolErrs = append(*toolErrs, ToolError{Stage: "bruteforce", Tool: "shuffledns", Error: res.Err.Error()})
	}

	// Next fast path: dnsx bruteforce
	if util.HaveCommand("dnsx") {
		subCtx, cancel := context.WithTimeout(ctx, cfg.BruteTimeout)
		defer cancel()
		args := []string{
			"-d", cfg.Domain,
			"-w", wordsFile,
			"-silent",
			"-retry", "2",
			"-t", fmt.Sprintf("%d", minInt(cfg.DNSThreads, 600)),
			"-rl", fmt.Sprintf("%d", cfg.DNSRateLimit),
			"-r", resolverFile,
		}
		res := util.RunCommand(subCtx, cfg.BruteTimeout, "dnsx", args...)
		if res.Err == nil {
			hosts := normalizeCandidates(splitLines(res.Stdout), cfg.Domain)
			logf("[brute] dnsx candidates=%d", len(hosts))
			return hosts
		}
		*toolErrs = append(*toolErrs, ToolError{Stage: "bruteforce", Tool: "dnsx", Error: res.Err.Error()})
	}

	// Internal fallback: generate candidates; DNS resolution happens in dedicated phase.
	out := make([]string, 0, len(words))
	for _, w := range words {
		if validLabel(w) {
			out = append(out, w+"."+cfg.Domain)
		}
	}
	out = util.UniqueSorted(out)
	logf("[brute] internal fallback candidates=%d", len(out))
	return out
}

func runRecursivePassiveCollection(
	ctx context.Context,
	cfg config.Config,
	store *SafeStore,
	toolErrs *[]ToolError,
	logf func(string, ...any),
) []string {
	if !cfg.EnableRecursive {
		return nil
	}

	seeds := selectRecursiveSeeds(store, cfg.RecursiveTopSeeds, cfg.Domain)
	if len(seeds) == 0 {
		return nil
	}
	logf("[recursive] seeds=%d", len(seeds))

	type item struct {
		raw []string
		err *ToolError
	}
	outCh := make(chan item, len(seeds)*3)
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)

	runCollector := func(seed, tool string, fn func(context.Context, string, time.Duration) ([]string, error)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			subCtx, cancel := context.WithTimeout(ctx, cfg.ToolTimeout)
			defer cancel()
			hosts, err := fn(subCtx, seed, cfg.ToolTimeout)
			if err != nil {
				outCh <- item{err: &ToolError{Stage: "recursive", Tool: tool, Error: err.Error()}}
				return
			}
			outCh <- item{raw: hosts}
		}()
	}

	haveSubfinder := util.HaveCommand("subfinder")
	haveAmass := util.HaveCommand("amass")
	haveAssetfinder := util.HaveCommand("assetfinder")

	for _, seed := range seeds {
		if haveSubfinder {
			runCollector(seed, "subfinder", collectSubfinderForDomain)
		}
		if haveAmass {
			runCollector(seed, "amass", collectAmassForDomain)
		}
		if haveAssetfinder {
			runCollector(seed, "assetfinder", collectAssetfinderForDomain)
		}
	}

	wg.Wait()
	close(outCh)

	all := make([]string, 0, 4096)
	for it := range outCh {
		if it.err != nil {
			*toolErrs = append(*toolErrs, *it.err)
			continue
		}
		all = append(all, it.raw...)
	}
	normalized := normalizeCandidates(all, cfg.Domain)
	logf("[recursive] candidates=%d", len(normalized))
	return normalized
}

func runEnrichmentCollection(
	ctx context.Context,
	cfg config.Config,
	hosts []string,
	toolErrs *[]ToolError,
	logf func(string, ...any),
) []string {
	if len(hosts) == 0 {
		return nil
	}
	if len(hosts) > cfg.MaxEnrichmentHosts {
		hosts = hosts[:cfg.MaxEnrichmentHosts]
	}

	results := make([]string, 0, 8192)
	appendParsed := func(raw string, source string) {
		if strings.TrimSpace(raw) == "" {
			return
		}
		found := extractScopedHostsFromBlob(raw, cfg.Domain)
		if len(found) == 0 {
			return
		}
		logf("[enrich] %s extracted=%d", source, len(found))
		results = append(results, found...)
	}

	hostsFile, cleanupHosts, err := writeTempList(cfg.OutputDir, "hosts-*.txt", hosts)
	if err == nil {
		defer cleanupHosts()
	}

	// CSP extraction via httpx
	if cfg.EnableCSPExtraction && util.HaveCommand("httpx") && err == nil {
		subCtx, cancel := context.WithTimeout(ctx, cfg.BruteTimeout)
		res := util.RunCommand(
			subCtx,
			cfg.BruteTimeout,
			"httpx",
			"-l", hostsFile,
			"-csp-probe",
			"-silent",
			"-threads", fmt.Sprintf("%d", minInt(cfg.HTTPThreads, 300)),
			"-rate-limit", fmt.Sprintf("%d", maxInt(100, cfg.DNSRateLimit/2)),
		)
		cancel()
		if res.Err != nil {
			*toolErrs = append(*toolErrs, ToolError{Stage: "enrichment", Tool: "httpx-csp", Error: res.Err.Error()})
		} else {
			appendParsed(res.Stdout, "httpx-csp")
		}
	}

	// TLS SAN/CN extraction via tlsx
	if cfg.EnableTLSEnumeration && util.HaveCommand("tlsx") && err == nil {
		subCtx, cancel := context.WithTimeout(ctx, cfg.BruteTimeout)
		res := util.RunCommand(
			subCtx,
			cfg.BruteTimeout,
			"tlsx",
			"-l", hostsFile,
			"-san",
			"-cn",
			"-silent",
			"-c", fmt.Sprintf("%d", minInt(cfg.HTTPThreads, 250)),
		)
		cancel()
		if res.Err != nil {
			*toolErrs = append(*toolErrs, ToolError{Stage: "enrichment", Tool: "tlsx", Error: res.Err.Error()})
		} else {
			appendParsed(res.Stdout, "tlsx")
		}
	}

	// Archive sources from domain.
	if cfg.EnableArchiveSources {
		if util.HaveCommand("gau") {
			subCtx, cancel := context.WithTimeout(ctx, cfg.BruteTimeout)
			res := util.RunCommand(subCtx, cfg.BruteTimeout, "gau", "--subs", cfg.Domain)
			cancel()
			if res.Err != nil {
				*toolErrs = append(*toolErrs, ToolError{Stage: "enrichment", Tool: "gau", Error: res.Err.Error()})
			} else {
				appendParsed(res.Stdout, "gau")
			}
		}
		if util.HaveCommand("waybackurls") {
			subCtx, cancel := context.WithTimeout(ctx, cfg.BruteTimeout)
			res := util.RunCommand(subCtx, cfg.BruteTimeout, "waybackurls", cfg.Domain)
			cancel()
			if res.Err != nil {
				*toolErrs = append(*toolErrs, ToolError{Stage: "enrichment", Tool: "waybackurls", Error: res.Err.Error()})
			} else {
				appendParsed(res.Stdout, "waybackurls")
			}
		}
		if util.HaveCommand("urlfinder") {
			subCtx, cancel := context.WithTimeout(ctx, cfg.BruteTimeout)
			res := util.RunCommand(subCtx, cfg.BruteTimeout, "urlfinder", "-d", cfg.Domain, "-all")
			cancel()
			if res.Err != nil {
				*toolErrs = append(*toolErrs, ToolError{Stage: "enrichment", Tool: "urlfinder", Error: res.Err.Error()})
			} else {
				appendParsed(res.Stdout, "urlfinder")
			}
		}
	}

	return util.UniqueSorted(results)
}

func selectRecursiveSeeds(store *SafeStore, top int, domain string) []string {
	type seed struct {
		name      string
		sourceCnt int
		depth     int
	}
	snap := store.Snapshot()
	seeds := make([]seed, 0, len(snap))
	for _, c := range snap {
		if !c.Resolved || c.Wildcard || c.Name == domain {
			continue
		}
		left := strings.TrimSuffix(c.Name, "."+domain)
		d := strings.Count(left, ".") + 1
		seeds = append(seeds, seed{name: c.Name, sourceCnt: c.SourceCount(), depth: d})
	}
	sort.Slice(seeds, func(i, j int) bool {
		if seeds[i].sourceCnt == seeds[j].sourceCnt {
			if seeds[i].depth == seeds[j].depth {
				return seeds[i].name < seeds[j].name
			}
			return seeds[i].depth < seeds[j].depth
		}
		return seeds[i].sourceCnt > seeds[j].sourceCnt
	})
	if len(seeds) > top {
		seeds = seeds[:top]
	}
	out := make([]string, 0, len(seeds))
	for _, s := range seeds {
		out = append(out, s.name)
	}
	return out
}

func loadBruteforceWordlist(cfg config.Config) []string {
	if cfg.BruteWordlistFile != "" {
		if lines, err := util.ReadLines(cfg.BruteWordlistFile); err == nil && len(lines) > 0 {
			return sanitizeWordlist(lines, cfg.MaxBruteforceWords)
		}
	}
	if cfg.WordlistFile != "" {
		if lines, err := util.ReadLines(cfg.WordlistFile); err == nil && len(lines) > 0 {
			return sanitizeWordlist(lines, cfg.MaxBruteforceWords)
		}
	}
	return defaultBruteforceWords(cfg.MaxBruteforceWords)
}

func sanitizeWordlist(lines []string, limit int) []string {
	out := make([]string, 0, minInt(len(lines), limit))
	for _, l := range lines {
		l = strings.ToLower(strings.TrimSpace(l))
		if !validLabel(l) {
			continue
		}
		out = append(out, l)
		if len(out) >= limit {
			break
		}
	}
	return util.UniqueSorted(out)
}

func defaultBruteforceWords(limit int) []string {
	words := []string{
		"www", "api", "app", "dev", "test", "stage", "staging", "prod", "uat", "qa",
		"admin", "portal", "dashboard", "auth", "login", "sso", "mfa", "iam", "id",
		"cdn", "static", "assets", "img", "media", "files", "upload", "download",
		"internal", "intranet", "vpn", "remote", "proxy", "gateway", "edge", "lb",
		"mail", "smtp", "imap", "pop", "mx", "ns1", "ns2", "dns", "resolver",
		"db", "mysql", "postgres", "redis", "mongo", "cache", "search", "elastic",
		"kibana", "grafana", "prometheus", "monitor", "status", "health", "ready",
		"metrics", "logs", "siem", "soc", "jenkins", "git", "gitlab", "github", "ci",
		"cd", "build", "artifact", "registry", "repo", "docker", "k8s", "kubernetes",
		"api-dev", "api-stage", "api-prod", "m", "mobile", "beta", "new", "old",
		"billing", "payments", "checkout", "shop", "store", "docs", "swagger", "graphql",
		"webhooks", "events", "pubsub", "queue", "rabbit", "kafka", "stream",
	}
	if limit <= 0 || limit > len(words) {
		limit = len(words)
	}
	return words[:limit]
}

func writeTempList(baseDir, pattern string, lines []string) (string, func(), error) {
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return "", nil, err
	}
	f, err := os.CreateTemp(baseDir, pattern)
	if err != nil {
		return "", nil, err
	}
	path := f.Name()
	f.Close()
	if err := util.WriteLines(path, lines); err != nil {
		_ = os.Remove(path)
		return "", nil, err
	}
	cleanup := func() { _ = os.Remove(path) }
	return path, cleanup, nil
}

func normalizeCandidates(raw []string, domain string) []string {
	out := make([]string, 0, len(raw))
	for _, s := range raw {
		if h, ok := util.NormalizeCandidate(s, domain); ok {
			out = append(out, h)
		}
	}
	return util.UniqueSorted(out)
}

func collectSubfinderForDomain(ctx context.Context, domain string, timeout time.Duration) ([]string, error) {
	res := util.RunCommand(ctx, timeout, "subfinder", "-silent", "-all", "-d", domain)
	if res.Err != nil {
		return nil, res.Err
	}
	return splitLines(res.Stdout), nil
}

func collectAmassForDomain(ctx context.Context, domain string, timeout time.Duration) ([]string, error) {
	res := util.RunCommand(ctx, timeout, "amass", "enum", "-passive", "-norecursive", "-noalts", "-d", domain)
	if res.Err != nil {
		return nil, res.Err
	}
	return splitLines(res.Stdout), nil
}

func collectAssetfinderForDomain(ctx context.Context, domain string, timeout time.Duration) ([]string, error) {
	res := util.RunCommand(ctx, timeout, "assetfinder", "--subs-only", domain)
	if res.Err != nil {
		return nil, res.Err
	}
	return splitLines(res.Stdout), nil
}

func extractScopedHostsFromBlob(blob, domain string) []string {
	if strings.TrimSpace(blob) == "" {
		return nil
	}
	dEsc := regexp.QuoteMeta(strings.ToLower(domain))
	rx := regexp.MustCompile(`(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+` + dEsc)
	matches := rx.FindAllString(strings.ToLower(blob), -1)
	if len(matches) == 0 {
		return nil
	}
	return normalizeCandidates(matches, domain)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
