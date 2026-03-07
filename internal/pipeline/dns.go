package pipeline

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"ultrarecon/internal/config"
	"ultrarecon/internal/util"
)

type dnsResolver struct {
	Addr string
	RTT  time.Duration
}

type resolveTask struct {
	Name       string
	SourceHint int
}

type resolveResult struct {
	Name  string
	IPs   []string
	Votes int
}

func prepareResolvers(ctx context.Context, cfg config.Config, logf func(string, ...any)) []dnsResolver {
	rawResolvers := loadResolverPool(ctx, cfg, logf)
	if len(rawResolvers) == 0 {
		rawResolvers = defaultResolvers()
	}
	if cfg.MaxResolverPool > 0 && len(rawResolvers) > cfg.MaxResolverPool {
		rawResolvers = shuffled(rawResolvers)
		rawResolvers = rawResolvers[:cfg.MaxResolverPool]
		logf("[dns] resolver pool capped=%d", len(rawResolvers))
	}
	logf("[dns] resolvers loaded: %d", len(rawResolvers))

	resolvers := benchmarkResolvers(ctx, cfg, rawResolvers, logf)
	if len(resolvers) == 0 {
		logf("[dns] benchmark fallback: built-in resolvers")
		resolvers = benchmarkResolvers(ctx, cfg, defaultResolvers(), logf)
	}
	if len(resolvers) == 0 {
		for _, r := range defaultResolvers() {
			resolvers = append(resolvers, dnsResolver{Addr: ensureResolverPort(r), RTT: 0})
		}
	}
	logf("[dns] resolvers selected: %d", len(resolvers))
	return resolvers
}

func runDNSResolvePhase(
	ctx context.Context,
	cfg config.Config,
	store *SafeStore,
	resolvers []dnsResolver,
	names []string,
	logf func(string, ...any),
) int {
	if len(names) == 0 || len(resolvers) == 0 {
		return 0
	}

	type sourceCountLookup map[string]int
	counts := make(sourceCountLookup, len(names))
	for _, c := range store.Snapshot() {
		counts[c.Name] = c.SourceCount()
	}

	tasks := make(chan resolveTask, len(names))
	results := make(chan resolveResult, len(names))
	for _, n := range names {
		tasks <- resolveTask{Name: n, SourceHint: counts[n]}
	}
	close(tasks)

	var rrCounter uint32
	workers := cfg.DNSThreads
	if workers < 1 {
		workers = 1
	}
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range tasks {
				ips, votes := resolveWithConsensus(ctx, task.Name, task.SourceHint, resolvers, cfg, &rrCounter)
				if len(ips) == 0 {
					continue
				}
				results <- resolveResult{Name: task.Name, IPs: ips, Votes: votes}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	resolved := 0
	for res := range results {
		store.MarkResolved(res.Name, res.IPs, res.Votes)
		resolved++
	}
	logf("[dns] resolved=%d/%d", resolved, len(names))
	return resolved
}

func resolveWithConsensus(
	ctx context.Context,
	host string,
	sourceCount int,
	resolvers []dnsResolver,
	cfg config.Config,
	rrCounter *uint32,
) ([]string, int) {
	if len(resolvers) == 0 {
		return nil, 0
	}
	requiredVotes := cfg.DNSConsensusMin
	if sourceCount <= 1 || cfg.StrictValidation {
		if requiredVotes < 2 {
			requiredVotes = 2
		}
	}
	if cfg.HomeSafe {
		requiredVotes = 1
	}
	if requiredVotes > len(resolvers) {
		requiredVotes = len(resolvers)
	}

	maxChecks := requiredVotes + 1
	if sourceCount <= 1 || cfg.StrictValidation {
		maxChecks = requiredVotes + 2
	}
	if cfg.HomeSafe {
		maxChecks = 1
	}
	if maxChecks > len(resolvers) {
		maxChecks = len(resolvers)
	}

	ipSet := make(map[string]struct{}, 4)
	votes := 0
	start := int(atomic.AddUint32(rrCounter, 1)-1) % len(resolvers)

	for i := 0; i < maxChecks; i++ {
		if ctx.Err() != nil {
			break
		}
		r := resolvers[(start+i)%len(resolvers)].Addr

		var ips []string
		for retry := 0; retry <= cfg.DNSRetries; retry++ {
			resIPs, err := queryDomain(r, host, cfg.DNSQueryTimeout)
			if err == nil && len(resIPs) > 0 {
				ips = resIPs
				break
			}
			if ctx.Err() != nil {
				break
			}
		}
		if len(ips) == 0 {
			continue
		}
		votes++
		for _, ip := range ips {
			ipSet[ip] = struct{}{}
		}
		if votes >= requiredVotes {
			break
		}
	}

	// Adaptive fallback: accept single-vote candidate if many independent passive sources agree.
	if votes == 1 && requiredVotes > 1 && sourceCount >= 3 && !cfg.StrictValidation {
		requiredVotes = 1
	}
	if votes < requiredVotes {
		return nil, 0
	}

	out := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out, votes
}

func detectWildcardParents(
	ctx context.Context,
	cfg config.Config,
	store *SafeStore,
	resolvers []dnsResolver,
	logf func(string, ...any),
) map[string]map[string]struct{} {
	if len(resolvers) == 0 {
		return nil
	}
	parentCount := make(map[string]int)
	for _, c := range store.Snapshot() {
		if !c.Resolved || c.Wildcard {
			continue
		}
		for _, parent := range util.ParentDomains(c.Name, cfg.Domain) {
			parentCount[parent]++
		}
	}

	type pair struct {
		Name  string
		Count int
	}
	parents := make([]pair, 0, len(parentCount))
	for p, n := range parentCount {
		if n >= cfg.WildcardMinChildren {
			parents = append(parents, pair{Name: p, Count: n})
		}
	}
	sort.Slice(parents, func(i, j int) bool { return parents[i].Count > parents[j].Count })
	if len(parents) > cfg.MaxWildcardParents {
		parents = parents[:cfg.MaxWildcardParents]
	}
	if len(parents) == 0 {
		return nil
	}

	var rrCounter uint32
	out := make(map[string]map[string]struct{})
	var mu sync.Mutex
	parentCh := make(chan pair, len(parents))
	for _, p := range parents {
		parentCh <- p
	}
	close(parentCh)

	workers := 64
	if workers > len(parents) {
		workers = len(parents)
	}
	if workers < 1 {
		workers = 1
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for parent := range parentCh {
				wild, ips := testWildcardParent(ctx, cfg, parent.Name, resolvers, &rrCounter)
				if !wild || len(ips) == 0 {
					continue
				}
				mu.Lock()
				out[parent.Name] = ips
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	logf("[dns] wildcard parents detected=%d tested=%d", len(out), len(parents))
	return out
}

func applyWildcardFilter(store *SafeStore, cfg config.Config, wildcardParents map[string]map[string]struct{}) int {
	if len(wildcardParents) == 0 {
		return 0
	}
	filtered := 0
	for _, c := range store.Snapshot() {
		if !c.Resolved || c.Wildcard {
			continue
		}
		ips := c.IPs
		if len(ips) == 0 {
			continue
		}
		for _, parent := range util.ParentDomains(c.Name, cfg.Domain) {
			wIPs, ok := wildcardParents[parent]
			if !ok {
				continue
			}
			if ipSubset(ips, wIPs) {
				store.MarkWildcard(c.Name)
				filtered++
				break
			}
		}
	}
	return filtered
}

func testWildcardParent(
	ctx context.Context,
	cfg config.Config,
	parent string,
	resolvers []dnsResolver,
	rrCounter *uint32,
) (bool, map[string]struct{}) {
	threshold := cfg.WildcardTests
	if threshold > 1 {
		threshold--
	}
	if cfg.WildcardTests <= 2 {
		threshold = cfg.WildcardTests
	}
	if threshold < 1 {
		threshold = 1
	}

	hits := 0
	ipSet := make(map[string]struct{}, 4)
	for i := 0; i < cfg.WildcardTests; i++ {
		if ctx.Err() != nil {
			break
		}
		randHost := util.RandomLabel(12) + "." + parent
		start := int(atomic.AddUint32(rrCounter, 1)-1) % len(resolvers)
		// Try two resolvers per test to reduce resolver-specific noise.
		resolved := false
		for k := 0; k < 2 && k < len(resolvers); k++ {
			r := resolvers[(start+k)%len(resolvers)].Addr
			ips, err := queryDomain(r, randHost, cfg.DNSQueryTimeout)
			if err != nil || len(ips) == 0 {
				continue
			}
			hits++
			for _, ip := range ips {
				ipSet[ip] = struct{}{}
			}
			resolved = true
			break
		}
		if !resolved {
			continue
		}
	}
	return hits >= threshold, ipSet
}

func queryDomain(resolverAddr, host string, timeout time.Duration) ([]string, error) {
	addr := ensureResolverPort(resolverAddr)
	client := &dns.Client{
		Timeout: timeout,
		Net:     "udp",
	}

	ipSet := make(map[string]struct{}, 4)

	for _, qType := range []uint16{dns.TypeA, dns.TypeAAAA} {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(host), qType)
		in, _, err := client.Exchange(m, addr)
		if err != nil || in == nil {
			continue
		}
		if in.Rcode != dns.RcodeSuccess {
			continue
		}
		for _, ans := range in.Answer {
			switch rr := ans.(type) {
			case *dns.A:
				ipSet[rr.A.String()] = struct{}{}
			case *dns.AAAA:
				ipSet[rr.AAAA.String()] = struct{}{}
			}
		}
	}

	if len(ipSet) == 0 {
		return nil, fmt.Errorf("no records")
	}
	out := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out, nil
}

func benchmarkResolvers(
	ctx context.Context,
	cfg config.Config,
	resolvers []string,
	logf func(string, ...any),
) []dnsResolver {
	if len(resolvers) == 0 {
		return nil
	}
	type resolverScore struct {
		Addr    string
		RTT     time.Duration
		Success int
	}
	out := make([]resolverScore, 0, len(resolvers))
	var mu sync.Mutex
	var noisyCount int64
	var weakCount int64
	var probeCounter uint64
	jobs := make(chan string, len(resolvers))
	for _, r := range resolvers {
		jobs <- ensureResolverPort(r)
	}
	close(jobs)

	workers := 200
	if workers > len(resolvers) {
		workers = len(resolvers)
	}
	if workers < 1 {
		workers = 1
	}

	minSuccess := 1
	if cfg.StrictValidation || len(resolvers) > cfg.MaxResolvers*3 {
		minSuccess = 2
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := range jobs {
				if ctx.Err() != nil {
					return
				}
				success, avgRTT, noisy := probeResolverQuality(r, cfg.DNSQueryTimeout, &probeCounter)
				if noisy {
					atomic.AddInt64(&noisyCount, 1)
					continue
				}
				if success < minSuccess {
					atomic.AddInt64(&weakCount, 1)
					continue
				}
				mu.Lock()
				out = append(out, resolverScore{Addr: r, RTT: avgRTT, Success: success})
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	sort.Slice(out, func(i, j int) bool {
		if out[i].Success == out[j].Success {
			if out[i].RTT == out[j].RTT {
				return out[i].Addr < out[j].Addr
			}
			return out[i].RTT < out[j].RTT
		}
		return out[i].Success > out[j].Success
	})

	final := make([]dnsResolver, 0, len(out))
	for _, r := range out {
		final = append(final, dnsResolver{Addr: r.Addr, RTT: r.RTT})
	}
	if cfg.MaxResolvers > 0 && len(final) > cfg.MaxResolvers {
		final = final[:cfg.MaxResolvers]
	}
	logf("[dns] resolver benchmark success=%d/%d noisy=%d weak=%d", len(final), len(resolvers), noisyCount, weakCount)
	return final
}

func probeResolverQuality(addr string, timeout time.Duration, probeCounter *uint64) (int, time.Duration, bool) {
	queries := []string{"one.one.one.one", "cloudflare.com"}
	success := 0
	var rttTotal time.Duration
	for _, host := range queries {
		started := time.Now()
		ips, err := queryDomain(addr, host, timeout)
		if err != nil || len(ips) == 0 {
			continue
		}
		success++
		rttTotal += time.Since(started)
	}
	if success == 0 {
		return 0, 0, false
	}
	// Drop resolvers that answer random names under .invalid (black-lies/noisy behavior).
	for i := 0; i < 2; i++ {
		id := atomic.AddUint64(probeCounter, 1)
		bogus := fmt.Sprintf("nx-%d-%d.ultrarecon.invalid", time.Now().UnixNano(), id)
		ips, err := queryDomain(addr, bogus, timeout)
		if err == nil && len(ips) > 0 {
			return success, rttTotal / time.Duration(success), true
		}
	}
	return success, rttTotal / time.Duration(success), false
}

func loadResolverPool(ctx context.Context, cfg config.Config, logf func(string, ...any)) []string {
	if strings.TrimSpace(cfg.ResolversFile) != "" {
		out := loadResolversFromFile(cfg.ResolversFile)
		if len(out) > 0 {
			return out
		}
		logf("[dns] custom resolvers file yielded no valid IPv4 resolvers: %s", cfg.ResolversFile)
		return nil
	}
	if cfg.EnableTrickestResolvers {
		out := loadResolversFromTrickest(ctx, cfg, logf)
		if len(out) > 0 {
			return out
		}
	}
	return nil
}

func loadResolversFromFile(path string) []string {
	lines, err := util.ReadLines(path)
	if err != nil {
		return nil
	}
	return parseResolverLines(lines)
}

func loadResolversFromTrickest(ctx context.Context, cfg config.Config, logf func(string, ...any)) []string {
	cachePath := filepath.Join(cfg.OutputDir, "resolvers_trickest.txt")
	urls := []string{
		"https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-extended.txt",
		"https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt",
		"https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt",
	}
	timeout := cfg.ResolverFetchTimeout
	if timeout <= 0 {
		timeout = 35 * time.Second
	}

	for _, u := range urls {
		lines, err := downloadResolverList(ctx, u, timeout)
		if err != nil {
			logf("[dns] resolver source fetch failed: %s (%v)", u, err)
			continue
		}
		parsed := parseResolverLines(lines)
		if len(parsed) == 0 {
			continue
		}
		if err := util.WriteLines(cachePath, parsed); err != nil {
			logf("[dns] resolver cache write failed: %v", err)
		}
		logf("[dns] resolver source loaded: %s count=%d", u, len(parsed))
		return parsed
	}

	if cached, err := util.ReadLines(cachePath); err == nil {
		parsed := parseResolverLines(cached)
		if len(parsed) > 0 {
			logf("[dns] resolver source fallback: cache count=%d", len(parsed))
			return parsed
		}
	}
	return nil
}

func downloadResolverList(ctx context.Context, rawURL string, timeout time.Duration) ([]string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ultrarecon/1.0")
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("http status %d", resp.StatusCode)
	}
	blob, err := io.ReadAll(io.LimitReader(resp.Body, 15*1024*1024))
	if err != nil {
		return nil, err
	}
	text := strings.ReplaceAll(string(blob), "\r", "")
	return strings.Split(text, "\n"), nil
}

func parseResolverLines(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if idx := strings.Index(line, ";"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		line = strings.TrimPrefix(line, "udp://")
		line = strings.TrimPrefix(line, "tcp://")
		if line == "" {
			continue
		}

		host := line
		port := "53"
		if strings.Count(line, ":") == 1 {
			h, p, err := net.SplitHostPort(line)
			if err == nil {
				host = strings.TrimSpace(h)
				if strings.TrimSpace(p) != "" {
					port = strings.TrimSpace(p)
				}
			} else {
				parts := strings.SplitN(line, ":", 2)
				host = strings.TrimSpace(parts[0])
				if len(parts) == 2 && strings.TrimSpace(parts[1]) != "" {
					port = strings.TrimSpace(parts[1])
				}
			}
		} else if strings.Contains(line, ":") {
			// Skip IPv6 for now; resolver pipeline currently expects IPv4:port.
			continue
		}

		ip := net.ParseIP(host)
		if ip == nil || ip.To4() == nil {
			continue
		}
		if p, err := strconv.Atoi(port); err != nil || p <= 0 || p > 65535 {
			port = "53"
		}
		out = append(out, ip.String()+":"+port)
	}
	return util.UniqueSorted(out)
}

func defaultResolvers() []string {
	return []string{
		"1.1.1.1:53",
		"1.0.0.1:53",
		"8.8.8.8:53",
		"8.8.4.4:53",
		"9.9.9.9:53",
		"149.112.112.112:53",
		"208.67.222.222:53",
		"208.67.220.220:53",
	}
}

func ensureResolverPort(addr string) string {
	if addr == "" {
		return ""
	}
	if strings.Count(addr, ":") == 1 {
		if _, _, err := net.SplitHostPort(addr); err == nil {
			return addr
		}
	}
	if net.ParseIP(addr) != nil {
		return addr + ":53"
	}
	// last fallback
	if strings.Contains(addr, ":") {
		return addr
	}
	return addr + ":53"
}

func ipSubset(a, b map[string]struct{}) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	for ip := range a {
		if _, ok := b[ip]; !ok {
			return false
		}
	}
	return true
}

func shuffled(items []string) []string {
	out := append([]string(nil), items...)
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}
