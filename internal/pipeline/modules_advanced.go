package pipeline

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"ultrarecon/internal/config"
	"ultrarecon/internal/util"
)

func runNoerrorCollection(
	ctx context.Context,
	cfg config.Config,
	resolvers []dnsResolver,
	toolErrs *[]ToolError,
	logf func(string, ...any),
) []string {
	if !cfg.EnableNoerror || len(resolvers) == 0 {
		return nil
	}
	words := loadBruteforceWordlist(cfg)
	if len(words) == 0 {
		return nil
	}
	if len(words) > cfg.MaxNoerrorWords {
		words = words[:cfg.MaxNoerrorWords]
	}

	// Guard: skip NOERROR stage on black-lies style behavior.
	if detectsNoerrorBlackLies(cfg, resolvers) {
		logf("[noerror] skipped due to black-lies/noerror-on-random behavior")
		return nil
	}

	tasks := make(chan string, len(words))
	for _, w := range words {
		tasks <- w
	}
	close(tasks)

	var rrCounter uint32
	workers := minInt(cfg.DNSThreads, 180)
	if cfg.HomeSafe {
		workers = minInt(workers, 50)
	}
	if workers < 1 {
		workers = 1
	}

	results := make(chan string, len(words))
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for w := range tasks {
				host := w + "." + cfg.Domain
				start := int(atomic.AddUint32(&rrCounter, 1)-1) % len(resolvers)
				noerror := false
				for retry := 0; retry <= cfg.DNSRetries; retry++ {
					r := resolvers[(start+retry)%len(resolvers)].Addr
					ok, err := queryNoerrorCode(r, host, cfg.DNSQueryTimeout)
					if err != nil {
						continue
					}
					if ok {
						noerror = true
						break
					}
				}
				if noerror {
					results <- host
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	out := make([]string, 0, len(words)/5)
	for h := range results {
		out = append(out, h)
	}
	out = normalizeCandidates(out, cfg.Domain)
	if len(out) > cfg.MaxResolveQueue {
		out = out[:cfg.MaxResolveQueue]
	}
	logf("[noerror] candidates=%d", len(out))
	return out
}

func runDNSPivotCollection(
	ctx context.Context,
	cfg config.Config,
	store *SafeStore,
	resolvers []dnsResolver,
	toolErrs *[]ToolError,
	logf func(string, ...any),
) []string {
	if !cfg.EnableDNSPivot || len(resolvers) == 0 {
		return nil
	}
	seedHosts := finalResolvedNames(store)
	if len(seedHosts) == 0 {
		return nil
	}
	if len(seedHosts) > cfg.MaxDNSPivotHosts {
		seedHosts = seedHosts[:cfg.MaxDNSPivotHosts]
	}

	type outRow struct {
		cands []string
	}
	outCh := make(chan outRow, len(seedHosts))
	var rrCounter uint32
	workers := minInt(cfg.DNSThreads, 120)
	if cfg.HomeSafe {
		workers = minInt(workers, 40)
	}
	if workers < 1 {
		workers = 1
	}
	tasks := make(chan string, len(seedHosts))
	for _, h := range seedHosts {
		tasks <- h
	}
	close(tasks)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range tasks {
				start := int(atomic.AddUint32(&rrCounter, 1)-1) % len(resolvers)
				r := resolvers[start].Addr
				cands, err := queryPivotRecords(r, host, cfg.Domain, cfg.DNSQueryTimeout)
				if err != nil {
					continue
				}
				if len(cands) > 0 {
					outCh <- outRow{cands: cands}
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(outCh)
	}()

	all := make([]string, 0, 4096)
	for row := range outCh {
		all = append(all, row.cands...)
	}

	// Optional PTR pivot for already discovered IPs.
	if ptr := runPTRPivot(ctx, cfg, store, resolvers, toolErrs, logf); len(ptr) > 0 {
		all = append(all, ptr...)
	}

	all = normalizeCandidates(all, cfg.Domain)
	if len(all) > cfg.MaxResolveQueue {
		all = all[:cfg.MaxResolveQueue]
	}
	logf("[dns-pivot] candidates=%d", len(all))
	return all
}

func runRecursiveBruteforceCollection(
	ctx context.Context,
	cfg config.Config,
	store *SafeStore,
	resolvers []dnsResolver,
	toolErrs *[]ToolError,
	logf func(string, ...any),
) []string {
	if !cfg.EnableRecursiveBrute {
		return nil
	}
	seeds := selectRecursiveSeeds(store, cfg.RecursiveBruteSeeds, cfg.Domain)
	if len(seeds) == 0 {
		return nil
	}
	words := loadBruteforceWordlist(cfg)
	if len(words) == 0 {
		return nil
	}
	if len(words) > cfg.RecursiveBruteWords {
		words = words[:cfg.RecursiveBruteWords]
	}

	wordFile, cleanupWords, err := writeTempList(cfg.OutputDir, "rb-words-*.txt", words)
	if err != nil {
		*toolErrs = append(*toolErrs, ToolError{Stage: "recursive_brute", Tool: "internal", Error: err.Error()})
		return nil
	}
	defer cleanupWords()

	resolverLines := make([]string, 0, len(resolvers))
	for _, r := range resolvers {
		resolverLines = append(resolverLines, r.Addr)
	}
	resolverFile, cleanupRes, err := writeTempList(cfg.OutputDir, "rb-resolvers-*.txt", resolverLines)
	if err != nil {
		*toolErrs = append(*toolErrs, ToolError{Stage: "recursive_brute", Tool: "internal", Error: err.Error()})
		return nil
	}
	defer cleanupRes()

	type chunk struct {
		cands []string
		err   *ToolError
	}
	outCh := make(chan chunk, len(seeds))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for _, seed := range seeds {
		seed := seed
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			local := make([]string, 0, len(words))

			if util.HaveCommand("dnsx") {
				subCtx, cancel := context.WithTimeout(ctx, cfg.BruteTimeout)
				args := []string{
					"-d", seed,
					"-w", wordFile,
					"-silent",
					"-retry", "1",
					"-t", fmt.Sprintf("%d", minInt(cfg.DNSThreads, 260)),
					"-rl", fmt.Sprintf("%d", cfg.DNSRateLimit),
					"-r", resolverFile,
				}
				res := util.RunCommand(subCtx, cfg.BruteTimeout, "dnsx", args...)
				cancel()
				if res.Err == nil {
					local = append(local, splitLines(res.Stdout)...)
				} else {
					outCh <- chunk{err: &ToolError{Stage: "recursive_brute", Tool: "dnsx", Error: res.Err.Error()}}
				}
			} else {
				for _, w := range words {
					local = append(local, w+"."+seed)
				}
			}

			if len(local) > 0 {
				outCh <- chunk{cands: local}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(outCh)
	}()

	all := make([]string, 0, cfg.MaxRecursiveBrute)
	for c := range outCh {
		if c.err != nil {
			*toolErrs = append(*toolErrs, *c.err)
			continue
		}
		if len(all) < cfg.MaxRecursiveBrute {
			remaining := cfg.MaxRecursiveBrute - len(all)
			if len(c.cands) > remaining {
				all = append(all, c.cands[:remaining]...)
			} else {
				all = append(all, c.cands...)
			}
		}
	}
	all = normalizeCandidates(all, cfg.Domain)
	if len(all) > cfg.MaxRecursiveBrute {
		all = all[:cfg.MaxRecursiveBrute]
	}
	logf("[recursive-brute] candidates=%d", len(all))
	return all
}

func runAnalyticsPivotCollection(
	ctx context.Context,
	cfg config.Config,
	store *SafeStore,
	toolErrs *[]ToolError,
	logf func(string, ...any),
) []string {
	if !cfg.EnableAnalyticsPivot {
		return nil
	}
	if !util.HaveCommand("analyticsrelationships") {
		return nil
	}
	snap := store.Snapshot()
	inputs := make([]string, 0, cfg.MaxAnalyticsInputs)
	seen := make(map[string]struct{})

	for _, c := range snap {
		if c.Wildcard || !c.Resolved {
			continue
		}
		if len(c.LiveURLs) > 0 {
			for _, u := range c.LiveURLs {
				if _, ok := seen[u]; ok {
					continue
				}
				seen[u] = struct{}{}
				inputs = append(inputs, u)
				if len(inputs) >= cfg.MaxAnalyticsInputs {
					break
				}
			}
		} else {
			u := "https://" + c.Name
			if _, ok := seen[u]; !ok {
				seen[u] = struct{}{}
				inputs = append(inputs, u)
			}
		}
		if len(inputs) >= cfg.MaxAnalyticsInputs {
			break
		}
	}
	if len(inputs) == 0 {
		return nil
	}

	inBlob := strings.Join(inputs, "\n") + "\n"
	analyticsTimeout := minDuration(cfg.BruteTimeout, 2*time.Minute)
	if analyticsTimeout < 30*time.Second {
		analyticsTimeout = 30 * time.Second
	}
	subCtx, cancel := context.WithTimeout(ctx, analyticsTimeout)
	res := util.RunCommandInput(subCtx, analyticsTimeout, inBlob, "analyticsrelationships", "-ch")
	cancel()
	out := extractScopedHostsFromBlob(res.Stdout, cfg.Domain)
	if len(out) > 0 {
		logf("[analytics] candidates=%d", len(out))
		return out
	}
	if res.Err != nil {
		blob := strings.ToLower(res.Stderr + "\n" + res.Err.Error())
		// analyticsrelationships is known to panic on some providers; skip noisily failing runs.
		if strings.Contains(blob, "panic:") || strings.Contains(blob, "nil pointer") || strings.Contains(blob, "builtwith") {
			logf("[analytics] skipped unstable analyticsrelationships output")
			return nil
		}
		*toolErrs = append(*toolErrs, ToolError{Stage: "analytics", Tool: "analyticsrelationships", Error: res.Err.Error()})
		return nil
	}
	logf("[analytics] candidates=%d", len(out))
	return out
}

func queryNoerrorCode(resolver, host string, timeout time.Duration) (bool, error) {
	client := &dns.Client{
		Timeout: timeout,
		Net:     "udp",
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	in, _, err := client.Exchange(m, ensureResolverPort(resolver))
	if err != nil || in == nil {
		return false, err
	}
	if in.Rcode == dns.RcodeSuccess {
		return true, nil
	}
	if in.Rcode == dns.RcodeNameError {
		return false, nil
	}
	return false, fmt.Errorf("rcode=%d", in.Rcode)
}

func detectsNoerrorBlackLies(cfg config.Config, resolvers []dnsResolver) bool {
	if len(resolvers) == 0 {
		return false
	}
	checks := 2
	hits := 0
	for i := 0; i < checks; i++ {
		host := util.RandomLabel(12) + "." + cfg.Domain
		ok, err := queryNoerrorCode(resolvers[i%len(resolvers)].Addr, host, cfg.DNSQueryTimeout)
		if err != nil {
			continue
		}
		if ok {
			hits++
		}
	}
	return hits == checks
}

func queryPivotRecords(resolver, host, scopeDomain string, timeout time.Duration) ([]string, error) {
	client := &dns.Client{
		Timeout: timeout,
		Net:     "udp",
	}
	types := []uint16{dns.TypeCNAME, dns.TypeNS, dns.TypeMX, dns.TypeSRV, dns.TypeTXT}
	out := make([]string, 0, 16)
	for _, t := range types {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(host), t)
		in, _, err := client.Exchange(m, ensureResolverPort(resolver))
		if err != nil || in == nil || in.Rcode != dns.RcodeSuccess {
			continue
		}
		for _, ans := range in.Answer {
			switch rr := ans.(type) {
			case *dns.CNAME:
				out = append(out, rr.Target)
			case *dns.NS:
				out = append(out, rr.Ns)
			case *dns.MX:
				out = append(out, rr.Mx)
			case *dns.SRV:
				out = append(out, rr.Target)
			case *dns.TXT:
				for _, txt := range rr.Txt {
					out = append(out, extractScopedHostsFromBlob(txt, scopeDomain)...)
				}
			default:
				out = append(out, ans.String())
			}
		}
	}
	return out, nil
}

func runPTRPivot(
	ctx context.Context,
	cfg config.Config,
	store *SafeStore,
	resolvers []dnsResolver,
	toolErrs *[]ToolError,
	logf func(string, ...any),
) []string {
	ips := collectResolvedIPs(store)
	if len(ips) == 0 {
		return nil
	}
	if len(ips) > minInt(cfg.MaxDNSPivotHosts, 2000) {
		ips = ips[:minInt(cfg.MaxDNSPivotHosts, 2000)]
	}
	ipFile, cleanupIPs, err := writeTempList(cfg.OutputDir, "ptr-ips-*.txt", ips)
	if err != nil {
		*toolErrs = append(*toolErrs, ToolError{Stage: "dns_pivot", Tool: "internal", Error: err.Error()})
		return nil
	}
	defer cleanupIPs()

	resolverLines := make([]string, 0, len(resolvers))
	for _, r := range resolvers {
		resolverLines = append(resolverLines, r.Addr)
	}
	resolverFile, cleanupRes, err := writeTempList(cfg.OutputDir, "ptr-resolvers-*.txt", resolverLines)
	if err != nil {
		*toolErrs = append(*toolErrs, ToolError{Stage: "dns_pivot", Tool: "internal", Error: err.Error()})
		return nil
	}
	defer cleanupRes()

	// Prefer dnsx ptr when present.
	if util.HaveCommand("dnsx") {
		subCtx, cancel := context.WithTimeout(ctx, cfg.BruteTimeout)
		args := []string{
			"-l", ipFile,
			"-ptr",
			"-resp-only",
			"-silent",
			"-r", resolverFile,
			"-retry", "1",
			"-t", fmt.Sprintf("%d", minInt(cfg.DNSThreads, 180)),
			"-rl", fmt.Sprintf("%d", cfg.DNSRateLimit),
		}
		res := util.RunCommand(subCtx, cfg.BruteTimeout, "dnsx", args...)
		cancel()
		if res.Err != nil {
			*toolErrs = append(*toolErrs, ToolError{Stage: "dns_pivot", Tool: "dnsx-ptr", Error: res.Err.Error()})
			return nil
		}
		out := extractScopedHostsFromBlob(res.Stdout, cfg.Domain)
		logf("[dns-pivot] ptr_candidates=%d", len(out))
		return out
	}
	return nil
}

func collectResolvedIPs(store *SafeStore) []string {
	seen := make(map[string]struct{})
	for _, c := range store.Snapshot() {
		if !c.Resolved || c.Wildcard {
			continue
		}
		for ip := range c.IPs {
			seen[ip] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for ip := range seen {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}
