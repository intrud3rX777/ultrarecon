package pipeline

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"ultrarecon/internal/config"
	"ultrarecon/internal/util"
)

func runZoneTransferCollection(
	ctx context.Context,
	cfg config.Config,
	resolvers []dnsResolver,
	toolErrs *[]ToolError,
	logf func(string, ...any),
) []string {
	if !cfg.EnableZoneTransfer || len(resolvers) == 0 {
		return nil
	}

	nsHosts, err := queryNSRecords(resolvers[0].Addr, cfg.Domain, cfg.DNSQueryTimeout)
	if err != nil {
		*toolErrs = append(*toolErrs, ToolError{Stage: "zone_transfer", Tool: "ns_query", Error: err.Error()})
		return nil
	}
	if len(nsHosts) == 0 {
		return nil
	}
	if len(nsHosts) > 10 {
		nsHosts = nsHosts[:10]
	}

	transferTimeout := minDuration(cfg.ToolTimeout, 20*time.Second)
	if transferTimeout < 5*time.Second {
		transferTimeout = 5 * time.Second
	}

	all := make([]string, 0, 1024)
	for _, ns := range nsHosts {
		select {
		case <-ctx.Done():
			out := normalizeCandidates(all, cfg.Domain)
			if len(out) > cfg.MaxZoneTransferHosts {
				out = out[:cfg.MaxZoneTransferHosts]
			}
			return out
		default:
		}

		var nsIPs []string
		for i := 0; i < minInt(len(resolvers), 2); i++ {
			r := resolvers[i].Addr
			ips, qErr := queryDomain(r, ns, cfg.DNSQueryTimeout)
			if qErr == nil && len(ips) > 0 {
				nsIPs = ips
				break
			}
		}
		if len(nsIPs) == 0 {
			*toolErrs = append(*toolErrs, ToolError{
				Stage: "zone_transfer",
				Tool:  "axfr:" + ns,
				Error: "failed to resolve NS host",
			})
			continue
		}

		var success bool
		var lastErr error
		for _, ip := range nsIPs {
			subCtx, cancel := context.WithTimeout(ctx, transferTimeout)
			cands, txErr := attemptAXFR(subCtx, ip, cfg.Domain, cfg.MaxZoneTransferHosts)
			cancel()
			if txErr != nil {
				lastErr = txErr
				continue
			}
			if len(cands) > 0 {
				success = true
				all = append(all, cands...)
				break
			}
		}
		if !success && lastErr != nil {
			*toolErrs = append(*toolErrs, ToolError{
				Stage: "zone_transfer",
				Tool:  "axfr:" + ns,
				Error: lastErr.Error(),
			})
		}
	}

	out := normalizeCandidates(all, cfg.Domain)
	if len(out) > cfg.MaxZoneTransferHosts {
		out = out[:cfg.MaxZoneTransferHosts]
	}
	logf("[zone-transfer] candidates=%d", len(out))
	return out
}

func runScrapingPivotCollection(
	ctx context.Context,
	cfg config.Config,
	store *SafeStore,
	toolErrs *[]ToolError,
	logf func(string, ...any),
) []string {
	if !cfg.EnableScrapingPivot {
		return nil
	}

	inputs := collectScrapeInputs(store, cfg.MaxScrapeInputs)
	if len(inputs) == 0 {
		return nil
	}

	inputFile, cleanup, err := writeTempList(cfg.OutputDir, "scrape-inputs-*.txt", inputs)
	if err != nil {
		*toolErrs = append(*toolErrs, ToolError{Stage: "scraping", Tool: "internal", Error: err.Error()})
		return nil
	}
	defer cleanup()

	inBlob := strings.Join(inputs, "\n") + "\n"
	results := make([]string, 0, 8192)
	appendParsed := func(raw string, source string) {
		if strings.TrimSpace(raw) == "" {
			return
		}
		found := extractScopedHostsFromBlob(raw, cfg.Domain)
		if len(found) == 0 {
			return
		}
		logf("[scraping] %s extracted=%d", source, len(found))
		results = append(results, found...)
	}

	if util.HaveCommand("katana") {
		subCtx, cancel := context.WithTimeout(ctx, cfg.BruteTimeout)
		res := util.RunCommand(
			subCtx,
			cfg.BruteTimeout,
			"katana",
			"-list", inputFile,
			"-silent",
			"-d", strconv.Itoa(cfg.ScrapeDepth),
			"-c", strconv.Itoa(minInt(cfg.HTTPThreads, 80)),
		)
		cancel()
		if res.Err != nil {
			subCtx2, cancel2 := context.WithTimeout(ctx, cfg.BruteTimeout)
			res2 := util.RunCommand(subCtx2, cfg.BruteTimeout, "katana", "-list", inputFile, "-silent")
			cancel2()
			if res2.Err != nil {
				*toolErrs = append(*toolErrs, ToolError{Stage: "scraping", Tool: "katana", Error: res.Err.Error()})
			} else {
				appendParsed(res2.Stdout, "katana")
			}
		} else {
			appendParsed(res.Stdout, "katana")
		}
	}

	if util.HaveCommand("hakrawler") {
		attempts := [][]string{
			{"-d", strconv.Itoa(cfg.ScrapeDepth)},
			{"-depth", strconv.Itoa(cfg.ScrapeDepth)},
			{"-d", strconv.Itoa(cfg.ScrapeDepth), "-s"},
			{},
		}
		var worked bool
		var lastErr error
		for _, args := range attempts {
			subCtx, cancel := context.WithTimeout(ctx, cfg.BruteTimeout)
			res := util.RunCommandInput(subCtx, cfg.BruteTimeout, inBlob, "hakrawler", args...)
			cancel()
			if res.Err == nil {
				appendParsed(res.Stdout, "hakrawler")
				worked = true
				break
			}
			lastErr = res.Err
			if !strings.Contains(strings.ToLower(res.Stderr), "flag provided but not defined") {
				continue
			}
		}
		if !worked && lastErr != nil {
			*toolErrs = append(*toolErrs, ToolError{Stage: "scraping", Tool: "hakrawler", Error: lastErr.Error()})
		}
	}

	if util.HaveCommand("gospider") {
		subCtx, cancel := context.WithTimeout(ctx, cfg.BruteTimeout)
		res := util.RunCommand(
			subCtx,
			cfg.BruteTimeout,
			"gospider",
			"-S", inputFile,
			"-d", strconv.Itoa(cfg.ScrapeDepth),
			"-q",
			"-c", strconv.Itoa(minInt(cfg.HTTPThreads, 40)),
			"-t", strconv.Itoa(minInt(cfg.HTTPThreads, 40)),
		)
		cancel()
		if res.Err != nil {
			subCtx2, cancel2 := context.WithTimeout(ctx, cfg.BruteTimeout)
			res2 := util.RunCommand(subCtx2, cfg.BruteTimeout, "gospider", "-S", inputFile, "-q")
			cancel2()
			if res2.Err != nil {
				*toolErrs = append(*toolErrs, ToolError{Stage: "scraping", Tool: "gospider", Error: res.Err.Error()})
			} else {
				appendParsed(res2.Stdout, "gospider")
			}
		} else {
			appendParsed(res.Stdout, "gospider")
		}
	}

	out := normalizeCandidates(results, cfg.Domain)
	if len(out) > cfg.MaxScrapeCandidates {
		out = out[:cfg.MaxScrapeCandidates]
	}
	logf("[scraping] candidates=%d", len(out))
	return out
}

func queryNSRecords(resolver, domain string, timeout time.Duration) ([]string, error) {
	client := &dns.Client{
		Timeout: timeout,
		Net:     "udp",
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	in, _, err := client.Exchange(m, ensureResolverPort(resolver))
	if err != nil || in == nil {
		return nil, err
	}
	if in.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("rcode=%d", in.Rcode)
	}
	out := make([]string, 0, 4)
	for _, ans := range in.Answer {
		rr, ok := ans.(*dns.NS)
		if !ok {
			continue
		}
		ns := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(rr.Ns)), ".")
		if ns != "" {
			out = append(out, ns)
		}
	}
	return util.UniqueSorted(out), nil
}

func attemptAXFR(ctx context.Context, serverIP, domain string, limit int) ([]string, error) {
	addr := net.JoinHostPort(strings.TrimSpace(serverIP), "53")
	if strings.TrimSpace(serverIP) == "" {
		return nil, fmt.Errorf("empty server")
	}

	timeout := 7 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		remaining := time.Until(dl)
		if remaining > 0 && remaining < timeout {
			timeout = remaining
		}
	}
	xfr := &dns.Transfer{
		DialTimeout: timeout,
		ReadTimeout: timeout,
	}
	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(domain))

	envCh, err := xfr.In(m, addr)
	if err != nil {
		return nil, err
	}

	out := make([]string, 0, 128)
	for {
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		case env, ok := <-envCh:
			if !ok {
				return out, nil
			}
			if env == nil {
				continue
			}
			if env.Error != nil {
				return out, env.Error
			}
			for _, rr := range env.RR {
				if rr == nil {
					continue
				}
				out = append(out, rr.Header().Name)
				out = append(out, extractScopedHostsFromBlob(rr.String(), domain)...)
				if limit > 0 && len(out) >= limit {
					return out, nil
				}
			}
		}
	}
}

func collectScrapeInputs(store *SafeStore, max int) []string {
	if max <= 0 {
		return nil
	}
	snap := store.Snapshot()
	out := make([]string, 0, max)
	seen := make(map[string]struct{}, max)

	for _, c := range snap {
		if !c.Resolved || c.Wildcard || len(c.LiveURLs) == 0 {
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
			if len(out) >= max {
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
		if len(out) >= max {
			break
		}
	}
	return out
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
