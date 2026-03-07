package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"ultrarecon/internal/config"
	"ultrarecon/internal/util"
)

type collectorResult struct {
	Name      string
	Hosts     []string
	Err       error
	ToolError *ToolError
}

var errCollectorSkipped = errors.New("collector skipped")

func runPassiveCollection(
	ctx context.Context,
	cfg config.Config,
	store *SafeStore,
	toolErrs *[]ToolError,
	logf func(string, ...any),
) []string {
	collectors := []struct {
		name string
		fn   func(context.Context, config.Config) ([]string, error)
	}{
		{name: "subfinder", fn: collectSubfinder},
		{name: "assetfinder", fn: collectAssetfinder},
		{name: "amass", fn: collectAmassPassive},
		{name: "chaos", fn: collectChaos},
		{name: "crtsh", fn: collectCRTSh},
		{name: "certspotter", fn: collectCertSpotter},
		{name: "anubis", fn: collectAnubis},
		{name: "alienvault", fn: collectAlienVault},
		{name: "rapiddns", fn: collectRapidDNS},
		{name: "hackertarget", fn: collectHackerTarget},
	}

	resCh := make(chan collectorResult, len(collectors))
	var wg sync.WaitGroup
	for _, c := range collectors {
		c := c
		wg.Add(1)
		go func() {
			defer wg.Done()
			subCtx, cancel := context.WithTimeout(ctx, cfg.ToolTimeout)
			defer cancel()

			start := time.Now()
			hosts, err := c.fn(subCtx, cfg)
			if err != nil {
				if errors.Is(err, errCollectorSkipped) {
					logf("[passive] %s skipped in %s: %v", c.name, time.Since(start).Round(time.Millisecond), err)
					resCh <- collectorResult{Name: c.name, Hosts: nil}
					return
				}
				te := ToolError{
					Stage: "passive",
					Tool:  c.name,
					Error: err.Error(),
				}
				resCh <- collectorResult{Name: c.name, Err: err, ToolError: &te}
				logf("[passive] %s failed in %s: %v", c.name, time.Since(start).Round(time.Millisecond), err)
				return
			}
			logf("[passive] %s completed in %s (%d raw)", c.name, time.Since(start).Round(time.Millisecond), len(hosts))
			resCh <- collectorResult{Name: c.name, Hosts: hosts}
		}()
	}
	wg.Wait()
	close(resCh)

	all := make([]string, 0, 4096)
	for res := range resCh {
		if res.ToolError != nil {
			*toolErrs = append(*toolErrs, *res.ToolError)
			continue
		}
		normalized := make([]string, 0, len(res.Hosts))
		for _, raw := range res.Hosts {
			if host, ok := util.NormalizeCandidate(raw, cfg.Domain); ok {
				normalized = append(normalized, host)
			}
		}
		normalized = util.UniqueSorted(normalized)
		if len(normalized) > cfg.MaxPassivePerSource {
			normalized = trimCandidatesByPriority(normalized, cfg.Domain, cfg.MaxPassivePerSource)
			logf("[passive] %s capped_to=%d", res.Name, len(normalized))
		}
		added := store.AddBatch(normalized, "passive:"+res.Name)
		logf("[passive] %s accepted=%d added=%d", res.Name, len(normalized), added)
		all = append(all, normalized...)
	}
	all = util.UniqueSorted(all)
	if len(all) > cfg.MaxPassiveCandidates {
		all = trimCandidatesByPriority(all, cfg.Domain, cfg.MaxPassiveCandidates)
	}
	return all
}

func collectSubfinder(ctx context.Context, cfg config.Config) ([]string, error) {
	res := util.RunCommand(ctx, cfg.ToolTimeout, "subfinder", "-silent", "-all", "-d", cfg.Domain)
	if res.Err != nil {
		return nil, res.Err
	}
	return splitLines(res.Stdout), nil
}

func collectAssetfinder(ctx context.Context, cfg config.Config) ([]string, error) {
	res := util.RunCommand(ctx, cfg.ToolTimeout, "assetfinder", "--subs-only", cfg.Domain)
	if res.Err != nil {
		return nil, res.Err
	}
	return splitLines(res.Stdout), nil
}

func collectAmassPassive(ctx context.Context, cfg config.Config) ([]string, error) {
	return runAmassPassive(ctx, cfg.ToolTimeout, cfg.Domain, cfg.OutputDir)
}

func collectChaos(ctx context.Context, cfg config.Config) ([]string, error) {
	if strings.TrimSpace(os.Getenv("PDCP_API_KEY")) == "" &&
		strings.TrimSpace(os.Getenv("CHAOS_KEY")) == "" &&
		strings.TrimSpace(os.Getenv("CHAOS_API_KEY")) == "" {
		return nil, fmt.Errorf("%w: PDCP_API_KEY/CHAOS_KEY not set", errCollectorSkipped)
	}
	res := util.RunCommand(ctx, cfg.ToolTimeout, "chaos", "-d", cfg.Domain, "-silent")
	if res.Err != nil {
		low := strings.ToLower(strings.TrimSpace(res.Stderr))
		if strings.Contains(low, "pdcp_api_key not specified") || strings.Contains(low, "api key") {
			return nil, fmt.Errorf("%w: chaos api key unavailable", errCollectorSkipped)
		}
		return nil, res.Err
	}
	return splitLines(res.Stdout), nil
}

func collectCRTSh(ctx context.Context, cfg config.Config) ([]string, error) {
	u := "https://crt.sh/?q=%25." + url.QueryEscape(cfg.Domain) + "&output=json"
	body, err := httpGet(ctx, cfg.ToolTimeout, u)
	if err != nil {
		return nil, err
	}
	var rows []map[string]any
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("crtsh parse: %w", err)
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		val, _ := row["name_value"].(string)
		if val == "" {
			continue
		}
		for _, line := range strings.Split(val, "\n") {
			line = strings.TrimPrefix(strings.TrimSpace(line), "*.")
			if line != "" {
				out = append(out, line)
			}
		}
	}
	return util.UniqueSorted(out), nil
}

func collectHackerTarget(ctx context.Context, cfg config.Config) ([]string, error) {
	u := "https://api.hackertarget.com/hostsearch/?q=" + url.QueryEscape(cfg.Domain)
	body, err := httpGet(ctx, cfg.ToolTimeout, u)
	if err != nil {
		return nil, err
	}
	lines := splitLines(string(body))
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		parts := strings.Split(line, ",")
		if len(parts) > 0 {
			out = append(out, strings.TrimSpace(parts[0]))
		}
	}
	return util.UniqueSorted(out), nil
}

func collectCertSpotter(ctx context.Context, cfg config.Config) ([]string, error) {
	u := "https://api.certspotter.com/v1/issuances?domain=" + url.QueryEscape(cfg.Domain) + "&include_subdomains=true&expand=dns_names"
	body, err := httpGet(ctx, cfg.ToolTimeout, u)
	if err != nil {
		return nil, err
	}
	var rows []struct {
		DNSNames []string `json:"dns_names"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("certspotter parse: %w", err)
	}
	out := make([]string, 0, len(rows)*2)
	for _, row := range rows {
		for _, n := range row.DNSNames {
			n = strings.TrimSpace(strings.TrimPrefix(n, "*."))
			if n != "" {
				out = append(out, n)
			}
		}
	}
	return util.UniqueSorted(out), nil
}

func collectAnubis(ctx context.Context, cfg config.Config) ([]string, error) {
	u := "https://jldc.me/anubis/subdomains/" + url.QueryEscape(cfg.Domain)
	body, err := httpGet(ctx, cfg.ToolTimeout, u)
	if err != nil {
		return nil, err
	}
	var arr []string
	if err := json.Unmarshal(body, &arr); err != nil {
		return nil, fmt.Errorf("anubis parse: %w", err)
	}
	out := make([]string, 0, len(arr))
	for _, n := range arr {
		n = strings.TrimSpace(strings.TrimPrefix(n, "*."))
		if n != "" {
			out = append(out, n)
		}
	}
	return util.UniqueSorted(out), nil
}

func collectAlienVault(ctx context.Context, cfg config.Config) ([]string, error) {
	u := "https://otx.alienvault.com/api/v1/indicators/domain/" + url.PathEscape(cfg.Domain) + "/passive_dns"
	body, err := httpGet(ctx, cfg.ToolTimeout, u)
	if err != nil {
		return nil, err
	}
	var obj struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, fmt.Errorf("alienvault parse: %w", err)
	}
	out := make([]string, 0, len(obj.PassiveDNS))
	for _, row := range obj.PassiveDNS {
		if row.Hostname != "" {
			out = append(out, row.Hostname)
		}
	}
	return util.UniqueSorted(out), nil
}

func collectRapidDNS(ctx context.Context, cfg config.Config) ([]string, error) {
	u := "https://rapiddns.io/subdomain/" + url.PathEscape(cfg.Domain) + "?full=1#result"
	body, err := httpGet(ctx, cfg.ToolTimeout, u)
	if err != nil {
		return nil, err
	}
	pattern := regexp.MustCompile(`(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+` + regexp.QuoteMeta(cfg.Domain))
	matches := pattern.FindAllString(strings.ToLower(string(body)), -1)
	return util.UniqueSorted(matches), nil
}

func httpGet(ctx context.Context, timeout time.Duration, rawURL string) ([]byte, error) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ultrarecon/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("http status %d for %s", resp.StatusCode, rawURL)
	}
	const maxBody = 25 * 1024 * 1024
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	total := 0
	for {
		n, readErr := resp.Body.Read(tmp)
		if n > 0 {
			total += n
			if total > maxBody {
				return nil, fmt.Errorf("response too large from %s", rawURL)
			}
			buf = append(buf, tmp[:n]...)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return nil, readErr
		}
	}
	return buf, nil
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	lines := strings.Split(strings.ReplaceAll(s, "\r", ""), "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// strip probable line prefixes like "host,ip"
		if strings.Count(line, ",") == 1 {
			parts := strings.Split(line, ",")
			if len(parts) == 2 && strings.Count(parts[1], ".") == 3 {
				line = strings.TrimSpace(parts[0])
			}
		}
		// strip accidental ports
		if idx := strings.LastIndex(line, ":"); idx > 0 {
			if _, err := strconv.Atoi(line[idx+1:]); err == nil {
				line = line[:idx]
			}
		}
		out = append(out, line)
	}
	return out
}

func trimCandidatesByPriority(hosts []string, domain string, max int) []string {
	if max <= 0 || len(hosts) <= max {
		return hosts
	}
	type row struct {
		host  string
		score int
	}
	rows := make([]row, 0, len(hosts))
	for _, h := range hosts {
		left := strings.TrimSuffix(h, "."+domain)
		depth := strings.Count(left, ".") + 1
		if h == domain {
			depth = 0
		}
		score := 1000 - depth*40 - len(left)
		if strings.Contains(left, "dev") || strings.Contains(left, "stg") || strings.Contains(left, "prod") || strings.Contains(left, "api") {
			score += 25
		}
		rows = append(rows, row{host: h, score: score})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].score == rows[j].score {
			return rows[i].host < rows[j].host
		}
		return rows[i].score > rows[j].score
	})
	out := make([]string, 0, max)
	for i := 0; i < max && i < len(rows); i++ {
		out = append(out, rows[i].host)
	}
	return util.UniqueSorted(out)
}
