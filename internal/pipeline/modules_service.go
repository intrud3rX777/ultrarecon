package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"ultrarecon/internal/config"
	"ultrarecon/internal/util"
)

func runServiceDiscovery(
	ctx context.Context,
	cfg config.Config,
	store *SafeStore,
	hosts []string,
	toolErrs *[]ToolError,
	logf func(string, ...any),
) []ServiceRow {
	if !cfg.EnableServiceDiscovery || len(hosts) == 0 {
		return nil
	}
	if len(hosts) > cfg.MaxServiceHosts {
		hosts = hosts[:cfg.MaxServiceHosts]
	}

	hostFile, cleanupHosts, err := writeTempList(cfg.OutputDir, "service-hosts-*.txt", hosts)
	if err != nil {
		*toolErrs = append(*toolErrs, ToolError{Stage: "service_discovery", Tool: "internal", Error: err.Error()})
		return nil
	}
	defer cleanupHosts()

	rows := make([]ServiceRow, 0, minInt(cfg.MaxServiceRows, len(hosts)*2))
	httpTargets := make(map[string]struct{}, len(hosts)*2)
	for _, h := range hosts {
		httpTargets[h] = struct{}{}
	}

	// Port discovery with naabu.
	if util.HaveCommand("naabu") {
		naabuOut, err := runNaabu(ctx, cfg, hostFile)
		if err != nil {
			*toolErrs = append(*toolErrs, ToolError{Stage: "service_discovery", Tool: "naabu", Error: err.Error()})
		} else {
			for _, line := range splitLines(naabuOut) {
				host, port, ok := parseHostPortLine(line)
				if !ok {
					continue
				}
				if norm, inScope := util.NormalizeCandidate(host, cfg.Domain); inScope {
					host = norm
				} else {
					continue
				}
				store.MarkPortOpen(host, port)
				rows = append(rows, ServiceRow{
					Host:   host,
					Port:   port,
					Source: "naabu",
				})
				if isLikelyHTTPPort(port) {
					httpTargets[fmt.Sprintf("%s:%d", host, port)] = struct{}{}
				}
			}
		}
	} else {
		*toolErrs = append(*toolErrs, ToolError{Stage: "service_discovery", Tool: "naabu", Error: "tool missing: naabu"})
	}

	if len(rows) > cfg.MaxServiceRows {
		rows = rows[:cfg.MaxServiceRows]
	}

	// HTTP service fingerprinting with httpx.
	httpTargetList := make([]string, 0, len(httpTargets))
	for t := range httpTargets {
		httpTargetList = append(httpTargetList, t)
	}
	sort.Strings(httpTargetList)
	httpTargetsFile, cleanupTargets, err := writeTempList(cfg.OutputDir, "service-targets-*.txt", httpTargetList)
	if err == nil {
		defer cleanupTargets()
	}

	httpRows := 0
	if util.HaveCommand("httpx") && err == nil {
		httpxOut, runErr := runHTTPXServices(ctx, cfg, httpTargetsFile)
		if runErr != nil {
			*toolErrs = append(*toolErrs, ToolError{Stage: "service_discovery", Tool: "httpx", Error: runErr.Error()})
		} else {
			for _, raw := range splitLines(httpxOut) {
				row, ok := parseHTTPXServiceRow(raw, cfg.Domain)
				if !ok {
					continue
				}
				row.Source = "httpx"
				rows = append(rows, row)
				httpRows++
				if row.Port > 0 {
					store.MarkPortOpen(row.Host, row.Port)
				}
				if row.URL != "" {
					store.MarkLive(row.Host, row.URL)
				}
				if len(rows) >= cfg.MaxServiceRows {
					break
				}
			}
		}
	}

	// Lightweight TLS discovery hints.
	tlsRows := 0
	if util.HaveCommand("tlsx") {
		tlsxOut, runErr := runTLSXServices(ctx, cfg, hostFile)
		if runErr != nil {
			*toolErrs = append(*toolErrs, ToolError{Stage: "service_discovery", Tool: "tlsx", Error: runErr.Error()})
		} else {
			for _, raw := range splitLines(tlsxOut) {
				host := extractServiceHost(raw, cfg.Domain)
				if host == "" {
					continue
				}
				rows = append(rows, ServiceRow{
					Host:   host,
					Source: "tlsx",
				})
				tlsRows++
				if len(rows) >= cfg.MaxServiceRows {
					break
				}
			}
		}
	}

	rows = dedupeServiceRows(rows, cfg.MaxServiceRows)
	logf("[service] hosts=%d rows=%d http_rows=%d tls_rows=%d", len(hosts), len(rows), httpRows, tlsRows)
	return rows
}

func runNaabu(ctx context.Context, cfg config.Config, hostFile string) (string, error) {
	workers := minInt(cfg.HTTPThreads, 120)
	if workers < 10 {
		workers = 10
	}
	attempts := [][]string{
		{"-silent", "-l", hostFile, "-top-ports", strconv.Itoa(cfg.ServiceTopPorts), "-rate", strconv.Itoa(cfg.ServiceRate), "-c", strconv.Itoa(workers)},
		{"-silent", "-l", hostFile, "-top-ports", strconv.Itoa(cfg.ServiceTopPorts), "-rate", strconv.Itoa(cfg.ServiceRate)},
		{"-silent", "-l", hostFile, "-top-ports", strconv.Itoa(cfg.ServiceTopPorts)},
	}
	var lastErr error
	for _, args := range attempts {
		subCtx, cancel := context.WithTimeout(ctx, cfg.BruteTimeout)
		res := util.RunCommand(subCtx, cfg.BruteTimeout, "naabu", args...)
		cancel()
		if strings.TrimSpace(res.Stdout) != "" && res.Err == nil {
			return res.Stdout, nil
		}
		if res.Err != nil {
			lastErr = res.Err
		}
		if !flagError(res.Stderr) {
			if strings.TrimSpace(res.Stdout) != "" {
				return res.Stdout, nil
			}
		}
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", fmt.Errorf("naabu returned no output")
}

func runHTTPXServices(ctx context.Context, cfg config.Config, targetFile string) (string, error) {
	timeoutSec := int(cfg.HTTPTimeout.Seconds())
	if timeoutSec < 3 {
		timeoutSec = 3
	}
	attempts := [][]string{
		{
			"-l", targetFile,
			"-silent",
			"-json",
			"-status-code",
			"-title",
			"-tech-detect",
			"-server",
			"-asn",
			"-cdn",
			"-threads", strconv.Itoa(minInt(cfg.HTTPThreads, 220)),
			"-rate-limit", strconv.Itoa(maxInt(120, cfg.DNSRateLimit)),
			"-timeout", strconv.Itoa(timeoutSec),
		},
		{
			"-l", targetFile,
			"-silent",
			"-json",
			"-status-code",
			"-title",
			"-tech-detect",
			"-server",
			"-threads", strconv.Itoa(minInt(cfg.HTTPThreads, 220)),
			"-rate-limit", strconv.Itoa(maxInt(120, cfg.DNSRateLimit)),
			"-timeout", strconv.Itoa(timeoutSec),
		},
		{
			"-l", targetFile,
			"-silent",
			"-json",
		},
	}
	var lastErr error
	for _, args := range attempts {
		subCtx, cancel := context.WithTimeout(ctx, cfg.BruteTimeout)
		res := util.RunCommand(subCtx, cfg.BruteTimeout, "httpx", args...)
		cancel()
		if strings.TrimSpace(res.Stdout) != "" && res.Err == nil {
			return res.Stdout, nil
		}
		if res.Err != nil {
			lastErr = res.Err
		}
		if !flagError(res.Stderr) {
			if strings.TrimSpace(res.Stdout) != "" {
				return res.Stdout, nil
			}
		}
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", fmt.Errorf("httpx returned no output")
}

func runTLSXServices(ctx context.Context, cfg config.Config, hostFile string) (string, error) {
	attempts := [][]string{
		{
			"-l", hostFile,
			"-silent",
			"-san",
			"-cn",
			"-c", strconv.Itoa(minInt(cfg.HTTPThreads, 150)),
		},
		{
			"-l", hostFile,
			"-silent",
			"-c", strconv.Itoa(minInt(cfg.HTTPThreads, 150)),
		},
	}
	var lastErr error
	for _, args := range attempts {
		subCtx, cancel := context.WithTimeout(ctx, cfg.BruteTimeout)
		res := util.RunCommand(subCtx, cfg.BruteTimeout, "tlsx", args...)
		cancel()
		if strings.TrimSpace(res.Stdout) != "" && res.Err == nil {
			return res.Stdout, nil
		}
		if res.Err != nil {
			lastErr = res.Err
		}
		if !flagError(res.Stderr) && strings.TrimSpace(res.Stdout) != "" {
			return res.Stdout, nil
		}
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", fmt.Errorf("tlsx returned no output")
}

func parseHTTPXServiceRow(raw, domain string) (ServiceRow, bool) {
	var row ServiceRow
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return row, false
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(raw), &obj); err != nil {
		return row, false
	}
	host := ""
	if v, ok := obj["host"].(string); ok {
		host = extractServiceHost(v, domain)
	}
	if host == "" {
		if v, ok := obj["input"].(string); ok {
			host = extractServiceHost(v, domain)
		}
	}
	if host == "" {
		if v, ok := obj["url"].(string); ok {
			host = extractServiceHost(v, domain)
		}
	}
	if host == "" {
		return row, false
	}

	row.Host = host
	row.URL = serviceString(obj["url"])
	row.Scheme = serviceString(obj["scheme"])
	row.StatusCode = serviceInt(obj["status_code"])
	row.Title = serviceString(obj["title"])
	row.WebServer = serviceString(obj["webserver"])
	row.Technologies = serviceStringSlice(obj["tech"])
	row.Port = serviceInt(obj["port"])
	row.CDN = serviceCDN(obj["cdn"])
	row.ASN = serviceASN(obj["asn"])
	return row, true
}

func parseHostPortLine(line string) (string, int, bool) {
	line = strings.TrimSpace(strings.ToLower(line))
	if line == "" {
		return "", 0, false
	}
	line = strings.TrimPrefix(line, "http://")
	line = strings.TrimPrefix(line, "https://")
	line = strings.TrimSuffix(line, "/")
	if line == "" {
		return "", 0, false
	}
	if host, port, err := net.SplitHostPort(line); err == nil {
		p, err := strconv.Atoi(strings.TrimSpace(port))
		if err != nil || p <= 0 || p > 65535 {
			return "", 0, false
		}
		return strings.TrimSpace(host), p, true
	}
	idx := strings.LastIndex(line, ":")
	if idx <= 0 || idx >= len(line)-1 {
		return "", 0, false
	}
	host := strings.TrimSpace(line[:idx])
	p, err := strconv.Atoi(strings.TrimSpace(line[idx+1:]))
	if err != nil || p <= 0 || p > 65535 {
		return "", 0, false
	}
	return host, p, true
}

func isLikelyHTTPPort(port int) bool {
	switch port {
	case 80, 81, 443, 591, 593, 8000, 8008, 8080, 8081, 8088, 8089, 8443, 8888, 9000, 9443:
		return true
	default:
		return false
	}
}

func dedupeServiceRows(rows []ServiceRow, limit int) []ServiceRow {
	if len(rows) == 0 {
		return nil
	}
	out := make([]ServiceRow, 0, minInt(len(rows), limit))
	seen := make(map[string]struct{}, len(rows))
	for _, r := range rows {
		key := fmt.Sprintf("%s|%d|%s|%s|%d", r.Host, r.Port, r.URL, r.Source, r.StatusCode)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, r)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host == out[j].Host {
			if out[i].Port == out[j].Port {
				if out[i].Source == out[j].Source {
					return out[i].URL < out[j].URL
				}
				return out[i].Source < out[j].Source
			}
			return out[i].Port < out[j].Port
		}
		return out[i].Host < out[j].Host
	})
	return out
}

func flagError(stderr string) bool {
	low := strings.ToLower(strings.TrimSpace(stderr))
	return strings.Contains(low, "flag provided but not defined") ||
		strings.Contains(low, "unknown flag") ||
		strings.Contains(low, "unknown shorthand")
}

func extractServiceHost(raw, domain string) string {
	if host, ok := util.NormalizeCandidate(raw, domain); ok {
		return host
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	if u.Host == "" {
		return ""
	}
	if host, ok := util.NormalizeCandidate(u.Host, domain); ok {
		return host
	}
	return ""
}

func serviceString(v any) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

func serviceInt(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(t))
		if err != nil {
			return 0
		}
		return n
	default:
		return 0
	}
}

func serviceStringSlice(v any) []string {
	if v == nil {
		return nil
	}
	arr, ok := v.([]any)
	if !ok {
		if ss, ok2 := v.([]string); ok2 {
			return util.UniqueSorted(ss)
		}
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			s = strings.TrimSpace(s)
			if s != "" {
				out = append(out, s)
			}
		}
	}
	return util.UniqueSorted(out)
}

func serviceCDN(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case bool:
		if t {
			return "detected"
		}
		return ""
	default:
		return ""
	}
}

func serviceASN(v any) string {
	obj, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	num := ""
	name := ""
	if x, ok := obj["as-number"]; ok {
		num = strings.TrimSpace(fmt.Sprintf("%v", x))
	}
	if x, ok := obj["as-name"]; ok {
		name = strings.TrimSpace(fmt.Sprintf("%v", x))
	}
	if num != "" && name != "" {
		return num + " " + name
	}
	if num != "" {
		return num
	}
	return name
}
