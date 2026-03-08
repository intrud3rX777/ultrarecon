package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"ultrarecon/internal/config"
	"ultrarecon/internal/util"
)

func runContentDiscovery(
	ctx context.Context,
	cfg config.Config,
	store *SafeStore,
	surfaceRows []SurfaceRow,
	toolErrs *[]ToolError,
	logf func(string, ...any),
) ([]ContentRow, []string) {
	if !cfg.EnableContentDiscovery {
		return nil, nil
	}

	paramKeys := topParamKeys(surfaceRows, cfg.MaxParamKeys)
	contentRows := seedContentRowsFromSurface(surfaceRows, cfg.MaxContentRows/3)

	hosts := collectContentHosts(store, cfg.MaxContentHosts)
	if len(hosts) == 0 {
		logf("[content] hosts=0 seeded=%d ffuf=0 params=%d", len(contentRows), len(paramKeys))
		return dedupeContentRows(contentRows, cfg.MaxContentRows), paramKeys
	}

	if !util.HaveCommand("ffuf") {
		*toolErrs = append(*toolErrs, ToolError{Stage: "content_discovery", Tool: "ffuf", Error: "tool missing: ffuf"})
		logf("[content] ffuf missing hosts=%d seeded=%d ffuf=0 params=%d", len(hosts), len(contentRows), len(paramKeys))
		return dedupeContentRows(contentRows, cfg.MaxContentRows), paramKeys
	}

	words := loadBruteforceWordlist(cfg)
	if len(words) > 250 {
		words = words[:250]
	}
	if len(words) == 0 {
		logf("[content] wordlist empty; skipping ffuf")
		return dedupeContentRows(contentRows, cfg.MaxContentRows), paramKeys
	}
	wordFile, cleanupWords, err := writeTempList(cfg.OutputDir, "content-words-*.txt", words)
	if err != nil {
		*toolErrs = append(*toolErrs, ToolError{Stage: "content_discovery", Tool: "internal", Error: err.Error()})
		return dedupeContentRows(contentRows, cfg.MaxContentRows), paramKeys
	}
	defer cleanupWords()

	rowsCh := make(chan []ContentRow, len(hosts))
	errCh := make(chan error, len(hosts))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup

	for _, host := range hosts {
		host := host
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			rows, runErr := runFFUFForHost(ctx, cfg, host, wordFile)
			if runErr != nil {
				errCh <- runErr
				return
			}
			rowsCh <- rows
		}()
	}
	wg.Wait()
	close(rowsCh)
	close(errCh)

	for rows := range rowsCh {
		contentRows = append(contentRows, rows...)
		if len(contentRows) >= cfg.MaxContentRows {
			break
		}
	}
	for e := range errCh {
		*toolErrs = append(*toolErrs, ToolError{Stage: "content_discovery", Tool: "ffuf", Error: e.Error()})
	}

	contentRows = dedupeContentRows(contentRows, cfg.MaxContentRows)
	for _, row := range contentRows {
		if row.Host != "" && row.Path != "" {
			store.AddNote(row.Host, "content:"+row.Path)
		}
	}
	logf("[content] hosts=%d rows=%d ffuf=%d params=%d", len(hosts), len(contentRows), countContentRowsBySource(contentRows, "ffuf"), len(paramKeys))
	return contentRows, paramKeys
}

func runFFUFForHost(ctx context.Context, cfg config.Config, host, wordFile string) ([]ContentRow, error) {
	targets := []string{
		"https://" + host + "/FUZZ",
		"http://" + host + "/FUZZ",
	}
	attemptPerTarget := [][]string{
		{"-w", wordFile, "-ac", "-mc", "200,204,301,302,307,401,403,405", "-rate", strconv.Itoa(cfg.ContentRate), "-t", strconv.Itoa(minInt(cfg.HTTPThreads, 60)), "-of", "json", "-noninteractive"},
		{"-w", wordFile, "-mc", "200,204,301,302,307,401,403,405", "-rate", strconv.Itoa(cfg.ContentRate), "-t", strconv.Itoa(minInt(cfg.HTTPThreads, 60)), "-of", "json", "-noninteractive"},
		{"-w", wordFile, "-mc", "200,204,301,302,307,401,403,405", "-rate", strconv.Itoa(cfg.ContentRate), "-of", "json", "-noninteractive"},
		{"-w", wordFile, "-mc", "200,204,301,302,307,401,403,405", "-of", "json", "-noninteractive"},
	}
	var lastErr error

	for _, target := range targets {
		for _, baseArgs := range attemptPerTarget {
			outFile, err := os.CreateTemp(cfg.OutputDir, "ffuf-*.json")
			if err != nil {
				return nil, err
			}
			outPath := outFile.Name()
			outFile.Close()

			args := make([]string, 0, len(baseArgs)+4)
			args = append(args, "-u", target)
			args = append(args, baseArgs...)
			args = append(args, "-o", outPath)

			subCtx, cancel := context.WithTimeout(ctx, minDuration(cfg.BruteTimeout, 45*time.Second))
			res := util.RunCommand(subCtx, minDuration(cfg.BruteTimeout, 45*time.Second), "ffuf", args...)
			cancel()

			rows, parseErr := parseFFUFJSON(outPath, host)
			_ = os.Remove(outPath)
			if parseErr == nil && len(rows) > 0 {
				return rows, nil
			}
			if res.Err == nil && parseErr == nil {
				continue
			}
			if flagError(res.Stderr) {
				continue
			}
			if parseErr != nil {
				lastErr = parseErr
				continue
			}
			lastErr = summarizeToolFailure(res.Err, res.Stderr)
		}
	}
	if lastErr != nil {
		return nil, fmt.Errorf("ffuf %s: %w", host, lastErr)
	}
	return nil, nil
}

func parseFFUFJSON(path, host string) ([]ContentRow, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var obj struct {
		Results []struct {
			URL    string `json:"url"`
			Status int    `json:"status"`
			Words  int    `json:"words"`
			Length int    `json:"length"`
		} `json:"results"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, err
	}
	rows := make([]ContentRow, 0, len(obj.Results))
	for _, r := range obj.Results {
		u, err := url.Parse(strings.TrimSpace(r.URL))
		if err != nil || u.Host == "" {
			continue
		}
		pathVal := u.EscapedPath()
		if pathVal == "" {
			pathVal = "/"
		}
		rows = append(rows, ContentRow{
			URL:        r.URL,
			Host:       host,
			Path:       pathVal,
			StatusCode: r.Status,
			Words:      r.Words,
			Length:     r.Length,
			Source:     "ffuf",
		})
	}
	return rows, nil
}

func topParamKeys(rows []SurfaceRow, limit int) []string {
	if limit <= 0 || len(rows) == 0 {
		return nil
	}
	freq := make(map[string]int, 256)
	for _, r := range rows {
		for _, p := range r.ParamKeys {
			p = strings.TrimSpace(strings.ToLower(p))
			if p == "" {
				continue
			}
			freq[p]++
		}
	}
	type kv struct {
		Key string
		N   int
	}
	arr := make([]kv, 0, len(freq))
	for k, n := range freq {
		arr = append(arr, kv{Key: k, N: n})
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].N == arr[j].N {
			return arr[i].Key < arr[j].Key
		}
		return arr[i].N > arr[j].N
	})
	if len(arr) > limit {
		arr = arr[:limit]
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		out = append(out, e.Key)
	}
	return out
}

func seedContentRowsFromSurface(rows []SurfaceRow, limit int) []ContentRow {
	if limit <= 0 || len(rows) == 0 {
		return nil
	}
	out := make([]ContentRow, 0, minInt(limit, len(rows)))
	for _, r := range rows {
		if r.Category != "admin" && r.Category != "auth" && r.Category != "upload" && r.Category != "api" {
			continue
		}
		out = append(out, ContentRow{
			URL:    r.URL,
			Host:   r.Host,
			Path:   r.Path,
			Source: "surface",
		})
		if len(out) >= limit {
			break
		}
	}
	return out
}

func collectContentHosts(store *SafeStore, limit int) []string {
	if limit <= 0 {
		return nil
	}
	snap := store.Snapshot()
	out := make([]string, 0, limit)
	for _, c := range snap {
		if !c.Resolved || c.Wildcard {
			continue
		}
		if !c.Live && len(c.LiveURLs) == 0 {
			continue
		}
		out = append(out, c.Name)
		if len(out) >= limit {
			break
		}
	}
	if len(out) > 0 {
		return util.UniqueSorted(out)
	}
	for _, c := range snap {
		if !c.Resolved || c.Wildcard {
			continue
		}
		out = append(out, c.Name)
		if len(out) >= limit {
			break
		}
	}
	return util.UniqueSorted(out)
}

func dedupeContentRows(rows []ContentRow, limit int) []ContentRow {
	if len(rows) == 0 {
		return nil
	}
	out := make([]ContentRow, 0, minInt(len(rows), limit))
	seen := make(map[string]struct{}, len(rows))
	for _, r := range rows {
		key := r.URL + "|" + strconv.Itoa(r.StatusCode) + "|" + r.Source
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
			if out[i].Path == out[j].Path {
				return out[i].URL < out[j].URL
			}
			return out[i].Path < out[j].Path
		}
		return out[i].Host < out[j].Host
	})
	return out
}
