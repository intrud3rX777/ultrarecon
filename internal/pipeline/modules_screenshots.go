package pipeline

import (
	"context"
	"fmt"
	"hash/fnv"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"

	"ultrarecon/internal/config"
)

type screenshotTarget struct {
	Host string
	URL  string
}

func runScreenshots(
	ctx context.Context,
	cfg config.Config,
	store *SafeStore,
	toolErrs *[]ToolError,
	logf func(string, ...any),
) []ScreenshotRow {
	if !cfg.EnableScreenshots {
		return nil
	}

	targets := selectScreenshotTargets(store, cfg.MaxScreenshotTargets)
	if len(targets) == 0 {
		logf("[screenshots] targets=0")
		return nil
	}

	outDir := filepath.Join(cfg.OutputDir, "screenshots")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		errMsg := fmt.Sprintf("create screenshot dir: %v", err)
		*toolErrs = append(*toolErrs, ToolError{Stage: "screenshots", Tool: "chromium", Error: errMsg})
		logf("[screenshots] failed: %s", errMsg)
		return failedScreenshotRows(targets, errMsg, "failed")
	}

	browserPath, err := findChromiumExecutable()
	if err != nil {
		errMsg := err.Error()
		*toolErrs = append(*toolErrs, ToolError{Stage: "screenshots", Tool: "chromium", Error: errMsg})
		logf("[screenshots] skipped: %s", errMsg)
		return failedScreenshotRows(targets, errMsg, "skipped")
	}

	workers := cfg.ScreenshotConcurrency
	if workers < 1 {
		workers = 1
	}
	if workers > len(targets) {
		workers = len(targets)
	}
	logf("[screenshots] targets=%d workers=%d browser=%s timeout=%s", len(targets), workers, browserPath, cfg.ScreenshotTimeout.Round(time.Millisecond))

	allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(browserPath),
		chromedp.WindowSize(1440, 900),
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("hide-scrollbars", true),
		chromedp.Flag("mute-audio", true),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("disable-dev-shm-usage", true),
	)
	if runtime.GOOS == "linux" {
		allocOpts = append(allocOpts, chromedp.Flag("no-sandbox", true))
	}

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, allocOpts...)
	defer cancelAlloc()
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()
	if err := chromedp.Run(browserCtx); err != nil {
		errMsg := fmt.Sprintf("start browser: %v", err)
		*toolErrs = append(*toolErrs, ToolError{Stage: "screenshots", Tool: "chromium", Error: errMsg})
		logf("[screenshots] failed: %s", errMsg)
		return failedScreenshotRows(targets, errMsg, "failed")
	}

	tasks := make(chan screenshotTarget, len(targets))
	results := make(chan ScreenshotRow, len(targets))
	for _, t := range targets {
		tasks <- t
	}
	close(tasks)

	var processed int64
	var captured int64
	progressDone := make(chan struct{})
	go reportScreenshotProgress(progressDone, len(targets), &processed, &captured, logf)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range tasks {
				row := captureScreenshot(browserCtx, outDir, target, cfg.ScreenshotTimeout)
				if strings.EqualFold(row.Status, "captured") {
					atomic.AddInt64(&captured, 1)
				}
				atomic.AddInt64(&processed, 1)
				results <- row
			}
		}()
	}

	go func() {
		wg.Wait()
		close(progressDone)
		close(results)
	}()

	rows := make([]ScreenshotRow, 0, len(targets))
	for row := range results {
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Host == rows[j].Host {
			return rows[i].URL < rows[j].URL
		}
		return rows[i].Host < rows[j].Host
	})
	logf("[screenshots] captured=%d/%d", countCapturedScreenshots(rows), len(rows))
	return rows
}

func selectScreenshotTargets(store *SafeStore, max int) []screenshotTarget {
	if max <= 0 {
		return nil
	}
	type rankedTarget struct {
		host        string
		url         string
		sourceCount int
		openPorts   int
	}
	rows := make([]rankedTarget, 0, max)
	for _, c := range store.Snapshot() {
		if !c.Live || !c.Resolved || c.Wildcard {
			continue
		}
		url := preferredLiveURL(c.LiveURLs)
		if url == "" {
			continue
		}
		rows = append(rows, rankedTarget{
			host:        c.Name,
			url:         url,
			sourceCount: c.SourceCount(),
			openPorts:   len(c.OpenPorts),
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].openPorts != rows[j].openPorts {
			return rows[i].openPorts > rows[j].openPorts
		}
		if rows[i].sourceCount != rows[j].sourceCount {
			return rows[i].sourceCount > rows[j].sourceCount
		}
		return rows[i].host < rows[j].host
	})
	if len(rows) > max {
		rows = rows[:max]
	}
	out := make([]screenshotTarget, 0, len(rows))
	for _, row := range rows {
		out = append(out, screenshotTarget{Host: row.host, URL: row.url})
	}
	return out
}

func preferredLiveURL(urls []string) string {
	if len(urls) == 0 {
		return ""
	}
	cp := append([]string(nil), urls...)
	sort.Slice(cp, func(i, j int) bool {
		aHTTPS := strings.HasPrefix(strings.ToLower(cp[i]), "https://")
		bHTTPS := strings.HasPrefix(strings.ToLower(cp[j]), "https://")
		if aHTTPS != bHTTPS {
			return aHTTPS
		}
		if len(cp[i]) != len(cp[j]) {
			return len(cp[i]) < len(cp[j])
		}
		return cp[i] < cp[j]
	})
	return cp[0]
}

func captureScreenshot(browserCtx context.Context, outDir string, target screenshotTarget, timeout time.Duration) ScreenshotRow {
	row := ScreenshotRow{
		Host:   target.Host,
		URL:    target.URL,
		Status: "failed",
		Source: "chromedp",
	}

	tabCtx, cancelTab := chromedp.NewContext(browserCtx)
	defer cancelTab()
	taskCtx, cancelTimeout := context.WithTimeout(tabCtx, timeout)
	defer cancelTimeout()

	var (
		buf   []byte
		title string
	)
	settle := minDuration(timeout/5, 2*time.Second)
	if settle < 1200*time.Millisecond {
		settle = 1200 * time.Millisecond
	}
	err := chromedp.Run(taskCtx,
		network.Enable(),
		emulation.SetDeviceMetricsOverride(1440, 900, 1, false),
		emulation.SetUserAgentOverride("UltraRecon/1.0"),
		chromedp.Navigate(target.URL),
		chromedp.Sleep(settle),
		chromedp.ActionFunc(func(ctx context.Context) error {
			var t string
			if err := chromedp.Title(&t).Do(ctx); err == nil {
				title = strings.TrimSpace(t)
			}
			return nil
		}),
		chromedp.ActionFunc(func(ctx context.Context) error {
			var err error
			buf, err = page.CaptureScreenshot().WithFormat(page.CaptureScreenshotFormatPng).Do(ctx)
			return err
		}),
	)
	if err != nil {
		row.Error = err.Error()
		return row
	}

	fileName := screenshotFileName(target)
	fullPath := filepath.Join(outDir, fileName)
	if err := os.WriteFile(fullPath, buf, 0o644); err != nil {
		row.Error = err.Error()
		return row
	}
	row.Status = "captured"
	row.Title = title
	row.File = filepath.ToSlash(filepath.Join("screenshots", fileName))
	return row
}

func reportScreenshotProgress(done <-chan struct{}, total int, processed *int64, captured *int64, logf func(string, ...any)) {
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
			logf("[screenshots] progress=%d/%d captured=%d", p, total, int(atomic.LoadInt64(captured)))
		}
	}
}

func failedScreenshotRows(targets []screenshotTarget, errMsg string, status string) []ScreenshotRow {
	rows := make([]ScreenshotRow, 0, len(targets))
	for _, target := range targets {
		rows = append(rows, ScreenshotRow{
			Host:   target.Host,
			URL:    target.URL,
			Status: status,
			Error:  errMsg,
			Source: "chromedp",
		})
	}
	return rows
}

func screenshotFileName(target screenshotTarget) string {
	safeHost := sanitizeScreenshotLabel(target.Host)
	if safeHost == "" {
		safeHost = "host"
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(strings.ToLower(strings.TrimSpace(target.URL))))
	return fmt.Sprintf("%s-%x.png", safeHost, h.Sum64())
}

func sanitizeScreenshotLabel(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(v))
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('-')
	}
	out := strings.Trim(b.String(), "-")
	out = strings.ReplaceAll(out, "--", "-")
	return out
}

func findChromiumExecutable() (string, error) {
	envVars := []string{"CHROME_PATH", "CHROMIUM_PATH", "EDGE_PATH"}
	for _, key := range envVars {
		if p := strings.TrimSpace(os.Getenv(key)); p != "" && fileExists(p) {
			return p, nil
		}
	}

	commands := []string{
		"chrome",
		"google-chrome",
		"google-chrome-stable",
		"chromium",
		"chromium-browser",
		"msedge",
		"microsoft-edge",
		"brave",
		"brave-browser",
	}
	for _, name := range commands {
		if p, err := exec.LookPath(name); err == nil && strings.TrimSpace(p) != "" {
			return p, nil
		}
	}

	for _, p := range knownBrowserPaths() {
		if fileExists(p) {
			return p, nil
		}
	}
	return "", fmt.Errorf("no Chromium-based browser found; set CHROME_PATH or install Chrome, Edge, or Chromium")
}

func knownBrowserPaths() []string {
	paths := make([]string, 0, 20)
	switch runtime.GOOS {
	case "windows":
		local := os.Getenv("LOCALAPPDATA")
		programFiles := os.Getenv("ProgramFiles")
		programFiles86 := os.Getenv("ProgramFiles(x86)")
		paths = append(paths,
			filepath.Join(programFiles, "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(programFiles86, "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(local, "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(programFiles, "Microsoft", "Edge", "Application", "msedge.exe"),
			filepath.Join(programFiles86, "Microsoft", "Edge", "Application", "msedge.exe"),
			filepath.Join(local, "Microsoft", "Edge", "Application", "msedge.exe"),
			filepath.Join(programFiles, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
			filepath.Join(programFiles86, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
			filepath.Join(local, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
		)
	case "darwin":
		paths = append(paths,
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
			"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
		)
	default:
		paths = append(paths,
			"/usr/bin/google-chrome",
			"/usr/bin/google-chrome-stable",
			"/usr/bin/chromium",
			"/usr/bin/chromium-browser",
			"/snap/bin/chromium",
			"/usr/bin/microsoft-edge",
			"/usr/bin/brave-browser",
		)
	}
	return paths
}

func fileExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}
