package pipeline

import (
	"context"
	"crypto/tls"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"ultrarecon/internal/config"
)

func runHTTPProbe(ctx context.Context, cfg config.Config, store *SafeStore, hosts []string, logf func(string, ...any)) int {
	if !cfg.EnableHTTPProbe || len(hosts) == 0 {
		return 0
	}

	client := &http.Client{
		Timeout: cfg.HTTPTimeout,
		Transport: &http.Transport{
			MaxIdleConns:          cfg.HTTPThreads * 2,
			MaxIdleConnsPerHost:   4,
			MaxConnsPerHost:       4,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: cfg.HTTPTimeout,
			IdleConnTimeout:       30 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // recon context: allow broad probing.
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	tasks := make(chan string, len(hosts))
	for _, h := range hosts {
		tasks <- h
	}
	close(tasks)

	var wg sync.WaitGroup
	workers := cfg.HTTPThreads
	if workers < 1 {
		workers = 1
	}
	var processed int64
	var live int64
	logf("[http] probing targets=%d workers=%d timeout=%s", len(hosts), workers, cfg.HTTPTimeout.Round(time.Millisecond))
	progressDone := make(chan struct{})
	go reportHTTPProbeProgress(progressDone, len(hosts), &processed, &live, logf)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range tasks {
				if ctx.Err() != nil {
					return
				}
				if url, ok := probeHost(ctx, client, host); ok {
					store.MarkLive(host, url)
					atomic.AddInt64(&live, 1)
				}
				atomic.AddInt64(&processed, 1)
			}
		}()
	}
	wg.Wait()
	close(progressDone)
	finalLive := int(atomic.LoadInt64(&live))
	logf("[http] live=%d/%d", finalLive, len(hosts))
	return finalLive
}

func probeHost(ctx context.Context, client *http.Client, host string) (string, bool) {
	for _, scheme := range []string{"https://", "http://"} {
		u := scheme + host
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "ultrarecon/1.0")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		// Any valid HTTP response means host is alive.
		if resp.StatusCode >= 100 && resp.StatusCode <= 599 {
			return u, true
		}
	}
	return "", false
}

func reportHTTPProbeProgress(done <-chan struct{}, total int, processed *int64, live *int64, logf func(string, ...any)) {
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
			logf("[http] progress=%d/%d live=%d", p, total, int(atomic.LoadInt64(live)))
		}
	}
}
