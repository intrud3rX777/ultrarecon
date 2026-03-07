package pipeline

import (
	"context"
	"crypto/tls"
	"net/http"
	"sync"
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
	liveCh := make(chan string, len(hosts))

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
					liveCh <- host
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(liveCh)
	}()

	live := 0
	for range liveCh {
		live++
	}
	logf("[http] live=%d/%d", live, len(hosts))
	return live
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
