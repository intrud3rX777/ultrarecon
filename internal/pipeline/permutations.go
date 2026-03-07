package pipeline

import (
	"sort"
	"strings"

	"ultrarecon/internal/config"
	"ultrarecon/internal/util"
)

func generatePermutations(cfg config.Config, store *SafeStore, logf func(string, ...any)) []string {
	if !cfg.EnablePermutations || cfg.MaxPermutations == 0 {
		return nil
	}

	baseLabels := collectTopLabels(cfg, store)
	if len(baseLabels) == 0 {
		return nil
	}
	words := loadPermutationWordlist(cfg)
	if len(words) == 0 {
		return nil
	}

	existing := make(map[string]struct{}, store.Count())
	for _, name := range store.Names() {
		existing[name] = struct{}{}
	}

	outSet := make(map[string]struct{}, cfg.MaxPermutations)
	for _, token := range baseLabels {
		for _, word := range words {
			for _, label := range combineLabels(token, word) {
				host := label + "." + cfg.Domain
				if _, ok := existing[host]; ok {
					continue
				}
				outSet[host] = struct{}{}
				if len(outSet) >= cfg.MaxPermutations {
					return mapKeysSorted(outSet)
				}
			}
		}
	}
	out := mapKeysSorted(outSet)
	logf("[perm] generated=%d (labels=%d words=%d)", len(out), len(baseLabels), len(words))
	return out
}

func collectTopLabels(cfg config.Config, store *SafeStore) []string {
	freq := make(map[string]int)
	for _, c := range store.Snapshot() {
		if !c.Resolved || c.Wildcard {
			continue
		}
		if c.Name == cfg.Domain {
			continue
		}
		left := strings.TrimSuffix(c.Name, "."+cfg.Domain)
		if left == "" || strings.Contains(left, ".") {
			// only first-level labels drive permutations.
			if strings.Contains(left, ".") {
				left = strings.Split(left, ".")[0]
			} else {
				continue
			}
		}
		for _, t := range splitToken(left) {
			if len(t) < 2 {
				continue
			}
			freq[t]++
		}
	}

	type pair struct {
		token string
		n     int
	}
	arr := make([]pair, 0, len(freq))
	for t, n := range freq {
		arr = append(arr, pair{token: t, n: n})
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].n == arr[j].n {
			return arr[i].token < arr[j].token
		}
		return arr[i].n > arr[j].n
	})
	limit := cfg.PermutationTopLabels
	if len(arr) < limit {
		limit = len(arr)
	}
	out := make([]string, 0, limit)
	for i := 0; i < limit; i++ {
		out = append(out, arr[i].token)
	}
	return out
}

func loadPermutationWordlist(cfg config.Config) []string {
	if cfg.WordlistFile != "" {
		if lines, err := util.ReadLines(cfg.WordlistFile); err == nil && len(lines) > 0 {
			out := make([]string, 0, len(lines))
			for _, l := range lines {
				l = strings.ToLower(strings.TrimSpace(l))
				if len(l) < 2 || len(l) > 30 {
					continue
				}
				if strings.ContainsAny(l, " /\\:@") {
					continue
				}
				out = append(out, l)
			}
			return util.UniqueSorted(out)
		}
	}
	return defaultPermutationWords()
}

func combineLabels(token, word string) []string {
	out := make([]string, 0, 16)
	labels := []string{
		word + "-" + token,
		token + "-" + word,
		word + token,
		token + word,
		token + "-dev",
		token + "-stg",
		token + "-prod",
		token + "-api",
		"api-" + token,
		word + "-" + token + "-api",
	}
	for _, l := range labels {
		if validLabel(l) {
			out = append(out, l)
		}
	}
	for i := 1; i <= 3; i++ {
		a := token + word + string(rune('0'+i))
		b := word + token + string(rune('0'+i))
		if validLabel(a) {
			out = append(out, a)
		}
		if validLabel(b) {
			out = append(out, b)
		}
	}
	return out
}

func splitToken(s string) []string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return nil
	}
	repl := strings.NewReplacer("-", ".", "_", ".", " ", ".", "/", ".", "\\", ".")
	s = repl.Replace(s)
	parts := strings.Split(s, ".")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if validLabel(p) {
			out = append(out, p)
		}
	}
	return util.UniqueSorted(out)
}

func validLabel(s string) bool {
	if len(s) < 2 || len(s) > 63 {
		return false
	}
	if strings.HasPrefix(s, "-") || strings.HasSuffix(s, "-") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			continue
		}
		return false
	}
	return true
}

func mapKeysSorted(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func defaultPermutationWords() []string {
	return []string{
		"api", "app", "auth", "beta", "cache", "cdn", "ci", "cms", "corp", "data",
		"db", "dev", "docs", "edge", "gateway", "git", "grafana", "img", "internal", "k8s",
		"lb", "login", "mail", "mobile", "monitor", "mta", "new", "old", "ops", "portal",
		"prod", "qa", "sandbox", "search", "secure", "shop", "sso", "stage", "staging", "static",
		"status", "storage", "svc", "test", "uat", "upload", "vpn", "web", "www", "zero",
	}
}
