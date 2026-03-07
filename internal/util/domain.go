package util

import (
	"math/rand"
	"strings"
	"time"
)

var seededRand = rand.New(rand.NewSource(time.Now().UnixNano()))

// NormalizeCandidate normalizes and validates a candidate domain.
// Returns normalized hostname and whether it is in scope.
func NormalizeCandidate(raw, scopeDomain string) (string, bool) {
	s := strings.TrimSpace(strings.ToLower(raw))
	s = strings.Trim(s, "\"'`")
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", false
	}

	// Parse URLs or host:port style.
	s = stripSchemeAndPath(s)
	s = stripPort(s)
	if s == "" {
		return "", false
	}
	if strings.Contains(s, "_") {
		return "", false
	}
	if !isHostname(s) {
		return "", false
	}
	if !IsInScope(s, scopeDomain) {
		return "", false
	}
	return s, true
}

func IsInScope(host, domain string) bool {
	if host == domain {
		return true
	}
	return strings.HasSuffix(host, "."+domain)
}

func ParentDomains(host, baseDomain string) []string {
	if !IsInScope(host, baseDomain) {
		return nil
	}
	parts := strings.Split(host, ".")
	if len(parts) < 3 {
		return nil
	}
	out := make([]string, 0, len(parts)-2)
	for i := 1; i < len(parts)-1; i++ {
		p := strings.Join(parts[i:], ".")
		if IsInScope(p, baseDomain) {
			out = append(out, p)
		}
	}
	return out
}

func RandomLabel(n int) string {
	if n < 6 {
		n = 6
	}
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = chars[seededRand.Intn(len(chars))]
	}
	return string(buf)
}

func stripSchemeAndPath(s string) string {
	if idx := strings.Index(s, "://"); idx >= 0 {
		s = s[idx+3:]
	}
	if idx := strings.IndexAny(s, "/?#"); idx >= 0 {
		s = s[:idx]
	}
	return strings.TrimSpace(s)
}

func stripPort(s string) string {
	// IPv6 not expected for hostname candidates.
	if strings.Count(s, ":") == 1 {
		left, right, ok := strings.Cut(s, ":")
		if ok && right != "" {
			return left
		}
	}
	return s
}

func isHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	if strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, lbl := range labels {
		if len(lbl) == 0 || len(lbl) > 63 {
			return false
		}
		if lbl[0] == '-' || lbl[len(lbl)-1] == '-' {
			return false
		}
		for i := 0; i < len(lbl); i++ {
			c := lbl[i]
			if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
				continue
			}
			return false
		}
	}
	return true
}
