package pipeline

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"ultrarecon/internal/config"
	"ultrarecon/internal/util"
)

func computeScores(store *SafeStore) {
	for _, c := range store.Snapshot() {
		score := 0.0

		src := float64(c.SourceCount())
		if src > 5 {
			src = 5
		}
		score += (src / 5.0) * 0.35

		if c.Resolved {
			score += 0.35
		}

		if c.ResolverVotes >= 2 {
			score += 0.15
		} else if c.ResolverVotes == 1 {
			score += 0.08
		}

		if c.Live {
			score += 0.12
		}
		if len(c.OpenPorts) > 0 {
			score += 0.05
		}

		if c.Wildcard {
			score -= 0.35
		}

		if score < 0 {
			score = 0
		}
		if score > 1 {
			score = 1
		}

		store.setConfidence(c.Name, score)
	}
}

func writeArtifacts(
	cfg config.Config,
	store *SafeStore,
	passive []string,
	noerror []string,
	dnsPivot []string,
	asnCIDR []string,
	zoneTransfer []string,
	brute []string,
	recursive []string,
	recursiveBrute []string,
	enrichment []string,
	analytics []string,
	scraping []string,
	permutations []string,
	gotator []string,
	serviceRows []ServiceRow,
	surfaceRows []SurfaceRow,
	contentRows []ContentRow,
	paramKeys []string,
	securityFindings []SecurityFinding,
	summary *Summary,
) error {
	output := cfg.OutputDir
	surfaceURLs := urlsFromSurfaceRows(surfaceRows)

	snapshot := store.Snapshot()
	allNames := make([]string, 0, len(snapshot))
	resolved := make([]string, 0, len(snapshot))
	final := make([]string, 0, len(snapshot))
	live := make([]string, 0, len(snapshot))
	rows := make([]any, 0, len(snapshot))

	for _, c := range snapshot {
		allNames = append(allNames, c.Name)
		if c.Resolved {
			resolved = append(resolved, c.Name)
		}
		if c.Resolved && !c.Wildcard {
			final = append(final, c.Name)
		}
		if c.Live {
			live = append(live, c.Name)
		}
		rows = append(rows, ScoredRow{
			Name:          c.Name,
			Sources:       c.SourceList(),
			SourceCount:   c.SourceCount(),
			Resolved:      c.Resolved,
			IPs:           c.IPList(),
			ResolverVotes: c.ResolverVotes,
			Wildcard:      c.Wildcard,
			Live:          c.Live,
			LiveURLs:      c.LiveURLs,
			Confidence:    c.Confidence,
			Notes:         c.Notes,
			OpenPorts:     c.PortList(),
		})
	}

	sort.Strings(allNames)
	sort.Strings(resolved)
	sort.Strings(final)
	sort.Strings(live)

	if cfg.FinalOnly {
		if err := util.WriteLines(filepath.Join(output, "final_subdomains.txt"), final); err != nil {
			return err
		}
		if err := util.WriteLines(filepath.Join(output, "live_subdomains.txt"), live); err != nil {
			return err
		}
		if err := util.WriteJSONLines(filepath.Join(output, "scored_subdomains.jsonl"), rows); err != nil {
			return err
		}
		if err := toJSONLines(filepath.Join(output, "service_assets.jsonl"), serviceRows); err != nil {
			return err
		}
		if err := util.WriteLines(filepath.Join(output, "surface_urls.txt"), surfaceURLs); err != nil {
			return err
		}
		if err := toJSONLines(filepath.Join(output, "surface_endpoints.jsonl"), surfaceRows); err != nil {
			return err
		}
		if err := toJSONLines(filepath.Join(output, "content_paths.jsonl"), contentRows); err != nil {
			return err
		}
		if err := util.WriteLines(filepath.Join(output, "param_keys.txt"), paramKeys); err != nil {
			return err
		}
		if err := toJSONLines(filepath.Join(output, "security_findings.jsonl"), securityFindings); err != nil {
			return err
		}
		if err := util.WriteJSON(filepath.Join(output, "summary.json"), summary); err != nil {
			return err
		}
		if err := writeFinalReport(output, cfg.Phase, summary, final, live); err != nil {
			return err
		}
		return nil
	}

	if err := util.WriteLines(filepath.Join(output, "01_passive_raw.txt"), passive); err != nil {
		return err
	}
	if err := util.WriteLines(filepath.Join(output, "02_noerror_candidates.txt"), noerror); err != nil {
		return err
	}
	if err := util.WriteLines(filepath.Join(output, "03_dns_pivot_candidates.txt"), dnsPivot); err != nil {
		return err
	}
	if err := util.WriteLines(filepath.Join(output, "04_asn_cidr_candidates.txt"), asnCIDR); err != nil {
		return err
	}
	if err := util.WriteLines(filepath.Join(output, "05_zone_transfer_candidates.txt"), zoneTransfer); err != nil {
		return err
	}
	if err := util.WriteLines(filepath.Join(output, "06_bruteforce_candidates.txt"), brute); err != nil {
		return err
	}
	if err := util.WriteLines(filepath.Join(output, "07_recursive_candidates.txt"), recursive); err != nil {
		return err
	}
	if err := util.WriteLines(filepath.Join(output, "08_recursive_bruteforce_candidates.txt"), recursiveBrute); err != nil {
		return err
	}
	if err := util.WriteLines(filepath.Join(output, "09_enrichment_candidates.txt"), enrichment); err != nil {
		return err
	}
	if err := util.WriteLines(filepath.Join(output, "10_analytics_candidates.txt"), analytics); err != nil {
		return err
	}
	if err := util.WriteLines(filepath.Join(output, "11_scraping_candidates.txt"), scraping); err != nil {
		return err
	}
	if err := util.WriteLines(filepath.Join(output, "12_permutations_generated.txt"), permutations); err != nil {
		return err
	}
	if err := util.WriteLines(filepath.Join(output, "18_gotator_candidates.txt"), gotator); err != nil {
		return err
	}
	if err := toJSONLines(filepath.Join(output, "19_service_assets.jsonl"), serviceRows); err != nil {
		return err
	}
	if err := util.WriteLines(filepath.Join(output, "20_surface_urls.txt"), surfaceURLs); err != nil {
		return err
	}
	if err := toJSONLines(filepath.Join(output, "21_surface_endpoints.jsonl"), surfaceRows); err != nil {
		return err
	}
	if err := toJSONLines(filepath.Join(output, "22_content_paths.jsonl"), contentRows); err != nil {
		return err
	}
	if err := util.WriteLines(filepath.Join(output, "23_param_keys.txt"), paramKeys); err != nil {
		return err
	}
	if err := toJSONLines(filepath.Join(output, "24_security_findings.jsonl"), securityFindings); err != nil {
		return err
	}

	if err := util.WriteLines(filepath.Join(output, "13_all_candidates.txt"), allNames); err != nil {
		return err
	}
	if err := util.WriteLines(filepath.Join(output, "14_resolved_all.txt"), resolved); err != nil {
		return err
	}
	if err := util.WriteLines(filepath.Join(output, "15_final_subdomains.txt"), final); err != nil {
		return err
	}
	if err := util.WriteLines(filepath.Join(output, "16_live_hosts.txt"), live); err != nil {
		return err
	}
	if err := util.WriteJSONLines(filepath.Join(output, "17_scored.jsonl"), rows); err != nil {
		return err
	}
	if err := util.WriteJSON(filepath.Join(output, "summary.json"), summary); err != nil {
		return err
	}
	if err := writeFinalReport(output, cfg.Phase, summary, final, live); err != nil {
		return err
	}
	return nil
}

func writeFinalReport(output, phase string, summary *Summary, final, live []string) error {
	artifacts := []string{
		"- final_subdomains.txt",
		"- live_subdomains.txt",
		"- surface_urls.txt",
		"- surface_endpoints.jsonl",
		"- content_paths.jsonl",
		"- param_keys.txt",
		"- security_findings.jsonl",
		"- service_assets.jsonl",
		"- summary.json",
	}
	if summary.FinalOnly {
		artifacts = append(artifacts, "- scored_subdomains.jsonl")
	} else {
		artifacts = append(artifacts, "- 17_scored.jsonl", "- 19_service_assets.jsonl", "- 20_surface_urls.txt", "- 21_surface_endpoints.jsonl", "- 22_content_paths.jsonl", "- 23_param_keys.txt", "- 24_security_findings.jsonl")
	}

	lines := []string{
		"# UltraRecon Final Report",
		"",
		fmt.Sprintf("- generated: %s", time.Now().UTC().Format(time.RFC3339)),
		fmt.Sprintf("- phase: %s", strings.ToLower(strings.TrimSpace(phase))),
		fmt.Sprintf("- domain: %s", summary.Domain),
		fmt.Sprintf("- duration: %s", summary.Duration),
		fmt.Sprintf("- final_subdomains: %d", len(final)),
		fmt.Sprintf("- live_subdomains: %d", len(live)),
		"",
		"## Final Artifacts",
	}
	lines = append(lines, artifacts...)
	return util.WriteLines(filepath.Join(output, "report.md"), lines)
}

func toJSONLines[T any](path string, rows []T) error {
	anyRows := make([]any, 0, len(rows))
	for _, r := range rows {
		anyRows = append(anyRows, r)
	}
	return util.WriteJSONLines(path, anyRows)
}

func (s *SafeStore) setConfidence(name string, score float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.entries[name]; ok {
		c.Confidence = score
	}
}
