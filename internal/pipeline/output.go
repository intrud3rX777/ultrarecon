package pipeline

import (
	"fmt"
	"html/template"
	"os"
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
	jsRows []JSAnalysisRow,
	contentRows []ContentRow,
	paramKeys []string,
	securityFindings []SecurityFinding,
	screenshotRows []ScreenshotRow,
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
		if cfg.EnableDiagnostics && len(summary.PassiveDiagnostics) > 0 {
			if err := toJSONLines(filepath.Join(output, "passive_diagnostics.jsonl"), passiveDiagnosticRows(summary.PassiveDiagnostics)); err != nil {
				return err
			}
		}
		if err := util.WriteLines(filepath.Join(output, "final_subdomains.txt"), final); err != nil {
			return err
		}
		if err := util.WriteLines(filepath.Join(output, "live_subdomains.txt"), live); err != nil {
			return err
		}
		if err := util.WriteJSONLines(filepath.Join(output, "scored_subdomains.jsonl"), rows); err != nil {
			return err
		}
		if cfg.EnableServiceDiscovery {
			if err := toJSONLines(filepath.Join(output, "service_assets.jsonl"), serviceRows); err != nil {
				return err
			}
		}
		if cfg.EnableSurfaceMapping {
			if err := util.WriteLines(filepath.Join(output, "surface_urls.txt"), surfaceURLs); err != nil {
				return err
			}
			if err := toJSONLines(filepath.Join(output, "surface_endpoints.jsonl"), surfaceRows); err != nil {
				return err
			}
			if cfg.EnableJSAnalysis {
				if err := toJSONLines(filepath.Join(output, "js_analysis.jsonl"), jsRows); err != nil {
					return err
				}
			}
		}
		if cfg.EnableContentDiscovery {
			if err := toJSONLines(filepath.Join(output, "content_paths.jsonl"), contentRows); err != nil {
				return err
			}
			if err := toJSONLines(filepath.Join(output, "ffuf_results.jsonl"), ffufRows(contentRows)); err != nil {
				return err
			}
			if err := util.WriteLines(filepath.Join(output, "param_keys.txt"), paramKeys); err != nil {
				return err
			}
		}
		if cfg.EnableSecurityChecks {
			if err := toJSONLines(filepath.Join(output, "security_findings.jsonl"), securityFindings); err != nil {
				return err
			}
		}
		if cfg.EnableScreenshots {
			if err := toJSONLines(filepath.Join(output, "screenshots.jsonl"), screenshotRows); err != nil {
				return err
			}
			if err := writeScreenshotGallery(output, screenshotRows); err != nil {
				return err
			}
		}
		if err := util.WriteJSON(filepath.Join(output, "summary.json"), summary); err != nil {
			return err
		}
		if err := writeFinalReport(output, cfg, summary, final, live); err != nil {
			return err
		}
		return nil
	}

	if cfg.EnableDiagnostics && len(summary.PassiveDiagnostics) > 0 {
		if err := toJSONLines(filepath.Join(output, "00_passive_diagnostics.jsonl"), passiveDiagnosticRows(summary.PassiveDiagnostics)); err != nil {
			return err
		}
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
	if cfg.EnableServiceDiscovery {
		if err := toJSONLines(filepath.Join(output, "19_service_assets.jsonl"), serviceRows); err != nil {
			return err
		}
	}
	if cfg.EnableSurfaceMapping {
		if err := util.WriteLines(filepath.Join(output, "20_surface_urls.txt"), surfaceURLs); err != nil {
			return err
		}
		if err := toJSONLines(filepath.Join(output, "21_surface_endpoints.jsonl"), surfaceRows); err != nil {
			return err
		}
		if cfg.EnableJSAnalysis {
			if err := toJSONLines(filepath.Join(output, "21b_js_analysis.jsonl"), jsRows); err != nil {
				return err
			}
		}
	}
	if cfg.EnableContentDiscovery {
		if err := toJSONLines(filepath.Join(output, "22_content_paths.jsonl"), contentRows); err != nil {
			return err
		}
		if err := toJSONLines(filepath.Join(output, "22b_ffuf_results.jsonl"), ffufRows(contentRows)); err != nil {
			return err
		}
		if err := util.WriteLines(filepath.Join(output, "23_param_keys.txt"), paramKeys); err != nil {
			return err
		}
	}
	if cfg.EnableSecurityChecks {
		if err := toJSONLines(filepath.Join(output, "24_security_findings.jsonl"), securityFindings); err != nil {
			return err
		}
	}
	if cfg.EnableScreenshots {
		if err := toJSONLines(filepath.Join(output, "25_screenshots.jsonl"), screenshotRows); err != nil {
			return err
		}
		if err := writeScreenshotGallery(output, screenshotRows); err != nil {
			return err
		}
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
	if err := writeFinalReport(output, cfg, summary, final, live); err != nil {
		return err
	}
	return nil
}

func writeFinalReport(output string, cfg config.Config, summary *Summary, final, live []string) error {
	artifacts := []string{
		"- final_subdomains.txt",
		"- live_subdomains.txt",
		"- summary.json",
	}
	if cfg.EnableServiceDiscovery {
		artifacts = append(artifacts, "- service_assets.jsonl")
	}
	if cfg.EnableSurfaceMapping {
		artifacts = append(artifacts, "- surface_urls.txt", "- surface_endpoints.jsonl")
		if cfg.EnableJSAnalysis {
			artifacts = append(artifacts, "- js_analysis.jsonl")
		}
	}
	if cfg.EnableContentDiscovery {
		artifacts = append(artifacts, "- content_paths.jsonl", "- ffuf_results.jsonl", "- param_keys.txt")
	}
	if cfg.EnableSecurityChecks {
		artifacts = append(artifacts, "- security_findings.jsonl")
	}
	if cfg.EnableScreenshots {
		artifacts = append(artifacts, "- screenshots_gallery.html", "- screenshots/")
	}
	if summary.FinalOnly {
		if cfg.EnableDiagnostics && len(summary.PassiveDiagnostics) > 0 {
			artifacts = append(artifacts, "- passive_diagnostics.jsonl")
		}
		artifacts = append(artifacts, "- scored_subdomains.jsonl")
		if cfg.EnableScreenshots {
			artifacts = append(artifacts, "- screenshots.jsonl")
		}
	} else {
		if cfg.EnableDiagnostics && len(summary.PassiveDiagnostics) > 0 {
			artifacts = append(artifacts, "- 00_passive_diagnostics.jsonl")
		}
		artifacts = append(artifacts, "- 17_scored.jsonl")
		if cfg.EnableServiceDiscovery {
			artifacts = append(artifacts, "- 19_service_assets.jsonl")
		}
		if cfg.EnableSurfaceMapping {
			artifacts = append(artifacts, "- 20_surface_urls.txt", "- 21_surface_endpoints.jsonl")
			if cfg.EnableJSAnalysis {
				artifacts = append(artifacts, "- 21b_js_analysis.jsonl")
			}
		}
		if cfg.EnableContentDiscovery {
			artifacts = append(artifacts, "- 22_content_paths.jsonl", "- 22b_ffuf_results.jsonl", "- 23_param_keys.txt")
		}
		if cfg.EnableSecurityChecks {
			artifacts = append(artifacts, "- 24_security_findings.jsonl")
		}
		if cfg.EnableScreenshots {
			artifacts = append(artifacts, "- 25_screenshots.jsonl")
		}
	}

	lines := []string{
		"# UltraRecon Final Report",
		"",
		fmt.Sprintf("- generated: %s", time.Now().UTC().Format(time.RFC3339)),
		fmt.Sprintf("- phase: %s", strings.ToLower(strings.TrimSpace(cfg.Phase))),
		fmt.Sprintf("- domain: %s", summary.Domain),
		fmt.Sprintf("- duration: %s", summary.Duration),
		fmt.Sprintf("- final_subdomains: %d", len(final)),
		fmt.Sprintf("- live_subdomains: %d", len(live)),
	}
	if cfg.EnableScreenshots {
		lines = append(lines, fmt.Sprintf("- screenshots: %d/%d", summary.ScreenshotsCaptured, summary.ScreenshotTargets))
	}
	lines = append(lines, "", "## Final Artifacts")
	lines = append(lines, artifacts...)
	if cfg.EnableDiagnostics {
		lines = append(lines, "", "## Passive Diagnostics")
		unusual := unusualPassiveDiagnostics(summary.PassiveDiagnostics)
		if len(unusual) == 0 {
			lines = append(lines, "- no passive sources were skipped, failed, or downgraded")
		} else {
			for _, diag := range unusual {
				line := fmt.Sprintf("- %s: status=%s duration=%s", diag.Collector, diag.Status, diag.Duration)
				if diag.Reason != "" {
					line += fmt.Sprintf(" reason=%s", diag.Reason)
				}
				line += fmt.Sprintf(" raw=%d accepted=%d added=%d", diag.RawCount, diag.Accepted, diag.Added)
				lines = append(lines, line)
			}
		}
	}
	return util.WriteLines(filepath.Join(output, "report.md"), lines)
}

func writeScreenshotGallery(output string, rows []ScreenshotRow) error {
	type screenshotCard struct {
		Host  string
		URL   string
		File  string
		Title string
	}
	cards := make([]screenshotCard, 0, len(rows))
	for _, row := range rows {
		if !strings.EqualFold(strings.TrimSpace(row.Status), "captured") || strings.TrimSpace(row.File) == "" {
			continue
		}
		cards = append(cards, screenshotCard{
			Host:  row.Host,
			URL:   row.URL,
			File:  filepath.ToSlash(row.File),
			Title: row.Title,
		})
	}
	sort.Slice(cards, func(i, j int) bool {
		if cards[i].Host == cards[j].Host {
			return cards[i].URL < cards[j].URL
		}
		return cards[i].Host < cards[j].Host
	})
	const gallery = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>UltraRecon Screenshots</title>
  <style>
    :root {
      --bg: #f3efe5;
      --panel: #fffdf8;
      --ink: #1f1a17;
      --muted: #6d6257;
      --line: #d7c8b7;
      --accent: #0f766e;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(15,118,110,0.12), transparent 36%),
        linear-gradient(180deg, #f8f3ea 0%, var(--bg) 100%);
    }
    header {
      padding: 28px 24px 12px;
    }
    h1 {
      margin: 0 0 6px;
      font-size: 28px;
    }
    p {
      margin: 0;
      color: var(--muted);
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 18px;
      padding: 24px;
    }
    .card {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 18px;
      overflow: hidden;
      box-shadow: 0 16px 40px rgba(31, 26, 23, 0.08);
    }
    .card img {
      display: block;
      width: 100%;
      height: auto;
      background: #e8ddd0;
      aspect-ratio: 16 / 10;
      object-fit: cover;
    }
    .meta {
      padding: 14px 16px 18px;
    }
    .meta strong {
      display: block;
      margin-bottom: 4px;
      font-size: 15px;
    }
    .meta a {
      color: var(--accent);
      text-decoration: none;
      word-break: break-all;
    }
    .meta small {
      display: block;
      margin-top: 8px;
      color: var(--muted);
    }
    .empty {
      padding: 24px;
    }
  </style>
</head>
<body>
  <header>
    <h1>UltraRecon Screenshots</h1>
    <p>Captured screenshots for final live subdomains.</p>
  </header>
  {{if .}}
  <section class="grid">
    {{range .}}
    <article class="card">
      <a href="{{.File}}"><img src="{{.File}}" alt="{{.Host}}"></a>
      <div class="meta">
        <strong>{{.Host}}</strong>
        <a href="{{.URL}}">{{.URL}}</a>
        {{if .Title}}<small>{{.Title}}</small>{{end}}
      </div>
    </article>
    {{end}}
  </section>
  {{else}}
  <section class="empty">
    <p>No screenshots were captured for this run.</p>
  </section>
  {{end}}
</body>
</html>`
	tpl, err := template.New("gallery").Parse(gallery)
	if err != nil {
		return err
	}
	path := filepath.Join(output, "screenshots_gallery.html")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return tpl.Execute(f, cards)
}

func toJSONLines[T any](path string, rows []T) error {
	anyRows := make([]any, 0, len(rows))
	for _, r := range rows {
		anyRows = append(anyRows, r)
	}
	return util.WriteJSONLines(path, anyRows)
}

func passiveDiagnosticRows(diags []PassiveCollectorDiagnostic) []PassiveCollectorDiagnostic {
	out := make([]PassiveCollectorDiagnostic, 0, len(diags))
	out = append(out, diags...)
	return out
}

func unusualPassiveDiagnostics(diags []PassiveCollectorDiagnostic) []PassiveCollectorDiagnostic {
	out := make([]PassiveCollectorDiagnostic, 0, len(diags))
	for _, diag := range diags {
		if diag.Status == "completed" {
			continue
		}
		out = append(out, diag)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Status == out[j].Status {
			return out[i].Collector < out[j].Collector
		}
		return out[i].Status < out[j].Status
	})
	return out
}

func ffufRows(rows []ContentRow) []ContentRow {
	out := make([]ContentRow, 0, len(rows))
	for _, row := range rows {
		if strings.EqualFold(strings.TrimSpace(row.Source), "ffuf") {
			out = append(out, row)
		}
	}
	return out
}

func (s *SafeStore) setConfidence(name string, score float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.entries[name]; ok {
		c.Confidence = score
	}
}
