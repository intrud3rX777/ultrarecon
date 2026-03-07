package pipeline

import "time"

type StageStat struct {
	Name     string `json:"name"`
	Duration string `json:"duration"`
	Details  string `json:"details,omitempty"`
}

type ToolError struct {
	Stage string `json:"stage"`
	Tool  string `json:"tool"`
	Error string `json:"error"`
}

type Summary struct {
	Domain                  string      `json:"domain"`
	Phase                   string      `json:"phase"`
	FinalOnly               bool        `json:"final_only"`
	OutputDir               string      `json:"output_dir"`
	StartedAt               time.Time   `json:"started_at"`
	FinishedAt              time.Time   `json:"finished_at"`
	Duration                string      `json:"duration"`
	PassiveDiscovered       int         `json:"passive_discovered"`
	ResolvedInitial         int         `json:"resolved_initial"`
	WildcardFiltered        int         `json:"wildcard_filtered"`
	NoerrorDiscovered       int         `json:"noerror_discovered"`
	ResolvedNoerror         int         `json:"resolved_noerror"`
	DNSPivotDiscovered      int         `json:"dns_pivot_discovered"`
	ResolvedDNSPivot        int         `json:"resolved_dns_pivot"`
	ASNDiscovered           int         `json:"asn_discovered"`
	ResolvedASN             int         `json:"resolved_asn"`
	ZoneTransferDiscovered  int         `json:"zone_transfer_discovered"`
	ResolvedZoneTransfer    int         `json:"resolved_zone_transfer"`
	BruteforceGenerated     int         `json:"bruteforce_generated"`
	ResolvedBruteforce      int         `json:"resolved_bruteforce"`
	RecursiveDiscovered     int         `json:"recursive_discovered"`
	ResolvedRecursive       int         `json:"resolved_recursive"`
	RecursiveBruteFound     int         `json:"recursive_brute_discovered"`
	ResolvedRecursiveBrute  int         `json:"resolved_recursive_brute"`
	EnrichmentDiscovered    int         `json:"enrichment_discovered"`
	ResolvedEnrichment      int         `json:"resolved_enrichment"`
	AnalyticsDiscovered     int         `json:"analytics_discovered"`
	ResolvedAnalytics       int         `json:"resolved_analytics"`
	ScrapingDiscovered      int         `json:"scraping_discovered"`
	ResolvedScraping        int         `json:"resolved_scraping"`
	PermutationGenerated    int         `json:"permutation_generated"`
	ResolvedPermutations    int         `json:"resolved_permutations"`
	GotatorGenerated        int         `json:"gotator_generated"`
	ResolvedGotator         int         `json:"resolved_gotator"`
	ServiceHostsScanned     int         `json:"service_hosts_scanned"`
	ServiceRows             int         `json:"service_rows"`
	ServiceOpenPorts        int         `json:"service_open_ports"`
	ServiceLiveURLs         int         `json:"service_live_urls"`
	SurfaceURLs             int         `json:"surface_urls"`
	SurfacePaths            int         `json:"surface_paths"`
	ContentRows             int         `json:"content_rows"`
	ParamKeys               int         `json:"param_keys"`
	SecurityFindings        int         `json:"security_findings"`
	SecurityHighCritical    int         `json:"security_high_critical"`
	FinalResolved           int         `json:"final_resolved"`
	LiveHosts               int         `json:"live_hosts"`
	SelectedResolvers       int         `json:"selected_resolvers"`
	ResolversBenchSucceeded int         `json:"resolvers_bench_succeeded,omitempty"`
	Stages                  []StageStat `json:"stages"`
	ToolErrors              []ToolError `json:"tool_errors,omitempty"`
}

type ScoredRow struct {
	Name          string   `json:"name"`
	Sources       []string `json:"sources"`
	SourceCount   int      `json:"source_count"`
	Resolved      bool     `json:"resolved"`
	IPs           []string `json:"ips,omitempty"`
	ResolverVotes int      `json:"resolver_votes"`
	Wildcard      bool     `json:"wildcard"`
	Live          bool     `json:"live"`
	LiveURLs      []string `json:"live_urls,omitempty"`
	Confidence    float64  `json:"confidence"`
	Notes         []string `json:"notes,omitempty"`
	OpenPorts     []int    `json:"open_ports,omitempty"`
}

type ServiceRow struct {
	Host         string   `json:"host"`
	Port         int      `json:"port,omitempty"`
	URL          string   `json:"url,omitempty"`
	Scheme       string   `json:"scheme,omitempty"`
	StatusCode   int      `json:"status_code,omitempty"`
	Title        string   `json:"title,omitempty"`
	WebServer    string   `json:"webserver,omitempty"`
	Technologies []string `json:"technologies,omitempty"`
	CDN          string   `json:"cdn,omitempty"`
	ASN          string   `json:"asn,omitempty"`
	Source       string   `json:"source"`
}

type SurfaceRow struct {
	URL       string   `json:"url"`
	Host      string   `json:"host"`
	Path      string   `json:"path"`
	Category  string   `json:"category"`
	ParamKeys []string `json:"param_keys,omitempty"`
	HasParams bool     `json:"has_params"`
	Source    string   `json:"source"`
}

type ContentRow struct {
	URL        string `json:"url"`
	Host       string `json:"host"`
	Path       string `json:"path,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	Words      int    `json:"words,omitempty"`
	Length     int    `json:"length,omitempty"`
	Source     string `json:"source"`
}

type SecurityFinding struct {
	Target     string `json:"target,omitempty"`
	MatchedAt  string `json:"matched_at,omitempty"`
	TemplateID string `json:"template_id,omitempty"`
	Name       string `json:"name,omitempty"`
	Severity   string `json:"severity,omitempty"`
	Type       string `json:"type,omitempty"`
	Source     string `json:"source"`
}
