package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"ultrarecon/internal/config"
	"ultrarecon/internal/pipeline"
	"ultrarecon/internal/setup"
	"ultrarecon/internal/util"
)

func main() {
	cfg := config.Default()
	var installTools bool
	var installOptional bool
	var installTimeout time.Duration
	var modulesCSV string
	var runSetup bool
	var forceSetup bool

	flag.StringVar(&cfg.Domain, "d", "", "target domain (required)")
	flag.StringVar(&cfg.Domain, "domain", "", "target domain (required)")
	flag.StringVar(&cfg.Profile, "profile", cfg.Profile, "scan profile: speed|balanced|strict")
	flag.StringVar(&cfg.Phase, "phase", cfg.Phase, "run phase: all|subdomains|probe")
	flag.StringVar(&cfg.OutputDir, "o", cfg.OutputDir, "output directory")
	flag.StringVar(&cfg.OutputDir, "output", cfg.OutputDir, "output directory")
	flag.StringVar(&cfg.InputSubdomainsFile, "subdomains-in", cfg.InputSubdomainsFile, "input subdomain file (required for --phase probe unless resuming)")
	flag.BoolVar(&cfg.Resume, "resume", cfg.Resume, "resume from the latest saved checkpoint in the output directory")
	flag.StringVar(&cfg.ResumeFrom, "resume-from", cfg.ResumeFrom, "resume from a specific previously checkpointed stage")
	flag.StringVar(&cfg.ResolversFile, "resolvers", "", "custom resolvers file")
	flag.StringVar(&cfg.WordlistFile, "wordlist", "", "custom permutation wordlist")
	flag.StringVar(&cfg.BruteWordlistFile, "brute-wordlist", "", "custom bruteforce wordlist")
	flag.StringVar(&modulesCSV, "modules", "", "comma-separated modules to run (e.g. passive,noerror,dns-pivot,http-probe)")

	flag.DurationVar(&cfg.PassiveTimeout, "passive-timeout", cfg.PassiveTimeout, "passive collection timeout")
	flag.DurationVar(&cfg.ToolTimeout, "tool-timeout", cfg.ToolTimeout, "timeout per external tool/API collector")
	flag.DurationVar(&cfg.BruteTimeout, "brute-timeout", cfg.BruteTimeout, "bruteforce/enrichment external tool timeout")
	flag.DurationVar(&cfg.HTTPTimeout, "http-timeout", cfg.HTTPTimeout, "http probe timeout per request")
	flag.DurationVar(&cfg.DNSQueryTimeout, "dns-timeout", cfg.DNSQueryTimeout, "dns query timeout")
	flag.DurationVar(&cfg.ResolverFetchTimeout, "resolver-fetch-timeout", cfg.ResolverFetchTimeout, "timeout for downloading resolver lists")

	flag.IntVar(&cfg.DNSThreads, "dns-threads", cfg.DNSThreads, "dns worker count")
	flag.IntVar(&cfg.HTTPThreads, "http-threads", cfg.HTTPThreads, "http worker count")
	flag.IntVar(&cfg.DNSRateLimit, "dns-rate", cfg.DNSRateLimit, "dns tool rate limit for compatible tools")
	flag.IntVar(&cfg.MaxResolvers, "max-resolvers", cfg.MaxResolvers, "max resolvers kept after benchmark")
	flag.IntVar(&cfg.MaxResolverPool, "max-resolver-pool", cfg.MaxResolverPool, "max resolver pool size benchmarked before selection")
	flag.IntVar(&cfg.DNSConsensusMin, "dns-consensus", cfg.DNSConsensusMin, "minimum resolver confirmations")
	flag.IntVar(&cfg.DNSRetries, "dns-retries", cfg.DNSRetries, "retries per resolver query")
	flag.BoolVar(&cfg.EnableTrickestResolvers, "trickest-resolvers", cfg.EnableTrickestResolvers, "use Trickest public resolver lists when --resolvers is not provided")

	flag.IntVar(&cfg.WildcardTests, "wildcard-tests", cfg.WildcardTests, "random probes per parent wildcard check")
	flag.IntVar(&cfg.WildcardMinChildren, "wildcard-min-children", cfg.WildcardMinChildren, "minimum children before parent wildcard checks")
	flag.IntVar(&cfg.MaxWildcardParents, "wildcard-max-parents", cfg.MaxWildcardParents, "max parent domains to wildcard-test")
	flag.IntVar(&cfg.MaxPassivePerSource, "max-passive-source", cfg.MaxPassivePerSource, "max passive candidates accepted per source")
	flag.IntVar(&cfg.MaxPassiveCandidates, "max-passive-total", cfg.MaxPassiveCandidates, "max total passive candidates before active resolution")
	flag.IntVar(&cfg.MaxResolveQueue, "max-resolve-queue", cfg.MaxResolveQueue, "max hostnames queued for any DNS resolve stage")

	flag.BoolVar(&cfg.EnablePassive, "passive", cfg.EnablePassive, "enable passive collection stage")
	flag.BoolVar(&cfg.EnableBruteforce, "bruteforce", cfg.EnableBruteforce, "enable bruteforce expansion stage")
	flag.IntVar(&cfg.MaxBruteforceWords, "max-brute-words", cfg.MaxBruteforceWords, "max bruteforce words loaded/generated")
	flag.BoolVar(&cfg.EnableNoerror, "noerror", cfg.EnableNoerror, "enable NOERROR discovery stage")
	flag.IntVar(&cfg.MaxNoerrorWords, "max-noerror-words", cfg.MaxNoerrorWords, "max words used for NOERROR discovery")
	flag.BoolVar(&cfg.EnableDNSPivot, "dns-pivot", cfg.EnableDNSPivot, "enable DNS records pivot stage")
	flag.IntVar(&cfg.MaxDNSPivotHosts, "max-dns-pivot-hosts", cfg.MaxDNSPivotHosts, "max resolved hosts fed into DNS pivoting")
	flag.BoolVar(&cfg.EnableASNExpansion, "asn-expansion", cfg.EnableASNExpansion, "enable ASN/CIDR expansion stage")
	flag.IntVar(&cfg.MaxASNCIDRs, "max-asn-cidrs", cfg.MaxASNCIDRs, "max CIDR ranges retained from ASN discovery")
	flag.IntVar(&cfg.ASNIPsPerCIDR, "asn-ips-per-cidr", cfg.ASNIPsPerCIDR, "max sampled IPs per CIDR for PTR discovery")
	flag.IntVar(&cfg.MaxASNProbeIPs, "max-asn-probe-ips", cfg.MaxASNProbeIPs, "max total sampled IPs for ASN PTR probing")
	flag.IntVar(&cfg.MaxASNCandidates, "max-asn-candidates", cfg.MaxASNCandidates, "max ASN expansion candidates retained")
	flag.BoolVar(&cfg.EnableZoneTransfer, "zone-transfer", cfg.EnableZoneTransfer, "enable AXFR/zone transfer stage")
	flag.IntVar(&cfg.MaxZoneTransferHosts, "max-zone-transfer-hosts", cfg.MaxZoneTransferHosts, "max zone-transfer candidates retained")
	flag.BoolVar(&cfg.EnableRecursive, "recursive", cfg.EnableRecursive, "enable recursive passive expansion")
	flag.IntVar(&cfg.RecursiveTopSeeds, "recursive-top", cfg.RecursiveTopSeeds, "top seed subdomains used for recursive passive")
	flag.BoolVar(&cfg.EnableRecursiveBrute, "recursive-brute", cfg.EnableRecursiveBrute, "enable recursive bruteforce stage")
	flag.IntVar(&cfg.RecursiveBruteSeeds, "recursive-brute-seeds", cfg.RecursiveBruteSeeds, "max seed hosts for recursive bruteforce")
	flag.IntVar(&cfg.RecursiveBruteWords, "recursive-brute-words", cfg.RecursiveBruteWords, "max wordlist size for recursive bruteforce")
	flag.IntVar(&cfg.MaxRecursiveBrute, "max-recursive-brute", cfg.MaxRecursiveBrute, "max recursive bruteforce candidates retained")
	flag.BoolVar(&cfg.EnableCSPExtraction, "csp", cfg.EnableCSPExtraction, "enable CSP-based subdomain extraction")
	flag.BoolVar(&cfg.EnableArchiveSources, "archives", cfg.EnableArchiveSources, "enable wayback/gau archive extraction")
	flag.BoolVar(&cfg.EnableTLSEnumeration, "tls", cfg.EnableTLSEnumeration, "enable TLS SAN/CN extraction")
	flag.BoolVar(&cfg.EnableAnalyticsPivot, "analytics", cfg.EnableAnalyticsPivot, "enable analyticsrelationship pivot stage")
	flag.IntVar(&cfg.MaxAnalyticsInputs, "max-analytics-inputs", cfg.MaxAnalyticsInputs, "max host/url inputs for analytics pivot")
	flag.BoolVar(&cfg.EnableScrapingPivot, "scraping", cfg.EnableScrapingPivot, "enable web scraping pivot stage")
	flag.IntVar(&cfg.MaxScrapeInputs, "max-scrape-inputs", cfg.MaxScrapeInputs, "max live hosts/urls fed into scraping pivot")
	flag.IntVar(&cfg.MaxScrapeCandidates, "max-scrape-candidates", cfg.MaxScrapeCandidates, "max scraping candidates retained")
	flag.IntVar(&cfg.ScrapeDepth, "scrape-depth", cfg.ScrapeDepth, "max crawl depth for scraping tools")
	flag.IntVar(&cfg.MaxEnrichmentHosts, "max-enrich-hosts", cfg.MaxEnrichmentHosts, "max hosts fed into enrichment stages")

	flag.BoolVar(&cfg.EnablePermutations, "permutations", cfg.EnablePermutations, "enable adaptive permutation expansion")
	flag.IntVar(&cfg.MaxPermutations, "max-permutations", cfg.MaxPermutations, "max generated permutations")
	flag.IntVar(&cfg.PermutationTopLabels, "perm-top-labels", cfg.PermutationTopLabels, "max top labels used for permutations")
	flag.BoolVar(&cfg.EnableGotator, "gotator", cfg.EnableGotator, "enable gotator-based permutations")
	flag.IntVar(&cfg.GotatorDepth, "gotator-depth", cfg.GotatorDepth, "gotator permutation depth")
	flag.IntVar(&cfg.MaxGotatorInputs, "max-gotator-inputs", cfg.MaxGotatorInputs, "max resolved hosts fed into gotator")
	flag.IntVar(&cfg.MaxGotatorCandidates, "max-gotator-candidates", cfg.MaxGotatorCandidates, "max gotator candidates retained")
	flag.BoolVar(&cfg.EnableServiceDiscovery, "service-discovery", cfg.EnableServiceDiscovery, "enable host/service discovery (ports/http/tls)")
	flag.IntVar(&cfg.MaxServiceHosts, "max-service-hosts", cfg.MaxServiceHosts, "max resolved hosts fed into service discovery")
	flag.IntVar(&cfg.ServiceTopPorts, "service-top-ports", cfg.ServiceTopPorts, "top ports scanned for service discovery")
	flag.IntVar(&cfg.ServiceRate, "service-rate", cfg.ServiceRate, "naabu scan rate for service discovery")
	flag.IntVar(&cfg.MaxServiceRows, "max-service-rows", cfg.MaxServiceRows, "max service rows retained in output")
	flag.BoolVar(&cfg.EnableSurfaceMapping, "surface-mapping", cfg.EnableSurfaceMapping, "enable phase-3 web surface mapping")
	flag.IntVar(&cfg.MaxSurfaceInputs, "max-surface-inputs", cfg.MaxSurfaceInputs, "max live/resolved inputs fed into surface mapping")
	flag.IntVar(&cfg.MaxSurfaceURLs, "max-surface-urls", cfg.MaxSurfaceURLs, "max collected urls retained in surface mapping")
	flag.IntVar(&cfg.MaxSurfaceRows, "max-surface-rows", cfg.MaxSurfaceRows, "max surface endpoint rows retained")
	flag.BoolVar(&cfg.EnableJSAnalysis, "js-analysis", cfg.EnableJSAnalysis, "analyze discovered javascript files for extra endpoints and hosts")
	flag.IntVar(&cfg.MaxJSFiles, "max-js-files", cfg.MaxJSFiles, "max javascript files fetched for analysis")
	flag.IntVar(&cfg.MaxJSDiscoveries, "max-js-discoveries", cfg.MaxJSDiscoveries, "max urls/endpoints retained from javascript analysis")
	flag.BoolVar(&cfg.EnableContentDiscovery, "content-discovery", cfg.EnableContentDiscovery, "enable phase-4 content/parameter discovery")
	flag.IntVar(&cfg.MaxContentHosts, "max-content-hosts", cfg.MaxContentHosts, "max hosts scanned by content discovery")
	flag.IntVar(&cfg.MaxContentRows, "max-content-rows", cfg.MaxContentRows, "max content discovery rows retained")
	flag.IntVar(&cfg.MaxParamKeys, "max-param-keys", cfg.MaxParamKeys, "max parameter keys retained")
	flag.IntVar(&cfg.ContentRate, "content-rate", cfg.ContentRate, "request rate for content discovery tools")
	flag.BoolVar(&cfg.EnableSecurityChecks, "security-checks", cfg.EnableSecurityChecks, "enable phase-5 automated security checks")
	flag.IntVar(&cfg.MaxSecurityTargets, "max-security-targets", cfg.MaxSecurityTargets, "max targets fed into automated security checks")
	flag.IntVar(&cfg.MaxSecurityFindings, "max-security-findings", cfg.MaxSecurityFindings, "max automated security findings retained")
	flag.BoolVar(&cfg.EnableHTTPProbe, "http-probe", cfg.EnableHTTPProbe, "enable live http probing")
	flag.BoolVar(&cfg.EnableScreenshots, "screenshots", cfg.EnableScreenshots, "capture screenshots for final live subdomains")
	flag.IntVar(&cfg.MaxScreenshotTargets, "max-screenshot-targets", cfg.MaxScreenshotTargets, "max live urls captured in the screenshot stage")
	flag.IntVar(&cfg.ScreenshotConcurrency, "screenshot-concurrency", cfg.ScreenshotConcurrency, "parallel screenshot workers")
	flag.DurationVar(&cfg.ScreenshotTimeout, "screenshot-timeout", cfg.ScreenshotTimeout, "timeout per screenshot capture")
	flag.BoolVar(&cfg.StrictValidation, "strict", cfg.StrictValidation, "force stricter multi-resolver validation")
	flag.BoolVar(&cfg.EnableDiagnostics, "diagnostics", cfg.EnableDiagnostics, "print and save passive-source diagnostics")
	flag.BoolVar(&cfg.Verbose, "v", cfg.Verbose, "verbose console logs")
	flag.BoolVar(&cfg.Verbose, "verbose", cfg.Verbose, "verbose console logs")
	flag.BoolVar(&cfg.HomeSafe, "home-safe", cfg.HomeSafe, "enable conservative home-network safety limits")
	flag.BoolVar(&cfg.FinalOnly, "final-only", cfg.FinalOnly, "write clean final artifacts only")
	flag.BoolVar(&installTools, "install-tools", true, "auto-install missing dependencies")
	flag.BoolVar(&installOptional, "install-optional", true, "install optional tools for broader coverage")
	flag.BoolVar(&runSetup, "setup", true, "run first-time API/provider setup when no saved configuration exists")
	flag.BoolVar(&forceSetup, "setup-force", false, "rerun API/provider setup and overwrite the saved configuration")
	flag.DurationVar(&installTimeout, "install-timeout", 18*time.Minute, "timeout for each dependency install command")

	flag.Parse()
	if strings.TrimSpace(cfg.ResumeFrom) != "" {
		cfg.Resume = true
	}

	if cfg.Domain == "" {
		fmt.Fprintln(os.Stderr, "error: -d/--domain is required")
		flag.Usage()
		os.Exit(2)
	}
	cfg.Phase = normalizePhaseCLI(cfg.Phase)
	cfg.ApplyProfile()
	applyPhaseDefaults(&cfg)
	if err := applyModuleSelection(&cfg, modulesCSV); err != nil {
		fmt.Fprintf(os.Stderr, "invalid --modules: %v\n", err)
		os.Exit(2)
	}
	util.SetTrace(cfg.Verbose)
	if _, err := setup.EnsureFirstRun(runSetup, forceSetup, cfg.Verbose); err != nil {
		fmt.Fprintf(os.Stderr, "setup failed: %v\n", err)
		os.Exit(1)
	}
	if cfg.Verbose {
		fmt.Printf("[verbose] config phase=%s profile=%s home_safe=%v final_only=%v resume=%v resume_from=%s setup=%v setup_force=%v diagnostics=%v install_tools=%v install_optional=%v\n",
			cfg.Phase, cfg.Profile, cfg.HomeSafe, cfg.FinalOnly, cfg.Resume, cfg.ResumeFrom, runSetup, forceSetup, cfg.EnableDiagnostics, installTools, installOptional)
		fmt.Printf("[verbose] dns max_resolvers=%d max_pool=%d trickest=%v resolver_fetch_timeout=%s\n",
			cfg.MaxResolvers, cfg.MaxResolverPool, cfg.EnableTrickestResolvers, cfg.ResolverFetchTimeout)
		fmt.Printf("[verbose] modules passive=%v noerror=%v dns_pivot=%v asn=%v zone_transfer=%v brute=%v recursive=%v recursive_brute=%v enrichment=%v analytics=%v scraping=%v permutations=%v gotator=%v service=%v surface=%v js=%v content=%v security=%v http_probe=%v screenshots=%v\n",
			cfg.EnablePassive, cfg.EnableNoerror, cfg.EnableDNSPivot, cfg.EnableASNExpansion, cfg.EnableZoneTransfer,
			cfg.EnableBruteforce, cfg.EnableRecursive, cfg.EnableRecursiveBrute,
			(cfg.EnableCSPExtraction || cfg.EnableArchiveSources || cfg.EnableTLSEnumeration),
			cfg.EnableAnalyticsPivot, cfg.EnableScrapingPivot, cfg.EnablePermutations, cfg.EnableGotator, cfg.EnableServiceDiscovery,
			cfg.EnableSurfaceMapping, cfg.EnableJSAnalysis, cfg.EnableContentDiscovery, cfg.EnableSecurityChecks, cfg.EnableHTTPProbe, cfg.EnableScreenshots)
		fmt.Printf("[verbose] screenshots targets=%d concurrency=%d timeout=%s\n",
			cfg.MaxScreenshotTargets, cfg.ScreenshotConcurrency, cfg.ScreenshotTimeout)
	}

	if installTools {
		depRes := pipeline.EnsureDependencies(context.Background(), cfg, installOptional, installTimeout, cfg.Verbose)
		for _, f := range depRes.Failed {
			fmt.Fprintf(os.Stderr, "[bootstrap] %s failed: %s\n", f.Tool, f.Error)
		}
		if cfg.Verbose {
			if len(depRes.Installed) > 0 {
				fmt.Printf("[bootstrap] installed: %v\n", depRes.Installed)
			}
			if len(depRes.Skipped) > 0 {
				fmt.Printf("[bootstrap] skipped: %v\n", depRes.Skipped)
			}
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	start := time.Now()
	summary, err := pipeline.Execute(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ultrarecon failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("ultrarecon complete\n")
	fmt.Printf("domain: %s\n", summary.Domain)
	fmt.Printf("phase: %s\n", cfg.Phase)
	fmt.Printf("final_resolved: %d\n", summary.FinalResolved)
	fmt.Printf("live_hosts: %d\n", summary.LiveHosts)
	if cfg.EnableScreenshots {
		fmt.Printf("screenshots: %d/%d\n", summary.ScreenshotsCaptured, summary.ScreenshotTargets)
	}
	fmt.Printf("duration: %s\n", summary.Duration)
	fmt.Printf("output: %s\n", summary.OutputDir)
	fmt.Printf("host: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	_ = start
}

func applyPhaseDefaults(cfg *config.Config) {
	switch normalizePhaseCLI(cfg.Phase) {
	case "probe":
		cfg.EnablePassive = false
		cfg.EnableNoerror = false
		cfg.EnableDNSPivot = false
		cfg.EnableASNExpansion = false
		cfg.EnableZoneTransfer = false
		cfg.EnableBruteforce = false
		cfg.EnableRecursive = false
		cfg.EnableRecursiveBrute = false
		cfg.EnableCSPExtraction = false
		cfg.EnableArchiveSources = false
		cfg.EnableTLSEnumeration = false
		cfg.EnableAnalyticsPivot = false
		cfg.EnablePermutations = false
		cfg.EnableGotator = false
		cfg.EnableScrapingPivot = false
		cfg.EnableServiceDiscovery = true
		cfg.EnableSurfaceMapping = true
		cfg.EnableJSAnalysis = true
		cfg.EnableContentDiscovery = true
		cfg.EnableSecurityChecks = true
		cfg.EnableHTTPProbe = true
		cfg.EnableScreenshots = true
	}
}

func applyModuleSelection(cfg *config.Config, raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	set := make(map[string]struct{})
	for _, t := range strings.Split(raw, ",") {
		k := strings.ToLower(strings.TrimSpace(t))
		if k == "" {
			continue
		}
		set[k] = struct{}{}
	}
	if len(set) == 0 {
		return errors.New("empty module list")
	}

	// Reset first; then enable explicit modules only.
	cfg.EnablePassive = false
	cfg.EnableNoerror = false
	cfg.EnableDNSPivot = false
	cfg.EnableASNExpansion = false
	cfg.EnableZoneTransfer = false
	cfg.EnableBruteforce = false
	cfg.EnableRecursive = false
	cfg.EnableRecursiveBrute = false
	cfg.EnableCSPExtraction = false
	cfg.EnableArchiveSources = false
	cfg.EnableTLSEnumeration = false
	cfg.EnableAnalyticsPivot = false
	cfg.EnablePermutations = false
	cfg.EnableGotator = false
	cfg.EnableScrapingPivot = false
	cfg.EnableServiceDiscovery = false
	cfg.EnableSurfaceMapping = false
	cfg.EnableJSAnalysis = false
	cfg.EnableContentDiscovery = false
	cfg.EnableSecurityChecks = false
	cfg.EnableHTTPProbe = false
	cfg.EnableScreenshots = false

	phase := normalizePhaseCLI(cfg.Phase)
	for m := range set {
		switch m {
		case "all":
			if phase == "probe" {
				cfg.EnableServiceDiscovery = true
				cfg.EnableSurfaceMapping = true
				cfg.EnableJSAnalysis = true
				cfg.EnableContentDiscovery = true
				cfg.EnableSecurityChecks = true
				cfg.EnableHTTPProbe = true
				cfg.EnableScreenshots = true
			} else {
				cfg.EnablePassive = true
				cfg.EnableNoerror = true
				cfg.EnableDNSPivot = true
				cfg.EnableASNExpansion = true
				cfg.EnableZoneTransfer = true
				cfg.EnableBruteforce = true
				cfg.EnableRecursive = true
				cfg.EnableRecursiveBrute = true
				cfg.EnableCSPExtraction = true
				cfg.EnableArchiveSources = true
				cfg.EnableTLSEnumeration = true
				cfg.EnableAnalyticsPivot = true
				cfg.EnablePermutations = true
				cfg.EnableGotator = true
				cfg.EnableScrapingPivot = true
				cfg.EnableServiceDiscovery = true
				cfg.EnableSurfaceMapping = true
				cfg.EnableJSAnalysis = true
				cfg.EnableContentDiscovery = true
				cfg.EnableSecurityChecks = true
				cfg.EnableHTTPProbe = true
				cfg.EnableScreenshots = true
			}
		case "passive":
			if phase == "probe" {
				return fmt.Errorf("module %q is not valid in probe phase", m)
			}
			cfg.EnablePassive = true
		case "noerror":
			if phase == "probe" {
				return fmt.Errorf("module %q is not valid in probe phase", m)
			}
			cfg.EnableNoerror = true
		case "dns-pivot", "dnspivot":
			if phase == "probe" {
				return fmt.Errorf("module %q is not valid in probe phase", m)
			}
			cfg.EnableDNSPivot = true
		case "asn", "asn-cidr", "cidr", "asn-expansion":
			if phase == "probe" {
				return fmt.Errorf("module %q is not valid in probe phase", m)
			}
			cfg.EnableASNExpansion = true
		case "zone-transfer", "zonetransfer", "axfr":
			if phase == "probe" {
				return fmt.Errorf("module %q is not valid in probe phase", m)
			}
			cfg.EnableZoneTransfer = true
		case "bruteforce", "brute":
			if phase == "probe" {
				return fmt.Errorf("module %q is not valid in probe phase", m)
			}
			cfg.EnableBruteforce = true
		case "recursive":
			if phase == "probe" {
				return fmt.Errorf("module %q is not valid in probe phase", m)
			}
			cfg.EnableRecursive = true
		case "recursive-brute", "recursive_brute":
			if phase == "probe" {
				return fmt.Errorf("module %q is not valid in probe phase", m)
			}
			cfg.EnableRecursiveBrute = true
		case "enrichment", "enrich":
			if phase == "probe" {
				return fmt.Errorf("module %q is not valid in probe phase", m)
			}
			cfg.EnableCSPExtraction = true
			cfg.EnableArchiveSources = true
			cfg.EnableTLSEnumeration = true
		case "csp":
			if phase == "probe" {
				return fmt.Errorf("module %q is not valid in probe phase", m)
			}
			cfg.EnableCSPExtraction = true
		case "archives", "archive":
			if phase == "probe" {
				return fmt.Errorf("module %q is not valid in probe phase", m)
			}
			cfg.EnableArchiveSources = true
		case "tls":
			if phase == "probe" {
				return fmt.Errorf("module %q is not valid in probe phase", m)
			}
			cfg.EnableTLSEnumeration = true
		case "analytics":
			if phase == "probe" {
				return fmt.Errorf("module %q is not valid in probe phase", m)
			}
			cfg.EnableAnalyticsPivot = true
		case "scraping", "scrape":
			if phase == "probe" {
				return fmt.Errorf("module %q is not valid in probe phase", m)
			}
			cfg.EnableScrapingPivot = true
		case "permutations", "permute", "permutation":
			if phase == "probe" {
				return fmt.Errorf("module %q is not valid in probe phase", m)
			}
			cfg.EnablePermutations = true
		case "gotator":
			if phase == "probe" {
				return fmt.Errorf("module %q is not valid in probe phase", m)
			}
			cfg.EnableGotator = true
		case "service", "services", "service-discovery", "service_discovery":
			cfg.EnableServiceDiscovery = true
		case "surface", "surface-mapping", "surface_mapping", "web-surface", "web_surface":
			cfg.EnableSurfaceMapping = true
			cfg.EnableJSAnalysis = true
		case "js", "javascript", "js-analysis", "js_analysis":
			cfg.EnableSurfaceMapping = true
			cfg.EnableJSAnalysis = true
		case "content", "content-discovery", "content_discovery", "params", "fuzz":
			cfg.EnableContentDiscovery = true
		case "security", "security-checks", "security_checks", "vuln", "vulns":
			cfg.EnableSecurityChecks = true
		case "http-probe", "probe", "live":
			cfg.EnableHTTPProbe = true
		case "screenshot", "screenshots", "visual":
			cfg.EnableScreenshots = true
		default:
			return fmt.Errorf("unknown module %q", m)
		}
	}

	return nil
}

func normalizePhaseCLI(v string) string {
	p := strings.ToLower(strings.TrimSpace(v))
	switch p {
	case "", "all":
		return "all"
	case "sub", "subs", "subdomains", "enum", "enumeration":
		return "subdomains"
	case "probe", "http", "live":
		return "probe"
	default:
		return p
	}
}
