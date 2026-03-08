package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Config controls ultrarecon scan behavior.
type Config struct {
	Profile                 string
	Phase                   string
	HomeSafe                bool
	FinalOnly               bool
	Resume                  bool
	ResumeFrom              string
	Domain                  string
	OutputDir               string
	InputSubdomainsFile     string
	ResolversFile           string
	WordlistFile            string
	BruteWordlistFile       string
	PassiveTimeout          time.Duration
	ToolTimeout             time.Duration
	BruteTimeout            time.Duration
	HTTPTimeout             time.Duration
	DNSQueryTimeout         time.Duration
	ResolverFetchTimeout    time.Duration
	DNSThreads              int
	HTTPThreads             int
	DNSRateLimit            int
	MaxResolvers            int
	MaxResolverPool         int
	DNSConsensusMin         int
	DNSRetries              int
	EnableTrickestResolvers bool
	WildcardTests           int
	WildcardMinChildren     int
	MaxWildcardParents      int
	EnablePassive           bool
	EnableBruteforce        bool
	MaxBruteforceWords      int
	EnableNoerror           bool
	MaxNoerrorWords         int
	EnableDNSPivot          bool
	MaxDNSPivotHosts        int
	EnableASNExpansion      bool
	MaxASNCIDRs             int
	ASNIPsPerCIDR           int
	MaxASNProbeIPs          int
	MaxASNCandidates        int
	EnableZoneTransfer      bool
	MaxZoneTransferHosts    int
	EnableRecursive         bool
	RecursiveTopSeeds       int
	EnableRecursiveBrute    bool
	RecursiveBruteSeeds     int
	RecursiveBruteWords     int
	MaxRecursiveBrute       int
	EnableCSPExtraction     bool
	EnableArchiveSources    bool
	EnableTLSEnumeration    bool
	EnableAnalyticsPivot    bool
	MaxAnalyticsInputs      int
	EnableScrapingPivot     bool
	MaxScrapeInputs         int
	MaxScrapeCandidates     int
	ScrapeDepth             int
	MaxEnrichmentHosts      int
	EnablePermutations      bool
	EnableGotator           bool
	EnableServiceDiscovery  bool
	EnableSurfaceMapping    bool
	EnableJSAnalysis        bool
	EnableContentDiscovery  bool
	EnableSecurityChecks    bool
	EnableHTTPProbe         bool
	EnableScreenshots       bool
	MaxPermutations         int
	PermutationTopLabels    int
	GotatorDepth            int
	MaxGotatorInputs        int
	MaxGotatorCandidates    int
	MaxServiceHosts         int
	ServiceTopPorts         int
	ServiceRate             int
	MaxServiceRows          int
	MaxSurfaceInputs        int
	MaxSurfaceURLs          int
	MaxSurfaceRows          int
	MaxJSFiles              int
	MaxJSDiscoveries        int
	MaxContentHosts         int
	MaxContentRows          int
	MaxParamKeys            int
	ContentRate             int
	MaxSecurityTargets      int
	MaxSecurityFindings     int
	MaxScreenshotTargets    int
	ScreenshotConcurrency   int
	ScreenshotTimeout       time.Duration
	MaxPassivePerSource     int
	MaxPassiveCandidates    int
	MaxResolveQueue         int
	StrictValidation        bool
	EnableDiagnostics       bool
	Verbose                 bool
}

// Default returns a tuned baseline for speed+accuracy balance.
func Default() Config {
	cpus := runtime.NumCPU()
	dnsThreads := cpus * 80
	httpThreads := cpus * 40
	if dnsThreads < 200 {
		dnsThreads = 200
	}
	if httpThreads < 100 {
		httpThreads = 100
	}
	if dnsThreads > 1200 {
		dnsThreads = 1200
	}
	if httpThreads > 600 {
		httpThreads = 600
	}

	return Config{
		Profile:                 "balanced",
		Phase:                   "all",
		HomeSafe:                true,
		FinalOnly:               true,
		Resume:                  false,
		ResumeFrom:              "",
		OutputDir:               "output_ultra",
		PassiveTimeout:          5 * time.Minute,
		ToolTimeout:             4 * time.Minute,
		BruteTimeout:            6 * time.Minute,
		HTTPTimeout:             8 * time.Second,
		DNSQueryTimeout:         2 * time.Second,
		ResolverFetchTimeout:    35 * time.Second,
		DNSThreads:              dnsThreads,
		HTTPThreads:             httpThreads,
		DNSRateLimit:            1200,
		MaxResolvers:            64,
		MaxResolverPool:         1600,
		DNSConsensusMin:         1,
		DNSRetries:              2,
		EnableTrickestResolvers: true,
		WildcardTests:           3,
		WildcardMinChildren:     2,
		MaxWildcardParents:      400,
		EnablePassive:           true,
		EnableBruteforce:        true,
		MaxBruteforceWords:      2500,
		EnableNoerror:           true,
		MaxNoerrorWords:         1400,
		EnableDNSPivot:          true,
		MaxDNSPivotHosts:        3000,
		EnableASNExpansion:      true,
		MaxASNCIDRs:             40,
		ASNIPsPerCIDR:           24,
		MaxASNProbeIPs:          800,
		MaxASNCandidates:        6000,
		EnableZoneTransfer:      true,
		MaxZoneTransferHosts:    20000,
		EnableRecursive:         true,
		RecursiveTopSeeds:       15,
		EnableRecursiveBrute:    true,
		RecursiveBruteSeeds:     8,
		RecursiveBruteWords:     450,
		MaxRecursiveBrute:       12000,
		EnableCSPExtraction:     true,
		EnableArchiveSources:    true,
		EnableTLSEnumeration:    true,
		EnableAnalyticsPivot:    true,
		MaxAnalyticsInputs:      900,
		EnableScrapingPivot:     true,
		MaxScrapeInputs:         450,
		MaxScrapeCandidates:     18000,
		ScrapeDepth:             2,
		MaxEnrichmentHosts:      15000,
		EnablePermutations:      true,
		EnableGotator:           true,
		EnableServiceDiscovery:  true,
		EnableSurfaceMapping:    true,
		EnableJSAnalysis:        true,
		EnableContentDiscovery:  true,
		EnableSecurityChecks:    true,
		EnableHTTPProbe:         true,
		EnableScreenshots:       true,
		MaxPermutations:         220000,
		PermutationTopLabels:    220,
		GotatorDepth:            1,
		MaxGotatorInputs:        1400,
		MaxGotatorCandidates:    100000,
		MaxServiceHosts:         2200,
		ServiceTopPorts:         120,
		ServiceRate:             1600,
		MaxServiceRows:          80000,
		MaxSurfaceInputs:        600,
		MaxSurfaceURLs:          80000,
		MaxSurfaceRows:          60000,
		MaxJSFiles:              80,
		MaxJSDiscoveries:        5000,
		MaxContentHosts:         80,
		MaxContentRows:          12000,
		MaxParamKeys:            2000,
		ContentRate:             220,
		MaxSecurityTargets:      1200,
		MaxSecurityFindings:     5000,
		MaxScreenshotTargets:    120,
		ScreenshotConcurrency:   4,
		ScreenshotTimeout:       18 * time.Second,
		MaxPassivePerSource:     6000,
		MaxPassiveCandidates:    25000,
		MaxResolveQueue:         20000,
		StrictValidation:        false,
		EnableDiagnostics:       false,
		Verbose:                 false,
	}
}

// ApplyProfile adjusts settings for a chosen runtime profile.
func (c *Config) ApplyProfile() {
	switch strings.ToLower(strings.TrimSpace(c.Profile)) {
	case "speed":
		c.DNSThreads = maxInt(c.DNSThreads, 700)
		c.HTTPThreads = maxInt(c.HTTPThreads, 400)
		c.DNSRateLimit = maxInt(c.DNSRateLimit, 2500)
		c.MaxResolverPool = maxInt(c.MaxResolverPool, 2600)
		c.DNSConsensusMin = 1
		c.WildcardTests = 2
		c.StrictValidation = false
		c.MaxBruteforceWords = maxInt(c.MaxBruteforceWords, 3500)
		c.MaxNoerrorWords = maxInt(c.MaxNoerrorWords, 2200)
		c.MaxDNSPivotHosts = maxInt(c.MaxDNSPivotHosts, 5000)
		c.MaxASNCIDRs = maxInt(c.MaxASNCIDRs, 70)
		c.ASNIPsPerCIDR = maxInt(c.ASNIPsPerCIDR, 40)
		c.MaxASNProbeIPs = maxInt(c.MaxASNProbeIPs, 1800)
		c.MaxASNCandidates = maxInt(c.MaxASNCandidates, 12000)
		c.MaxZoneTransferHosts = maxInt(c.MaxZoneTransferHosts, 30000)
		c.RecursiveTopSeeds = maxInt(c.RecursiveTopSeeds, 20)
		c.RecursiveBruteSeeds = maxInt(c.RecursiveBruteSeeds, 12)
		c.RecursiveBruteWords = maxInt(c.RecursiveBruteWords, 700)
		c.MaxRecursiveBrute = maxInt(c.MaxRecursiveBrute, 18000)
		c.MaxAnalyticsInputs = maxInt(c.MaxAnalyticsInputs, 1200)
		c.MaxScrapeInputs = maxInt(c.MaxScrapeInputs, 700)
		c.MaxScrapeCandidates = maxInt(c.MaxScrapeCandidates, 26000)
		c.ScrapeDepth = maxInt(c.ScrapeDepth, 2)
		c.MaxEnrichmentHosts = maxInt(c.MaxEnrichmentHosts, 22000)
		c.MaxPermutations = minInt(maxInt(c.MaxPermutations, 250000), 350000)
		c.MaxGotatorInputs = maxInt(c.MaxGotatorInputs, 2200)
		c.MaxGotatorCandidates = minInt(maxInt(c.MaxGotatorCandidates, 140000), 260000)
		c.GotatorDepth = minInt(maxInt(c.GotatorDepth, 1), 2)
		c.MaxServiceHosts = maxInt(c.MaxServiceHosts, 3200)
		c.ServiceTopPorts = maxInt(c.ServiceTopPorts, 140)
		c.ServiceRate = maxInt(c.ServiceRate, 3000)
		c.MaxServiceRows = maxInt(c.MaxServiceRows, 120000)
		c.MaxSurfaceInputs = maxInt(c.MaxSurfaceInputs, 1000)
		c.MaxSurfaceURLs = maxInt(c.MaxSurfaceURLs, 140000)
		c.MaxSurfaceRows = maxInt(c.MaxSurfaceRows, 100000)
		c.MaxJSFiles = maxInt(c.MaxJSFiles, 120)
		c.MaxJSDiscoveries = maxInt(c.MaxJSDiscoveries, 9000)
		c.MaxContentHosts = maxInt(c.MaxContentHosts, 140)
		c.MaxContentRows = maxInt(c.MaxContentRows, 22000)
		c.MaxParamKeys = maxInt(c.MaxParamKeys, 3500)
		c.ContentRate = maxInt(c.ContentRate, 500)
		c.MaxSecurityTargets = maxInt(c.MaxSecurityTargets, 2200)
		c.MaxSecurityFindings = maxInt(c.MaxSecurityFindings, 9000)
		c.MaxScreenshotTargets = maxInt(c.MaxScreenshotTargets, 240)
		c.ScreenshotConcurrency = maxInt(c.ScreenshotConcurrency, 6)
	case "strict":
		c.DNSThreads = minInt(c.DNSThreads, 500)
		c.HTTPThreads = minInt(c.HTTPThreads, 250)
		c.DNSRateLimit = minInt(c.DNSRateLimit, 1200)
		c.MaxResolverPool = minInt(c.MaxResolverPool, 900)
		c.DNSConsensusMin = maxInt(c.DNSConsensusMin, 2)
		c.WildcardTests = maxInt(c.WildcardTests, 4)
		c.StrictValidation = true
		c.MaxBruteforceWords = minInt(c.MaxBruteforceWords, 1800)
		c.MaxNoerrorWords = minInt(c.MaxNoerrorWords, 1000)
		c.MaxDNSPivotHosts = minInt(c.MaxDNSPivotHosts, 2500)
		c.MaxASNCIDRs = minInt(c.MaxASNCIDRs, 30)
		c.ASNIPsPerCIDR = minInt(c.ASNIPsPerCIDR, 18)
		c.MaxASNProbeIPs = minInt(c.MaxASNProbeIPs, 600)
		c.MaxASNCandidates = minInt(c.MaxASNCandidates, 4500)
		c.MaxZoneTransferHosts = minInt(c.MaxZoneTransferHosts, 12000)
		c.RecursiveTopSeeds = minInt(c.RecursiveTopSeeds, 10)
		c.RecursiveBruteSeeds = minInt(c.RecursiveBruteSeeds, 6)
		c.RecursiveBruteWords = minInt(c.RecursiveBruteWords, 350)
		c.MaxRecursiveBrute = minInt(c.MaxRecursiveBrute, 8000)
		c.MaxAnalyticsInputs = minInt(c.MaxAnalyticsInputs, 700)
		c.MaxScrapeInputs = minInt(c.MaxScrapeInputs, 300)
		c.MaxScrapeCandidates = minInt(c.MaxScrapeCandidates, 12000)
		c.ScrapeDepth = minInt(c.ScrapeDepth, 2)
		c.MaxEnrichmentHosts = minInt(c.MaxEnrichmentHosts, 10000)
		c.MaxPermutations = minInt(c.MaxPermutations, 150000)
		c.MaxGotatorInputs = minInt(c.MaxGotatorInputs, 900)
		c.MaxGotatorCandidates = minInt(c.MaxGotatorCandidates, 70000)
		c.GotatorDepth = minInt(maxInt(c.GotatorDepth, 1), 2)
		c.MaxServiceHosts = minInt(c.MaxServiceHosts, 1400)
		c.ServiceTopPorts = minInt(c.ServiceTopPorts, 80)
		c.ServiceRate = minInt(c.ServiceRate, 900)
		c.MaxServiceRows = minInt(c.MaxServiceRows, 45000)
		c.MaxSurfaceInputs = minInt(c.MaxSurfaceInputs, 400)
		c.MaxSurfaceURLs = minInt(c.MaxSurfaceURLs, 60000)
		c.MaxSurfaceRows = minInt(c.MaxSurfaceRows, 45000)
		c.MaxJSFiles = minInt(c.MaxJSFiles, 40)
		c.MaxJSDiscoveries = minInt(c.MaxJSDiscoveries, 2000)
		c.MaxContentHosts = minInt(c.MaxContentHosts, 60)
		c.MaxContentRows = minInt(c.MaxContentRows, 7000)
		c.MaxParamKeys = minInt(c.MaxParamKeys, 1400)
		c.ContentRate = minInt(c.ContentRate, 160)
		c.MaxSecurityTargets = minInt(c.MaxSecurityTargets, 900)
		c.MaxSecurityFindings = minInt(c.MaxSecurityFindings, 3000)
		c.MaxScreenshotTargets = minInt(c.MaxScreenshotTargets, 100)
		c.ScreenshotConcurrency = minInt(c.ScreenshotConcurrency, 3)
	default:
		// balanced
	}

	if c.HomeSafe {
		c.DNSThreads = minInt(c.DNSThreads, 280)
		c.HTTPThreads = minInt(c.HTTPThreads, 180)
		c.DNSRateLimit = minInt(c.DNSRateLimit, 700)
		c.MaxResolverPool = minInt(c.MaxResolverPool, 300)
		c.DNSRetries = minInt(c.DNSRetries, 1)
		if c.DNSQueryTimeout > 1500*time.Millisecond {
			c.DNSQueryTimeout = 1500 * time.Millisecond
		}
		if c.ResolverFetchTimeout > 20*time.Second {
			c.ResolverFetchTimeout = 20 * time.Second
		}
		c.MaxPassivePerSource = minInt(c.MaxPassivePerSource, 1800)
		c.MaxPassiveCandidates = minInt(c.MaxPassiveCandidates, 5000)
		c.MaxResolveQueue = minInt(c.MaxResolveQueue, 2500)
		c.MaxBruteforceWords = minInt(c.MaxBruteforceWords, 1500)
		c.MaxNoerrorWords = minInt(c.MaxNoerrorWords, 700)
		c.MaxDNSPivotHosts = minInt(c.MaxDNSPivotHosts, 1200)
		c.MaxASNCIDRs = minInt(c.MaxASNCIDRs, 20)
		c.ASNIPsPerCIDR = minInt(c.ASNIPsPerCIDR, 10)
		c.MaxASNProbeIPs = minInt(c.MaxASNProbeIPs, 250)
		c.MaxASNCandidates = minInt(c.MaxASNCandidates, 2200)
		c.MaxZoneTransferHosts = minInt(c.MaxZoneTransferHosts, 6000)
		c.RecursiveBruteSeeds = minInt(c.RecursiveBruteSeeds, 4)
		c.RecursiveBruteWords = minInt(c.RecursiveBruteWords, 220)
		c.MaxRecursiveBrute = minInt(c.MaxRecursiveBrute, 3500)
		c.MaxAnalyticsInputs = minInt(c.MaxAnalyticsInputs, 300)
		c.MaxScrapeInputs = minInt(c.MaxScrapeInputs, 120)
		c.MaxScrapeCandidates = minInt(c.MaxScrapeCandidates, 4500)
		c.ScrapeDepth = minInt(c.ScrapeDepth, 1)
		c.MaxPermutations = minInt(c.MaxPermutations, 90000)
		c.MaxGotatorInputs = minInt(c.MaxGotatorInputs, 450)
		c.MaxGotatorCandidates = minInt(c.MaxGotatorCandidates, 25000)
		c.GotatorDepth = 1
		c.MaxServiceHosts = minInt(c.MaxServiceHosts, 380)
		c.ServiceTopPorts = minInt(c.ServiceTopPorts, 40)
		c.ServiceRate = minInt(c.ServiceRate, 220)
		c.MaxServiceRows = minInt(c.MaxServiceRows, 12000)
		c.MaxSurfaceInputs = minInt(c.MaxSurfaceInputs, 140)
		c.MaxSurfaceURLs = minInt(c.MaxSurfaceURLs, 22000)
		c.MaxSurfaceRows = minInt(c.MaxSurfaceRows, 15000)
		c.MaxJSFiles = minInt(c.MaxJSFiles, 24)
		c.MaxJSDiscoveries = minInt(c.MaxJSDiscoveries, 800)
		c.MaxContentHosts = minInt(c.MaxContentHosts, 24)
		c.MaxContentRows = minInt(c.MaxContentRows, 2500)
		c.MaxParamKeys = minInt(c.MaxParamKeys, 600)
		c.ContentRate = minInt(c.ContentRate, 80)
		c.MaxSecurityTargets = minInt(c.MaxSecurityTargets, 300)
		c.MaxSecurityFindings = minInt(c.MaxSecurityFindings, 1200)
		c.MaxScreenshotTargets = minInt(c.MaxScreenshotTargets, 60)
		c.ScreenshotConcurrency = minInt(c.ScreenshotConcurrency, 2)
	}
}

// Normalize validates and finalizes derived config values.
func (c *Config) Normalize() error {
	rawPhase := c.Phase
	c.Phase = normalizePhase(c.Phase)
	if c.Phase == "" {
		return fmt.Errorf("invalid phase %q (supported: all, subdomains, probe)", rawPhase)
	}

	c.Domain = strings.ToLower(strings.TrimSpace(c.Domain))
	c.Domain = strings.TrimSuffix(c.Domain, ".")
	if err := validateDomain(c.Domain); err != nil {
		return err
	}
	c.ResumeFrom = strings.TrimSpace(c.ResumeFrom)
	if c.ResumeFrom != "" {
		c.Resume = true
	}

	if strings.TrimSpace(c.OutputDir) == "" {
		return errors.New("output directory cannot be empty")
	}

	absOut, err := filepath.Abs(c.OutputDir)
	if err != nil {
		return fmt.Errorf("resolve output dir: %w", err)
	}
	c.OutputDir = absOut

	if strings.TrimSpace(c.InputSubdomainsFile) != "" {
		absIn, err := filepath.Abs(c.InputSubdomainsFile)
		if err != nil {
			return fmt.Errorf("resolve subdomains input: %w", err)
		}
		c.InputSubdomainsFile = absIn
	}

	if c.DNSThreads < 1 {
		c.DNSThreads = 1
	}
	if c.HTTPThreads < 1 {
		c.HTTPThreads = 1
	}
	if c.MaxResolvers < 4 {
		c.MaxResolvers = 4
	}
	if c.MaxResolverPool < c.MaxResolvers {
		c.MaxResolverPool = c.MaxResolvers
	}
	if c.ResolverFetchTimeout < 5*time.Second {
		c.ResolverFetchTimeout = 5 * time.Second
	}
	if c.DNSRateLimit < 50 {
		c.DNSRateLimit = 50
	}
	if c.DNSConsensusMin < 1 {
		c.DNSConsensusMin = 1
	}
	if c.DNSConsensusMin > 3 {
		c.DNSConsensusMin = 3
	}
	if c.DNSRetries < 0 {
		c.DNSRetries = 0
	}
	if c.WildcardTests < 1 {
		c.WildcardTests = 1
	}
	if c.WildcardMinChildren < 1 {
		c.WildcardMinChildren = 1
	}
	if c.MaxWildcardParents < 1 {
		c.MaxWildcardParents = 1
	}
	if c.MaxBruteforceWords < 1 {
		c.MaxBruteforceWords = 1
	}
	if c.MaxNoerrorWords < 1 {
		c.MaxNoerrorWords = 1
	}
	if c.MaxDNSPivotHosts < 1 {
		c.MaxDNSPivotHosts = 1
	}
	if c.MaxASNCIDRs < 1 {
		c.MaxASNCIDRs = 1
	}
	if c.ASNIPsPerCIDR < 1 {
		c.ASNIPsPerCIDR = 1
	}
	if c.MaxASNProbeIPs < 1 {
		c.MaxASNProbeIPs = 1
	}
	if c.MaxASNCandidates < 1 {
		c.MaxASNCandidates = 1
	}
	if c.MaxZoneTransferHosts < 1 {
		c.MaxZoneTransferHosts = 1
	}
	if c.RecursiveTopSeeds < 1 {
		c.RecursiveTopSeeds = 1
	}
	if c.RecursiveBruteSeeds < 1 {
		c.RecursiveBruteSeeds = 1
	}
	if c.RecursiveBruteWords < 1 {
		c.RecursiveBruteWords = 1
	}
	if c.MaxRecursiveBrute < 1 {
		c.MaxRecursiveBrute = 1
	}
	if c.MaxAnalyticsInputs < 1 {
		c.MaxAnalyticsInputs = 1
	}
	if c.MaxScrapeInputs < 1 {
		c.MaxScrapeInputs = 1
	}
	if c.MaxScrapeCandidates < 1 {
		c.MaxScrapeCandidates = 1
	}
	if c.ScrapeDepth < 1 {
		c.ScrapeDepth = 1
	}
	if c.MaxEnrichmentHosts < 1 {
		c.MaxEnrichmentHosts = 1
	}
	if c.MaxPermutations < 0 {
		c.MaxPermutations = 0
	}
	if c.PermutationTopLabels < 1 {
		c.PermutationTopLabels = 1
	}
	if c.GotatorDepth < 1 {
		c.GotatorDepth = 1
	}
	if c.GotatorDepth > 3 {
		c.GotatorDepth = 3
	}
	if c.MaxGotatorInputs < 1 {
		c.MaxGotatorInputs = 1
	}
	if c.MaxGotatorCandidates < 1 {
		c.MaxGotatorCandidates = 1
	}
	if c.MaxServiceHosts < 1 {
		c.MaxServiceHosts = 1
	}
	if c.ServiceTopPorts < 1 {
		c.ServiceTopPorts = 1
	}
	if c.ServiceTopPorts > 1000 {
		c.ServiceTopPorts = 1000
	}
	if c.ServiceRate < 10 {
		c.ServiceRate = 10
	}
	if c.MaxServiceRows < 1 {
		c.MaxServiceRows = 1
	}
	if c.MaxSurfaceInputs < 1 {
		c.MaxSurfaceInputs = 1
	}
	if c.MaxSurfaceURLs < 1 {
		c.MaxSurfaceURLs = 1
	}
	if c.MaxSurfaceRows < 1 {
		c.MaxSurfaceRows = 1
	}
	if c.MaxJSFiles < 1 {
		c.MaxJSFiles = 1
	}
	if c.MaxJSDiscoveries < 1 {
		c.MaxJSDiscoveries = 1
	}
	if c.MaxContentHosts < 1 {
		c.MaxContentHosts = 1
	}
	if c.MaxContentRows < 1 {
		c.MaxContentRows = 1
	}
	if c.MaxParamKeys < 1 {
		c.MaxParamKeys = 1
	}
	if c.ContentRate < 10 {
		c.ContentRate = 10
	}
	if c.MaxSecurityTargets < 1 {
		c.MaxSecurityTargets = 1
	}
	if c.MaxSecurityFindings < 1 {
		c.MaxSecurityFindings = 1
	}
	if c.MaxScreenshotTargets < 1 {
		c.MaxScreenshotTargets = 1
	}
	if c.ScreenshotConcurrency < 1 {
		c.ScreenshotConcurrency = 1
	}
	if c.ScreenshotConcurrency > 16 {
		c.ScreenshotConcurrency = 16
	}
	if c.ScreenshotTimeout < 5*time.Second {
		c.ScreenshotTimeout = 5 * time.Second
	}
	if c.MaxPassivePerSource < 100 {
		c.MaxPassivePerSource = 100
	}
	if c.MaxPassiveCandidates < 100 {
		c.MaxPassiveCandidates = 100
	}
	if c.MaxResolveQueue < 100 {
		c.MaxResolveQueue = 100
	}

	if c.ResolversFile != "" {
		if _, err := os.Stat(c.ResolversFile); err != nil {
			return fmt.Errorf("resolvers file %q not accessible: %w", c.ResolversFile, err)
		}
	}
	if c.InputSubdomainsFile != "" {
		if _, err := os.Stat(c.InputSubdomainsFile); err != nil {
			return fmt.Errorf("subdomains input file %q not accessible: %w", c.InputSubdomainsFile, err)
		}
	}
	if c.Phase == "probe" && strings.TrimSpace(c.InputSubdomainsFile) == "" && !c.Resume {
		return errors.New("phase probe requires --subdomains-in file")
	}
	if c.WordlistFile != "" {
		if _, err := os.Stat(c.WordlistFile); err != nil {
			return fmt.Errorf("wordlist file %q not accessible: %w", c.WordlistFile, err)
		}
	}
	if c.BruteWordlistFile != "" {
		if _, err := os.Stat(c.BruteWordlistFile); err != nil {
			return fmt.Errorf("brute wordlist file %q not accessible: %w", c.BruteWordlistFile, err)
		}
	}
	if err := os.MkdirAll(c.OutputDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	return nil
}

func validateDomain(d string) error {
	if d == "" {
		return errors.New("domain is required")
	}
	if strings.ContainsAny(d, " /\\:@") {
		return fmt.Errorf("invalid domain: %q", d)
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return fmt.Errorf("invalid domain %q: expected fqdn", d)
	}
	for _, label := range labels {
		if label == "" {
			return fmt.Errorf("invalid domain %q: empty label", d)
		}
		if len(label) > 63 {
			return fmt.Errorf("invalid domain %q: label too long", d)
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("invalid domain %q: label edge hyphen", d)
		}
		for _, ch := range label {
			if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' {
				continue
			}
			return fmt.Errorf("invalid domain %q: bad character %q", d, ch)
		}
	}
	return nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func normalizePhase(v string) string {
	p := strings.ToLower(strings.TrimSpace(v))
	switch p {
	case "", "all":
		return "all"
	case "sub", "subs", "subdomains", "enum", "enumeration":
		return "subdomains"
	case "probe", "http", "live":
		return "probe"
	default:
		return ""
	}
}
