package pipeline

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"ultrarecon/internal/config"
	"ultrarecon/internal/util"
)

func Execute(ctx context.Context, cfg config.Config) (*Summary, error) {
	if err := cfg.Normalize(); err != nil {
		return nil, err
	}
	if cfg.Phase != "probe" && !hasAnySubdomainModuleEnabled(cfg) {
		return nil, fmt.Errorf("no subdomain modules enabled; use --modules or enable individual stages")
	}

	started := time.Now().UTC()
	summary := &Summary{
		Domain:    cfg.Domain,
		Phase:     cfg.Phase,
		FinalOnly: cfg.FinalOnly,
		OutputDir: cfg.OutputDir,
		StartedAt: started,
	}

	store := NewSafeStore()
	var toolErrs []ToolError
	var passiveHosts []string
	var noerrorHosts []string
	var dnsPivotHosts []string
	var asnHosts []string
	var zoneTransferHosts []string
	var bruteHosts []string
	var recursiveHosts []string
	var recursiveBruteHosts []string
	var enrichmentHosts []string
	var analyticsHosts []string
	var scrapingHosts []string
	var permutations []string
	var gotatorHosts []string
	var serviceRows []ServiceRow
	var surfaceRows []SurfaceRow
	var contentRows []ContentRow
	var paramKeys []string
	var securityFindings []SecurityFinding
	var resolvers []dnsResolver

	checkpoint, err := loadResumeCheckpoint(cfg)
	if err != nil {
		return nil, err
	}
	appendLog := false
	completedStages := make(map[string]struct{})
	if checkpoint != nil {
		appendLog = true
		loadedSummary := checkpoint.Summary
		summary = &loadedSummary
		if summary.OutputDir == "" {
			summary.OutputDir = cfg.OutputDir
		}
		if summary.StartedAt.IsZero() {
			summary.StartedAt = started
		} else {
			started = summary.StartedAt
		}
		store = restoreCheckpointStore(checkpoint.Store)
		toolErrs = append([]ToolError(nil), checkpoint.ToolErrors...)
		passiveHosts = append([]string(nil), checkpoint.Artifacts.PassiveHosts...)
		noerrorHosts = append([]string(nil), checkpoint.Artifacts.NoerrorHosts...)
		dnsPivotHosts = append([]string(nil), checkpoint.Artifacts.DNSPivotHosts...)
		asnHosts = append([]string(nil), checkpoint.Artifacts.ASNHosts...)
		zoneTransferHosts = append([]string(nil), checkpoint.Artifacts.ZoneTransferHosts...)
		bruteHosts = append([]string(nil), checkpoint.Artifacts.BruteHosts...)
		recursiveHosts = append([]string(nil), checkpoint.Artifacts.RecursiveHosts...)
		recursiveBruteHosts = append([]string(nil), checkpoint.Artifacts.RecursiveBruteHosts...)
		enrichmentHosts = append([]string(nil), checkpoint.Artifacts.EnrichmentHosts...)
		analyticsHosts = append([]string(nil), checkpoint.Artifacts.AnalyticsHosts...)
		scrapingHosts = append([]string(nil), checkpoint.Artifacts.ScrapingHosts...)
		permutations = append([]string(nil), checkpoint.Artifacts.Permutations...)
		gotatorHosts = append([]string(nil), checkpoint.Artifacts.GotatorHosts...)
		serviceRows = append([]ServiceRow(nil), checkpoint.Artifacts.ServiceRows...)
		surfaceRows = append([]SurfaceRow(nil), checkpoint.Artifacts.SurfaceRows...)
		contentRows = append([]ContentRow(nil), checkpoint.Artifacts.ContentRows...)
		paramKeys = append([]string(nil), checkpoint.Artifacts.ParamKeys...)
		securityFindings = append([]SecurityFinding(nil), checkpoint.Artifacts.SecurityFindings...)
		resolvers = restoreCheckpointResolvers(checkpoint.Resolvers)
		completedStages = checkpointCompletedStages(summary)
	}

	logf, diagf, closeLog, err := initLogger(cfg.OutputDir, cfg.Verbose, cfg.EnableDiagnostics, appendLog)
	if err != nil {
		return nil, err
	}
	defer closeLog()

	logf("ultrarecon started domain=%s output=%s", cfg.Domain, cfg.OutputDir)
	if checkpoint != nil {
		logf("[resume] loaded checkpoint stage=%s completed=%d", checkpoint.CurrentStage, len(summary.Stages))
		if _, ok := completedStages["write_artifacts"]; ok && strings.TrimSpace(cfg.ResumeFrom) == "" {
			logf("[resume] latest checkpoint already completed")
			return summary, nil
		}
	}

	currentArtifacts := func() checkpointArtifacts {
		return checkpointArtifacts{
			PassiveHosts:        passiveHosts,
			NoerrorHosts:        noerrorHosts,
			DNSPivotHosts:       dnsPivotHosts,
			ASNHosts:            asnHosts,
			ZoneTransferHosts:   zoneTransferHosts,
			BruteHosts:          bruteHosts,
			RecursiveHosts:      recursiveHosts,
			RecursiveBruteHosts: recursiveBruteHosts,
			EnrichmentHosts:     enrichmentHosts,
			AnalyticsHosts:      analyticsHosts,
			ScrapingHosts:       scrapingHosts,
			Permutations:        permutations,
			GotatorHosts:        gotatorHosts,
			ServiceRows:         serviceRows,
			SurfaceRows:         surfaceRows,
			ContentRows:         contentRows,
			ParamKeys:           paramKeys,
			SecurityFindings:    securityFindings,
		}
	}

	stage := func(name string, fn func() error) error {
		if _, ok := completedStages[name]; ok {
			logf("[stage] skip  %s (resume)", name)
			return nil
		}
		logf("[stage] start %s", name)
		s := time.Now()
		err := fn()
		dur := time.Since(s).Round(time.Millisecond)
		st := StageStat{
			Name:     name,
			Duration: dur.String(),
		}
		if err != nil {
			st.Details = err.Error()
			summary.Stages = append(summary.Stages, st)
			logf("[stage] fail  %s (%s): %v", name, dur, err)
			return err
		}
		summary.Stages = append(summary.Stages, st)
		if saveErr := saveCheckpointState(cfg, name, summary, store, toolErrs, resolvers, currentArtifacts()); saveErr != nil {
			summary.Stages[len(summary.Stages)-1].Details = saveErr.Error()
			logf("[stage] fail  %s (%s): %v", name, dur, saveErr)
			return fmt.Errorf("save checkpoint after %s: %w", name, saveErr)
		}
		completedStages[name] = struct{}{}
		logf("[stage] done  %s (%s)", name, dur)
		return nil
	}

	if cfg.Phase == "probe" {
		if err := stage("load_input_subdomains", func() error {
			seedHosts, err := loadInputSubdomains(cfg.InputSubdomainsFile, cfg.Domain)
			if err != nil {
				return err
			}
			if len(seedHosts) == 0 {
				return fmt.Errorf("input subdomain file has no valid in-scope hosts")
			}
			store.AddBatch(seedHosts, "input:file")
			passiveHosts = seedHosts
			summary.PassiveDiscovered = len(seedHosts)
			logf("[input] loaded=%d", len(seedHosts))
			return nil
		}); err != nil {
			return nil, err
		}
	} else if cfg.EnablePassive {
		if err := stage("passive_collection", func() error {
			pCtx, cancel := context.WithTimeout(ctx, cfg.PassiveTimeout)
			defer cancel()
			passiveHosts, summary.PassiveDiagnostics = runPassiveCollection(pCtx, cfg, store, &toolErrs, logf, diagf)
			summary.PassiveDiscovered = len(passiveHosts)
			return nil
		}); err != nil {
			return nil, err
		}
	}

	if err := stage("resolver_selection", func() error {
		resolvers = prepareResolvers(ctx, cfg, logf)
		if len(resolvers) == 0 {
			return fmt.Errorf("no working resolvers")
		}
		summary.SelectedResolvers = len(resolvers)
		summary.ResolversBenchSucceeded = len(resolvers)
		return nil
	}); err != nil {
		return nil, err
	}

	if store.Count() > 0 {
		if err := stage("initial_dns_resolve", func() error {
			names := limitResolveQueue(store, cfg.Domain, store.Names(), cfg.MaxResolveQueue)
			summary.ResolvedInitial = runDNSResolvePhase(ctx, cfg, store, resolvers, names, logf)
			return nil
		}); err != nil {
			return nil, err
		}

		if err := stage("wildcard_filter_initial", func() error {
			wild := detectWildcardParents(ctx, cfg, store, resolvers, logf)
			summary.WildcardFiltered += applyWildcardFilter(store, cfg, wild)
			return nil
		}); err != nil {
			return nil, err
		}
	}

	if cfg.Phase != "probe" && cfg.EnableNoerror {
		if err := stage("noerror_collection", func() error {
			noerrorHosts = runNoerrorCollection(ctx, cfg, resolvers, &toolErrs, logf)
			summary.NoerrorDiscovered = len(noerrorHosts)
			added := store.AddBatch(noerrorHosts, "generated:noerror")
			logf("[noerror] added=%d", added)
			return nil
		}); err != nil {
			return nil, err
		}
		if len(noerrorHosts) > 0 {
			if err := stage("noerror_dns_resolve", func() error {
				names := limitResolveQueue(store, cfg.Domain, noerrorHosts, cfg.MaxResolveQueue)
				summary.ResolvedNoerror = runDNSResolvePhase(ctx, cfg, store, resolvers, names, logf)
				return nil
			}); err != nil {
				return nil, err
			}
			if err := stage("wildcard_filter_noerror", func() error {
				wild := detectWildcardParents(ctx, cfg, store, resolvers, logf)
				summary.WildcardFiltered += applyWildcardFilter(store, cfg, wild)
				return nil
			}); err != nil {
				return nil, err
			}
		}
	}

	if cfg.Phase != "probe" && cfg.EnableDNSPivot {
		if err := stage("dns_pivot_collection", func() error {
			dnsPivotHosts = runDNSPivotCollection(ctx, cfg, store, resolvers, &toolErrs, logf)
			summary.DNSPivotDiscovered = len(dnsPivotHosts)
			added := store.AddBatch(dnsPivotHosts, "generated:dns_pivot")
			logf("[dns-pivot] added=%d", added)
			return nil
		}); err != nil {
			return nil, err
		}
		if len(dnsPivotHosts) > 0 {
			if err := stage("dns_pivot_resolve", func() error {
				names := limitResolveQueue(store, cfg.Domain, dnsPivotHosts, cfg.MaxResolveQueue)
				summary.ResolvedDNSPivot = runDNSResolvePhase(ctx, cfg, store, resolvers, names, logf)
				return nil
			}); err != nil {
				return nil, err
			}
			if err := stage("wildcard_filter_dns_pivot", func() error {
				wild := detectWildcardParents(ctx, cfg, store, resolvers, logf)
				summary.WildcardFiltered += applyWildcardFilter(store, cfg, wild)
				return nil
			}); err != nil {
				return nil, err
			}
		}
	}

	if cfg.Phase != "probe" && cfg.EnableASNExpansion {
		if err := stage("asn_cidr_collection", func() error {
			asnHosts = runASNExpansionCollection(ctx, cfg, resolvers, &toolErrs, logf)
			summary.ASNDiscovered = len(asnHosts)
			added := store.AddBatch(asnHosts, "generated:asn_cidr")
			logf("[asn] added=%d", added)
			return nil
		}); err != nil {
			return nil, err
		}
		if len(asnHosts) > 0 {
			if err := stage("asn_cidr_resolve", func() error {
				names := limitResolveQueue(store, cfg.Domain, asnHosts, cfg.MaxResolveQueue)
				summary.ResolvedASN = runDNSResolvePhase(ctx, cfg, store, resolvers, names, logf)
				return nil
			}); err != nil {
				return nil, err
			}
			if err := stage("wildcard_filter_asn_cidr", func() error {
				wild := detectWildcardParents(ctx, cfg, store, resolvers, logf)
				summary.WildcardFiltered += applyWildcardFilter(store, cfg, wild)
				return nil
			}); err != nil {
				return nil, err
			}
		}
	}

	if cfg.Phase != "probe" && cfg.EnableZoneTransfer {
		if err := stage("zone_transfer_collection", func() error {
			zoneTransferHosts = runZoneTransferCollection(ctx, cfg, resolvers, &toolErrs, logf)
			summary.ZoneTransferDiscovered = len(zoneTransferHosts)
			added := store.AddBatch(zoneTransferHosts, "generated:zone_transfer")
			logf("[zone-transfer] added=%d", added)
			return nil
		}); err != nil {
			return nil, err
		}
		if len(zoneTransferHosts) > 0 {
			if err := stage("zone_transfer_resolve", func() error {
				names := limitResolveQueue(store, cfg.Domain, zoneTransferHosts, cfg.MaxResolveQueue)
				summary.ResolvedZoneTransfer = runDNSResolvePhase(ctx, cfg, store, resolvers, names, logf)
				return nil
			}); err != nil {
				return nil, err
			}
			if err := stage("wildcard_filter_zone_transfer", func() error {
				wild := detectWildcardParents(ctx, cfg, store, resolvers, logf)
				summary.WildcardFiltered += applyWildcardFilter(store, cfg, wild)
				return nil
			}); err != nil {
				return nil, err
			}
		}
	}

	if cfg.Phase != "probe" && cfg.EnableBruteforce {
		if err := stage("bruteforce_collection", func() error {
			bruteHosts = runBruteforceCollection(ctx, cfg, resolvers, &toolErrs, logf)
			summary.BruteforceGenerated = len(bruteHosts)
			added := store.AddBatch(bruteHosts, "generated:bruteforce")
			logf("[brute] added=%d", added)
			return nil
		}); err != nil {
			return nil, err
		}
		if len(bruteHosts) > 0 {
			if err := stage("bruteforce_dns_resolve", func() error {
				names := limitResolveQueue(store, cfg.Domain, bruteHosts, cfg.MaxResolveQueue)
				summary.ResolvedBruteforce = runDNSResolvePhase(ctx, cfg, store, resolvers, names, logf)
				return nil
			}); err != nil {
				return nil, err
			}
			if err := stage("wildcard_filter_bruteforce", func() error {
				wild := detectWildcardParents(ctx, cfg, store, resolvers, logf)
				summary.WildcardFiltered += applyWildcardFilter(store, cfg, wild)
				return nil
			}); err != nil {
				return nil, err
			}
		}
	}

	if cfg.Phase != "probe" && cfg.EnableRecursive {
		if err := stage("recursive_passive_collection", func() error {
			recursiveHosts = runRecursivePassiveCollection(ctx, cfg, store, &toolErrs, logf)
			summary.RecursiveDiscovered = len(recursiveHosts)
			added := store.AddBatch(recursiveHosts, "generated:recursive")
			logf("[recursive] added=%d", added)
			return nil
		}); err != nil {
			return nil, err
		}
		if len(recursiveHosts) > 0 {
			if err := stage("recursive_dns_resolve", func() error {
				names := limitResolveQueue(store, cfg.Domain, recursiveHosts, cfg.MaxResolveQueue)
				summary.ResolvedRecursive = runDNSResolvePhase(ctx, cfg, store, resolvers, names, logf)
				return nil
			}); err != nil {
				return nil, err
			}
			if err := stage("wildcard_filter_recursive", func() error {
				wild := detectWildcardParents(ctx, cfg, store, resolvers, logf)
				summary.WildcardFiltered += applyWildcardFilter(store, cfg, wild)
				return nil
			}); err != nil {
				return nil, err
			}
		}
	}

	if cfg.Phase != "probe" && cfg.EnableRecursiveBrute {
		if err := stage("recursive_bruteforce_collection", func() error {
			recursiveBruteHosts = runRecursiveBruteforceCollection(ctx, cfg, store, resolvers, &toolErrs, logf)
			summary.RecursiveBruteFound = len(recursiveBruteHosts)
			added := store.AddBatch(recursiveBruteHosts, "generated:recursive_brute")
			logf("[recursive-brute] added=%d", added)
			return nil
		}); err != nil {
			return nil, err
		}
		if len(recursiveBruteHosts) > 0 {
			if err := stage("recursive_bruteforce_resolve", func() error {
				names := limitResolveQueue(store, cfg.Domain, recursiveBruteHosts, cfg.MaxResolveQueue)
				summary.ResolvedRecursiveBrute = runDNSResolvePhase(ctx, cfg, store, resolvers, names, logf)
				return nil
			}); err != nil {
				return nil, err
			}
			if err := stage("wildcard_filter_recursive_bruteforce", func() error {
				wild := detectWildcardParents(ctx, cfg, store, resolvers, logf)
				summary.WildcardFiltered += applyWildcardFilter(store, cfg, wild)
				return nil
			}); err != nil {
				return nil, err
			}
		}
	}

	if cfg.Phase != "probe" && (cfg.EnableCSPExtraction || cfg.EnableArchiveSources || cfg.EnableTLSEnumeration) {
		if err := stage("enrichment_collection", func() error {
			baseResolved := finalResolvedNames(store)
			enrichmentHosts = runEnrichmentCollection(ctx, cfg, baseResolved, &toolErrs, logf)
			summary.EnrichmentDiscovered = len(enrichmentHosts)
			added := store.AddBatch(enrichmentHosts, "generated:enrichment")
			logf("[enrich] added=%d", added)
			return nil
		}); err != nil {
			return nil, err
		}
		if len(enrichmentHosts) > 0 {
			if err := stage("enrichment_dns_resolve", func() error {
				names := limitResolveQueue(store, cfg.Domain, enrichmentHosts, cfg.MaxResolveQueue)
				summary.ResolvedEnrichment = runDNSResolvePhase(ctx, cfg, store, resolvers, names, logf)
				return nil
			}); err != nil {
				return nil, err
			}
			if err := stage("wildcard_filter_enrichment", func() error {
				wild := detectWildcardParents(ctx, cfg, store, resolvers, logf)
				summary.WildcardFiltered += applyWildcardFilter(store, cfg, wild)
				return nil
			}); err != nil {
				return nil, err
			}
		}
	}

	if cfg.Phase != "probe" && cfg.EnableAnalyticsPivot {
		if err := stage("analytics_pivot_collection", func() error {
			analyticsHosts = runAnalyticsPivotCollection(ctx, cfg, store, &toolErrs, logf)
			summary.AnalyticsDiscovered = len(analyticsHosts)
			added := store.AddBatch(analyticsHosts, "generated:analytics")
			logf("[analytics] added=%d", added)
			return nil
		}); err != nil {
			return nil, err
		}
		if len(analyticsHosts) > 0 {
			if err := stage("analytics_pivot_resolve", func() error {
				names := limitResolveQueue(store, cfg.Domain, analyticsHosts, cfg.MaxResolveQueue)
				summary.ResolvedAnalytics = runDNSResolvePhase(ctx, cfg, store, resolvers, names, logf)
				return nil
			}); err != nil {
				return nil, err
			}
			if err := stage("wildcard_filter_analytics", func() error {
				wild := detectWildcardParents(ctx, cfg, store, resolvers, logf)
				summary.WildcardFiltered += applyWildcardFilter(store, cfg, wild)
				return nil
			}); err != nil {
				return nil, err
			}
		}
	}

	if cfg.Phase != "probe" && cfg.EnablePermutations {
		if err := stage("permutation_generation", func() error {
			permutations = generatePermutations(cfg, store, logf)
			summary.PermutationGenerated = len(permutations)
			added := store.AddBatch(permutations, "generated:permutation")
			logf("[perm] added=%d", added)
			return nil
		}); err != nil {
			return nil, err
		}

		if len(permutations) > 0 {
			if err := stage("permutation_dns_resolve", func() error {
				names := limitResolveQueue(store, cfg.Domain, permutations, cfg.MaxResolveQueue)
				summary.ResolvedPermutations = runDNSResolvePhase(ctx, cfg, store, resolvers, names, logf)
				return nil
			}); err != nil {
				return nil, err
			}

			if err := stage("wildcard_filter_permutation", func() error {
				wild := detectWildcardParents(ctx, cfg, store, resolvers, logf)
				summary.WildcardFiltered += applyWildcardFilter(store, cfg, wild)
				return nil
			}); err != nil {
				return nil, err
			}
		}
	}

	if cfg.Phase != "probe" && cfg.EnableGotator {
		if err := stage("gotator_collection", func() error {
			gotatorHosts = runGotatorCollection(ctx, cfg, store, &toolErrs, logf)
			summary.GotatorGenerated = len(gotatorHosts)
			added := store.AddBatch(gotatorHosts, "generated:gotator")
			logf("[gotator] added=%d", added)
			return nil
		}); err != nil {
			return nil, err
		}
		if len(gotatorHosts) > 0 {
			if err := stage("gotator_dns_resolve", func() error {
				names := limitResolveQueue(store, cfg.Domain, gotatorHosts, cfg.MaxResolveQueue)
				summary.ResolvedGotator = runDNSResolvePhase(ctx, cfg, store, resolvers, names, logf)
				return nil
			}); err != nil {
				return nil, err
			}
			if err := stage("wildcard_filter_gotator", func() error {
				wild := detectWildcardParents(ctx, cfg, store, resolvers, logf)
				summary.WildcardFiltered += applyWildcardFilter(store, cfg, wild)
				return nil
			}); err != nil {
				return nil, err
			}
		}
	}

	if cfg.EnableServiceDiscovery {
		if err := stage("service_discovery", func() error {
			baseResolved := finalResolvedNames(store)
			if len(baseResolved) == 0 && cfg.Phase == "probe" {
				baseResolved = store.Names()
				logf("[service] fallback inputs=%d (no internally resolved hosts)", len(baseResolved))
			}
			serviceRows = runServiceDiscovery(ctx, cfg, store, baseResolved, &toolErrs, logf)
			summary.ServiceHostsScanned = minInt(len(baseResolved), cfg.MaxServiceHosts)
			summary.ServiceRows = len(serviceRows)
			summary.ServiceOpenPorts = countServiceOpenPorts(serviceRows)
			summary.ServiceLiveURLs = countServiceLiveURLs(serviceRows)
			return nil
		}); err != nil {
			return nil, err
		}
	}

	preScrapeResolved := finalResolvedNames(store)
	if cfg.EnableHTTPProbe && len(preScrapeResolved) > 0 {
		if err := stage("http_probe_initial", func() error {
			runHTTPProbe(ctx, cfg, store, preScrapeResolved, logf)
			return nil
		}); err != nil {
			return nil, err
		}
	}

	if cfg.Phase != "probe" && cfg.EnableScrapingPivot {
		if err := stage("scraping_pivot_collection", func() error {
			scrapingHosts = runScrapingPivotCollection(ctx, cfg, store, &toolErrs, logf)
			summary.ScrapingDiscovered = len(scrapingHosts)
			added := store.AddBatch(scrapingHosts, "generated:scraping")
			logf("[scraping] added=%d", added)
			return nil
		}); err != nil {
			return nil, err
		}
		if len(scrapingHosts) > 0 {
			if err := stage("scraping_pivot_resolve", func() error {
				names := limitResolveQueue(store, cfg.Domain, scrapingHosts, cfg.MaxResolveQueue)
				summary.ResolvedScraping = runDNSResolvePhase(ctx, cfg, store, resolvers, names, logf)
				return nil
			}); err != nil {
				return nil, err
			}
			if err := stage("wildcard_filter_scraping", func() error {
				wild := detectWildcardParents(ctx, cfg, store, resolvers, logf)
				summary.WildcardFiltered += applyWildcardFilter(store, cfg, wild)
				return nil
			}); err != nil {
				return nil, err
			}
			if cfg.EnableHTTPProbe {
				if err := stage("http_probe_scraping", func() error {
					runHTTPProbe(ctx, cfg, store, resolvedNamesFromList(store, scrapingHosts), logf)
					return nil
				}); err != nil {
					return nil, err
				}
			}
		}
	}

	if cfg.EnableSurfaceMapping {
		if err := stage("surface_mapping", func() error {
			surfaceRows = runSurfaceMapping(ctx, cfg, store, &toolErrs, logf)
			summary.SurfaceURLs = len(surfaceRows)
			summary.SurfacePaths = countSurfacePaths(surfaceRows)
			return nil
		}); err != nil {
			return nil, err
		}
	}

	if cfg.EnableContentDiscovery {
		if err := stage("content_discovery", func() error {
			contentRows, paramKeys = runContentDiscovery(ctx, cfg, store, surfaceRows, &toolErrs, logf)
			summary.ContentRows = len(contentRows)
			summary.ParamKeys = len(paramKeys)
			return nil
		}); err != nil {
			return nil, err
		}
	}

	if cfg.EnableSecurityChecks {
		if err := stage("security_checks", func() error {
			securityFindings = runSecurityChecks(ctx, cfg, store, surfaceRows, contentRows, &toolErrs, logf)
			summary.SecurityFindings = len(securityFindings)
			summary.SecurityHighCritical = countHighCritical(securityFindings)
			return nil
		}); err != nil {
			return nil, err
		}
	}

	finalResolved := finalResolvedNames(store)
	summary.FinalResolved = len(finalResolved)
	summary.LiveHosts = countLiveHosts(store)

	computeScores(store)
	summary.ToolErrors = toolErrs
	summary.FinishedAt = time.Now().UTC()
	summary.Duration = time.Since(started).Round(time.Millisecond).String()

	if err := stage("write_artifacts", func() error {
		return writeArtifacts(
			cfg, store,
			passiveHosts, noerrorHosts, dnsPivotHosts, asnHosts, zoneTransferHosts,
			bruteHosts, recursiveHosts, recursiveBruteHosts,
			enrichmentHosts, analyticsHosts, scrapingHosts, permutations, gotatorHosts, serviceRows,
			surfaceRows, contentRows, paramKeys, securityFindings, summary,
		)
	}); err != nil {
		return nil, err
	}

	logf("ultrarecon completed final_resolved=%d live=%d duration=%s", summary.FinalResolved, summary.LiveHosts, summary.Duration)
	return summary, nil
}

func initLogger(outputDir string, verbose bool, diagnostics bool, appendMode bool) (func(string, ...any), func(string, ...any), func(), error) {
	logPath := filepath.Join(outputDir, "ultrarecon.log")
	var (
		f   *os.File
		err error
	)
	if appendMode {
		f, err = os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	} else {
		f, err = os.Create(logPath)
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create log file: %w", err)
	}
	logger := log.New(f, "", log.LstdFlags)
	closeFn := func() {
		_ = f.Close()
	}
	logf := func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		logger.Println(msg)
		if verbose {
			fmt.Println(msg)
		}
	}
	diagf := func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		logger.Println(msg)
		if verbose || diagnostics {
			fmt.Println(msg)
		}
	}
	return logf, diagf, closeFn, nil
}

func finalResolvedNames(store *SafeStore) []string {
	snap := store.Snapshot()
	out := make([]string, 0, len(snap))
	for _, c := range snap {
		if c.Resolved && !c.Wildcard {
			out = append(out, c.Name)
		}
	}
	return out
}

func limitResolveQueue(store *SafeStore, domain string, names []string, limit int) []string {
	if limit <= 0 || len(names) <= limit {
		return names
	}
	type row struct {
		name      string
		score     int
		sourceCnt int
	}
	sourceCounts := make(map[string]int, len(names))
	for _, c := range store.Snapshot() {
		sourceCounts[c.Name] = c.SourceCount()
	}
	rows := make([]row, 0, len(names))
	for _, n := range names {
		left := strings.TrimSuffix(n, "."+domain)
		depth := strings.Count(left, ".") + 1
		if n == domain {
			depth = 0
		}
		score := 2000 - depth*50 - len(left)
		sc := sourceCounts[n]
		score += sc * 90
		if strings.Contains(left, "api") || strings.Contains(left, "auth") || strings.Contains(left, "admin") {
			score += 40
		}
		rows = append(rows, row{name: n, score: score, sourceCnt: sc})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].score == rows[j].score {
			return rows[i].name < rows[j].name
		}
		return rows[i].score > rows[j].score
	})
	out := make([]string, 0, limit)
	for i := 0; i < limit && i < len(rows); i++ {
		out = append(out, rows[i].name)
	}
	sort.Strings(out)
	return out
}

func resolvedNamesFromList(store *SafeStore, names []string) []string {
	if len(names) == 0 {
		return nil
	}
	want := make(map[string]struct{}, len(names))
	for _, n := range names {
		want[n] = struct{}{}
	}
	snap := store.Snapshot()
	out := make([]string, 0, len(names))
	for _, c := range snap {
		if _, ok := want[c.Name]; !ok {
			continue
		}
		if c.Resolved && !c.Wildcard {
			out = append(out, c.Name)
		}
	}
	sort.Strings(out)
	return out
}

func countLiveHosts(store *SafeStore) int {
	total := 0
	for _, c := range store.Snapshot() {
		if c.Live && c.Resolved && !c.Wildcard {
			total++
		}
	}
	return total
}

func countServiceOpenPorts(rows []ServiceRow) int {
	seen := make(map[string]struct{}, len(rows))
	for _, r := range rows {
		if r.Port <= 0 {
			continue
		}
		key := fmt.Sprintf("%s:%d", r.Host, r.Port)
		seen[key] = struct{}{}
	}
	return len(seen)
}

func countServiceLiveURLs(rows []ServiceRow) int {
	seen := make(map[string]struct{}, len(rows))
	for _, r := range rows {
		if strings.TrimSpace(r.URL) == "" {
			continue
		}
		seen[r.URL] = struct{}{}
	}
	return len(seen)
}

func countHighCritical(rows []SecurityFinding) int {
	total := 0
	for _, r := range rows {
		s := strings.ToLower(strings.TrimSpace(r.Severity))
		if s == "high" || s == "critical" {
			total++
		}
	}
	return total
}

func hasAnySubdomainModuleEnabled(cfg config.Config) bool {
	return cfg.EnablePassive ||
		cfg.EnableNoerror ||
		cfg.EnableDNSPivot ||
		cfg.EnableASNExpansion ||
		cfg.EnableZoneTransfer ||
		cfg.EnableBruteforce ||
		cfg.EnableRecursive ||
		cfg.EnableRecursiveBrute ||
		cfg.EnableCSPExtraction ||
		cfg.EnableArchiveSources ||
		cfg.EnableTLSEnumeration ||
		cfg.EnableAnalyticsPivot ||
		cfg.EnablePermutations ||
		cfg.EnableGotator ||
		cfg.EnableServiceDiscovery ||
		cfg.EnableSurfaceMapping ||
		cfg.EnableContentDiscovery ||
		cfg.EnableSecurityChecks ||
		cfg.EnableScrapingPivot
}

func loadInputSubdomains(path, domain string) ([]string, error) {
	lines, err := util.ReadLines(path)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(lines))
	for _, raw := range lines {
		if h, ok := util.NormalizeCandidate(raw, domain); ok {
			out = append(out, h)
		}
	}
	return util.UniqueSorted(out), nil
}
