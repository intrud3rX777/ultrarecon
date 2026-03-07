package pipeline

import (
	"context"
	"sort"
	"strconv"
	"strings"

	"ultrarecon/internal/config"
	"ultrarecon/internal/util"
)

func runGotatorCollection(
	ctx context.Context,
	cfg config.Config,
	store *SafeStore,
	toolErrs *[]ToolError,
	logf func(string, ...any),
) []string {
	if !cfg.EnableGotator || cfg.MaxGotatorCandidates <= 0 {
		return nil
	}

	inputs := collectGotatorInputs(cfg, store)
	if len(inputs) == 0 {
		return nil
	}
	words := loadPermutationWordlist(cfg)
	if len(words) == 0 {
		return nil
	}
	if len(words) > 3500 {
		words = words[:3500]
	}

	if !util.HaveCommand("gotator") {
		out := generateGotatorFallback(cfg, store, inputs, words)
		logf("[gotator] tool missing, fallback candidates=%d", len(out))
		return out
	}

	subFile, cleanupSub, err := writeTempList(cfg.OutputDir, "gotator-sub-*.txt", inputs)
	if err != nil {
		*toolErrs = append(*toolErrs, ToolError{Stage: "gotator", Tool: "internal", Error: err.Error()})
		return nil
	}
	defer cleanupSub()

	permFile, cleanupPerm, err := writeTempList(cfg.OutputDir, "gotator-perm-*.txt", words)
	if err != nil {
		*toolErrs = append(*toolErrs, ToolError{Stage: "gotator", Tool: "internal", Error: err.Error()})
		return nil
	}
	defer cleanupPerm()

	depth := strconv.Itoa(cfg.GotatorDepth)
	attempts := [][]string{
		{"-sub", subFile, "-perm", permFile, "-depth", depth, "-numbers", "10", "-mindup", "-adv", "-md"},
		{"-sub", subFile, "-perm", permFile, "-depth", depth, "-numbers", "10", "-mindup", "-adv"},
		{"-sub", subFile, "-perm", permFile, "-depth", depth, "-numbers", "10", "-mindup"},
		{"-sub", subFile, "-perm", permFile, "-depth", depth},
	}

	var stdout string
	var lastErr error
	for _, args := range attempts {
		subCtx, cancel := context.WithTimeout(ctx, cfg.BruteTimeout)
		res := util.RunCommand(subCtx, cfg.BruteTimeout, "gotator", args...)
		cancel()

		if strings.TrimSpace(res.Stdout) != "" {
			stdout = res.Stdout
			lastErr = nil
			break
		}
		if res.Err != nil {
			lastErr = res.Err
			if gotatorFlagError(res.Stderr) {
				continue
			}
		}
	}

	if strings.TrimSpace(stdout) == "" {
		if lastErr != nil {
			*toolErrs = append(*toolErrs, ToolError{Stage: "gotator", Tool: "gotator", Error: lastErr.Error()})
		}
		out := generateGotatorFallback(cfg, store, inputs, words)
		logf("[gotator] fallback candidates=%d", len(out))
		return out
	}

	out := normalizeCandidates(splitLines(stdout), cfg.Domain)
	if len(out) > cfg.MaxGotatorCandidates {
		out = out[:cfg.MaxGotatorCandidates]
	}
	logf("[gotator] inputs=%d words=%d candidates=%d", len(inputs), len(words), len(out))
	return out
}

func collectGotatorInputs(cfg config.Config, store *SafeStore) []string {
	type seed struct {
		name      string
		sourceCnt int
		depth     int
	}
	snap := store.Snapshot()
	seeds := make([]seed, 0, len(snap))
	for _, c := range snap {
		if !c.Resolved || c.Wildcard {
			continue
		}
		left := strings.TrimSuffix(c.Name, "."+cfg.Domain)
		depth := 0
		if left != "" {
			depth = strings.Count(left, ".") + 1
		}
		seeds = append(seeds, seed{name: c.Name, sourceCnt: c.SourceCount(), depth: depth})
	}
	sort.Slice(seeds, func(i, j int) bool {
		if seeds[i].sourceCnt == seeds[j].sourceCnt {
			if seeds[i].depth == seeds[j].depth {
				return seeds[i].name < seeds[j].name
			}
			return seeds[i].depth < seeds[j].depth
		}
		return seeds[i].sourceCnt > seeds[j].sourceCnt
	})

	if len(seeds) > cfg.MaxGotatorInputs {
		seeds = seeds[:cfg.MaxGotatorInputs]
	}
	out := make([]string, 0, len(seeds))
	for _, s := range seeds {
		out = append(out, s.name)
	}
	return out
}

func generateGotatorFallback(cfg config.Config, store *SafeStore, seeds, words []string) []string {
	if len(seeds) == 0 || len(words) == 0 {
		return nil
	}

	seedCap := minInt(len(seeds), 300)
	wordCap := minInt(len(words), 140)
	maxOut := cfg.MaxGotatorCandidates
	if cfg.HomeSafe {
		maxOut = minInt(maxOut, 15000)
	}
	if maxOut <= 0 {
		return nil
	}

	existing := make(map[string]struct{}, store.Count())
	for _, name := range store.Names() {
		existing[name] = struct{}{}
	}
	outSet := make(map[string]struct{}, maxOut)

	for i := 0; i < seedCap; i++ {
		seed := seeds[i]
		left := strings.TrimSuffix(seed, "."+cfg.Domain)
		if left == "" {
			continue
		}
		base := strings.Split(left, ".")[0]
		tokenSet := make(map[string]struct{}, 8)
		for _, t := range splitToken(base) {
			tokenSet[t] = struct{}{}
		}
		if folded := strings.ReplaceAll(left, ".", "-"); validLabel(folded) {
			tokenSet[folded] = struct{}{}
		}
		if validLabel(base) {
			tokenSet[base] = struct{}{}
		}
		if len(tokenSet) == 0 {
			continue
		}

		tokens := make([]string, 0, len(tokenSet))
		for t := range tokenSet {
			tokens = append(tokens, t)
		}
		sort.Strings(tokens)

		for _, token := range tokens {
			for w := 0; w < wordCap; w++ {
				for _, label := range combineLabels(token, words[w]) {
					candidates := []string{
						label + "." + cfg.Domain,
						label + "." + seed,
					}
					for _, host := range candidates {
						if _, ok := existing[host]; ok {
							continue
						}
						outSet[host] = struct{}{}
						if len(outSet) >= maxOut {
							return mapKeysSorted(outSet)
						}
					}
				}
			}
		}
	}
	return mapKeysSorted(outSet)
}

func gotatorFlagError(stderr string) bool {
	low := strings.ToLower(strings.TrimSpace(stderr))
	return strings.Contains(low, "flag provided but not defined") ||
		strings.Contains(low, "unknown flag") ||
		strings.Contains(low, "unknown shorthand")
}
