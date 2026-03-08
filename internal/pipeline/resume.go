package pipeline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"ultrarecon/internal/config"
)

const checkpointStateVersion = 3

type checkpointArtifacts struct {
	PassiveHosts        []string          `json:"passive_hosts,omitempty"`
	NoerrorHosts        []string          `json:"noerror_hosts,omitempty"`
	DNSPivotHosts       []string          `json:"dns_pivot_hosts,omitempty"`
	ASNHosts            []string          `json:"asn_hosts,omitempty"`
	ZoneTransferHosts   []string          `json:"zone_transfer_hosts,omitempty"`
	BruteHosts          []string          `json:"brute_hosts,omitempty"`
	RecursiveHosts      []string          `json:"recursive_hosts,omitempty"`
	RecursiveBruteHosts []string          `json:"recursive_brute_hosts,omitempty"`
	EnrichmentHosts     []string          `json:"enrichment_hosts,omitempty"`
	AnalyticsHosts      []string          `json:"analytics_hosts,omitempty"`
	ScrapingHosts       []string          `json:"scraping_hosts,omitempty"`
	Permutations        []string          `json:"permutations,omitempty"`
	GotatorHosts        []string          `json:"gotator_hosts,omitempty"`
	ServiceRows         []ServiceRow      `json:"service_rows,omitempty"`
	SurfaceRows         []SurfaceRow      `json:"surface_rows,omitempty"`
	JSRows              []JSAnalysisRow   `json:"js_rows,omitempty"`
	ContentRows         []ContentRow      `json:"content_rows,omitempty"`
	ParamKeys           []string          `json:"param_keys,omitempty"`
	SecurityFindings    []SecurityFinding `json:"security_findings,omitempty"`
	ScreenshotRows      []ScreenshotRow   `json:"screenshot_rows,omitempty"`
}

type checkpointCandidate struct {
	Name          string   `json:"name"`
	Sources       []string `json:"sources,omitempty"`
	Resolved      bool     `json:"resolved"`
	IPs           []string `json:"ips,omitempty"`
	ResolverVotes int      `json:"resolver_votes,omitempty"`
	Wildcard      bool     `json:"wildcard"`
	Live          bool     `json:"live"`
	LiveURLs      []string `json:"live_urls,omitempty"`
	OpenPorts     []int    `json:"open_ports,omitempty"`
	Confidence    float64  `json:"confidence,omitempty"`
	Notes         []string `json:"notes,omitempty"`
}

type checkpointResolver struct {
	Addr     string `json:"addr"`
	RTTNanos int64  `json:"rtt_nanos,omitempty"`
}

type checkpointState struct {
	Version         int                   `json:"version"`
	Domain          string                `json:"domain"`
	Phase           string                `json:"phase"`
	OutputDir       string                `json:"output_dir"`
	ConfigSignature string                `json:"config_signature"`
	CurrentStage    string                `json:"current_stage"`
	UpdatedAt       time.Time             `json:"updated_at"`
	Summary         Summary               `json:"summary"`
	ToolErrors      []ToolError           `json:"tool_errors,omitempty"`
	Store           []checkpointCandidate `json:"store,omitempty"`
	Resolvers       []checkpointResolver  `json:"resolvers,omitempty"`
	Artifacts       checkpointArtifacts   `json:"artifacts"`
}

func checkpointDir(output string) string {
	return filepath.Join(output, ".ultrarecon")
}

func latestCheckpointPath(output string) string {
	return filepath.Join(checkpointDir(output), "latest.json")
}

func stageCheckpointPath(output string, idx int, stage string) string {
	name := sanitizeCheckpointStage(stage)
	return filepath.Join(checkpointDir(output), fmt.Sprintf("%03d_%s.json", idx, name))
}

func sanitizeCheckpointStage(stage string) string {
	stage = strings.ToLower(strings.TrimSpace(stage))
	if stage == "" {
		return "stage"
	}
	var b strings.Builder
	b.Grow(len(stage))
	lastUnderscore := false
	for _, r := range stage {
		keep := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if keep {
			b.WriteRune(r)
			lastUnderscore = false
			continue
		}
		if !lastUnderscore {
			b.WriteByte('_')
			lastUnderscore = true
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "stage"
	}
	return out
}

func checkpointConfigSignature(cfg config.Config) string {
	clone := cfg
	clone.Verbose = false
	clone.Resume = false
	clone.ResumeFrom = ""
	data, err := json.Marshal(clone)
	if err != nil {
		return fmt.Sprintf("fallback:%s:%s:%s", cfg.Domain, cfg.Phase, cfg.OutputDir)
	}
	return string(data)
}

func makeCheckpointState(
	cfg config.Config,
	stage string,
	summary *Summary,
	store *SafeStore,
	toolErrs []ToolError,
	resolvers []dnsResolver,
	artifacts checkpointArtifacts,
) checkpointState {
	sum := *summary
	sum.Stages = append([]StageStat(nil), summary.Stages...)
	sum.ToolErrors = append([]ToolError(nil), toolErrs...)
	sum.FinalResolved = len(finalResolvedNames(store))
	sum.LiveHosts = countLiveHosts(store)
	return checkpointState{
		Version:         checkpointStateVersion,
		Domain:          cfg.Domain,
		Phase:           cfg.Phase,
		OutputDir:       cfg.OutputDir,
		ConfigSignature: checkpointConfigSignature(cfg),
		CurrentStage:    stage,
		UpdatedAt:       time.Now().UTC(),
		Summary:         sum,
		ToolErrors:      append([]ToolError(nil), toolErrs...),
		Store:           snapshotCheckpointCandidates(store.Snapshot()),
		Resolvers:       snapshotCheckpointResolvers(resolvers),
		Artifacts:       artifacts,
	}
}

func saveCheckpointState(
	cfg config.Config,
	stage string,
	summary *Summary,
	store *SafeStore,
	toolErrs []ToolError,
	resolvers []dnsResolver,
	artifacts checkpointArtifacts,
) error {
	if err := os.MkdirAll(checkpointDir(cfg.OutputDir), 0o755); err != nil {
		return fmt.Errorf("create checkpoint dir: %w", err)
	}
	state := makeCheckpointState(cfg, stage, summary, store, toolErrs, resolvers, artifacts)
	idx := len(state.Summary.Stages)
	if err := writeJSONAtomic(stageCheckpointPath(cfg.OutputDir, idx, stage), state); err != nil {
		return fmt.Errorf("write stage checkpoint: %w", err)
	}
	if err := writeJSONAtomic(latestCheckpointPath(cfg.OutputDir), state); err != nil {
		return fmt.Errorf("write latest checkpoint: %w", err)
	}
	return nil
}

func loadResumeCheckpoint(cfg config.Config) (*checkpointState, error) {
	wantResume := cfg.Resume || strings.TrimSpace(cfg.ResumeFrom) != ""
	if !wantResume {
		return nil, nil
	}
	latest, err := readCheckpointState(latestCheckpointPath(cfg.OutputDir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("resume requested but no checkpoint found in %s", checkpointDir(cfg.OutputDir))
		}
		return nil, err
	}
	if err := validateCheckpointState(cfg, latest); err != nil {
		return nil, err
	}
	stage := strings.TrimSpace(cfg.ResumeFrom)
	if stage == "" || strings.EqualFold(stage, "latest") {
		return latest, nil
	}
	idx := findCheckpointStageIndex(latest.Summary.Stages, stage)
	if idx < 0 {
		return nil, fmt.Errorf("resume-from stage %q not found in saved checkpoints", stage)
	}
	if idx == 0 {
		return nil, nil
	}
	prev := latest.Summary.Stages[idx-1]
	prevPath := stageCheckpointPath(cfg.OutputDir, idx, prev.Name)
	state, err := readCheckpointState(prevPath)
	if err != nil {
		return nil, fmt.Errorf("load resume-from checkpoint %q: %w", prev.Name, err)
	}
	if err := validateCheckpointState(cfg, state); err != nil {
		return nil, err
	}
	return state, nil
}

func readCheckpointState(path string) (*checkpointState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var state checkpointState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("decode checkpoint %s: %w", path, err)
	}
	if state.Version == 0 {
		state.Version = checkpointStateVersion
	}
	return &state, nil
}

func validateCheckpointState(cfg config.Config, state *checkpointState) error {
	if state == nil {
		return fmt.Errorf("empty checkpoint state")
	}
	if state.Version != checkpointStateVersion {
		return fmt.Errorf("checkpoint version mismatch: have %d want %d", state.Version, checkpointStateVersion)
	}
	if !strings.EqualFold(strings.TrimSpace(state.Domain), strings.TrimSpace(cfg.Domain)) {
		return fmt.Errorf("checkpoint domain mismatch: have %s want %s", state.Domain, cfg.Domain)
	}
	if strings.TrimSpace(state.Phase) != strings.TrimSpace(cfg.Phase) {
		return fmt.Errorf("checkpoint phase mismatch: have %s want %s", state.Phase, cfg.Phase)
	}
	if strings.TrimSpace(state.OutputDir) != strings.TrimSpace(cfg.OutputDir) {
		return fmt.Errorf("checkpoint output mismatch: have %s want %s", state.OutputDir, cfg.OutputDir)
	}
	if sig := checkpointConfigSignature(cfg); sig != state.ConfigSignature {
		return fmt.Errorf("checkpoint config mismatch; use the same scan configuration when resuming")
	}
	return nil
}

func findCheckpointStageIndex(stages []StageStat, name string) int {
	needle := strings.ToLower(strings.TrimSpace(name))
	for i, stage := range stages {
		if strings.ToLower(strings.TrimSpace(stage.Name)) == needle {
			return i
		}
	}
	return -1
}

func snapshotCheckpointCandidates(snapshot []*Candidate) []checkpointCandidate {
	out := make([]checkpointCandidate, 0, len(snapshot))
	for _, c := range snapshot {
		out = append(out, checkpointCandidate{
			Name:          c.Name,
			Sources:       c.SourceList(),
			Resolved:      c.Resolved,
			IPs:           c.IPList(),
			ResolverVotes: c.ResolverVotes,
			Wildcard:      c.Wildcard,
			Live:          c.Live,
			LiveURLs:      append([]string(nil), c.LiveURLs...),
			OpenPorts:     c.PortList(),
			Confidence:    c.Confidence,
			Notes:         append([]string(nil), c.Notes...),
		})
	}
	return out
}

func restoreCheckpointStore(rows []checkpointCandidate) *SafeStore {
	store := NewSafeStore()
	for _, row := range rows {
		candidate := &Candidate{
			Name:          row.Name,
			Sources:       make(map[string]struct{}, len(row.Sources)),
			Resolved:      row.Resolved,
			IPs:           make(map[string]struct{}, len(row.IPs)),
			ResolverVotes: row.ResolverVotes,
			Wildcard:      row.Wildcard,
			Live:          row.Live,
			LiveURLs:      append([]string(nil), row.LiveURLs...),
			OpenPorts:     make(map[int]struct{}, len(row.OpenPorts)),
			Confidence:    row.Confidence,
			Notes:         append([]string(nil), row.Notes...),
		}
		for _, source := range row.Sources {
			candidate.Sources[source] = struct{}{}
		}
		for _, ip := range row.IPs {
			candidate.IPs[ip] = struct{}{}
		}
		for _, port := range row.OpenPorts {
			candidate.OpenPorts[port] = struct{}{}
		}
		store.entries[row.Name] = candidate
	}
	return store
}

func snapshotCheckpointResolvers(resolvers []dnsResolver) []checkpointResolver {
	out := make([]checkpointResolver, 0, len(resolvers))
	for _, resolver := range resolvers {
		out = append(out, checkpointResolver{
			Addr:     resolver.Addr,
			RTTNanos: int64(resolver.RTT),
		})
	}
	return out
}

func restoreCheckpointResolvers(rows []checkpointResolver) []dnsResolver {
	out := make([]dnsResolver, 0, len(rows))
	for _, row := range rows {
		if strings.TrimSpace(row.Addr) == "" {
			continue
		}
		out = append(out, dnsResolver{Addr: row.Addr, RTT: time.Duration(row.RTTNanos)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RTT == out[j].RTT {
			return out[i].Addr < out[j].Addr
		}
		return out[i].RTT < out[j].RTT
	})
	return out
}

func checkpointCompletedStages(summary *Summary) map[string]struct{} {
	out := make(map[string]struct{}, len(summary.Stages))
	for _, stage := range summary.Stages {
		if strings.TrimSpace(stage.Name) == "" {
			continue
		}
		out[stage.Name] = struct{}{}
	}
	return out
}

func writeJSONAtomic(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*.json")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
