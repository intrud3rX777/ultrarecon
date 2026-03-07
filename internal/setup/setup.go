package setup

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type ProviderState struct {
	SetupCompleted       bool      `json:"setup_completed"`
	UpdatedAt            time.Time `json:"updated_at,omitempty"`
	ChaosAPIKey          string    `json:"chaos_api_key,omitempty"`
	GitHubTokens         []string  `json:"github_tokens,omitempty"`
	CensysAPIID          string    `json:"censys_api_id,omitempty"`
	CensysAPISecret      string    `json:"censys_api_secret,omitempty"`
	SecurityTrailsAPIKey string    `json:"securitytrails_api_key,omitempty"`
	VirusTotalAPIKey     string    `json:"virustotal_api_key,omitempty"`
	ShodanAPIKey         string    `json:"shodan_api_key,omitempty"`
	CertSpotterAPIKey    string    `json:"certspotter_api_key,omitempty"`
	BufferOverAPIKey     string    `json:"bufferover_api_key,omitempty"`
	BeVigilAPIKey        string    `json:"bevigil_api_key,omitempty"`
	BinaryEdgeAPIKey     string    `json:"binaryedge_api_key,omitempty"`
	C99APIKey            string    `json:"c99_api_key,omitempty"`
	FOFAEmail            string    `json:"fofa_email,omitempty"`
	FOFAKey              string    `json:"fofa_key,omitempty"`
	FullHuntAPIKey       string    `json:"fullhunt_api_key,omitempty"`
	HunterAPIKey         string    `json:"hunter_api_key,omitempty"`
	IntelXAPIKey         string    `json:"intelx_api_key,omitempty"`
	LeakIXAPIKey         string    `json:"leakix_api_key,omitempty"`
	NetlasAPIKey         string    `json:"netlas_api_key,omitempty"`
	PassiveTotalUser     string    `json:"passivetotal_user,omitempty"`
	PassiveTotalKey      string    `json:"passivetotal_key,omitempty"`
	QuakeAPIKey          string    `json:"quake_api_key,omitempty"`
	RobtexAPIKey         string    `json:"robtex_api_key,omitempty"`
	ThreatBookAPIKey     string    `json:"threatbook_api_key,omitempty"`
	WhoisXMLAPIKey       string    `json:"whoisxmlapi_key,omitempty"`
	ZoomEyeAPIKey        string    `json:"zoomeye_api_key,omitempty"`
}

func EnsureFirstRun(enabled, force, verbose bool) (*ProviderState, error) {
	path, err := statePath()
	if err != nil {
		return nil, err
	}
	state, err := loadState(path)
	if err != nil {
		return nil, err
	}
	if state != nil && state.SetupCompleted && !force {
		if err := applyProviderState(state, verbose); err != nil {
			return nil, err
		}
		return state, nil
	}
	if !enabled && !force {
		if state != nil {
			if err := applyProviderState(state, verbose); err != nil {
				return nil, err
			}
		}
		return state, nil
	}
	if !isInteractive(os.Stdin) {
		if force {
			return nil, fmt.Errorf("setup requested but stdin is not interactive")
		}
		if state != nil {
			if err := applyProviderState(state, verbose); err != nil {
				return nil, err
			}
		}
		return state, nil
	}
	if state == nil {
		state = &ProviderState{}
	}
	if err := runWizard(state); err != nil {
		return nil, err
	}
	state.SetupCompleted = true
	state.UpdatedAt = time.Now().UTC()
	if err := saveState(path, state); err != nil {
		return nil, err
	}
	if err := applyProviderState(state, verbose); err != nil {
		return nil, err
	}
	if verbose {
		fmt.Printf("[setup] saved provider state: %s\n", path)
	}
	return state, nil
}

func applyProviderState(state *ProviderState, verbose bool) error {
	if state == nil {
		return nil
	}
	setIfValue("PDCP_API_KEY", state.ChaosAPIKey)
	setIfValue("CHAOS_KEY", state.ChaosAPIKey)
	setIfValue("CHAOS_API_KEY", state.ChaosAPIKey)
	setIfValue("CENSYS_API_ID", state.CensysAPIID)
	setIfValue("CENSYS_API_SECRET", state.CensysAPISecret)
	setIfValue("SECURITYTRAILS_API_KEY", state.SecurityTrailsAPIKey)
	setIfValue("VIRUSTOTAL_API_KEY", state.VirusTotalAPIKey)
	setIfValue("SHODAN_API_KEY", state.ShodanAPIKey)
	setIfValue("CERTSPOTTER_API_KEY", state.CertSpotterAPIKey)
	setIfValue("BUFFEROVER_API_KEY", state.BufferOverAPIKey)
	if len(state.GitHubTokens) > 0 {
		setIfValue("GITHUB_TOKEN", state.GitHubTokens[0])
	}
	providerPath, err := subfinderProviderConfigPath()
	if err != nil {
		return err
	}
	if err := writeSubfinderProviderConfig(providerPath, state); err != nil {
		return err
	}
	if providerConfigEntryCount(state) > 0 {
		setIfValue("SUBFINDER_PROVIDER_CONFIG", providerPath)
		if verbose {
			fmt.Printf("[setup] subfinder provider config: %s\n", providerPath)
		}
	}
	if verbose {
		fmt.Printf("[setup] provider entries loaded: %d\n", providerConfigEntryCount(state))
	}
	return nil
}

func runWizard(state *ProviderState) error {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("[setup] first-run provider setup")
	fmt.Println("[setup] press Enter to skip any value")
	configure, err := promptYesNo(reader, "Configure API keys now? [Y/n]: ", true)
	if err != nil {
		return err
	}
	if !configure {
		return nil
	}

	state.ChaosAPIKey, err = promptValue(reader, "ProjectDiscovery / Chaos API key: ")
	if err != nil {
		return err
	}
	state.GitHubTokens, err = promptCSV(reader, "GitHub token(s), comma-separated: ")
	if err != nil {
		return err
	}
	state.CensysAPIID, err = promptValue(reader, "Censys API ID: ")
	if err != nil {
		return err
	}
	if state.CensysAPIID != "" {
		state.CensysAPISecret, err = promptValue(reader, "Censys API secret: ")
		if err != nil {
			return err
		}
	}
	state.SecurityTrailsAPIKey, err = promptValue(reader, "SecurityTrails API key: ")
	if err != nil {
		return err
	}
	state.VirusTotalAPIKey, err = promptValue(reader, "VirusTotal API key: ")
	if err != nil {
		return err
	}
	state.ShodanAPIKey, err = promptValue(reader, "Shodan API key: ")
	if err != nil {
		return err
	}
	state.CertSpotterAPIKey, err = promptValue(reader, "CertSpotter API key: ")
	if err != nil {
		return err
	}
	state.BufferOverAPIKey, err = promptValue(reader, "BufferOver API key: ")
	if err != nil {
		return err
	}
	moreProviders, err := promptYesNo(reader, "Configure extended passive-source provider keys for broader coverage? [y/N]: ", false)
	if err != nil {
		return err
	}
	if !moreProviders {
		return nil
	}
	state.BeVigilAPIKey, err = promptValue(reader, "BeVigil API key: ")
	if err != nil {
		return err
	}
	state.BinaryEdgeAPIKey, err = promptValue(reader, "BinaryEdge API key: ")
	if err != nil {
		return err
	}
	state.C99APIKey, err = promptValue(reader, "C99.nl API key: ")
	if err != nil {
		return err
	}
	state.FOFAEmail, err = promptValue(reader, "FOFA email: ")
	if err != nil {
		return err
	}
	if state.FOFAEmail != "" {
		state.FOFAKey, err = promptValue(reader, "FOFA key: ")
		if err != nil {
			return err
		}
	}
	state.FullHuntAPIKey, err = promptValue(reader, "FullHunt API key: ")
	if err != nil {
		return err
	}
	state.HunterAPIKey, err = promptValue(reader, "Hunter API key: ")
	if err != nil {
		return err
	}
	state.IntelXAPIKey, err = promptValue(reader, "IntelX API key: ")
	if err != nil {
		return err
	}
	state.LeakIXAPIKey, err = promptValue(reader, "LeakIX API key: ")
	if err != nil {
		return err
	}
	state.NetlasAPIKey, err = promptValue(reader, "Netlas API key: ")
	if err != nil {
		return err
	}
	state.PassiveTotalUser, err = promptValue(reader, "PassiveTotal username or email: ")
	if err != nil {
		return err
	}
	if state.PassiveTotalUser != "" {
		state.PassiveTotalKey, err = promptValue(reader, "PassiveTotal key: ")
		if err != nil {
			return err
		}
	}
	state.QuakeAPIKey, err = promptValue(reader, "Quake API key: ")
	if err != nil {
		return err
	}
	state.RobtexAPIKey, err = promptValue(reader, "Robtex API key: ")
	if err != nil {
		return err
	}
	state.ThreatBookAPIKey, err = promptValue(reader, "ThreatBook API key: ")
	if err != nil {
		return err
	}
	state.WhoisXMLAPIKey, err = promptValue(reader, "WhoisXML API key: ")
	if err != nil {
		return err
	}
	state.ZoomEyeAPIKey, err = promptValue(reader, "ZoomEye API key: ")
	if err != nil {
		return err
	}
	return nil
}

func loadState(path string) (*ProviderState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var state ProviderState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("decode provider state: %w", err)
	}
	return &state, nil
}

func saveState(path string, state *ProviderState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func statePath() (string, error) {
	base, err := baseConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "providers.json"), nil
}

func subfinderProviderConfigPath() (string, error) {
	if override := strings.TrimSpace(os.Getenv("ULTRARECON_SUBFINDER_PROVIDER_CONFIG")); override != "" {
		return override, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "subfinder", "provider-config.yaml"), nil
}

func baseConfigDir() (string, error) {
	if override := strings.TrimSpace(os.Getenv("ULTRARECON_CONFIG_HOME")); override != "" {
		return override, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "ultrarecon"), nil
}

func writeSubfinderProviderConfig(path string, state *ProviderState) error {
	lines := buildSubfinderProviderLines(state)
	if len(lines) == 0 {
		_ = os.Remove(path)
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	content := strings.Join(lines, "\n") + "\n"
	return os.WriteFile(path, []byte(content), 0o600)
}

func buildSubfinderProviderLines(state *ProviderState) []string {
	if state == nil {
		return nil
	}
	out := make([]string, 0, 32)
	appendList := func(name string, vals []string) {
		clean := normalizeList(vals)
		if len(clean) == 0 {
			return
		}
		out = append(out, name+":")
		for _, v := range clean {
			out = append(out, "  - "+yamlQuote(v))
		}
	}
	appendPair := func(name, left, right string) {
		left = strings.TrimSpace(left)
		right = strings.TrimSpace(right)
		if left == "" || right == "" {
			return
		}
		appendList(name, []string{left + ":" + right})
	}
	appendList("chaos", singleToList(state.ChaosAPIKey))
	appendList("github", state.GitHubTokens)
	appendPair("censys", state.CensysAPIID, state.CensysAPISecret)
	appendList("securitytrails", singleToList(state.SecurityTrailsAPIKey))
	appendList("virustotal", singleToList(state.VirusTotalAPIKey))
	appendList("shodan", singleToList(state.ShodanAPIKey))
	appendList("certspotter", singleToList(state.CertSpotterAPIKey))
	appendList("bufferover", singleToList(state.BufferOverAPIKey))
	appendList("bevigil", singleToList(state.BeVigilAPIKey))
	appendList("binaryedge", singleToList(state.BinaryEdgeAPIKey))
	appendList("c99", singleToList(state.C99APIKey))
	appendPair("fofa", state.FOFAEmail, state.FOFAKey)
	appendList("fullhunt", singleToList(state.FullHuntAPIKey))
	appendList("hunter", singleToList(state.HunterAPIKey))
	appendList("intelx", singleToList(state.IntelXAPIKey))
	appendList("leakix", singleToList(state.LeakIXAPIKey))
	appendList("netlas", singleToList(state.NetlasAPIKey))
	appendPair("passivetotal", state.PassiveTotalUser, state.PassiveTotalKey)
	appendList("quake", singleToList(state.QuakeAPIKey))
	appendList("robtex", singleToList(state.RobtexAPIKey))
	appendList("threatbook", singleToList(state.ThreatBookAPIKey))
	appendList("whoisxmlapi", singleToList(state.WhoisXMLAPIKey))
	appendList("zoomeyeapi", singleToList(state.ZoomEyeAPIKey))
	return out
}

func providerConfigEntryCount(state *ProviderState) int {
	return len(buildSubfinderProviderLines(state))
}

func promptYesNo(reader *bufio.Reader, label string, defaultYes bool) (bool, error) {
	fmt.Print(label)
	line, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	v := strings.ToLower(strings.TrimSpace(line))
	if v == "" {
		return defaultYes, nil
	}
	return v == "y" || v == "yes", nil
}

func promptValue(reader *bufio.Reader, label string) (string, error) {
	fmt.Print(label)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func promptCSV(reader *bufio.Reader, label string) ([]string, error) {
	val, err := promptValue(reader, label)
	if err != nil {
		return nil, err
	}
	if val == "" {
		return nil, nil
	}
	parts := strings.Split(val, ",")
	return normalizeList(parts), nil
}

func normalizeList(vals []string) []string {
	if len(vals) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(vals))
	out := make([]string, 0, len(vals))
	for _, val := range vals {
		val = strings.TrimSpace(val)
		if val == "" {
			continue
		}
		if _, ok := seen[val]; ok {
			continue
		}
		seen[val] = struct{}{}
		out = append(out, val)
	}
	return out
}

func singleToList(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return []string{strings.TrimSpace(v)}
}

func setIfValue(name, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	if strings.TrimSpace(os.Getenv(name)) != "" {
		return
	}
	_ = os.Setenv(name, value)
}

func yamlQuote(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	return `"` + v + `"`
}

func isInteractive(f *os.File) bool {
	if f == nil {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}
