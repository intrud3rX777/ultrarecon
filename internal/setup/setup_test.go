package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildSubfinderProviderLines(t *testing.T) {
	state := &ProviderState{
		ChaosAPIKey:          "chaos-key",
		GitHubTokens:         []string{"gh-one", "gh-one", "gh-two"},
		CensysAPIID:          "id",
		CensysAPISecret:      "secret",
		SecurityTrailsAPIKey: "securitytrails-key",
		VirusTotalAPIKey:     "virustotal-key",
		ShodanAPIKey:         "shodan-key",
		CertSpotterAPIKey:    "certspotter-key",
		BufferOverAPIKey:     "bufferover-key",
	}

	joined := strings.Join(buildSubfinderProviderLines(state), "\n")
	checks := []string{
		"chaos:\n  - \"chaos-key\"",
		"github:\n  - \"gh-one\"\n  - \"gh-two\"",
		"censys:\n  - \"id:secret\"",
		"securitytrails:\n  - \"securitytrails-key\"",
		"virustotal:\n  - \"virustotal-key\"",
		"shodan:\n  - \"shodan-key\"",
		"certspotter:\n  - \"certspotter-key\"",
		"bufferover:\n  - \"bufferover-key\"",
	}
	for _, want := range checks {
		if !strings.Contains(joined, want) {
			t.Fatalf("provider config missing %q in %q", want, joined)
		}
	}
}

func TestApplyProviderStateWritesProviderConfig(t *testing.T) {
	providerPath := filepath.Join(t.TempDir(), "provider-config.yaml")
	t.Setenv("ULTRARECON_SUBFINDER_PROVIDER_CONFIG", providerPath)
	t.Setenv("PDCP_API_KEY", "")
	t.Setenv("CHAOS_KEY", "")
	t.Setenv("CHAOS_API_KEY", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("SUBFINDER_PROVIDER_CONFIG", "")

	state := &ProviderState{
		ChaosAPIKey:  "chaos-key",
		GitHubTokens: []string{"gh-token"},
	}
	if err := applyProviderState(state, false); err != nil {
		t.Fatalf("applyProviderState error: %v", err)
	}
	if got := os.Getenv("PDCP_API_KEY"); got != "chaos-key" {
		t.Fatalf("PDCP_API_KEY=%q", got)
	}
	if got := os.Getenv("GITHUB_TOKEN"); got != "gh-token" {
		t.Fatalf("GITHUB_TOKEN=%q", got)
	}
	if got := os.Getenv("SUBFINDER_PROVIDER_CONFIG"); got != providerPath {
		t.Fatalf("SUBFINDER_PROVIDER_CONFIG=%q", got)
	}
	data, err := os.ReadFile(providerPath)
	if err != nil {
		t.Fatalf("read provider config: %v", err)
	}
	if !strings.Contains(string(data), "chaos:") {
		t.Fatalf("provider config missing chaos entry: %q", string(data))
	}
}

func TestApplyProviderStateSkipsEmptyProviderConfig(t *testing.T) {
	providerPath := filepath.Join(t.TempDir(), "provider-config.yaml")
	t.Setenv("ULTRARECON_SUBFINDER_PROVIDER_CONFIG", providerPath)
	t.Setenv("SUBFINDER_PROVIDER_CONFIG", "")

	if err := applyProviderState(&ProviderState{}, false); err != nil {
		t.Fatalf("applyProviderState error: %v", err)
	}
	if got := os.Getenv("SUBFINDER_PROVIDER_CONFIG"); got != "" {
		t.Fatalf("SUBFINDER_PROVIDER_CONFIG=%q", got)
	}
	if _, err := os.Stat(providerPath); !os.IsNotExist(err) {
		t.Fatalf("expected no provider config file, got err=%v", err)
	}
}
