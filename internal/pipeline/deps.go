package pipeline

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"ultrarecon/internal/config"
	"ultrarecon/internal/util"
)

type DependencyResult struct {
	Installed []string
	Failed    []ToolError
	Skipped   []string
}

type dependency struct {
	Name      string
	Install   []string
	Platforms map[string]bool
}

func EnsureDependencies(ctx context.Context, cfg config.Config, installOptional bool, timeout time.Duration, verbose bool) DependencyResult {
	ensureGoBinOnPath()
	res := DependencyResult{
		Installed: make([]string, 0, 16),
		Failed:    make([]ToolError, 0, 8),
		Skipped:   make([]string, 0, 8),
	}
	required := requiredToolsForConfig(cfg)

	deps := []dependency{
		{Name: "subfinder", Install: []string{"go", "install", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"}},
		{Name: "assetfinder", Install: []string{"go", "install", "github.com/tomnomnom/assetfinder@latest"}},
		{Name: "amass", Install: []string{"go", "install", "github.com/owasp-amass/amass/v5/cmd/amass@main"}},
		{Name: "chaos", Install: []string{"go", "install", "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"}},
		{Name: "asnmap", Install: []string{"go", "install", "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"}},
		{Name: "dnsx", Install: []string{"go", "install", "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"}},
		{Name: "naabu", Install: []string{"go", "install", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"}},
		{Name: "shuffledns", Install: []string{"go", "install", "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"}},
		{Name: "httpx", Install: []string{"go", "install", "github.com/projectdiscovery/httpx/cmd/httpx@latest"}},
		{Name: "tlsx", Install: []string{"go", "install", "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"}},
		{Name: "nuclei", Install: []string{"go", "install", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"}},
		{Name: "ffuf", Install: []string{"go", "install", "github.com/ffuf/ffuf/v2@latest"}},
		{Name: "katana", Install: []string{"go", "install", "github.com/projectdiscovery/katana/cmd/katana@latest"}},
		{Name: "hakrawler", Install: []string{"go", "install", "github.com/hakluke/hakrawler@latest"}},
		{Name: "gospider", Install: []string{"go", "install", "github.com/jaeles-project/gospider@latest"}},
		{Name: "gau", Install: []string{"go", "install", "github.com/lc/gau/v2/cmd/gau@latest"}},
		{Name: "waybackurls", Install: []string{"go", "install", "github.com/tomnomnom/waybackurls@latest"}},
		{Name: "urlfinder", Install: []string{"go", "install", "github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest"}},
		{Name: "analyticsrelationships", Install: []string{"go", "install", "github.com/Josue87/AnalyticsRelationships@latest"}},
		{Name: "gotator", Install: []string{"go", "install", "github.com/Josue87/gotator@latest"}},
		{Name: "hakip2host", Install: []string{"go", "install", "github.com/hakluke/hakip2host@latest"}},
		{Name: "csprecon", Install: []string{"go", "install", "github.com/edoardottt/csprecon/cmd/csprecon@latest"}},
		{Name: "findomain", Install: nil, Platforms: map[string]bool{"linux": true, "darwin": true}},
	}

	for _, dep := range deps {
		if len(dep.Platforms) > 0 && !dep.Platforms[runtime.GOOS] {
			if verbose {
				fmt.Printf("[bootstrap] skip %s: unsupported on %s\n", dep.Name, runtime.GOOS)
			}
			res.Skipped = append(res.Skipped, dep.Name)
			continue
		}
		if util.HaveCommand(dep.Name) {
			if verbose {
				fmt.Printf("[bootstrap] present: %s\n", dep.Name)
			}
			continue
		}
		requiredForRun := required[dep.Name]
		if !requiredForRun && !installOptional {
			if verbose {
				fmt.Printf("[bootstrap] skip %s: optional and --install-optional=false\n", dep.Name)
			}
			res.Skipped = append(res.Skipped, dep.Name)
			continue
		}
		if len(dep.Install) == 0 {
			if !requiredForRun {
				if verbose {
					fmt.Printf("[bootstrap] skip %s: no auto-installer available\n", dep.Name)
				}
				res.Skipped = append(res.Skipped, dep.Name)
				continue
			}
			res.Failed = append(res.Failed, ToolError{
				Stage: "bootstrap",
				Tool:  dep.Name,
				Error: "no auto-installer for this tool on current platform",
			})
			continue
		}
		if err := runInstallCommand(ctx, timeout, dep.Install, verbose); err != nil {
			res.Failed = append(res.Failed, ToolError{
				Stage: "bootstrap",
				Tool:  dep.Name,
				Error: err.Error(),
			})
			continue
		}
		if util.HaveCommand(dep.Name) {
			res.Installed = append(res.Installed, dep.Name)
			continue
		}

		// Go install may place binaries in GOPATH/bin not present in PATH yet.
		ensureGoBinOnPath()
		if util.HaveCommand(dep.Name) {
			res.Installed = append(res.Installed, dep.Name)
		} else {
			res.Failed = append(res.Failed, ToolError{
				Stage: "bootstrap",
				Tool:  dep.Name,
				Error: "install command completed but tool still not found in PATH",
			})
		}
	}

	return res
}

func requiredToolsForConfig(cfg config.Config) map[string]bool {
	req := make(map[string]bool)
	if cfg.EnablePassive && cfg.Phase != "probe" {
		req["subfinder"] = true
		req["assetfinder"] = true
		req["amass"] = true
	}
	if cfg.EnableBruteforce || cfg.EnableRecursiveBrute {
		req["dnsx"] = true
		req["shuffledns"] = true
	}
	if cfg.EnableASNExpansion {
		req["asnmap"] = true
	}
	if cfg.EnableCSPExtraction {
		req["httpx"] = true
	}
	if cfg.EnableTLSEnumeration {
		req["tlsx"] = true
	}
	if cfg.EnableArchiveSources {
		req["gau"] = true
		req["waybackurls"] = true
	}
	if cfg.EnableAnalyticsPivot {
		req["analyticsrelationships"] = true
	}
	if cfg.EnableGotator {
		req["gotator"] = true
	}
	if cfg.EnableServiceDiscovery {
		req["naabu"] = true
		req["httpx"] = true
		req["tlsx"] = true
	}
	if cfg.EnableSurfaceMapping {
		req["katana"] = true
		req["gau"] = true
		req["waybackurls"] = true
		req["urlfinder"] = true
	}
	if cfg.EnableContentDiscovery {
		req["ffuf"] = true
	}
	if cfg.EnableSecurityChecks {
		req["nuclei"] = true
	}
	if cfg.EnableScrapingPivot {
		req["katana"] = true
	}
	return req
}

func runInstallCommand(ctx context.Context, timeout time.Duration, cmdArgs []string, verbose bool) error {
	if len(cmdArgs) == 0 {
		return fmt.Errorf("empty install command")
	}
	runCtx := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(runCtx, cmdArgs[0], cmdArgs[1:]...)
	if verbose {
		fmt.Printf("[bootstrap] installing: %s\n", strings.Join(cmdArgs, " "))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s failed: %w", strings.Join(cmdArgs, " "), err)
	}
	return nil
}

func ensureGoBinOnPath() {
	gopath := os.Getenv("GOPATH")
	if strings.TrimSpace(gopath) == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return
		}
		if runtime.GOOS == "windows" {
			gopath = filepath.Join(home, "go")
		} else {
			gopath = filepath.Join(home, "go")
		}
	}
	goBin := filepath.Join(gopath, "bin")
	pathVar := os.Getenv("PATH")
	sep := string(os.PathListSeparator)
	parts := strings.Split(pathVar, sep)
	for _, p := range parts {
		if strings.EqualFold(strings.TrimSpace(p), strings.TrimSpace(goBin)) {
			return
		}
	}
	if pathVar == "" {
		_ = os.Setenv("PATH", goBin)
		return
	}
	_ = os.Setenv("PATH", goBin+sep+pathVar)
}
