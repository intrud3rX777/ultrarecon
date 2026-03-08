# UltraRecon

UltraRecon is a fast, accuracy-focused reconnaissance framework written in Go. It is designed to outperform shell-heavy recon pipelines by combining aggressive parallelism with stricter validation, wildcard control, resolver quality filtering, and clean phase-based outputs.

## What It Does

UltraRecon runs reconnaissance in modular phases:

- Phase 1: subdomain enumeration
- Phase 2: host and service discovery
- Phase 3: web surface mapping
- Phase 4: content and parameter discovery
- Phase 5: automated security checks

Each phase can run independently or as part of a full pipeline.

## Key Features

- Fast passive enumeration with multiple sources and external tools
- DNS validation with resolver benchmarking and noisy resolver rejection
- Wildcard detection and filtering
- Root bruteforce, recursive bruteforce, gotator mutations, and DNS pivots
- ASN and CIDR-based discovery with PTR enrichment
- Service discovery with `naabu`, `httpx`, and `tlsx`
- Visual validation with screenshots for final live subdomains
- URL and endpoint collection from crawlers and archive sources
- JavaScript analysis for extra endpoints and in-scope hosts
- Content discovery with `ffuf`
- Automated security checks with `nuclei`
- Clean final reports by default
- Stage-by-stage progress output by default, with exact command traces under `-v`
- Optional passive-source diagnostics with explicit skip, fail, and downgrade reasons
- Windows and Linux support
- Auto-install of supported dependencies with `--install-tools`
- Persistent stage checkpoints with `--resume` and `--resume-from`

## Recon Phases

### Phase 1: Subdomain Enumeration

This phase discovers in-scope subdomains using:

- Passive sources: `subfinder`, `assetfinder`, `amass`, `crt.sh`, `certspotter`, `anubis`, `rapiddns`, `alienvault`, `hackertarget`, and provider-backed sources configured through first-run setup
- DNS pivots from CNAME, NS, MX, SRV, TXT, and PTR data
- ASN and CIDR expansion with `asnmap`
- Bruteforce and recursive bruteforce
- Gotator-based mutations
- CSP, archive, TLS, scraping, and analytics enrichment

Final outputs:

- `final_subdomains.txt`
- `live_subdomains.txt`
- `scored_subdomains.jsonl`

### Phase 2: Service Discovery

This phase takes resolved hosts and identifies exposed services:

- Port discovery with `naabu`
- HTTP fingerprinting with `httpx`
- TLS metadata enrichment with `tlsx`

Final output:

- `service_assets.jsonl`

### Visual Validation

After live HTTP probing, UltraRecon can capture screenshots for final live subdomains using a local Chromium-based browser.

Final outputs:

- `screenshots.jsonl`
- `screenshots_gallery.html`
- `screenshots/`

### Phase 3: Surface Mapping

This phase builds a normalized web asset inventory:

- Crawl collection with `katana`
- Archive collection with `gau` and `waybackurls`
- URL collection with `urlfinder`
- URL normalization, categorization, and parameter extraction

Final outputs:

- `surface_urls.txt`
- `surface_endpoints.jsonl`
- `js_analysis.jsonl`

### Phase 4: Content Discovery

This phase expands the reachable attack surface:

- Targeted path discovery with `ffuf`
- Parameter-key aggregation from mapped endpoints
- Prioritization of auth, admin, API, and upload paths

Final outputs:

- `content_paths.jsonl`
- `ffuf_results.jsonl`
- `param_keys.txt`

### Phase 5: Security Checks

This phase runs high-signal automated checks:

- Curated `nuclei` runs over prioritized URLs
- Focus on medium/high/critical findings
- Structured output for downstream review

Final output:

- `security_findings.jsonl`

## Installation

Clone the repository first:

```bash
git clone https://github.com/intrud3rX777/ultrarecon.git
cd ultrarecon
```

### Build From Source

Linux or macOS:

```bash
go build -o ultrarecon ./cmd/ultrarecon
```

Windows:

```powershell
go build -o ultrarecon.exe ./cmd/ultrarecon
```

Run commands:

- Linux or macOS: `./ultrarecon`
- Windows PowerShell: `.\ultrarecon.exe`

### Auto-Install Dependencies

UltraRecon can install supported tools automatically:

```bash
./ultrarecon -d example.com --install-tools --install-optional
```

Windows PowerShell:

```powershell
.\ultrarecon.exe -d example.com --install-tools --install-optional
```

This only installs missing supported tools. Existing tools are reused.

Screenshot capture requires a local Chromium-based browser at runtime. UltraRecon will use Chrome, Edge, Chromium, or Brave if one is present. You can also point it explicitly with `CHROME_PATH`.

## First-Run Provider Setup

On the first interactive run, UltraRecon can prompt for optional API keys and tokens used by provider-backed passive sources.

Supported saved entries currently include:

- ProjectDiscovery or Chaos API key
- GitHub token(s)
- Censys API ID and secret
- SecurityTrails API key
- VirusTotal API key
- Shodan API key
- CertSpotter API key
- BufferOver API key
- Extended optional providers for broader subfinder coverage such as BeVigil, BinaryEdge, C99, FOFA, FullHunt, Hunter, IntelX, LeakIX, Netlas, PassiveTotal, Quake, Robtex, ThreatBook, WhoisXML, and ZoomEye

Behavior:

- Press `Enter` on any prompt to skip it
- The saved state is reused on later runs
- UltraRecon writes a `subfinder` `provider-config.yaml` automatically from the answers
- A second extended-provider section is optional and defaults to skip
- Use `--setup-force` to rerun the wizard and replace the saved values
- Use `--setup=false` to disable the prompt for a run

## Quick Start

Run the full pipeline:

```bash
./ultrarecon -d example.com --phase all --install-tools -v
```

Run only subdomain enumeration:

```bash
./ultrarecon -d example.com --phase subdomains -o out_subs -v
```

Run later phases from an existing subdomain list:

```bash
./ultrarecon -d example.com --phase probe --subdomains-in final_subdomains.txt --modules service-discovery,surface-mapping,content-discovery,security-checks,http-probe,screenshots -v
```

Windows PowerShell equivalents:

```powershell
.\ultrarecon.exe -d example.com --phase all --install-tools -v
.\ultrarecon.exe -d example.com --phase subdomains -o out_subs -v
.\ultrarecon.exe -d example.com --phase probe --subdomains-in final_subdomains.txt --modules service-discovery,surface-mapping,content-discovery,security-checks,http-probe,screenshots -v
```

Resume an interrupted run from the latest checkpoint in the same output directory:

```bash
./ultrarecon -d example.com --phase all -o output_ultra --resume -v
```

Resume from a specific previously checkpointed stage:

```bash
./ultrarecon -d example.com --phase all -o output_ultra --resume-from write_artifacts -v
```

## Common Usage

### Full Recon

```bash
./ultrarecon -d example.com --phase all --install-tools --install-optional -o output_ultra -v
```

### Phase 1 Only

```bash
./ultrarecon -d example.com --phase subdomains --modules all -o out_subdomains -v
```

### Phase 2 Only

```bash
./ultrarecon -d example.com --phase probe --subdomains-in final_subdomains.txt --modules service-discovery,http-probe -v
```

### Live Host Screenshots Only

```bash
./ultrarecon -d example.com --phase probe --subdomains-in final_subdomains.txt --modules http-probe,screenshots -v
```

### Phases 3, 4, and 5

```bash
./ultrarecon -d example.com --phase probe --subdomains-in final_subdomains.txt --modules surface-mapping,content-discovery,security-checks,http-probe -v
```

### Custom Resolver File

```bash
./ultrarecon -d example.com --resolvers resolvers.txt --max-resolvers 64
```

### Use Trickest Public Resolvers

```bash
./ultrarecon -d example.com --trickest-resolvers=true --max-resolver-pool 1800 --max-resolvers 64
```

### Passive Diagnostics

```bash
./ultrarecon -d example.com --phase subdomains --diagnostics -v
```

### Home Network Safe Mode

```bash
./ultrarecon -d example.com --home-safe
```

### VPS or Lab Mode

```bash
./ultrarecon -d example.com --home-safe=false --profile speed
```

## Important Flags

- `-d`, `--domain`: target domain
- `--phase`: `all`, `subdomains`, or `probe`
- `--modules`: run only specific modules
- `--subdomains-in`: input file for `probe` phase
- `--install-tools`: install missing supported dependencies
- `--install-optional`: also install optional tools
- `--setup`: enable or disable the first-run provider prompt
- `--setup-force`: rerun the first-run provider prompt and overwrite saved values
- `--diagnostics`: print and save passive-source diagnostics
- `--final-only`: write only final artifacts
- `--resume`: continue from the latest saved checkpoint in the output directory
- `--resume-from`: restart from a specific previously checkpointed stage
- `-v`, `--verbose`: show exact command traces in addition to stage progress
- `--profile`: `speed`, `balanced`, or `strict`
- `--home-safe`: safer limits for home or unstable links
- `--resolvers`: custom resolver file
- `--trickest-resolvers`: use Trickest resolver lists when no resolver file is supplied
- `--screenshots`: capture screenshots for final live subdomains
- `--max-screenshot-targets`: cap how many live URLs are captured
- `--screenshot-concurrency`: parallel screenshot workers
- `--screenshot-timeout`: timeout per screenshot
- `--js-analysis`: analyze JavaScript files discovered during surface mapping
- `--max-js-files`: cap JavaScript files fetched for analysis
- `--max-js-discoveries`: cap URLs/endpoints retained from JavaScript analysis
- `--security-timeout`: timeout per `nuclei` attempt during security checks

## Supported Module Names

- `passive`
- `noerror`
- `dns-pivot`
- `asn-expansion`
- `zone-transfer`
- `bruteforce`
- `recursive`
- `recursive-brute`
- `enrichment`
- `analytics`
- `scraping`
- `permutations`
- `gotator`
- `service-discovery`
- `surface-mapping`
- `js-analysis`
- `content-discovery`
- `security-checks`
- `http-probe`
- `screenshots`
- `all`

## Output Model

By default UltraRecon writes only clean, final artifacts:

- `final_subdomains.txt`
- `live_subdomains.txt`
- `scored_subdomains.jsonl`
- `service_assets.jsonl` when service discovery is enabled
- `surface_urls.txt` and `surface_endpoints.jsonl` when surface mapping is enabled
- `js_analysis.jsonl` when JavaScript analysis is enabled
- `content_paths.jsonl`, `ffuf_results.jsonl`, and `param_keys.txt` when content discovery is enabled
- `security_findings.jsonl` when security checks are enabled
- `screenshots.jsonl`, `screenshots_gallery.html`, and `screenshots/` when screenshots are enabled
- `passive_diagnostics.jsonl` when `--diagnostics` is enabled
- `summary.json`
- `report.md`
- `ultrarecon.log`

UltraRecon also keeps internal checkpoint files under `.ultrarecon/` inside the output directory so interrupted runs can continue safely.

If you want intermediate artifacts too:

```bash
./ultrarecon -d example.com --final-only=false
```

## Progress Output

UltraRecon prints clean progress by default:

- planned stage count
- current stage number and name
- per-stage result summaries such as resolver counts, live hosts, and screenshots captured

Use `-v` when you want exact external command traces in addition to the stage-level output.

## Accuracy Controls

UltraRecon is built to avoid the common failure modes of fast recon tools:

- It benchmarks resolvers before use
- It rejects weak or noisy resolvers
- It limits oversized resolver pools before they hurt speed
- It applies consensus-based DNS resolution
- It filters wildcard-heavy parents
- It keeps phase outputs separated and structured

## Safety Notes

- Use this only against targets you are authorized to test
- `--home-safe` is enabled by default for conservative network behavior
- For heavier scans, use a VPS or lab environment
- Some modules depend on external tools such as `naabu`, `ffuf`, and `nuclei`

## Repository

GitHub: `https://github.com/intrud3rX777/ultrarecon`


