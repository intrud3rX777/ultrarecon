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
- URL and endpoint collection from crawlers and archive sources
- Content discovery with `ffuf`
- Automated security checks with `nuclei`
- Clean final reports by default
- Windows and Linux support
- Auto-install of supported dependencies with `--install-tools`

## Recon Phases

### Phase 1: Subdomain Enumeration

This phase discovers in-scope subdomains using:

- Passive sources: `subfinder`, `assetfinder`, `amass`, `crt.sh`, `certspotter`, `anubis`, `rapiddns`, `bufferover`, `hackertarget`, and others
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

### Phase 3: Surface Mapping

This phase builds a normalized web asset inventory:

- Crawl collection with `katana`
- Archive collection with `gau` and `waybackurls`
- URL collection with `urlfinder`
- URL normalization, categorization, and parameter extraction

Final outputs:

- `surface_urls.txt`
- `surface_endpoints.jsonl`

### Phase 4: Content Discovery

This phase expands the reachable attack surface:

- Targeted path discovery with `ffuf`
- Parameter-key aggregation from mapped endpoints
- Prioritization of auth, admin, API, and upload paths

Final outputs:

- `content_paths.jsonl`
- `param_keys.txt`

### Phase 5: Security Checks

This phase runs high-signal automated checks:

- Curated `nuclei` runs over prioritized URLs
- Focus on medium/high/critical findings
- Structured output for downstream review

Final output:

- `security_findings.jsonl`

## Installation

### Build From Source

Linux or macOS:

```bash
go build -o ultrarecon ./cmd/ultrarecon
```

Windows:

```powershell
go build -o ultrarecon.exe ./cmd/ultrarecon
```

### Auto-Install Dependencies

UltraRecon can install supported tools automatically:

```bash
./ultrarecon -d example.com --install-tools --install-optional
```

This only installs missing supported tools. Existing tools are reused.

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
./ultrarecon -d example.com --phase probe --subdomains-in final_subdomains.txt --modules service-discovery,surface-mapping,content-discovery,security-checks,http-probe -v
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
- `--final-only`: write only final artifacts
- `-v`, `--verbose`: show stage-by-stage execution
- `--profile`: `speed`, `balanced`, or `strict`
- `--home-safe`: safer limits for home or unstable links
- `--resolvers`: custom resolver file
- `--trickest-resolvers`: use Trickest resolver lists when no resolver file is supplied

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
- `content-discovery`
- `security-checks`
- `http-probe`
- `all`

## Output Model

By default UltraRecon writes only clean, final artifacts:

- `final_subdomains.txt`
- `live_subdomains.txt`
- `scored_subdomains.jsonl`
- `service_assets.jsonl`
- `surface_urls.txt`
- `surface_endpoints.jsonl`
- `content_paths.jsonl`
- `param_keys.txt`
- `security_findings.jsonl`
- `summary.json`
- `report.md`
- `ultrarecon.log`

If you want intermediate artifacts too:

```bash
./ultrarecon -d example.com --final-only=false
```

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

## GitHub Publishing

This workspace is ready to publish, but Git is not available in the current environment and no GitHub CLI or token is configured. Once `git` is installed and authenticated, the usual flow is:

```bash
git init
git add .
git commit -m "Initial UltraRecon release"
git branch -M main
git remote add origin <your-repo-url>
git push -u origin main
```
