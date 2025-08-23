#!/bin/bash
# ReconPro v2.0 — Advanced Professional Recon Framework
# Author: RedVortex
# License: MIT (default). If --pro is used, commercial license terms apply.

# ------------------ CONFIGURATION & SETUP ------------------
set -o errexit    # Exit immediately if a command exits with a non-zero status.
set -o pipefail   # Exit if any command in a pipeline fails.
set -o nounset    # Treat unset variables as an error.
IFS=$'\n\t'       # Internal Field Separator for robust word splitting.

# Global variables (initialized to safe defaults)
CFG_FILE="./reconpro.conf"
LOGFILE="./reconpro.log"
OUTDIR="./reports"
PARALLEL=8
PRO_MODE=false
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
TARGETS=()
SCOPE_FILE=""
RECONPRO_LICENSE_KEY="" # Placeholder for license key

# API Keys (loaded from config or env)
SHODAN_API_KEY=""
CENSYS_API_KEY=""
CENSYS_API_SECRET=""
VIRUSTOTAL_API_KEY=""
SLACK_WEBHOOK_URL=""
TELEGRAM_BOT_TOKEN=""
TELEGRAM_CHAT_ID=""
DISCORD_WEBHOOK_URL=""

# Module control arrays (initialized as empty)
ONLY_MODULES=()
SKIP_MODULES=()
NO_CLEANUP=false

# ------------------ HELPER FUNCTIONS ------------------

# Colorized output
color() {
  case "$1" in
    red)    printf "\e[31m%s\e[0m" "$2";;
    green)  printf "\e[32m%s\e[0m" "$2";;
    yellow) printf "\e[33m%s\e[0m" "$2";;
    blue)   printf "\e[34m%s\e[0m" "$2";;
    purple) printf "\e[35m%s\e[0m" "$2";;
    cyan)   printf "\e[36m%s\e[0m" "$2";;
    *)      printf "%s" "$2";;
  esac
}

# Logging function
log() {
  echo "[$(date +"%F %T")] $*" | tee -a "$LOGFILE"
}

# Error and exit function
die() {
  log "$(color red "ERROR: $*")"
  exit 1
}

# Check if a command exists
check_cmd() {
  command -v "$1" >/dev/null 2>&1
}

# Require a command, add to missing list if not found
MISSING_DEPS=()
require() {
  if ! check_cmd "$1"; then
    echo "[!] Missing dependency: $(color yellow "$1")"
    MISSING_DEPS+=("$1")
  fi
}

# Safe filename generation
safe_name() {
  echo "$1" | sed 's/[^a-zA-Z0-9.-]//g'
}

# Load configuration from file
load_config() {
  if [[ -f "$CFG_FILE" ]]; then
    log "Loading configuration from $(color blue "$CFG_FILE")"
    # Source the config file, but protect against arbitrary code execution
    # Only allow specific variable assignments
    while IFS='=' read -r key value; do
      # Remove leading/trailing whitespace and quotes from key and value
      key=$(echo "$key" | xargs)
      value=$(echo "$value" | sed -e 's/^"//' -e 's/"$//' | xargs)

      case "$key" in
        OUTDIR) OUTDIR="$value";;
        PARALLEL) PARALLEL="$value";;
        PRO_MODE) PRO_MODE="$value";;
        RECONPRO_LICENSE_KEY) RECONPRO_LICENSE_KEY="$value";;
        SHODAN_API_KEY) SHODAN_API_KEY="$value";;
        CENSYS_API_KEY) CENSYS_API_KEY="$value";;
        CENSYS_API_SECRET) CENSYS_API_SECRET="$value";;
        VIRUSTOTAL_API_KEY) VIRUSTOTAL_API_KEY="$value";;
        SLACK_WEBHOOK_URL) SLACK_WEBHOOK_URL="$value";;
        TELEGRAM_BOT_TOKEN) TELEGRAM_BOT_TOKEN="$value";;
        TELEGRAM_CHAT_ID) TELEGRAM_CHAT_ID="$value";;
        DISCORD_WEBHOOK_URL) DISCORD_WEBHOOK_URL="$value";;
        # Add other configurable variables here
      esac
    done < "$CFG_FILE"
  fi
}

# ASCII Banner
print_banner() {
  cat << "EOF"
$(color green "
  ____                 ____                           
 |  _ \ ___  ___ ___  / ___| _ __   __ _  ___  _ __   
 | |) / _ \/ __/ __| \__ \| '_ \ / ` |/ _ \| ' \  
 |  _ <  _/\_ \__ \  __) | |) | (| | () | | | | 
 || \\||// |/| ./ \,|\/|| |_| 
                            |_|                       
")
$(color cyan "  v2.0 - Advanced Professional Recon Framework")
$(color yellow "  Author: RedVortex")
$(color purple "  License: MIT / Commercial")
EOF
}

# ------------------ DEPENDENCY CHECK ------------------

# Core dependencies (free features)
CORE_DEPS=(curl jq nmap whatweb sed awk sort uniq xargs grep)
# Pro dependencies (premium features)
PRO_DEPS=(assetfinder subfinder httpx amass linkfinder.py SecretFinder.py gf gau waybackurls katana hakrawler nuclei ffuf dalfox testssl.sh subjack wafw00f)

check_dependencies() {
  log "Checking core dependencies..."
  for d in "${CORE_DEPS[@]}"; do require "$d"; done

  if [ "$PRO_MODE" = true ]; then
    log "Checking Pro mode dependencies..."
    for d in "${PRO_DEPS[@]}"; do require "$d"; done
  fi

  if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    echo "\n$(color red "Missing tools: ${MISSING_DEPS[*]}")"
    echo "$(color yellow "Please install them. Example for Debian/Ubuntu:")"
    echo "$(color yellow "sudo apt update && sudo apt install -y ${MISSING_DEPS[*]}")"
    echo "$(color yellow "For Go tools (assetfinder, subfinder, httpx, amass, gau, waybackurls, katana, hakrawler, ffuf, dalfox, subjack, nuclei, gf, wafw00f):")"
    echo "$(color yellow "go install github.com/tool/repo@latest")"
    echo "$(color yellow "For Python tools (linkfinder.py, SecretFinder.py):")"
    echo "$(color yellow "pip install -r requirements.txt (after cloning their repos)")"
    # die "Exiting due to missing dependencies." # Uncomment to force exit
  fi
}

# ------------------ USAGE & ARGUMENT PARSING ------------------

usage() {
  print_banner
  cat <<EOF
Usage: reconpro.sh [options] -d domain.com | -l targets.txt

Options:
  -d, --domain <domain>         Target domain (e.g., example.com)
  -l, --list <targets.txt>      File with domains (one per line)
  -o, --outdir <dir>            Output directory (default: ./reports)
  -p, --parallel <n>            Parallel jobs (default: 8)
  --pro                         Enable Pro features (requires commercial license/API keys)
  --license <key>               Provide Pro license key (overrides config)
  --scope <file>                File with in-scope targets (one per line)
  --only <module>               Run only specific module(s) (comma-separated, e.g., subs,nmap)
  --skip <module>               Skip specific module(s) (comma-separated, e.g., js,archive)
  --no-cleanup                  Do not remove temporary files
  --config <file>               Specify a custom config file (default: ./reconpro.conf)
  -h, --help                    Show this help

Modules:
  subs      Subdomain Discovery (crt.sh, assetfinder, subfinder, amass)
  js        JS/Endpoint Analysis (linkfinder, SecretFinder, gf patterns)
  archive   Archive URL Scraping (gau, waybackurls, katana, hakrawler)
  vuln      Vulnerability Scanning (Nuclei, ffuf/gobuster, dalfox)
  takeover  Subdomain Takeover Detection (can-i-take-over-xyz)
  cloud     Cloud Misconfig Detection (S3, GCP, Azure, DO)
  waf       WAF/CDN Detection (wafw00f)
  nmap      Port Scanning (nmap)
  http      HTTP Headers & Security Headers
  finger    WhatWeb/Wappalyzer Fingerprinting
  shodan    Shodan Integration (Pro)
  censys    Censys Integration (Pro)
  virustotal VirusTotal Integration (Pro)
  cont      Continuous Recon (Pro)
  notify    Notifications (Pro)
  db        Database Storage (Pro)
  burp      Export to BurpSuite/JSON (Pro)
  fuzz      Smart Fuzzing (Pro)

Examples:
  reconpro.sh -d example.com
  reconpro.sh --pro -l targets.txt -o /tmp/recon_results --only subs,nmap
  reconpro.sh -d example.com --skip js,archive
EOF
  exit 0
}

# Input validation functions
validate_domain() {
  local domain="$1"
  # Basic regex for domain, allows subdomains and hyphens.
  # More robust validation might involve checking TLDs or using a dedicated library.
  if [[ ! "$domain" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$ ]]; then
    log "$(color red "Invalid domain format: $domain")"
    return 1
  fi
  return 0
}

validate_path() {
  local path="$1"
  # Checks for valid characters in a path. Does not validate existence.
  if [[ ! "$path" =~ ^[a-zA-Z0-9._\/-]+$ ]]; then
    log "$(color red "Invalid path format: $path")"
    return 1
  fi
  return 0
}

# Refactored parse_args function
parse_args() {
  # Local variables for argument processing, initialized to empty to prevent unbound errors
  local custom_cfg_file=""
  local only_modules_str=""
  local skip_modules_str=""
  local has_target_arg=false # Flag to check if -d or -l was provided

  # Use while : for robust argument parsing, breaking when no more args or -- is encountered
  while :; do
    case "$1" in
      -d|--domain)
        if [[ -z "$2" ]]; then die "Missing argument for $1"; fi
        validate_domain "$2" || die "Invalid domain provided: $2"
        TARGETS+=("$2")
        has_target_arg=true
        shift 2
        ;;
      -l|--list)
        if [[ -z "$2" ]]; then die "Missing argument for $1"; fi
        validate_path "$2" || die "Invalid path for target list: $2"
        if [[ ! -f "$2" ]]; then die "Target list file not found: $2"; fi
        
        # Read file line by line, validate each domain
        local line_num=0
        while IFS= read -r ln || [[ -n "$ln" ]]; do
          ((line_num++))
          local trimmed_ln=$(echo "$ln" | xargs) # Trim whitespace
          if [[ -n "$trimmed_ln" ]]; then # Only process non-empty lines
            validate_domain "$trimmed_ln" || die "Invalid domain in list '$2' at line $line_num: $trimmed_ln"
            TARGETS+=("$trimmed_ln")
          fi
        done < "$2"
        has_target_arg=true
        shift 2
        ;;
      -o|--outdir)
        if [[ -z "$2" ]]; then die "Missing argument for $1"; fi
        validate_path "$2" || die "Invalid output directory path: $2"
        OUTDIR="$2"
        shift 2
        ;;
      -p|--parallel)
        if [[ -z "$2" ]]; then die "Missing argument for $1"; fi
        if ! [[ "$2" =~ ^[0-9]+$ ]] || (( "$2" < 1 )); then die "Invalid parallel value: $2 (must be a positive integer)"; fi
        PARALLEL="$2"
        shift 2
        ;;
      --pro)
        PRO_MODE=true
        shift
        ;;
      --license)
        if [[ -z "$2" ]]; then die "Missing license key for $1"; fi
        RECONPRO_LICENSE_KEY="$2"
        PRO_MODE=true # Enabling Pro mode if license is provided
        shift 2
        ;;
      --scope)
        if [[ -z "$2" ]]; then die "Missing argument for $1"; fi
        validate_path "$2" || die "Invalid scope file path: $2"
        if [[ ! -f "$2" ]]; then die "Scope file not found: $2"; fi
        SCOPE_FILE="$2"
        shift 2
        ;;
      --only)
        if [[ -z "$2" ]]; then die "Missing argument for $1"; fi
        only_modules_str="$2"
        shift 2
        ;;
      --skip)
        if [[ -z "$2" ]]; then die "Missing argument for $1"; fi
        skip_modules_str="$2"
        shift 2
        ;;
      --no-cleanup)
        NO_CLEANUP=true
        shift
        ;;
      --config)
        if [[ -z "$2" ]]; then die "Missing argument for $1"; fi
        validate_path "$2" || die "Invalid config file path: $2"
        custom_cfg_file="$2"
        shift 2
        ;;
      -h|--help)
        usage
        # usage function exits, so no need for exit 0 here
        ;;
      --) # End of all options
        shift
        break
        ;;
      -?*) # Unknown option
        die "Unknown option: $1"
        ;;
      *) # No more options
        break
    esac
  done

  # Set CFG_FILE if a custom config was specified
  if [[ -n "$custom_cfg_file" ]]; then
    CFG_FILE="$custom_cfg_file"
  fi

  # Load config after parsing custom config file path, but before processing module flags
  # This allows command-line flags to override config file settings.
  load_config

  # Process --only and --skip flags into arrays
  # Use parameter expansion with :- to handle empty strings safely
  if [[ -n "${only_modules_str:-}" ]]; then
    IFS=',' read -r -a ONLY_MODULES <<< "$only_modules_str"
  fi
  if [[ -n "${skip_modules_str:-}" ]]; then
    IFS=',' read -r -a SKIP_MODULES <<< "$skip_modules_str"
  fi

  # Ensure TARGETS is populated. If not, show usage and exit.
  if ! "$has_target_arg" || [ ${#TARGETS[@]} -eq 0 ]; then
    log "$(color red "Error: No target domain(s) provided. Use -d or -l.")"
    usage # usage function exits
  fi
}

# Check if a module should run based on --only/--skip flags
should_run_module() {
  local module_name="$1"
  local run_this_module=true # Assume module should run by default

  # If --only is specified, module must be in ONLY_MODULES
  if [ ${#ONLY_MODULES[@]} -gt 0 ]; then
    run_this_module=false # If --only is used, default to not running unless explicitly listed
    for m in "${ONLY_MODULES[@]}"; do
      if [[ "$m" == "$module_name" ]]; then
        run_this_module=true
        break
      fi
    done
  fi

  # If --skip is specified, module must NOT be in SKIP_MODULES
  # This check overrides --only if a module is both --only'd and --skip'd
  if [ ${#SKIP_MODULES[@]} -gt 0 ]; then
    for m in "${SKIP_MODULES[@]}"; do
      if [[ "$m" == "$module_name" ]]; then
        run_this_module=false # If module is in SKIP_MODULES, it should not run
        break
      fi
    done
  fi

  # Return 0 for true (should run), 1 for false (should not run)
  "$run_this_module"
}

# ------------------ PRO MODE LICENSE CHECK ------------------

check_pro_license() {
  if [ "$PRO_MODE" = true ]; then
    log "Pro mode enabled. Checking license..."
    if [ -z "$RECONPRO_LICENSE_KEY" ]; then
      die "Pro mode requires a license key. Please provide via --license or in $CFG_FILE."
    fi
    # Placeholder for actual license validation API call
    # In a real scenario, this would contact your license server
    # Example: curl -s -H "X-License-Key: $RECONPRO_LICENSE_KEY" "https://your-license-server.com/validate" | grep -q "valid"
    log "$(color green "License key provided. (Validation placeholder)")"
    # if ! curl -s -H "X-License-Key: $RECONPRO_LICENSE_KEY" "https://your-license-server.com/validate" | grep -q "valid"; then
    #   die "Invalid or expired license key. Please check your license."
    # fi
  fi
}

# ------------------ CORE RECON MODULES ------------------

# Module: Scope Validation
module_scope_check() {
  local target="$1"
  if [[ -n "$SCOPE_FILE" ]]; then
    if [[ ! -f "$SCOPE_FILE" ]]; then die "Scope file not found: $SCOPE_FILE"; fi
    if ! grep -Fx "$target" "$SCOPE_FILE" >/dev/null; then
      die "Target $(color red "$target") is out of scope according to $(color blue "$SCOPE_FILE"). Exiting."
    fi
    log "[scope] $(color green "$target") is within scope."
  else
    log "[scope] No scope file provided; skipping validation."
  fi
}

# Module: Subdomain Enumeration (Passive + Active)
module_subs() {
  local domain="$1"
  local out_dir="$OUTDIR/$(safe_name "$domain")"
  local subs_file="$out_dir/subdomains.txt"
  mkdir -p "$out_dir"
  log "Starting subdomain enumeration for $(color blue "$domain")..."

  # Use a temporary file for raw results to deduplicate later
  local temp_subs=$(mktemp)

  # 1) crt.sh (Passive)
  log "[subs] Querying crt.sh..."
  curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' 2>/dev/null | sed 's/^\*\.//' | sort -u >> "$temp_subs" || true

  # 2) assetfinder (Passive/Active)
  if check_cmd assetfinder && [ "$PRO_MODE" = true ]; then
    log "[subs] Running assetfinder..."
    assetfinder --subs-only "$domain" 2>/dev/null >> "$temp_subs" || true
  fi

  # 3) subfinder (Passive/Active)
  if check_cmd subfinder && [ "$PRO_MODE" = true ]; then
    log "[subs] Running subfinder..."
    subfinder -silent -d "$domain" 2>/dev/null >> "$temp_subs" || true
  fi

  # 4) amass (Passive/Active - more comprehensive)
  if check_cmd amass && [ "$PRO_MODE" = true ]; then
    log "[subs] Running amass (passive)..."
    amass enum -passive -d "$domain" -oA "$out_dir/amass_passive" 2>/dev/null
    cat "$out_dir/amass_passive.txt" >> "$temp_subs" || true
    # Optional: Amass active scan (can be noisy)
    # log "[subs] Running amass (active)..."
    # amass enum -active -d "$domain" -oA "$out_dir/amass_active" 2>/dev/null
    # cat "$out_dir/amass_active.txt" >> "$temp_subs" || true
  fi

  # Deduplicate, sort, and save to final file
  sort -u "$temp_subs" -o "$subs_file" || true
  rm -f "$temp_subs"

  log "[subs] Found $(wc -l < "$subs_file") unique subdomains for $(color blue "$domain")."
}

# Module: Alive Checking (HTTPX or Curl fallback)
module_alive() {
  local domain="$1"
  local out_dir="$OUTDIR/$(safe_name "$domain")"
  local subs_file="$out_dir/subdomains.txt"
  local alive_file="$out_dir/alive.txt"
  local temp_alive=$(mktemp)

  if [ ! -s "$subs_file" ]; then log "No subdomains file found for $(color blue "$domain"). Skipping alive check."; return; fi
  log "Checking which hosts are alive for $(color blue "$domain")..."

  if check_cmd httpx && [ "$PRO_MODE" = true ]; then
    log "[alive] Using httpx for alive check..."
    httpx -silent -l "$subs_file" -status-code -o "$temp_alive" || true
  else
    log "[alive] Using crude curl check (httpx not found or Pro mode disabled)..."
    # Use xargs with parallel for faster curl checks
    cat "$subs_file" | xargs -P "$PARALLEL" -I {} bash -c '
      if curl -Is --max-time 5 "http://{}" >/dev/null 2>&1; then printf "%s\n" "{}";
      elif curl -Is --max-time 5 "https://{}" >/dev/null 2>&1; then printf "%s\n" "{}"; fi
    ' >> "$temp_alive" || true
  fi

  sort -u "$temp_alive" -o "$alive_file" || true
  rm -f "$temp_alive"
  log "[alive] Found $(wc -l < "$alive_file") alive hosts for $(color blue "$domain")."
}

# Module: JS/Endpoint Analysis
module_js() {
  local domain="$1"
  local out_dir="$OUTDIR/$(safe_name "$domain")"
  local alive_file="$out_dir/alive.txt"
  local js_file="$out_dir/js_endpoints.txt"
  local secrets_file="$out_dir/js_secrets.txt"
  local gf_patterns_file="$out_dir/gf_patterns.txt"

  if [ ! -s "$alive_file" ]; then log "No alive hosts for $(color blue "$domain"). Skipping JS analysis."; return; fi
  if [ "$PRO_MODE" = false ]; then log "JS/Endpoint analysis requires Pro mode. Skipping."; return; fi
  log "Starting JS/Endpoint analysis for $(color blue "$domain")..."

  # 1) linkfinder.py
  if check_cmd linkfinder.py; then
    log "[js] Running linkfinder.py..."
    while read -r host; do
      log "  -> linkfinder on $host"
      python3 "$(command -v linkfinder.py)" -i "https://$host" -o "$out_dir/linkfinder_$host.html" -oJ "$out_dir/linkfinder_$host.json" 2>/dev/null || true
      # Extract URLs from JSON and add to main JS file
      jq -r '.[].href' "$out_dir/linkfinder_$host.json" 2>/dev/null >> "$js_file" || true
    done < "$alive_file"
  fi

  # 2) SecretFinder.py
  if check_cmd SecretFinder.py; then
    log "[js] Running SecretFinder.py..."
    while read -r host; do
      log "  -> SecretFinder on $host"
      python3 "$(command -v SecretFinder.py)" -i "https://$host" -o "$out_dir/secretfinder_$host.json" 2>/dev/null || true
      jq -r '.[].secret' "$out_dir/secretfinder_$host.json" 2>/dev/null >> "$secrets_file" || true
    done < "$alive_file"
  fi

  # 3) gf patterns (requires gf and patterns installed)
  if check_cmd gf; then
    log "[js] Running gf patterns..."
    # Fetch all URLs from alive hosts using httpx or curl
    local all_urls=$(mktemp)
    if check_cmd httpx; then
      httpx -silent -l "$alive_file" -o "$all_urls" || true
    else
      cat "$alive_file" | xargs -P "$PARALLEL" -I {} bash -c '
        if curl -s --max-time 5 "http://{}" >/dev/null 2>&1; then printf "http://{}\n";
        elif curl -s --max-time 5 "https://{}" >/dev/null 2>&1; then printf "https://{}\n"; fi
      ' >> "$all_urls" || true
    fi

    # Run common gf patterns
    for pattern in xss sqli lfi redirect ssrf ssti rce; do
      log "  -> gf $pattern"
      cat "$all_urls" | gf "$pattern" >> "$gf_patterns_file" || true
    done
    rm -f "$all_urls"
  fi

  sort -u "$js_file" -o "$js_file" || true
  sort -u "$secrets_file" -o "$secrets_file" || true
  sort -u "$gf_patterns_file" -o "$gf_patterns_file" || true
  log "[js] JS/Endpoint analysis completed for $(color blue "$domain")."
}

# Module: Archive URL Scraping
module_archive() {
  local domain="$1"
  local out_dir="$OUTDIR/$(safe_name "$domain")"
  local alive_file="$out_dir/alive.txt"
  local archive_urls_file="$out_dir/archive_urls.txt"

  if [ ! -s "$alive_file" ]; then log "No alive hosts for $(color blue "$domain"). Skipping archive scraping."; return; fi
  if [ "$PRO_MODE" = false ]; then log "Archive URL scraping requires Pro mode. Skipping."; return; fi
  log "Starting archive URL scraping for $(color blue "$domain")..."

  local temp_archive=$(mktemp)

  # 1) gau (Get All URLs)
  if check_cmd gau; then
    log "[archive] Running gau..."
    gau "$domain" >> "$temp_archive" || true
  fi

  # 2) waybackurls
  if check_cmd waybackurls; then
    log "[archive] Running waybackurls..."
    waybackurls "$domain" >> "$temp_archive" || true
  fi

  # 3) katana (if installed and configured)
  if check_cmd katana; then
    log "[archive] Running katana..."
    katana -u "https://$domain" -silent -o "$out_dir/katana_urls.txt" 2>/dev/null || true
    cat "$out_dir/katana_urls.txt" >> "$temp_archive" || true
  fi

  # 4) hakrawler
  if check_cmd hakrawler; then
    log "[archive] Running hakrawler..."
    # Hakrawler typically crawls from a starting URL, so we'll use alive hosts
    while read -r host; do
      log "  -> hakrawler on $host"
      echo "https://$host" | hakrawler -url -depth 2 -scope "$domain" >> "$temp_archive" || true
    done < "$alive_file"
  fi

  sort -u "$temp_archive" -o "$archive_urls_file" || true
  rm -f "$temp_archive"
  log "[archive] Archive URL scraping completed for $(color blue "$domain"). Found $(wc -l < "$archive_urls_file") URLs."
}

# Module: Vulnerability Scanning
module_vuln() {
  local domain="$1"
  local out_dir="$OUTDIR/$(safe_name "$domain")"
  local alive_file="$out_dir/alive.txt"
  local vuln_report_file="$out_dir/vulnerabilities.txt"

  if [ ! -s "$alive_file" ]; then log "No alive hosts for $(color blue "$domain"). Skipping vulnerability scanning."; return; fi
  if [ "$PRO_MODE" = false ]; then log "Vulnerability scanning requires Pro mode. Skipping."; return; fi
  log "Starting vulnerability scanning for $(color blue "$domain")..."

  # 1) Nuclei (with curated templates)
  if check_cmd nuclei; then
    log "[vuln] Running Nuclei scans..."
    # You might want to specify a custom templates directory or specific templates
    nuclei -l "$alive_file" -o "$out_dir/nuclei_results.txt" -silent -stats -severity critical,high,medium 2>/dev/null || true
    cat "$out_dir/nuclei_results.txt" >> "$vuln_report_file" || true
  fi

  # 2) ffuf/gobuster (for common paths/files, already covered by module_ffuf)
  # This module focuses on active vuln scanning, ffuf for dirb is in module_js/fuzz

  # 3) dalfox (XSS scanner)
  if check_cmd dalfox; then
    log "[vuln] Running Dalfox (XSS scan)..."
    # Dalfox needs URLs, so we'll use alive hosts and potentially scraped URLs
    local urls_for_dalfox=$(mktemp)
    cat "$alive_file" >> "$urls_for_dalfox" || true
    [ -f "$out_dir/archive_urls.txt" ] && cat "$out_dir/archive_urls.txt" >> "$urls_for_dalfox" || true
    
    # Limit to a reasonable number of URLs for dalfox to avoid excessive runtime
    head -n 1000 "$urls_for_dalfox" | dalfox file - -o "$out_dir/dalfox_results.txt" -silent 2>/dev/null || true
    cat "$out_dir/dalfox_results.txt" >> "$vuln_report_file" || true
    rm -f "$urls_for_dalfox"
  fi

  log "[vuln] Vulnerability scanning completed for $(color blue "$domain")."
}

# Module: Subdomain Takeover Detection
module_takeover() {
  local domain="$1"
  local out_dir="$OUTDIR/$(safe_name "$domain")"
  local subs_file="$out_dir/subdomains.txt"
  local takeover_file="$out_dir/subdomain_takeovers.txt"

  if [ ! -s "$subs_file" ]; then log "No subdomains file for $(color blue "$domain"). Skipping takeover detection."; return; fi
  if [ "$PRO_MODE" = false ]; then log "Subdomain takeover detection requires Pro mode. Skipping."; return; fi
  log "Starting subdomain takeover detection for $(color blue "$domain")..."

  # Using subjack (which uses can-i-take-over-xyz fingerprints)
  if check_cmd subjack; then
    log "[takeover] Running subjack..."
    subjack -f "$subs_file" -o "$takeover_file" -ssl -timeout 10 -concurrency "$PARALLEL" 2>/dev/null || true
  else
    log "[takeover] subjack not found. Please install it for subdomain takeover detection."
  fi

  log "[takeover] Subdomain takeover detection completed for $(color blue "$domain")."
}

# Module: Cloud Misconfiguration Detection
module_cloud() {
  local domain="$1"
  local out_dir="$OUTDIR/$(safe_name "$domain")"
  local alive_file="$out_dir/alive.txt"
  local cloud_misconfig_file="$out_dir/cloud_misconfigs.txt"

  if [ ! -s "$alive_file" ]; then log "No alive hosts for $(color blue "$domain"). Skipping cloud misconfig detection."; return; fi
  if [ "$PRO_MODE" = false ]; then log "Cloud misconfig detection requires Pro mode. Skipping."; return; fi
  log "Starting cloud misconfiguration detection for $(color blue "$domain")..."

  # This is a complex module, often requiring specialized tools or custom scripts.
  # For demonstration, we'll use a simple check for common S3 bucket patterns.
  # More advanced detection would involve tools like 'Cloud-Bucket-Finder', 'S3Scanner', 'gcp-bucket-bruteforce', etc.

  log "[cloud] Checking for common S3 bucket patterns..."
  while read -r host; do
    # Simple check for S3 bucket naming conventions
    if [[ "$host" =~ \.s3\.amazonaws\.com$ || "$host" =~ \.s3-website-[a-z0-9-]+\.amazonaws\.com$ ]]; then
      echo "Potential S3 bucket: $host" >> "$cloud_misconfig_file"
      # Further checks could involve 'aws s3 ls s3://$host' if AWS CLI is configured
    fi
    # Add checks for other cloud providers (GCP, Azure, DigitalOcean)
    # Example: Check for common Azure blob storage patterns
    if [[ "$host" =~ \.blob\.core\.windows\.net$ ]]; then
      echo "Potential Azure Blob Storage: $host" >> "$cloud_misconfig_file"
    fi
    # Example: Check for DigitalOcean Spaces
    if [[ "$host" =~ \.digitaloceanspaces\.com$ ]]; then
      echo "Potential DigitalOcean Space: $host" >> "$cloud_misconfig_file"
    fi
  done < "$alive_file"

  log "[cloud] Cloud misconfiguration detection completed for $(color blue "$domain")."
}

# Module: WAF/CDN Detection
module_waf() {
  local domain="$1"
  local out_dir="$OUTDIR/$(safe_name "$domain")"
  local alive_file="$out_dir/alive.txt"
  local waf_cdn_file="$out_dir/waf_cdn_detection.txt"

  if [ ! -s "$alive_file" ]; then log "No alive hosts for $(color blue "$domain"). Skipping WAF/CDN detection."; return; fi
  log "Starting WAF/CDN detection for $(color blue "$domain")..."

  if check_cmd wafw00f; then
    log "[waf] Running wafw00f..."
    while read -r host; do
      log "  -> wafw00f on $host"
      wafw00f "https://$host" >> "$waf_cdn_file" 2>/dev/null || true
    done < "$alive_file"
  else
    log "[waf] wafw00f not found. Please install it for WAF/CDN detection."
  fi

  log "[waf] WAF/CDN detection completed for $(color blue "$domain")."
}

# Module: Port Scanning (Nmap)
module_nmap() {
  local target="$1" # Can be domain or IP
  local out_dir="$OUTDIR/$(safe_name "$target")"
  mkdir -p "$out_dir"
  log "Starting Nmap scans for $(color blue "$target")..."

  # Resolve target to IP if it's a domain
  local target_ip=""
  if [[ "$target" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    target_ip="$target"
  else
    target_ip=$(dig +short "$target" | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' | head -n 1)
    if [ -z "$target_ip" ]; then
      log "$(color yellow "Warning: Could not resolve IP for $target. Skipping Nmap.")"
      return
    fi
    log "[nmap] Resolved $target to $target_ip"
  fi

  # 1) Nmap Top 1000 Ports Scan
  log "[nmap] Running Nmap Top 1000 ports scan..."
  nmap -sV -T4 --top-ports 1000 -oA "$out_dir/nmap_top1000_${TIMESTAMP}" "$target_ip" || true

  # 2) Nmap Full Port Scan (only if Pro mode)
  if [ "$PRO_MODE" = true ]; then
    log "[nmap] Running Nmap Full port scan (Pro mode)..."
    nmap -p- --min-rate 1000 -sV -T4 -oA "$out_dir/nmap_full_${TIMESTAMP}" "$target_ip" || true
  fi

  log "[nmap] Nmap scans completed for $(color blue "$target")."
}

# Module: HTTP Headers & Security Headers
module_http() {
  local host="$1"
  local out_dir="$OUTDIR/$(safe_name "$host")"
  mkdir -p "$out_dir"
  local http_headers_file="$out_dir/http_headers.txt"
  local security_headers_file="$out_dir/security_headers.txt"

  log "Fetching HTTP headers for $(color blue "$host")..."
  # Try HTTPS first, then HTTP
  curl -Is --max-time 10 "https://$host" > "$http_headers_file" 2>/dev/null || \
  curl -Is --max-time 10 "http://$host" >> "$http_headers_file" 2>/dev/null || true

  if [ -s "$http_headers_file" ]; then
    # Extract security headers
    < "$http_headers_file" awk 'tolower($0) ~ /x-frame-options|content-security-policy|x-content-type-options|strict-transport-security|referrer-policy|permissions-policy/ {print}' > "$security_headers_file" || true
    log "[http] HTTP headers fetched for $(color blue "$host")."
  else
    log "$(color yellow "Warning: Could not fetch HTTP headers for $host.")"
  fi
}

# Module: WhatWeb/Wappalyzer Fingerprinting
module_finger() {
  local host="$1"
  local out_dir="$OUTDIR/$(safe_name "$host")"
  mkdir -p "$out_dir"
  local whatweb_file="$out_dir/whatweb.txt"

  log "Starting fingerprinting for $(color blue "$host")..."
  if check_cmd whatweb; then
    whatweb -v "$host" > "$whatweb_file" 2>/dev/null || true
  else
    echo "whatweb not installed" > "$whatweb_file"
    log "$(color yellow "Warning: whatweb not found. Skipping fingerprinting for $host.")"
  fi
  # Wappalyzer integration would typically be via a browser extension or a dedicated CLI tool (e.g., wappalyzer-cli)
  # For a pure bash script, whatweb is more straightforward.
  log "[finger] Fingerprinting completed for $(color blue "$host")."
}

# ------------------ PRO MODE ADVANCED MODULES ------------------

# Module: Shodan Integration
module_shodan() {
  local target="$1"
  local out_dir="$OUTDIR/$(safe_name "$target")"
  local shodan_file="$out_dir/shodan_results.json"

  if [ "$PRO_MODE" = false ]; then log "Shodan integration requires Pro mode. Skipping."; return; fi
  if [ -z "$SHODAN_API_KEY" ]; then log "$(color yellow "Shodan API key not configured. Skipping Shodan integration.")"; return; fi
  if ! check_cmd shodan; then log "$(color yellow "Shodan CLI not found. Please install it (pip install shodan). Skipping Shodan integration.")"; return; fi
  log "Querying Shodan for $(color blue "$target")..."

  # Shodan CLI needs to be configured with the API key first: shodan init YOUR_API_KEY
  # Or pass it directly if the CLI supports it, or use curl with the API.
  # For simplicity, assuming 'shodan init' has been run.
  shodan search --fields ip_str,port,org,os,product,version,cpe,vulns "$target" --json > "$shodan_file" 2>/dev/null || true
  log "[shodan] Shodan query completed for $(color blue "$target")."
}

# Module: Censys Integration
module_censys() {
  local target="$1"
  local out_dir="$OUTDIR/$(safe_name "$target")"
  local censys_file="$out_dir/censys_results.json"

  if [ "$PRO_MODE" = false ]; then log "Censys integration requires Pro mode. Skipping."; return; fi
  if [ -z "$CENSYS_API_KEY" ] || [ -z "$CENSYS_API_SECRET" ]; then log "$(color yellow "Censys API keys not configured. Skipping Censys integration.")"; return; fi
  if ! check_cmd censys; then log "$(color yellow "Censys CLI not found. Please install it (pip install censys). Skipping Censys integration.")"; return; fi
  log "Querying Censys for $(color blue "$target")..."

  # Censys CLI needs to be configured: censys config
  # Or use curl directly with API.
  censys search "$target" --json > "$censys_file" 2>/dev/null || true
  log "[censys] Censys query completed for $(color blue "$target")."
}

# Module: VirusTotal Integration
module_virustotal() {
  local target="$1"
  local out_dir="$OUTDIR/$(safe_name "$target")"
  local vt_file="$out_dir/virustotal_results.json"

  if [ "$PRO_MODE" = false ]; then log "VirusTotal integration requires Pro mode. Skipping."; return; fi
  if [ -z "$VIRUSTOTAL_API_KEY" ]; then log "$(color yellow "VirusTotal API key not configured. Skipping VirusTotal integration.")"; return; fi
  if ! check_cmd vt; then log "$(color yellow "VirusTotal CLI (vt-cli) not found. Please install it (pip install vt-cli). Skipping VirusTotal integration.")"; return; fi
  log "Querying VirusTotal for $(color blue "$target")..."

  # vt-cli needs to be configured: vt init YOUR_API_KEY
  # Or use curl directly with API.
  vt domain "$target" --json > "$vt_file" 2>/dev/null || true
  log "[virustotal] VirusTotal query completed for $(color blue "$target")."
}

# Module: Continuous Recon (Placeholder)
module_cont() {
  local target="$1"
  if [ "$PRO_MODE" = false ]; then log "Continuous recon requires Pro mode. Skipping."; return; fi
  log "Continuous recon for $(color blue "$target") is a Pro feature."
  log "This would involve setting up cron jobs or a persistent daemon to periodically re-run modules."
  log "Example: Add a cron entry like '0 */6 * * * /path/to/reconpro.sh -d $target --only subs,alive --no-cleanup'"
}

# Module: Notifications (Placeholder)
module_notify() {
  local target="$1"
  local message="$2"
  if [ "$PRO_MODE" = false ]; then log "Notifications require Pro mode. Skipping."; return; fi
  log "Sending notification for $(color blue "$target"): $message"

  if [[ -n "$SLACK_WEBHOOK_URL" ]]; then
    log "  -> Sending Slack notification..."
    curl -X POST -H 'Content-type: application/json' --data "{\"text\":\"ReconPro for $target: $message\"}" "$SLACK_WEBHOOK_URL" >/dev/null 2>&1 || true
  fi
  if [[ -n "$TELEGRAM_BOT_TOKEN" && -n "$TELEGRAM_CHAT_ID" ]]; then
    log "  -> Sending Telegram notification..."
    curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" -d "chat_id=$TELEGRAM_CHAT_ID&text=ReconPro for $target: $message" >/dev/null 2>&1 || true
  fi
  if [[ -n "$DISCORD_WEBHOOK_URL" ]]; then
    log "  -> Sending Discord notification..."
    curl -X POST -H 'Content-type: application/json' --data "{\"content\":\"ReconPro for $target: $message\"}" "$DISCORD_WEBHOOK_URL" >/dev/null 2>&1 || true
  fi
}

# Module: Database Storage (Placeholder)
module_db() {
  local target="$1"
  local out_dir="$OUTDIR/$(safe_name "$target")"
  if [ "$PRO_MODE" = false ]; then log "Database storage requires Pro mode. Skipping."; return; fi
  log "Database storage for $(color blue "$target") is a Pro feature."
  log "This would involve connecting to SQLite/Postgres and inserting recon data."
  log "Example: Using 'sqlite3' or 'psql' commands to store findings from various files."
  # Example for SQLite:
  # sqlite3 "$out_dir/recon.db" "CREATE TABLE IF NOT EXISTS subdomains (domain TEXT, subdomain TEXT UNIQUE);"
  # cat "$out_dir/subdomains.txt" | while read -r sub; do sqlite3 "$out_dir/recon.db" "INSERT OR IGNORE INTO subdomains (domain, subdomain) VALUES ('$target', '$sub');"; done
}

# Module: Export to BurpSuite/JSON (Placeholder)
module_burp() {
  local target="$1"
  local out_dir="$OUTDIR/$(safe_name "$target")"
  if [ "$PRO_MODE" = false ]; then log "BurpSuite/JSON export requires Pro mode. Skipping."; return; fi
  log "Exporting data for $(color blue "$target") to BurpSuite/JSON is a Pro feature."
  log "This would involve parsing existing recon files and formatting them into Burp XML or a custom JSON format."
  # Example: Convert alive.txt to a list of URLs for Burp's sitemap import
  # cat "$out_dir/alive.txt" | sed 's/^/https:\/\//' > "$out_dir/burp_urls.txt"
}

# Module: Smart Fuzzing (Placeholder)
module_fuzz() {
  local target="$1"
  local out_dir="$OUTDIR/$(safe_name "$target")"
  local alive_file="$out_dir/alive.txt"
  if [ "$PRO_MODE" = false ]; then log "Smart fuzzing requires Pro mode. Skipping."; return; fi
  if [ ! -s "$alive_file" ]; then log "No alive hosts for $(color blue "$domain"). Skipping smart fuzzing."; return; fi
  log "Smart fuzzing for $(color blue "$target") is a Pro feature."
  log "This would involve: "
  log "  - Auto parameter extraction from scraped URLs (e.g., from module_js, module_archive)."
  log "  - Using tools like ffuf/wfuzz with intelligent wordlists based on extracted parameters."
  log "  - Integrating dalfox for XSS, SQLmap for SQLi, or custom scripts for LFI/RCE checks."
  # Example:
  # if check_cmd ffuf; then
  #   log "  -> Running ffuf with extracted parameters..."
  #   # This is highly complex and needs a dedicated script to parse URLs and identify parameters
  #   # For example, parse URLs from archive_urls.txt, extract query params, then fuzz them.
  #   # ffuf -u "https://target.com/path?param=FUZZ" -w /path/to/wordlist.txt ...
  # fi
}

# ------------------ REPORTING MODULES ------------------

# Module: Generate Reports
module_report() {
  local target="$1"
  local d="$OUTDIR/$(safe_name "$target")"
  mkdir -p "$d"
  log "Generating reports for $(color blue "$target")..."

  # Markdown Report
  local md_file="$d/report_${TIMESTAMP}.md"
  log "[report] Generating Markdown report..."
  cat <<EOF > "$md_file"
# ReconPro Report for $target
*Generated:* $(date)
*Target Directory:* $d

## Summary
- *Subdomains Found:* $(wc -l < "$d/subdomains.txt" 2>/dev/null || echo 0)
- *Alive Hosts:* $(wc -l < "$d/alive.txt" 2>/dev/null || echo 0)
- *Potential Vulnerabilities:* $(wc -l < "$d/vulnerabilities.txt" 2>/dev/null || echo 0)
- *Subdomain Takeovers:* $(wc -l < "$d/subdomain_takeovers.txt" 2>/dev/null || echo 0)
- *Cloud Misconfigurations:* $(wc -l < "$d/cloud_misconfigs.txt" 2>/dev/null || echo 0)

## Subdomains
\\\`
$(head -n 200 "$d/subdomains.txt" 2>/dev/null || echo "No subdomains found or file empty.")
\\\`
... (truncated, see subdomains.txt for full list)

## Alive Hosts
\\\`
$(head -n 200 "$d/alive.txt" 2>/dev/null || echo "No alive hosts found or file empty.")
\\\`
... (truncated, see alive.txt for full list)

## Nmap Scan Summary (Top 1000 Ports)
\\\`
$(grep -E "open" "$d/nmap_top1000_${TIMESTAMP}.gnmap" 2>/dev/null | head -n 200 || echo "No Nmap results or file empty.")
\\\`
... (truncated, see nmap_top1000_${TIMESTAMP}.txt for full details)

## HTTP Security Headers
\\\`
$(cat "$d/security_headers.txt" 2>/dev/null || echo "No security headers found or file empty.")
\\\`

## WhatWeb Fingerprinting
\\\`
$(head -n 200 "$d/whatweb.txt" 2>/dev/null || echo "No WhatWeb results or file empty.")
\\\`
... (truncated, see whatweb.txt for full details)

## Vulnerability Scan Results
\\\`
$(head -n 200 "$d/vulnerabilities.txt" 2>/dev/null || echo "No vulnerabilities found or file empty.")
\\\`
... (truncated, see vulnerabilities.txt for full details)

## Subdomain Takeover Detections
\\\`
$(head -n 200 "$d/subdomain_takeovers.txt" 2>/dev/null || echo "No takeovers found or file empty.")
\\\`

## Cloud Misconfigurations
\\\`
$(head -n 200 "$d/cloud_misconfigs.txt" 2>/dev/null || echo "No cloud misconfigs found or file empty.")
\\\`

## WAF/CDN Detections
\\\`
$(head -n 200 "$d/waf_cdn_detection.txt" 2>/dev/null || echo "No WAF/CDN detections found or file empty.")
\\\`

EOF

  # JSON Report
  local json_file="$d/report_${TIMESTAMP}.json"
  log "[report] Generating JSON report..."
  jq -n \
    --arg target "$target" \
    --arg generated "$(date)" \
    --argjson subdomains "$(jq -R . "$d/subdomains.txt" 2>/dev/null | jq -s .)" \
    --argjson alive_hosts "$(jq -R . "$d/alive.txt" 2>/dev/null | jq -s .)" \
    --argjson vulnerabilities "$(jq -R . "$d/vulnerabilities.txt" 2>/dev/null | jq -s .)" \
    --argjson takeovers "$(jq -R . "$d/subdomain_takeovers.txt" 2>/dev/null | jq -s .)" \
    --argjson cloud_misconfigs "$(jq -R . "$d/cloud_misconfigs.txt" 2>/dev/null | jq -s .)" \
    --argjson waf_cdn "$(jq -R . "$d/waf_cdn_detection.txt" 2>/dev/null | jq -s .)" \
    '{
      "target": $target,
      "generated": $generated,
      "summary": {
        "subdomains_count": ($subdomains | length),
        "alive_hosts_count": ($alive_hosts | length),
        "vulnerabilities_count": ($vulnerabilities | length),
        "takeovers_count": ($takeovers | length),
        "cloud_misconfigs_count": ($cloud_misconfigs | length),
        "waf_cdn_count": ($waf_cdn | length)
      },
      "details": {
        "subdomains": $subdomains,
        "alive_hosts": $alive_hosts,
        "vulnerabilities": $vulnerabilities,
        "subdomain_takeovers": $takeovers,
        "cloud_misconfigs": $cloud_misconfigs,
        "waf_cdn_detections": $waf_cdn
      }
    }' > "$json_file" || true

  # CSV Report (simplified)
  local csv_file="$d/report_${TIMESTAMP}.csv"
  log "[report] Generating CSV report..."
  echo "Category,Item" > "$csv_file"
  [ -f "$d/subdomains.txt" ] && awk '{print "Subdomain,"$0}' "$d/subdomains.txt" >> "$csv_file"
  [ -f "$d/alive.txt" ] && awk '{print "Alive Host,"$0}' "$d/alive.txt" >> "$csv_file"
  [ -f "$d/vulnerabilities.txt" ] && awk '{print "Vulnerability,"$0}' "$d/vulnerabilities.txt" >> "$csv_file"
  [ -f "$d/subdomain_takeovers.txt" ] && awk '{print "Takeover,"$0}' "$d/subdomain_takeovers.txt" >> "$csv_file"
  [ -f "$d/cloud_misconfigs.txt" ] && awk '{print "Cloud Misconfig,"$0}' "$d/cloud_misconfigs.txt" >> "$csv_file"

  # HTML Report (basic, can be enhanced with Chart.js for interactive dashboard)
  local html_file="$d/report_${TIMESTAMP}.html"
  log "[report] Generating HTML report..."
  cat <<EOF > "$html_file"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReconPro Report: $target</title>
    <style>
        body { font-family: sans-serif; margin: 20px; background-color: #f4f4f4; color: #333; }
        .container { background-color: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1, h2, h3 { color: #0056b3; }
        pre { background-color: #eee; padding: 10px; border-radius: 4px; overflow-x: auto; }
        .summary-box { display: flex; flex-wrap: wrap; gap: 15px; margin-bottom: 20px; }
        .summary-item { background-color: #e9f7ef; border: 1px solid #d0e9d0; padding: 10px 15px; border-radius: 5px; flex: 1; min-width: 180px; text-align: center; }
        .summary-item h3 { margin: 0 0 5px 0; color: #28a745; }
        .summary-item p { margin: 0; font-size: 1.2em; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>ReconPro Report for $target</h1>
        <p><strong>Generated:</strong> $(date)</p>
        <p><strong>Target Directory:</strong> <code>$d</code></p>

        <h2>Summary</h2>
        <div class="summary-box">
            <div class="summary-item"><h3>Subdomains</h3><p>$(wc -l < "$d/subdomains.txt" 2>/dev/null || echo 0)</p></div>
            <div class="summary-item"><h3>Alive Hosts</h3><p>$(wc -l < "$d/alive.txt" 2>/dev/null || echo 0)</p></div>
            <div class="summary-item"><h3>Vulnerabilities</h3><p>$(wc -l < "$d/vulnerabilities.txt" 2>/dev/null || echo 0)</p></div>
            <div class="summary-item"><h3>Takeovers</h3><p>$(wc -l < "$d/subdomain_takeovers.txt" 2>/dev/null || echo 0)</p></div>
            <div class="summary-item"><h3>Cloud Misconfigs</h3><p>$(wc -l < "$d/cloud_misconfigs.txt" 2>/dev/null || echo 0)</p></div>
        </div>

        <h2>Subdomains</h2>
        <pre>$(head -n 200 "$d/subdomains.txt" 2>/dev/null || echo "No subdomains found or file empty.")</pre>
        <p>... (truncated, see <a href="subdomains.txt">subdomains.txt</a> for full list)</p>

        <h2>Alive Hosts</h2>
        <pre>$(head -n 200 "$d/alive.txt" 2>/dev/null || echo "No alive hosts found or file empty.")</pre>
        <p>... (truncated, see <a href="alive.txt">alive.txt</a> for full list)</p>

        <h2>Nmap Scan Summary (Top 1000 Ports)</h2>
        <pre>$(grep -E "open" "$d/nmap_top1000_${TIMESTAMP}.gnmap" 2>/dev/null | head -n 200 || echo "No Nmap results or file empty.")</pre>
        <p>... (truncated, see <a href="nmap_top1000_${TIMESTAMP}.txt">nmap_top1000_${TIMESTAMP}.txt</a> for full details)</p>

        <h2>HTTP Security Headers</h2>
        <pre>$(cat "$d/security_headers.txt" 2>/dev/null || echo "No security headers found or file empty.")</pre>

        <h2>WhatWeb Fingerprinting</h2>
        <pre>$(head -n 200 "$d/whatweb.txt" 2>/dev/null || echo "No WhatWeb results or file empty.")</pre>
        <p>... (truncated, see <a href="whatweb.txt">whatweb.txt</a> for full details)</p>

        <h2>Vulnerability Scan Results</h2>
        <pre>$(head -n 200 "$d/vulnerabilities.txt" 2>/dev/null || echo "No vulnerabilities found or file empty.")</pre>
        <p>... (truncated, see <a href="vulnerabilities.txt">vulnerabilities.txt</a> for full details)</p>

        <h2>Subdomain Takeover Detections</h2>
        <pre>$(head -n 200 "$d/subdomain_takeovers.txt" 2>/dev/null || echo "No takeovers found or file empty.")</pre>

        <h2>Cloud Misconfigurations</h2>
        <pre>$(head -n 200 "$d/cloud_misconfigs.txt" 2>/dev/null || echo "No cloud misconfigs found or file empty.")</pre>

        <h2>WAF/CDN Detections</h2>
        <pre>$(head -n 200 "$d/waf_cdn_detection.txt" 2>/dev/null || echo "No WAF/CDN detections found or file empty.")</pre>

        <!-- Add more sections for other modules as needed -->
    </div>
</body>
</html>
EOF

  # PDF Report (requires external tool like pandoc or wkhtmltopdf)
  # This is a placeholder as it adds external dependencies not typically in core Bash.
  # if check_cmd pandoc; then
  #   log "[report] Generating PDF report (via pandoc)..."
  #   pandoc "$md_file" -o "$d/report_${TIMESTAMP}.pdf" --pdf-engine=xelatex || true
  # elif check_cmd wkhtmltopdf; then
  #   log "[report] Generating PDF report (via wkhtmltopdf)..."
  #   wkhtmltopdf "$html_file" "$d/report_${TIMESTAMP}.pdf" || true
  # else
  #   log "$(color yellow "Warning: pandoc or wkhtmltopdf not found. Skipping PDF report generation.")"
  # fi

  log "[report] Reports generated for $(color blue "$target")."
}

# ------------------ EXECUTION FLOW ------------------

# Main function to orchestrate recon for a single target
main_target() {
  local target="$1"
  log "\n$(color green "====================================================")"
  log "$(color green " ReconPro START: $target")"
  log "$(color green "====================================================")"

  local target_dir="$OUTDIR/$(safe_name "$target")"
  mkdir -p "$target_dir"

  # Run modules based on --only/--skip flags and Pro mode status
  should_run_module "scope" && module_scope_check "$target"

  should_run_module "subs" && module_subs "$target"
  should_run_module "alive" && module_alive "$target" # Alive check is a prerequisite for many modules

  # Modules that run on the main target domain/IP
  should_run_module "nmap" && module_nmap "$target"
  should_run_module "http" && module_http "$target"
  should_run_module "finger" && module_finger "$target"
  should_run_module "waf" && module_waf "$target"

  # Pro-mode specific modules that run on the main target
  if [ "$PRO_MODE" = true ]; then
    should_run_module "shodan" && module_shodan "$target"
    should_run_module "censys" && module_censys "$target"
    should_run_module "virustotal" && module_virustotal "$target"
    should_run_module "cont" && module_cont "$target"
    should_run_module "db" && module_db "$target"
  fi

  # Modules that iterate over alive hosts
  if [ -f "$target_dir/alive.txt" ]; then
    log "Running host-specific modules for alive hosts..."
    # Read alive hosts into an array to avoid re-reading the file in a loop
    local alive_hosts_array=()
    mapfile -t alive_hosts_array < "$target_dir/alive.txt"

    for host in "${alive_hosts_array[@]}"; do
      log "  Processing alive host: $(color cyan "$host")"
      # Run Nmap, HTTP, Fingerprint for each alive host if not already done for main target
      # This can be redundant if target is already an IP, but useful for subdomains
      # should_run_module "nmap" && module_nmap "$host" # Consider if you want Nmap on every subdomain
      should_run_module "http" && module_http "$host"
      should_run_module "finger" && module_finger "$host"
      should_run_module "waf" && module_waf "$host"

      # Pro-mode specific modules that iterate over alive hosts
      if [ "$PRO_MODE" = true ]; then
        should_run_module "js" && module_js "$host" # JS analysis needs to be run on each host's URLs
        should_run_module "archive" && module_archive "$host" # Archive scraping can be per host or per domain
        should_run_module "vuln" && module_vuln "$host"
        should_run_module "takeover" && module_takeover "$host"
        should_run_module "cloud" && module_cloud "$host"
        should_run_module "fuzz" && module_fuzz "$host"
      fi
    done
  fi

  # Final reporting
  module_report "$target"

  # Pro-mode specific post-processing
  if [ "$PRO_MODE" = true ]; then
    should_run_module "burp" && module_burp "$target"
    should_run_module "notify" && module_notify "$target" "Recon completed for $target. Report available in $target_dir."
  fi

  log "$(color green "====================================================")"
  log "$(color green " ReconPro END: $target")"
  log "$(color green "====================================================\n")"
}

# ------------------ MAIN SCRIPT EXECUTION ------------------

main() {
  print_banner
  parse_args "$@" # Pass all command-line arguments to parse_args

  check_dependencies
  check_pro_license

  mkdir -p "$OUTDIR"
  log "ReconPro started. Log file: $(color blue "$LOGFILE")"
  log "Output directory: $(color blue "$OUTDIR")"
  log "Parallel jobs: $(color blue "$PARALLEL")"
  [ "$PRO_MODE" = true ] && log "$(color green "Pro Mode: Enabled")" || log "$(color yellow "Pro Mode: Disabled")"

  # Run for each target in parallel
  for t in "${TARGETS[@]}"; do
    main_target "$t" &
    # Control parallel jobs
    while [ $(jobs -r | wc -l) -ge "$PARALLEL" ]; do
      sleep 1
    done
  done
  wait # Wait for all background jobs to complete

  log "All recon tasks finished. Reports are in $(color blue "$OUTDIR")"

  # Cleanup temporary files if not disabled
  if [ "$NO_CLEANUP" != true ]; then
    log "Cleaning up temporary files..."
    find "$OUTDIR" -type f -name ".tmp" -delete 2>/dev/null || true
  fi
}

# Call the main function with all script arguments
main "$@"
