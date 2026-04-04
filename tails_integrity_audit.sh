#!/usr/bin/env bash
# =============================================================================
# tails_integrity_audit.sh
# =============================================================================
# Read-Only Integrity Audit Tool for TailsOS
#
#
#
#
#
#                                             :*%%%%%=.
#                                         .+@@@@@@@@@@@@%:
#                                       .*@@@@@@@@@@@@@@@@%:
#                                      .%@@@@@@@@@@@@@@@@@@@=
#                                      %@@@@@@@@@@@@@@@@@@@@@:
#                                     -@@@@@@@@@@@@@@@@@@@@@@@
#                                     %@@@@@@@@@@@@@@@@@@@@@@@
#                                     %@@@@@@@@@@@@@@@@@@@@@@@
#                  ..-===-:.          .@@@@@@@@@@@@@@@@@@@@@@@           .::::...
#               .*@@@@@@@@@@@%=.       #@@@@@@@@@@@@@@@@@@@@@.       .*@@@@@@@@@@%=.
#             .%@@@@@@@@@@@@@@@@+.      #@@@@@@@@@@@@@@@@@@@:      .@@@@@@@@@@@@@@@@#.
#            -@@@@@@@@@@@@@@@@@@@%.     .%@@@@@@@@@@@@@@@@@=      +@@@@@@@@@@@@@@@@@@@:
#           :@@@@@@@@@@@@@@@@@@@@@@:     .@@@@@@@@@@@@@@@@+      %@@@@@@@@@@@@@@@@@@@@@.
#          .@@@@@@@@@@@@@@@@@@@@@@@@=     .@@@@@@@@@@@@@@+     .@@@@@@@@@@@@@@@@@@@@@@@@.
#          .@@@@@@@@@@@@@@@@@@@@@@@@@#.    :@@@@@@@@@@@@*.    :@@@@@@@@@@@@@@@@@@@@@@@@@.
#          .@@@@@@@@@@@@@@@@@@@@@@@@@@@.    :@@@@@@@@@@%.   .+@@@@@@@@@@@@@@@@@@@@@@@@@@.
#          .@@@@@@@@@@@@@@@@@@@@@@@@@@@@:    -@@@@@@@@@.   .#@@@@@@@@@@@@@@@@@@@@@@@@@@@.
#           :@@@@@@@@@@@@@@@@@@@@@@@@@@@@=    *@@@@@@@.   .@@@@@@@@@@@@@@@@@@@@@@@@@@@@-
#            -@@@@@@@@@@@@@@@@@@@@@@@@@@@@#   :@@@@@@@.  -@@@@@@@@@@@@@@@@@@@@@@@@@@@@*
#             .#@@@@@@@@@@@@@@@@@@@@@@@@@@@@%@@@@@@@@@@%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@:
#               .#@@@@@@@@@@@@@@@@@@@@@@@@@@@@%:    .%@@@@@@@@@@@@@@@@@@@@@@@@@@@@%:
#                  .:==+#@@@@@@@@@@@@@@@@@@@@          %@@@@@@@@@@@@@@@@@@@@@#==.
#                                      .%@@@            @@@@*.
#                                       .@@%     ..     *@@.
#                                      .%@@@    =++=    @@@@-
#                 .-=@@@@@@@@@@@@@@@@@@@@@@@@.-++++++-.%@@@@@@@@@@@@@@@@@@@@@@%=:.
#               -@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%*++++*%@@@@@@@@@@@@@@@@@@@@@@@@@@@@%=
#             :@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%@@@@@@@@@%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@:
#            *@@@@@@@@@@@@@@@@@@@@@@@@@@@@=   =@@@@@@@.  :@@@@@@@@@@@@@@@@@@@@@@@@@@@@*
#          -@@@@@@@@@@@@@@@@@@@@@@@@@@@@.    %@@@@@@@.    %@@@@@@@@@@@@@@@@@@@@@@@@@@@-
#           .@@@@@@@@@@@@@@@@@@@@@@@@@@@%.   .%@@@@@@@@@.    *@@@@@@@@@@@@@@@@@@@@@@@@@@@.
#          .@@@@@@@@@@@@@@@@@@@@@@@@@@*.    +@@@@@@@@@@@.    -@@@@@@@@@@@@@@@@@@@@@@@@@@.
#          .@@@@@@@@@@@@@@@@@@@@@@@@@=     =@@@@@@@@@@@@*.    .@@@@@@@@@@@@@@@@@@@@@@@@@.
#          .@@@@@@@@@@@@@@@@@@@@@@@@:     -@@@@@@@@@@@@@@=     .%@@@@@@@@@@@@@@@@@@@@@@@.
#            @@@@@@@@@@@@@@@@@@@@@%      :@@@@@@@@@@@@@@@@=      #@@@@@@@@@@@@@@@@@@@@@.
#            .%@@@@@@@@@@@@@@@@@@*      .@@@@@@@@@@@@@@@@@@:      +@@@@@@@@@@@@@@@@@@@:
#             .=@@@@@@@@@@@@@@@@:      .@@@@@@@@@@@@@@@@@@@@.      .@@@@@@@@@@@@@@@@#.
#                :#@@@@@@@@@@*.        %@@@@@@@@@@@@@@@@@@@@%        .*@@@@@@@@@@%=.
#                    ..::..           +@@@@@@@@@@@@@@@@@@@@@@+           .::::..
#                                     %@@@@@@@@@@@@@@@@@@@@@@@
#                                     %@@@@@@@@@@@@@@@@@@@@@@@
#                                     %@@@@@@@@@@@@@@@@@@@@@@@
#                                     .@@@@@@@@@@@@@@@@@@@@@@.
#                                      -@@@@@@@@@@@@@@@@@@@@:
#                                       .%@@@@@@@@@@@@@@@@%.
#                                         :%@@@@@@@@@@@@#:
#                                             =%@@@@%+.
#
#
# Audit Modules:
#   1. Network Leak Test       Verify the Tails firewall drops clearnet traffic
#   2. Forensic Swap Scan      Detect swap partitions that could retain plaintext
#   3. Memory Wipe Audit       Confirm kernel memory-sanitisation flags are armed
#   4. Filesystem Integrity    Verify read-only root and Tor binary checksum
#   5. Metadata Audit          Scan Persistent/ files for dangerous metadata via mat2
#
# Design Philosophy:
#   This tool NEVER modifies the system. It reads, checks, and reports  nothing
#   more. Preserving the default Tails fingerprint is paramount: "Anonymity Loves
#   Company." Every user running a differently-hardened Tails is a unique
#   fingerprint. We do not contribute to that problem.
#
# Usage:
#   sudo ./tails_integrity_audit.sh [OPTIONS]
#
# Options:
#   --help         Display this help message
#   --version      Display version information
#   --log FILE     Write audit results to FILE (default: stdout only)
#   --module NAME  Run a single module (network|swap|memory|filesystem|metadata)
#   --no-color     Disable ANSI color output
#
# Requirements:
#   - TailsOS with unlocked Persistent Storage (for metadata module)
#   - Root privileges (for swap and network modules)
#   - mat2 (pre-installed on Tails, required for metadata module)
# =============================================================================

set -euo pipefail

readonly VERSION="1.0.0"
readonly SCRIPT_NAME="tails_integrity_audit.sh"

# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------

readonly PERSIST_ROOT="/live/persistence/TailsData_unlocked"
readonly TOR_BINARY="/usr/local/bin/tor"
readonly CMDLINE_FILE="/proc/cmdline"
readonly NETWORK_TEST_TARGET="8.8.8.8"

# Known-good SHA-256 for the Tor binary shipped with Tails 6.x.
# This value is intentionally left as a placeholder  the operator should
# populate it from a trusted Tails source or verified download.
readonly TOR_EXPECTED_SHA256="${TOR_AUDIT_CHECKSUM:-UNCONFIGURED}"

# ---------------------------------------------------------------------------
# COLOR / OUTPUT
# ---------------------------------------------------------------------------

_init_colors() {
    if [[ -t 1 && "${NO_COLOR:-}" == "" ]]; then
        readonly RED='\033[0;31m'
        readonly GREEN='\033[0;32m'
        readonly YELLOW='\033[1;33m'
        readonly CYAN='\033[0;36m'
        readonly BOLD='\033[1m'
        readonly DIM='\033[2m'
        readonly RESET='\033[0m'
    else
        readonly RED='' GREEN='' YELLOW='' CYAN='' BOLD='' DIM='' RESET=''
    fi
}

# ---------------------------------------------------------------------------
# LOGGING
# ---------------------------------------------------------------------------

LOG_FILE=""

_log_line() {
    local line="$1"
    printf '%s\n' "$line"
    if [[ -n "$LOG_FILE" ]]; then
        printf '%s\n' "$line" >> "$LOG_FILE"
    fi
}

section() {
    _log_line ""
    _log_line "$(printf "${BOLD}${CYAN}==> %s${RESET}" "$*")"
}

pass()  { _log_line "$(printf "  ${GREEN}[PASS]${RESET} %s" "$*")"; }
warn()  { _log_line "$(printf "  ${YELLOW}[WARN]${RESET} %s" "$*")"; }
fail()  { _log_line "$(printf "  ${RED}[FAIL]${RESET} %s" "$*")"; }
info()  { _log_line "$(printf "  ${DIM}[INFO]${RESET} %s" "$*")"; }

# Global counters
AUDIT_PASS=0
AUDIT_WARN=0
AUDIT_FAIL=0

record_pass() { pass "$1"; (( AUDIT_PASS++ )) || true; }
record_warn() { warn "$1"; (( AUDIT_WARN++ )) || true; }
record_fail() { fail "$1"; (( AUDIT_FAIL++ )) || true; }

# ---------------------------------------------------------------------------
# ARGUMENT PARSING
# ---------------------------------------------------------------------------

SINGLE_MODULE=""

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --help)
                show_help
                exit 0
                ;;
            --version)
                printf '%s version %s\n' "$SCRIPT_NAME" "$VERSION"
                exit 0
                ;;
            --log)
                [[ $# -ge 2 ]] || { printf 'ERROR: --log requires a file path argument\n' >&2; exit 1; }
                LOG_FILE="$2"
                shift
                ;;
            --module)
                [[ $# -ge 2 ]] || { printf 'ERROR: --module requires a module name\n' >&2; exit 1; }
                SINGLE_MODULE="$2"
                shift
                ;;
            --no-color)
                NO_COLOR=1
                export NO_COLOR
                ;;
            *)
                printf 'ERROR: Unknown option: %s\n' "$1" >&2
                show_help >&2
                exit 1
                ;;
        esac
        shift
    done
}

show_help() {
    printf '%b' "${BOLD}${SCRIPT_NAME}${RESET} v${VERSION}  Read-Only Integrity Audit for TailsOS

${BOLD}USAGE:${RESET}
    sudo ./${SCRIPT_NAME} [OPTIONS]

${BOLD}OPTIONS:${RESET}
    --help              Display this help message
    --version           Display version information
    --log FILE          Append audit output to FILE
    --module NAME       Run only one module:
                          network | swap | memory | filesystem | metadata
    --no-color          Disable ANSI color output

${BOLD}AUDIT MODULES:${RESET}
    network     Verify the Tails firewall drops clearnet ICMP traffic
    swap        Scan attached drives for active or available swap partitions
    memory      Confirm kernel memory-wipe flags in /proc/cmdline
    filesystem  Check root mount flags and Tor binary checksum
    metadata    Use mat2 to detect sensitive metadata in Persistent/ files

${BOLD}ENVIRONMENT:${RESET}
    TOR_AUDIT_CHECKSUM  Expected SHA-256 of the Tor binary (overrides built-in placeholder)

${BOLD}REQUIREMENTS:${RESET}
    Root privileges (for network and swap modules)
    mat2 (pre-installed on Tails, required for metadata module)
"
}

# ---------------------------------------------------------------------------
# PREFLIGHT
# ---------------------------------------------------------------------------

preflight_check() {
    if [[ "$(id -u)" -ne 0 ]]; then
        printf '%bERROR:%b This script must be run as root (use sudo).\n' "${RED}" "${RESET}" >&2
        exit 1
    fi

    # Verify we are actually on Tails
    if ! grep -qi 'tails' /etc/os-release 2>/dev/null; then
        warn "Could not confirm TailsOS via /etc/os-release  results may be unreliable."
    fi
}

# ---------------------------------------------------------------------------
# MODULE 1: NETWORK LEAK TEST
# ---------------------------------------------------------------------------
# Attempts a single ICMP ping to 8.8.8.8.  On a correctly configured Tails
# system the Tor firewall (nftables) drops all non-Tor clearnet traffic, so
# the ping must FAIL for the system to PASS this check.
# ---------------------------------------------------------------------------

audit_network_leak() {
    section "Module 1: Network Leak Test"
    info "Sending one ICMP packet to ${NETWORK_TEST_TARGET}  firewall should drop it."

    # ping exits 0 on success (reachable), non-zero on failure (dropped/unreachable).
    # -c1: one packet  -W2: 2-second wait  -n: no DNS  output suppressed.
    if ping -c1 -W2 -n "$NETWORK_TEST_TARGET" > /dev/null 2>&1; then
        record_fail "Clearnet ping to ${NETWORK_TEST_TARGET} SUCCEEDED  firewall is NOT blocking direct traffic!"
        warn "This may indicate the Tor firewall rules are misconfigured or disabled."
    else
        record_pass "Clearnet ping to ${NETWORK_TEST_TARGET} was dropped  firewall is enforcing Tor routing."
    fi
}

# ---------------------------------------------------------------------------
# MODULE 2: FORENSIC SWAP SCAN
# ---------------------------------------------------------------------------
# Iterates over all block devices matching /dev/sd* and /dev/nvme* to detect
# any partitions flagged as Linux swap (type 82 / type 8200).  Active swap is
# also checked via /proc/swaps.  Swap partitions retain plaintext memory pages
# and are a serious forensic risk on amnesic systems.
# ---------------------------------------------------------------------------

audit_swap_scan() {
    section "Module 2: Forensic Swap Scan"

    # Check active swap first  this is the most critical finding.
    local active_swap
    active_swap="$(awk 'NR>1 {print $1}' /proc/swaps 2>/dev/null)" || true

    if [[ -n "$active_swap" ]]; then
        while IFS= read -r swap_dev; do
            record_fail "ACTIVE swap detected on: ${swap_dev}  memory pages may be persisted to disk!"
        done <<< "$active_swap"
    else
        record_pass "No active swap partitions found in /proc/swaps."
    fi

    # Scan partition tables on attached drives for swap-type partitions.
    local found_swap_partition=false
    local device

    # Collect devices without globbing into a pipeline to avoid injection.
    while IFS= read -r device; do
        # lsblk outputs one line per partition; filter for swap type.
        local swap_parts
        swap_parts="$(lsblk -lno NAME,FSTYPE "$device" 2>/dev/null \
                      | awk '$2 == "swap" {print $1}')" || true

        if [[ -n "$swap_parts" ]]; then
            found_swap_partition=true
            while IFS= read -r part; do
                record_warn "Swap partition found on ${device}: /dev/${part} (not currently active, but present)."
            done <<< "$swap_parts"
        fi
    done < <(lsblk -ldno NAME,TYPE 2>/dev/null | awk '$2=="disk"{print "/dev/"$1}')

    if [[ "$found_swap_partition" == "false" ]]; then
        record_pass "No swap-type partitions detected on any attached block device."
    fi
}

# ---------------------------------------------------------------------------
# MODULE 3: MEMORY WIPE AUDIT
# ---------------------------------------------------------------------------
# Tails arms the kernel memory sanitiser at boot via two flags on the kernel
# command line.  This module reads /proc/cmdline and verifies both flags are
# present.  Their absence means freed kernel objects and pages are NOT wiped,
# leaving data recoverable after shutdown.
# ---------------------------------------------------------------------------

audit_memory_wipe() {
    section "Module 3: Memory Wipe Audit"

    local cmdline
    cmdline="$(cat "$CMDLINE_FILE")" || {
        record_fail "Cannot read ${CMDLINE_FILE}."
        return
    }

    info "Kernel cmdline: ${cmdline}"

    # slub_debug=P: poisons SLUB allocator objects on free (kernel object wipe).
    if printf '%s' "$cmdline" | grep -q 'slub_debug=P'; then
        record_pass "slub_debug=P is present  SLUB allocator poisoning is active."
    else
        record_fail "slub_debug=P is MISSING from kernel cmdline  freed kernel objects are NOT sanitised."
    fi

    # page_poison=1: poisons freed pages before they are reused (page wipe).
    if printf '%s' "$cmdline" | grep -q 'page_poison=1'; then
        record_pass "page_poison=1 is present  page-level memory poisoning is active."
    else
        record_warn "page_poison=1 is MISSING  this flag was deprecated in favour of 'init_on_free=1' in newer kernels."
        # Check the modern equivalent as a fallback.
        if printf '%s' "$cmdline" | grep -q 'init_on_free=1'; then
            record_pass "init_on_free=1 detected  modern equivalent of page_poison=1 is active."
        else
            record_fail "Neither page_poison=1 nor init_on_free=1 found  freed pages are NOT sanitised."
        fi
    fi
}

# ---------------------------------------------------------------------------
# MODULE 4: FILESYSTEM INTEGRITY
# ---------------------------------------------------------------------------
# Verifies two properties of the running Tails system:
#   a) The root filesystem (/) is mounted read-only, as expected for a live OS.
#   b) The Tor binary checksum matches the expected value, detecting tampering.
# ---------------------------------------------------------------------------

audit_filesystem_integrity() {
    section "Module 4: Filesystem Integrity"

    # --- 4a: Root mount flags ---
    local root_mount_opts
    root_mount_opts="$(awk '$2 == "/" {print $4}' /proc/mounts 2>/dev/null | head -1)" || true

    if [[ -z "$root_mount_opts" ]]; then
        record_fail "Could not determine root filesystem mount options from /proc/mounts."
    else
        info "Root mount options: ${root_mount_opts}"
        # Mount options are a comma-separated list; check for 'ro' as a discrete token.
        if printf '%s' "$root_mount_opts" | grep -qE '(^|,)ro(,|$)'; then
            record_pass "Root filesystem (/) is mounted read-only."
        else
            record_fail "Root filesystem (/) is NOT mounted read-only  this is unexpected for a live Tails session."
        fi
    fi

    # --- 4b: Tor binary checksum ---
    if [[ ! -f "$TOR_BINARY" ]]; then
        record_warn "Tor binary not found at ${TOR_BINARY}  skipping checksum verification."
        return
    fi

    local actual_sha256
    actual_sha256="$(sha256sum "$TOR_BINARY" | awk '{print $1}')" || {
        record_fail "sha256sum failed on ${TOR_BINARY}."
        return
    }

    info "Tor binary SHA-256: ${actual_sha256}"

    if [[ "$TOR_EXPECTED_SHA256" == "UNCONFIGURED" ]]; then
        record_warn "No expected checksum configured. Set TOR_AUDIT_CHECKSUM env var to enable verification."
        info "Current checksum recorded above  store it in a trusted location for future audits."
    elif [[ "$actual_sha256" == "$TOR_EXPECTED_SHA256" ]]; then
        record_pass "Tor binary checksum matches expected value."
    else
        record_fail "Tor binary checksum MISMATCH  binary may have been tampered with!"
        info "Expected: ${TOR_EXPECTED_SHA256}"
        info "Actual:   ${actual_sha256}"
    fi
}

# ---------------------------------------------------------------------------
# MODULE 5: METADATA AUDIT
# ---------------------------------------------------------------------------
# Uses mat2 (Metadata Anonymisation Toolkit, pre-installed on Tails) to
# inspect files in the Persistent Storage for embedded metadata that could
# de-anonymise the user if those files are shared.
#
# mat2 is invoked in check-only mode (--check)  it NEVER modifies files.
# ---------------------------------------------------------------------------

audit_metadata() {
    section "Module 5: Metadata Audit"

    if [[ ! -d "$PERSIST_ROOT" ]]; then
        record_warn "Persistent Storage not found at ${PERSIST_ROOT}  skipping metadata audit."
        info "Unlock Persistent Storage before running this module."
        return
    fi

    if ! command -v mat2 > /dev/null 2>&1; then
        record_warn "mat2 is not available  skipping metadata audit."
        info "mat2 is pre-installed on Tails. If missing, the system image may be non-standard."
        return
    fi

    # mat2 supports specific file types. We target common document/image formats.
    # The -print0 / read -r -d '' pattern handles filenames with spaces safely.
    # -maxdepth 6 bounds the scan to prevent stalls on deep or bind-mounted trees.
    local risky_files=()
    local risky_detail=()
    local clean_files=0
    local skipped_files=0
    local file

    while IFS= read -r -d '' file; do
        # mat2 --check exits 0 if clean, non-zero if metadata found or unsupported.
        local mat2_output
        if mat2_output="$(mat2 --check -- "$file" 2>&1)"; then
            (( clean_files++ )) || true
        else
            # Distinguish "has metadata" from "unsupported file type" via mat2 output.
            if printf '%s' "$mat2_output" | grep -qi 'not supported\|unknown\|cannot'; then
                (( skipped_files++ )) || true
            else
                risky_files+=( "$file" )
                risky_detail+=( "$mat2_output" )
            fi
        fi
    done < <(find "$PERSIST_ROOT" -maxdepth 6 -type f \( \
        -iname '*.pdf'  -o -iname '*.docx' -o -iname '*.odt'  \
        -o -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' \
        -o -iname '*.mp3' -o -iname '*.mp4'  -o -iname '*.mov' \
        -o -iname '*.pptx' -o -iname '*.xlsx' \
        \) -print0 2>/dev/null)

    info "mat2 scan complete. Clean: ${clean_files} | Risky: ${#risky_files[@]} | Skipped: ${skipped_files}"

    if [[ ${#risky_files[@]} -eq 0 ]]; then
        if [[ $clean_files -eq 0 ]]; then
            record_warn "No supported file types found in Persistent Storage to scan."
        else
            record_pass "No metadata detected in ${clean_files} scanned file(s)."
        fi
    else
        record_fail "${#risky_files[@]} file(s) contain potentially identifying metadata:"
        local i
        for i in "${!risky_files[@]}"; do
            # Strip the PERSIST_ROOT prefix so paths in output are relative  safer for logs.
            local display_path="${risky_files[$i]#"${PERSIST_ROOT}/"}"
            info "  → ${display_path}"
            # Print any detail mat2 provided (e.g. specific metadata keys found).
            if [[ -n "${risky_detail[$i]:-}" ]]; then
                info "    ${risky_detail[$i]}"
            fi
        done
        warn "Use 'mat2 <file>' to clean metadata. This audit tool does NOT modify files."
    fi
}

# ---------------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------------

print_summary() {
    local total=$(( AUDIT_PASS + AUDIT_WARN + AUDIT_FAIL ))
    printf '\n'
    printf '%b' "${BOLD}${CYAN}════════════════════════════════════════${RESET}\n"
    printf '%b' "${BOLD}           AUDIT SUMMARY${RESET}\n"
    printf '%b' "${BOLD}${CYAN}════════════════════════════════════════${RESET}\n"
    printf '%b' "  ${GREEN}PASS:${RESET}  ${AUDIT_PASS}\n"
    printf '%b' "  ${YELLOW}WARN:${RESET}  ${AUDIT_WARN}\n"
    printf '%b' "  ${RED}FAIL:${RESET}  ${AUDIT_FAIL}\n"
    printf '%b' "  ${DIM}TOTAL: ${total}${RESET}\n"
    printf '%b' "${BOLD}${CYAN}════════════════════════════════════════${RESET}\n"
    printf '\n'

    if [[ -n "$LOG_FILE" ]]; then
        printf '%b' "${DIM}Audit log written to: ${LOG_FILE}${RESET}\n"
    fi
}

# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

main() {
    parse_args "$@"
    _init_colors
    preflight_check

    printf '%b' "${BOLD}${CYAN}${SCRIPT_NAME}${RESET} v${VERSION}  TailsOS Read-Only Integrity Audit\n"
    printf '%b' "${DIM}$(date '+%Y-%m-%d %H:%M:%S UTC%z')${RESET}\n"

    if [[ -n "$LOG_FILE" ]]; then
        # Refuse to silently overwrite an existing file  append only.
        if [[ ! -e "$LOG_FILE" ]]; then
            printf '# %s v%s  Audit started %s\n' \
                "$SCRIPT_NAME" "$VERSION" "$(date '+%Y-%m-%d %H:%M:%S')" > "$LOG_FILE"
        fi
    fi

    case "$SINGLE_MODULE" in
        network)    audit_network_leak       ;;
        swap)       audit_swap_scan          ;;
        memory)     audit_memory_wipe        ;;
        filesystem) audit_filesystem_integrity ;;
        metadata)   audit_metadata           ;;
        "")
            audit_network_leak
            audit_swap_scan
            audit_memory_wipe
            audit_filesystem_integrity
            audit_metadata
            ;;
        *)
            printf 'ERROR: Unknown module "%s". Valid: network|swap|memory|filesystem|metadata\n' \
                "$SINGLE_MODULE" >&2
            exit 1
            ;;
    esac

    print_summary

    # Exit non-zero if any hard failures were found.
    [[ $AUDIT_FAIL -eq 0 ]]
}

main "$@"
