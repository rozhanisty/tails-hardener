#!/usr/bin/env bash
# =============================================================================
# tails_advanced_security.sh
# =============================================================================
# Advanced Security Automation for TailsOS
#
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
# Features:
#   - Custom nftables firewall rules persistence
#   - Additional software package management
#   - MAC address randomization policy
#   - Tor configuration persistence
#   - Kernel hardening via sysctl
#   - Security audit & health check
#   - Configuration backup & restore
#
# Usage:
#   sudo ./tails_advanced_security.sh [OPTIONS]
#
# Options:
#   --dry-run    Show what would be done without making changes
#   --help       Display this help message
#   --version    Display version information
#
# Requirements:
#   - TailsOS with unlocked Persistent Storage
#   - Root privileges
# =============================================================================

set -euo pipefail

readonly VERSION="2.1.0"

# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------

readonly PERSIST_ROOT="/live/persistence/TailsData_unlocked"
readonly PERSIST_CONF="${PERSIST_ROOT}/persistence.conf"

# Firewall
readonly FIREWALL_DIR="${PERSIST_ROOT}/firewall"
readonly FIREWALL_RULES_FILE="${FIREWALL_DIR}/custom-rules.nft"
readonly FIREWALL_BACKUP_DIR="${FIREWALL_DIR}/backups"

# Additional Software
readonly ASP_DIR="${PERSIST_ROOT}/additional-software"
readonly ASP_PACKAGES_FILE="${ASP_DIR}/packages.list"
readonly ASP_BACKUP_DIR="${ASP_DIR}/backups"

# MAC Randomization
readonly MAC_DIR="${PERSIST_ROOT}/mac-randomization"
readonly MAC_CONF_FILE="${MAC_DIR}/mac-policy.conf"
readonly MAC_BACKUP_DIR="${MAC_DIR}/backups"
readonly MAC_NM_CONF="/etc/NetworkManager/conf.d/99-tasa-mac.conf"

# Tor Configuration
readonly TOR_DIR="${PERSIST_ROOT}/tor-config"
readonly TOR_CUSTOM_FILE="${TOR_DIR}/custom-torrc"
readonly TOR_BACKUP_DIR="${TOR_DIR}/backups"
readonly TOR_APPLIED_MARKER="/run/tasa-tor-custom-applied"

# Kernel Hardening
readonly SYSCTL_DIR="${PERSIST_ROOT}/kernel-hardening"
readonly SYSCTL_CONF_FILE="${SYSCTL_DIR}/custom-sysctl.conf"
readonly SYSCTL_BACKUP_DIR="${SYSCTL_DIR}/backups"

# Configuration Archives
readonly CONFIG_ARCHIVE_DIR="${PERSIST_ROOT}/config-archives"

# General backups
readonly PERSIST_BACKUP_DIR="${PERSIST_ROOT}/backups"

# NetworkManager dispatcher directory (tmpfs — session-only)
readonly DISPATCHER_BASE="/etc/NetworkManager/dispatcher.d"

# Logging
readonly LOG_FILE="${PERSIST_ROOT}/tails_security_setup.log"
readonly LOG_MAX_SIZE=$((1024 * 1024))  # 1 MB

DRY_RUN=false

# Colors — disabled automatically when stdout is not a terminal
if [[ -t 1 ]]; then
    readonly RED='\033[0;31m'
    readonly GREEN='\033[0;32m'
    readonly YELLOW='\033[1;33m'
    readonly CYAN='\033[0;36m'
    readonly BLUE='\033[0;34m'
    readonly BOLD='\033[1m'
    readonly DIM='\033[2m'
    readonly RESET='\033[0m'
else
    readonly RED='' GREEN='' YELLOW='' CYAN='' BLUE='' BOLD='' DIM='' RESET=''
fi

# ---------------------------------------------------------------------------
# UTILITY FUNCTIONS
# ---------------------------------------------------------------------------

cleanup() {
    log INFO "Script execution completed or interrupted."
}

trap cleanup EXIT

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                DRY_RUN=true
                log INFO "Dry-run mode enabled"
                ;;
            --help)
                show_help
                exit 0
                ;;
            --version)
                echo "tails_advanced_security.sh version $VERSION"
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
        shift
    done
}

show_help() {
    cat << EOF
${BOLD}tails_advanced_security.sh${RESET} v${VERSION} — Advanced Security Automation for TailsOS

${BOLD}USAGE:${RESET}
    sudo ./tails_advanced_security.sh [OPTIONS]

${BOLD}OPTIONS:${RESET}
    --dry-run    Simulate all operations without writing to disk
    --help       Display this help message
    --version    Display version information

${BOLD}FEATURES:${RESET}
    Firewall management · Software persistence · MAC randomization
    Tor configuration · Kernel hardening · Security audit · Backup & restore

${BOLD}REQUIREMENTS:${RESET}
    TailsOS with unlocked Persistent Storage · Root privileges
EOF
}

log() {
    local level="$1"; shift
    local msg="$*"
    local ts; ts="$(date '+%Y-%m-%d %H:%M:%S')"
    local entry="[$ts] [${level^^}] $msg"

    if [[ -f "$LOG_FILE" ]] && \
       [[ $(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0) -gt $LOG_MAX_SIZE ]]; then
        mv "$LOG_FILE" "${LOG_FILE}.old"
    fi

    printf '%s\n' "$entry" | tee -a "$LOG_FILE" 2>/dev/null || true
}

info()    { echo -e "${GREEN}[INFO]${RESET}  $*";        log INFO  "$*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*";       log WARN  "$*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2;      log ERROR "$*"; }
section() { echo -e "\n${BOLD}${CYAN}==> $*${RESET}"; }

# Audit-mode status line — used by run_security_audit()
check_status() {
    local label="$1"
    local state="$2"   # ok | warn | fail
    local detail="${3:-}"
    case "${state}" in
        ok)   printf "  ${GREEN}[✓]${RESET} %-42s ${DIM}%s${RESET}\n" "${label}" "${detail}" ;;
        warn) printf "  ${YELLOW}[!]${RESET} %-42s ${DIM}%s${RESET}\n" "${label}" "${detail}" ;;
        fail) printf "  ${RED}[✗]${RESET} %-42s ${DIM}%s${RESET}\n" "${label}" "${detail}" ;;
    esac
}

backup_file() {
    local file="$1"
    local backup_dir="$2"
    if [[ -f "$file" ]]; then
        mkdir -p "$backup_dir"
        local dest="${backup_dir}/$(basename "$file").$(date +%Y%m%d_%H%M%S).bak"
        cp "$file" "$dest"
        info "Backed up $(basename "$file") → ${dest}"
    fi
}

execute() {
    if $DRY_RUN; then
        info "[DRY-RUN] Would execute: $*"
    else
        "$@"
    fi
}

# ---------------------------------------------------------------------------
# 1. ENVIRONMENT VALIDATION
# ---------------------------------------------------------------------------

validate_tails_environment() {
    section "Validating TailsOS Environment"

    # OS identity
    if [[ ! -f /etc/os-release ]]; then
        error "/etc/os-release not found — cannot confirm OS identity."
        exit 1
    fi
    # shellcheck source=/dev/null
    source /etc/os-release
    if [[ "${ID:-}" != "tails" ]]; then
        error "Not running on TailsOS (ID='${ID:-unknown}'). Aborting."
        exit 1
    fi
    info "OS confirmed: ${NAME} ${VERSION_ID:-} (ID=${ID})"

    # Live-boot environment
    if [[ ! -d /live ]]; then
        error "/live directory absent — unexpected for a live Tails session."
        exit 1
    fi
    info "Live boot environment detected."

    # Persistent volume
    if [[ ! -d "${PERSIST_ROOT}" ]]; then
        error "Persistent Storage not found at '${PERSIST_ROOT}'."
        error "Unlock Persistent Storage before running this script."
        exit 1
    fi
    if ! mountpoint -q "${PERSIST_ROOT}" 2>/dev/null; then
        warn "'${PERSIST_ROOT}' exists but is not a mount point — verify Persistent Storage is unlocked."
    else
        info "Persistent Storage mounted at '${PERSIST_ROOT}'."
    fi

    # Root
    if [[ "${EUID}" -ne 0 ]]; then
        error "This script must be run with root privileges (sudo)."
        exit 1
    fi
    info "Running as root."

    # Required commands
    local required_cmds=(nft apt-get sysctl)
    for cmd in "${required_cmds[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            error "Required command '${cmd}' not found in PATH."
            exit 1
        fi
    done
    info "Required commands available (nft, apt-get, sysctl)."

    # persistence.conf
    if [[ ! -f "${PERSIST_CONF}" ]]; then
        error "persistence.conf not found at '${PERSIST_CONF}'."
        exit 1
    fi
    info "persistence.conf found."

    echo ""
    info "Environment validation passed."
}

# ---------------------------------------------------------------------------
# 2. MAIN MENU
# ---------------------------------------------------------------------------

show_menu() {
    echo ""
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}${CYAN}║${RESET}       ${BOLD}TASA  ·  Advanced Security Feature Selection${RESET}               ${BOLD}${CYAN}║${RESET}"
    echo -e "${BOLD}${CYAN}╠══════════════════════════════════════════════════════════════════════╣${RESET}"
    echo -e "${BOLD}${CYAN}║${RESET}                                                                      ${BOLD}${CYAN}║${RESET}"
    echo -e "${BOLD}${CYAN}║${RESET}  ${BOLD}[1]${RESET} Firewall Management      — nftables rules & dispatcher         ${BOLD}${CYAN}║${RESET}"
    echo -e "${BOLD}${CYAN}║${RESET}  ${BOLD}[2]${RESET} Software Persistence     — Debian package management           ${BOLD}${CYAN}║${RESET}"
    echo -e "${BOLD}${CYAN}║${RESET}  ${BOLD}[3]${RESET} MAC Randomization        — hardware address privacy            ${BOLD}${CYAN}║${RESET}"
    echo -e "${BOLD}${CYAN}║${RESET}  ${BOLD}[4]${RESET} Tor Configuration        — custom torrc persistence            ${BOLD}${CYAN}║${RESET}"
    echo -e "${BOLD}${CYAN}║${RESET}  ${BOLD}[5]${RESET} Kernel Hardening         — sysctl privacy parameters           ${BOLD}${CYAN}║${RESET}"
    echo -e "${BOLD}${CYAN}║${RESET}  ${BOLD}[6]${RESET} Security Audit           — system health & config check        ${BOLD}${CYAN}║${RESET}"
    echo -e "${BOLD}${CYAN}║${RESET}  ${BOLD}[7]${RESET} Backup & Restore         — export / import configuration       ${BOLD}${CYAN}║${RESET}"
    echo -e "${BOLD}${CYAN}║${RESET}  ${BOLD}[8]${RESET} Status Overview          — current configuration at a glance   ${BOLD}${CYAN}║${RESET}"
    echo -e "${BOLD}${CYAN}║${RESET}                                                                      ${BOLD}${CYAN}║${RESET}"
    echo -e "${BOLD}${CYAN}║${RESET}  ${BOLD}[q]${RESET} Quit                                                           ${BOLD}${CYAN}║${RESET}"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
    read -r -p "  Enter choice [1-8 / q]: " MENU_CHOICE
}

# ---------------------------------------------------------------------------
# 3A. FEATURE: USER-DEFINED FIREWALL
# ---------------------------------------------------------------------------

ensure_firewall_persisted_in_conf() {
    if grep -qF "firewall" "${PERSIST_CONF}" 2>/dev/null; then
        info "Firewall directory already in persistence.conf."
    else
        warn "Firewall entry missing — adding to persistence.conf."
        {
            echo ""
            echo "# User-defined firewall rules (tails_advanced_security.sh)"
            echo "/live/persistence/TailsData_unlocked/firewall source=Firewall"
        } >> "${PERSIST_CONF}"
        info "Firewall persistence entry added."
    fi
}

install_firewall_dispatcher() {
    local path="${DISPATCHER_BASE}/99-tasa-firewall"
    cat > "${path}" << 'DISPATCHER'
#!/usr/bin/env bash
# TASA: Apply custom nftables rules from Persistent Storage at network pre-up.
RULES="/live/persistence/TailsData_unlocked/firewall/custom-rules.nft"
if [[ "$2" == "pre-up" ]] && [[ -f "${RULES}" ]]; then
    logger -t tasa-firewall "Applying custom nftables rules from ${RULES}"
    nft -f "${RULES}" || logger -t tasa-firewall "WARNING: nftables apply failed"
fi
DISPATCHER
    chmod 750 "${path}"
    info "Firewall dispatcher installed at '${path}' (this session)."
}

configure_firewall() {
    section "User-Defined Firewall Configuration"

    mkdir -p "${FIREWALL_DIR}"

    if [[ ! -f "${FIREWALL_RULES_FILE}" ]]; then
        cat > "${FIREWALL_RULES_FILE}" << 'NFT_TEMPLATE'
# =============================================================================
# TailsOS Custom nftables Rules — managed by tails_advanced_security.sh
# Applied AFTER Tails' base hardened ruleset at each boot via NM dispatcher.
#
# Quick reference:
#   table inet filter { chain input { type filter hook input priority 0; } }
#   ip saddr 192.168.1.0/24 accept
#   tcp dport 22 drop
#   log prefix "TASA: " drop
# =============================================================================
NFT_TEMPLATE
        info "Created rules template at '${FIREWALL_RULES_FILE}'."
    fi

    ensure_firewall_persisted_in_conf
    install_firewall_dispatcher

    echo ""
    echo "  ${BOLD}[a]${RESET} Add a new rule"
    echo "  ${BOLD}[r]${RESET} Remove a rule by line number"
    echo "  ${BOLD}[v]${RESET} View current rules file"
    echo "  ${BOLD}[t]${RESET} Test / apply rules to running kernel"
    echo "  ${BOLD}[s]${RESET} Show kernel ruleset (nft list ruleset)"
    echo "  ${BOLD}[b]${RESET} Back"
    echo ""
    read -r -p "  Choice [a/r/v/t/s/b]: " fw_choice

    case "${fw_choice,,}" in
        a)
            echo ""
            echo "  Enter a single-line nftables rule."
            echo "  Example: ip saddr 10.0.0.0/8 tcp dport 80 drop"
            echo ""
            read -r -p "  Rule: " new_rule
            [[ -z "${new_rule}" ]] && { warn "Empty input — nothing added."; return; }

            backup_file "${FIREWALL_RULES_FILE}" "${FIREWALL_BACKUP_DIR}"

            if echo "table inet _test { chain _c { ${new_rule}; } }" \
               | nft --check -f - 2>/dev/null; then
                info "Syntax OK — appending to ${FIREWALL_RULES_FILE}."
                execute bash -c "printf '# Added %s\n%s\n' \
                    \"$(date '+%Y-%m-%d %H:%M:%S')\" \
                    \"${new_rule}\" >> '${FIREWALL_RULES_FILE}'"
                info "Rule saved. Will be applied at next boot."
                echo ""
                read -r -p "  Apply to running kernel now? [y/N]: " apply_now
                if [[ "${apply_now,,}" == "y" ]]; then
                    execute nft -f "${FIREWALL_RULES_FILE}" \
                        && info "Rules applied to running kernel." \
                        || warn "nft returned errors — review the rules file."
                fi
            else
                error "Syntax check failed. Rule NOT saved."
            fi
            ;;

        r)
            if [[ ! -s "${FIREWALL_RULES_FILE}" ]]; then
                warn "Rules file is empty — nothing to remove."; return
            fi
            echo ""
            grep -n '' "${FIREWALL_RULES_FILE}"
            echo ""
            read -r -p "  Line number to delete: " del_line
            local total; total=$(wc -l < "${FIREWALL_RULES_FILE}")
            if ! [[ "${del_line}" =~ ^[0-9]+$ ]] || \
               [[ "${del_line}" -lt 1 ]] || [[ "${del_line}" -gt "${total}" ]]; then
                error "Invalid line number '${del_line}'."; return
            fi
            backup_file "${FIREWALL_RULES_FILE}" "${FIREWALL_BACKUP_DIR}"
            execute sed -i "${del_line}d" "${FIREWALL_RULES_FILE}"
            info "Line ${del_line} deleted."
            ;;

        v)
            echo ""; info "Contents of ${FIREWALL_RULES_FILE}:"; echo "---"
            cat "${FIREWALL_RULES_FILE}"; echo "---"
            ;;

        t)
            info "Applying: nft -f ${FIREWALL_RULES_FILE}"
            execute nft -f "${FIREWALL_RULES_FILE}" \
                && info "Rules applied to running kernel." \
                || error "nft reported errors — rules may not be fully applied."
            ;;

        s)
            info "Current kernel nftables ruleset:"; echo "---"
            nft list ruleset; echo "---"
            ;;

        b) return ;;
        *) warn "Unrecognised choice '${fw_choice}'." ;;
    esac
}

# ---------------------------------------------------------------------------
# 3B. FEATURE: ADDITIONAL SOFTWARE PERSISTENCE
# ---------------------------------------------------------------------------

ensure_asp_persisted_in_conf() {
    if grep -qE "AdditionalSoftware|additional-software" "${PERSIST_CONF}" 2>/dev/null; then
        info "Additional Software already in persistence.conf."
    else
        warn "Additional Software entry missing — adding it."
        backup_file "${PERSIST_CONF}" "${PERSIST_BACKUP_DIR}"
        execute bash -c "printf '\n# Additional Software (tails_advanced_security.sh)\n/usr/local/lib/tails-additional-software\n' >> '${PERSIST_CONF}'"
        info "Additional Software entry added."
    fi
}

configure_additional_software() {
    section "Additional Software Persistence"

    mkdir -p "${ASP_DIR}"

    if [[ ! -f "${ASP_PACKAGES_FILE}" ]]; then
        cat > "${ASP_PACKAGES_FILE}" << 'PKG_TEMPLATE'
# =============================================================================
# TailsOS Additional Software Package List — managed by tails_advanced_security.sh
# One Debian package name per line. Comments begin with #.
# Tails installs these from locally cached .deb files at boot.
# Discover packages: apt-cache search <keyword>
# =============================================================================
PKG_TEMPLATE
        info "Created packages.list template at '${ASP_PACKAGES_FILE}'."
    fi

    ensure_asp_persisted_in_conf

    echo ""
    echo "  ${BOLD}[a]${RESET} Add a package"
    echo "  ${BOLD}[r]${RESET} Remove a package"
    echo "  ${BOLD}[v]${RESET} View package list"
    echo "  ${BOLD}[c]${RESET} Check install status of listed packages"
    echo "  ${BOLD}[i]${RESET} Install + cache all listed packages (requires network)"
    echo "  ${BOLD}[b]${RESET} Back"
    echo ""
    read -r -p "  Choice [a/r/v/c/i/b]: " asp_choice

    case "${asp_choice,,}" in
        a)
            echo ""
            read -r -p "  Debian package name to add: " pkg_name
            [[ -z "${pkg_name}" ]] && { warn "Empty input — nothing added."; return; }

            if ! [[ "${pkg_name}" =~ ^[a-z0-9][a-z0-9.+\-]*$ ]]; then
                error "'${pkg_name}' is not a valid Debian package name."; return
            fi

            if ! apt-cache show "${pkg_name}" &>/dev/null; then
                warn "apt-cache has no record of '${pkg_name}'. Check your sources."
                read -r -p "  Add anyway? [y/N]: " force_add
                [[ "${force_add,,}" != "y" ]] && { warn "Skipped."; return; }
            fi

            if grep -qxF "${pkg_name}" "${ASP_PACKAGES_FILE}" 2>/dev/null; then
                warn "'${pkg_name}' is already in the list."; return
            fi

            backup_file "${ASP_PACKAGES_FILE}" "${ASP_BACKUP_DIR}"
            execute bash -c "echo '${pkg_name}' >> '${ASP_PACKAGES_FILE}'"
            info "'${pkg_name}' added — will be installed at next boot."
            ;;

        r)
            if ! grep -v '^#' "${ASP_PACKAGES_FILE}" | grep -q '[[:alnum:]]'; then
                warn "No active packages in the list."; return
            fi
            echo ""
            grep -v '^#' "${ASP_PACKAGES_FILE}" | grep '[[:alnum:]]' | nl -ba
            echo ""
            read -r -p "  Package name to remove: " rm_pkg
            if grep -qxF "${rm_pkg}" "${ASP_PACKAGES_FILE}"; then
                local esc; esc=$(printf '%s\n' "${rm_pkg}" | sed 's/[[\.*^$()+?{|]/\\&/g')
                backup_file "${ASP_PACKAGES_FILE}" "${ASP_BACKUP_DIR}"
                execute sed -i "/^${esc}$/d" "${ASP_PACKAGES_FILE}"
                info "'${rm_pkg}' removed from the list."
            else
                warn "'${rm_pkg}' not found in the list."
            fi
            ;;

        v)
            echo ""; info "Contents of ${ASP_PACKAGES_FILE}:"; echo "---"
            cat "${ASP_PACKAGES_FILE}"; echo "---"
            ;;

        c)
            mapfile -t pkgs < <(grep -v '^#' "${ASP_PACKAGES_FILE}" | grep '[[:alnum:]]')
            if [[ ${#pkgs[@]} -eq 0 ]]; then
                warn "No packages listed."; return
            fi
            echo ""
            for pkg in "${pkgs[@]}"; do
                if dpkg -s "${pkg}" &>/dev/null 2>&1; then
                    local ver; ver=$(dpkg -s "${pkg}" | grep '^Version:' | awk '{print $2}')
                    check_status "${pkg}" "ok" "installed (${ver})"
                else
                    check_status "${pkg}" "warn" "not installed this session"
                fi
            done
            echo ""
            ;;

        i)
            mapfile -t pkgs < <(grep -v '^#' "${ASP_PACKAGES_FILE}" | grep '[[:alnum:]]')
            if [[ ${#pkgs[@]} -eq 0 ]]; then
                warn "No packages listed — nothing to install."; return
            fi
            info "Updating apt cache…"
            execute apt-get update -qq
            info "Installing: ${pkgs[*]}"
            execute DEBIAN_FRONTEND=noninteractive \
                apt-get install -y --no-install-recommends "${pkgs[@]}" \
                && info "All packages installed." \
                || error "apt-get returned errors — review output above."
            info "Confirm the list in the Additional Software GUI for offline .deb caching."
            ;;

        b) return ;;
        *) warn "Unrecognised choice '${asp_choice}'." ;;
    esac
}

# ---------------------------------------------------------------------------
# 3C. FEATURE: MAC ADDRESS RANDOMIZATION
# ---------------------------------------------------------------------------

install_mac_dispatcher() {
    local path="${DISPATCHER_BASE}/98-tasa-mac"
    cat > "${path}" << 'DISPATCHER'
#!/usr/bin/env bash
# TASA: Apply MAC randomization policy from Persistent Storage at network pre-up.
MAC_CONF="/live/persistence/TailsData_unlocked/mac-randomization/mac-policy.conf"
DEST="/etc/NetworkManager/conf.d/99-tasa-mac.conf"
if [[ "$2" == "pre-up" ]] && [[ -f "${MAC_CONF}" ]] && [[ ! -f "${DEST}" ]]; then
    cp "${MAC_CONF}" "${DEST}"
    logger -t tasa-mac "MAC policy applied from ${MAC_CONF}"
fi
DISPATCHER
    chmod 750 "${path}"
    info "MAC randomization dispatcher installed (this session)."
}

configure_mac_randomization() {
    section "MAC Address Randomization"

    mkdir -p "${MAC_DIR}"

    local current_policy="not configured"
    if [[ -f "${MAC_CONF_FILE}" ]]; then
        current_policy=$(grep -oE 'random|stable' "${MAC_CONF_FILE}" | head -1 || echo "custom")
    fi

    echo ""
    echo -e "  Current policy: ${BOLD}${current_policy}${RESET}"
    echo ""
    echo "  ${BOLD}[1]${RESET} Full randomization   — new random MAC per connection (max privacy)"
    echo "  ${BOLD}[2]${RESET} Stable randomization — consistent MAC per network (less fingerprint)"
    echo "  ${BOLD}[3]${RESET} Remove policy        — revert to Tails default behaviour"
    echo "  ${BOLD}[v]${RESET} View current policy file"
    echo "  ${BOLD}[b]${RESET} Back"
    echo ""
    read -r -p "  Choice [1/2/3/v/b]: " mac_choice

    case "${mac_choice}" in
        1)
            backup_file "${MAC_CONF_FILE}" "${MAC_BACKUP_DIR}"
            cat > "${MAC_CONF_FILE}" << 'MAC_CONF'
# TASA: MAC Address Randomization Policy — Full Random
# Applied at network pre-up via NetworkManager dispatcher.

[connection]
wifi.cloned-mac-address=random
ethernet.cloned-mac-address=random

[device]
wifi.scan-rand-mac-address=yes
MAC_CONF
            install_mac_dispatcher
            execute cp "${MAC_CONF_FILE}" "${MAC_NM_CONF}"
            info "Full MAC randomization enabled and applied this session."
            ;;

        2)
            backup_file "${MAC_CONF_FILE}" "${MAC_BACKUP_DIR}"
            cat > "${MAC_CONF_FILE}" << 'MAC_CONF'
# TASA: MAC Address Randomization Policy — Stable
# Consistent MAC per SSID/network; still avoids hardware MAC exposure.

[connection]
wifi.cloned-mac-address=stable
ethernet.cloned-mac-address=stable

[device]
wifi.scan-rand-mac-address=yes
MAC_CONF
            install_mac_dispatcher
            execute cp "${MAC_CONF_FILE}" "${MAC_NM_CONF}"
            info "Stable MAC randomization enabled and applied this session."
            ;;

        3)
            if [[ -f "${MAC_CONF_FILE}" ]]; then
                backup_file "${MAC_CONF_FILE}" "${MAC_BACKUP_DIR}"
                execute rm -f "${MAC_CONF_FILE}" "${MAC_NM_CONF}"
                info "Custom MAC policy removed. Tails default behaviour restored."
            else
                warn "No custom MAC policy found."
            fi
            ;;

        v)
            if [[ -f "${MAC_CONF_FILE}" ]]; then
                echo ""; cat "${MAC_CONF_FILE}"
            else
                warn "No custom MAC policy configured."
            fi
            ;;

        b) return ;;
        *) warn "Invalid choice." ;;
    esac
}

# ---------------------------------------------------------------------------
# 3D. FEATURE: TOR CONFIGURATION PERSISTENCE
# ---------------------------------------------------------------------------

install_tor_dispatcher() {
    local path="${DISPATCHER_BASE}/97-tasa-tor"
    cat > "${path}" << 'DISPATCHER'
#!/usr/bin/env bash
# TASA: Append custom torrc entries from Persistent Storage once per session.
TOR_CUSTOM="/live/persistence/TailsData_unlocked/tor-config/custom-torrc"
MARKER="/run/tasa-tor-custom-applied"

if [[ "$2" == "up" ]] && [[ -f "${TOR_CUSTOM}" ]] && [[ ! -f "${MARKER}" ]]; then
    # Wait briefly for Tor to initialise
    local retries=5
    while [[ ${retries} -gt 0 ]]; do
        systemctl is-active --quiet tor 2>/dev/null && break
        sleep 2
        (( retries-- )) || true
    done
    if systemctl is-active --quiet tor 2>/dev/null; then
        cat "${TOR_CUSTOM}" >> /etc/tor/torrc
        touch "${MARKER}"
        systemctl reload tor 2>/dev/null || true
        logger -t tasa-tor "Custom torrc appended from ${TOR_CUSTOM}"
    else
        logger -t tasa-tor "WARNING: Tor not active — custom torrc not applied"
    fi
fi
DISPATCHER
    chmod 750 "${path}"
    info "Tor configuration dispatcher installed (this session)."
}

configure_tor() {
    section "Tor Configuration Persistence"

    mkdir -p "${TOR_DIR}"

    if [[ ! -f "${TOR_CUSTOM_FILE}" ]]; then
        cat > "${TOR_CUSTOM_FILE}" << 'TOR_TEMPLATE'
# =============================================================================
# TailsOS Custom Tor Configuration — managed by tails_advanced_security.sh
# These entries are APPENDED to /etc/tor/torrc once per session at network-up.
# Do NOT duplicate directives that Tails already sets (e.g. SocksPort, User).
#
# Common additions:
#   UseBridges 1
#   Bridge obfs4 <addr>:<port> <fingerprint> cert=<cert> iat-mode=0
#   ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy
#   StrictNodes 1
#   ExitNodes {us},{gb}
# =============================================================================
# TASA-CUSTOM-START
TOR_TEMPLATE
        info "Created custom-torrc template at '${TOR_CUSTOM_FILE}'."
    fi

    install_tor_dispatcher

    echo ""
    echo "  ${BOLD}[a]${RESET} Add a torrc directive"
    echo "  ${BOLD}[r]${RESET} Remove a directive by line number"
    echo "  ${BOLD}[v]${RESET} View current custom config"
    echo "  ${BOLD}[t]${RESET} Apply custom config this session (appends to /etc/tor/torrc)"
    echo "  ${BOLD}[b]${RESET} Back"
    echo ""
    read -r -p "  Choice [a/r/v/t/b]: " tor_choice

    case "${tor_choice,,}" in
        a)
            echo ""
            echo "  Enter a torrc directive (e.g. 'UseBridges 1' or 'Bridge obfs4 ...')"
            read -r -p "  Entry: " tor_entry
            [[ -z "${tor_entry}" ]] && { warn "Empty input — nothing added."; return; }

            backup_file "${TOR_CUSTOM_FILE}" "${TOR_BACKUP_DIR}"
            execute bash -c "echo '${tor_entry}' >> '${TOR_CUSTOM_FILE}'"
            info "Directive added. Will be applied at next network-up event."
            ;;

        r)
            if [[ ! -s "${TOR_CUSTOM_FILE}" ]]; then
                warn "Config file is empty."; return
            fi
            echo ""
            grep -n '' "${TOR_CUSTOM_FILE}"
            echo ""
            read -r -p "  Line number to delete: " del_line
            local total; total=$(wc -l < "${TOR_CUSTOM_FILE}")
            if ! [[ "${del_line}" =~ ^[0-9]+$ ]] || \
               [[ "${del_line}" -lt 1 ]] || [[ "${del_line}" -gt "${total}" ]]; then
                error "Invalid line number '${del_line}'."; return
            fi
            backup_file "${TOR_CUSTOM_FILE}" "${TOR_BACKUP_DIR}"
            execute sed -i "${del_line}d" "${TOR_CUSTOM_FILE}"
            info "Line ${del_line} deleted."
            ;;

        v)
            echo ""; info "Contents of ${TOR_CUSTOM_FILE}:"; echo "---"
            cat "${TOR_CUSTOM_FILE}"; echo "---"
            ;;

        t)
            if [[ -f "${TOR_APPLIED_MARKER}" ]]; then
                warn "Custom Tor config already applied this session (marker exists)."
                read -r -p "  Force reapply? [y/N]: " force_tor
                [[ "${force_tor,,}" != "y" ]] && return
                execute rm -f "${TOR_APPLIED_MARKER}"
            fi
            if systemctl is-active --quiet tor 2>/dev/null; then
                execute bash -c "cat '${TOR_CUSTOM_FILE}' >> /etc/tor/torrc"
                execute touch "${TOR_APPLIED_MARKER}"
                execute systemctl reload tor 2>/dev/null \
                    && info "Custom Tor config applied and Tor reloaded." \
                    || warn "Tor reload failed — check: systemctl status tor"
            else
                warn "Tor service is not running. Start Tor first."
            fi
            ;;

        b) return ;;
        *) warn "Invalid choice." ;;
    esac
}

# ---------------------------------------------------------------------------
# 3E. FEATURE: KERNEL HARDENING (SYSCTL)
# ---------------------------------------------------------------------------

write_privacy_sysctl_preset() {
    cat > "${SYSCTL_CONF_FILE}" << 'SYSCTL'
# =============================================================================
# TailsOS Kernel Privacy Hardening — managed by tails_advanced_security.sh
# Preset: Privacy / Security
# Applied via: sysctl -p and NM dispatcher at network pre-up
# =============================================================================

# Restrict kernel symbol addresses from unprivileged users
kernel.kptr_restrict = 2
# Restrict access to kernel log
kernel.dmesg_restrict = 1
# Disable unprivileged BPF (reduces attack surface)
kernel.unprivileged_bpf_disabled = 1
# Harden the BPF JIT compiler
net.core.bpf_jit_harden = 2
# Restrict ptrace to direct parent only (reduces lateral movement)
kernel.yama.ptrace_scope = 1

# SYN flood protection
net.ipv4.tcp_syncookies = 1
# Reverse path filtering — anti-spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
# Reject ICMP redirect messages (prevents route hijacking)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
# Disable sending ICMP redirects
net.ipv4.conf.all.send_redirects = 0
# Log martian packets (packets with impossible source addresses)
net.ipv4.conf.all.log_martians = 1
# Ignore broadcast ICMP pings
net.ipv4.icmp_echo_ignore_broadcasts = 1
# Ignore bogus ICMP error responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Full Address Space Layout Randomisation
kernel.randomize_va_space = 2
# Protect symlinks and hardlinks against TOCTOU attacks
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
# Prevent setuid programs from dumping core
fs.suid_dumpable = 0
SYSCTL
}

install_sysctl_dispatcher() {
    local path="${DISPATCHER_BASE}/96-tasa-sysctl"
    cat > "${path}" << 'DISPATCHER'
#!/usr/bin/env bash
# TASA: Apply kernel hardening parameters from Persistent Storage at network pre-up.
SYSCTL_CONF="/live/persistence/TailsData_unlocked/kernel-hardening/custom-sysctl.conf"
if [[ "$2" == "pre-up" ]] && [[ -f "${SYSCTL_CONF}" ]]; then
    sysctl -p "${SYSCTL_CONF}" 2>/dev/null || \
        logger -t tasa-sysctl "WARNING: some sysctl parameters failed to apply"
    logger -t tasa-sysctl "Kernel hardening parameters applied from ${SYSCTL_CONF}"
fi
DISPATCHER
    chmod 750 "${path}"
    info "Kernel hardening dispatcher installed (this session)."
}

configure_kernel_hardening() {
    section "Kernel Hardening (sysctl)"

    mkdir -p "${SYSCTL_DIR}"

    echo ""
    echo "  ${BOLD}[p]${RESET} Apply Privacy Preset  — 20 hardened kernel parameters"
    echo "  ${BOLD}[a]${RESET} Add custom parameter  — key = value"
    echo "  ${BOLD}[r]${RESET} Remove a parameter    — by line number"
    echo "  ${BOLD}[v]${RESET} View current config"
    echo "  ${BOLD}[t]${RESET} Apply to running kernel (sysctl -p)"
    echo "  ${BOLD}[b]${RESET} Back"
    echo ""
    read -r -p "  Choice [p/a/r/v/t/b]: " sysctl_choice

    case "${sysctl_choice,,}" in
        p)
            backup_file "${SYSCTL_CONF_FILE}" "${SYSCTL_BACKUP_DIR}"
            write_privacy_sysctl_preset
            install_sysctl_dispatcher
            info "Privacy preset written to ${SYSCTL_CONF_FILE}."
            execute sysctl -p "${SYSCTL_CONF_FILE}" 2>&1 \
                && info "Parameters applied to running kernel." \
                || warn "Some parameters may not apply — check kernel version support."
            ;;

        a)
            echo ""
            echo "  Format: key = value   (e.g. net.ipv4.ip_forward = 0)"
            read -r -p "  Entry: " sysctl_entry
            [[ -z "${sysctl_entry}" ]] && { warn "Empty input."; return; }

            if ! echo "${sysctl_entry}" | grep -qE '^[a-zA-Z_][a-zA-Z0-9_.]*\s*=\s*[0-9]+'; then
                warn "Entry should be: key = numeric_value. Proceed anyway?"
                read -r -p "  [y/N]: " force_add
                [[ "${force_add,,}" != "y" ]] && return
            fi

            if [[ ! -f "${SYSCTL_CONF_FILE}" ]]; then
                printf '# TailsOS Custom Kernel Parameters\n# managed by tails_advanced_security.sh\n' \
                    > "${SYSCTL_CONF_FILE}"
            fi

            backup_file "${SYSCTL_CONF_FILE}" "${SYSCTL_BACKUP_DIR}"
            execute bash -c "echo '${sysctl_entry}' >> '${SYSCTL_CONF_FILE}'"
            info "Parameter added to ${SYSCTL_CONF_FILE}."
            ;;

        r)
            if [[ ! -s "${SYSCTL_CONF_FILE}" ]]; then
                warn "Config file is empty."; return
            fi
            echo ""
            grep -n '' "${SYSCTL_CONF_FILE}"
            echo ""
            read -r -p "  Line number to delete: " del_line
            local total; total=$(wc -l < "${SYSCTL_CONF_FILE}")
            if ! [[ "${del_line}" =~ ^[0-9]+$ ]] || \
               [[ "${del_line}" -lt 1 ]] || [[ "${del_line}" -gt "${total}" ]]; then
                error "Invalid line number '${del_line}'."; return
            fi
            backup_file "${SYSCTL_CONF_FILE}" "${SYSCTL_BACKUP_DIR}"
            execute sed -i "${del_line}d" "${SYSCTL_CONF_FILE}"
            info "Line ${del_line} removed."
            ;;

        v)
            if [[ -f "${SYSCTL_CONF_FILE}" ]]; then
                echo ""; info "Contents of ${SYSCTL_CONF_FILE}:"; echo "---"
                cat "${SYSCTL_CONF_FILE}"; echo "---"
            else
                warn "No kernel hardening config found."
            fi
            ;;

        t)
            if [[ -f "${SYSCTL_CONF_FILE}" ]]; then
                execute sysctl -p "${SYSCTL_CONF_FILE}" 2>&1 \
                    && info "Kernel parameters applied." \
                    || warn "Some parameters failed — check output above."
            else
                warn "No config file found. Apply a preset or add parameters first."
            fi
            ;;

        b) return ;;
        *) warn "Invalid choice." ;;
    esac
}

# ---------------------------------------------------------------------------
# 3F. FEATURE: SECURITY AUDIT
# ---------------------------------------------------------------------------

run_security_audit() {
    section "Security Audit & Health Check"
    echo ""

    # --- Firewall ---
    local nft_lines
    nft_lines=$(nft list ruleset 2>/dev/null | wc -l || echo 0)
    if [[ "${nft_lines}" -gt 5 ]]; then
        check_status "nftables ruleset loaded" "ok" "${nft_lines} lines"
    else
        check_status "nftables ruleset loaded" "warn" "minimal/empty — Tails default only"
    fi

    if [[ -f "${FIREWALL_RULES_FILE}" ]] && [[ -s "${FIREWALL_RULES_FILE}" ]]; then
        local fw_rules
        fw_rules=$(grep -cv '^[[:space:]]*#\|^[[:space:]]*$' "${FIREWALL_RULES_FILE}" || true)
        check_status "Custom nftables rules persisted" "ok" "${fw_rules} active rule(s)"
    else
        check_status "Custom nftables rules persisted" "warn" "none configured"
    fi

    if [[ -x "${DISPATCHER_BASE}/99-tasa-firewall" ]]; then
        check_status "Firewall dispatcher installed" "ok" "active this session"
    else
        check_status "Firewall dispatcher installed" "warn" "not installed — run Firewall Management"
    fi

    # --- MAC ---
    if [[ -f "${MAC_CONF_FILE}" ]]; then
        local mac_mode
        mac_mode=$(grep -oE 'random|stable' "${MAC_CONF_FILE}" | head -1 || echo "custom")
        check_status "MAC randomization policy" "ok" "mode: ${mac_mode}"
    else
        check_status "MAC randomization policy" "warn" "not configured (hardware MAC exposed)"
    fi

    if [[ -f "${MAC_NM_CONF}" ]]; then
        check_status "MAC randomization active" "ok" "NM config present this session"
    else
        check_status "MAC randomization active" "warn" "NM config not applied this session"
    fi

    # --- Tor ---
    if systemctl is-active --quiet tor 2>/dev/null; then
        check_status "Tor service" "ok" "running"
    else
        check_status "Tor service" "warn" "not active"
    fi

    local tor_entry_count=0
    if [[ -f "${TOR_CUSTOM_FILE}" ]]; then
        tor_entry_count=$(grep -cv '^#\|^[[:space:]]*$\|TASA-CUSTOM' "${TOR_CUSTOM_FILE}" 2>/dev/null || true)
    fi
    if [[ "${tor_entry_count}" -gt 0 ]]; then
        check_status "Custom torrc directives" "ok" "${tor_entry_count} entry(s)"
    else
        check_status "Custom torrc directives" "warn" "none — using Tails defaults"
    fi

    if [[ -f "${TOR_APPLIED_MARKER}" ]]; then
        check_status "Custom torrc applied" "ok" "applied this session"
    else
        check_status "Custom torrc applied" "warn" "not applied this session"
    fi

    # --- Kernel ---
    if [[ -f "${SYSCTL_CONF_FILE}" ]] && [[ -s "${SYSCTL_CONF_FILE}" ]]; then
        local sysctl_count
        sysctl_count=$(grep -cv '^#\|^[[:space:]]*$' "${SYSCTL_CONF_FILE}" || true)
        check_status "Kernel hardening config" "ok" "${sysctl_count} parameter(s) configured"
    else
        check_status "Kernel hardening config" "warn" "not configured"
    fi

    local aslr; aslr=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo "?")
    if [[ "${aslr}" == "2" ]]; then
        check_status "ASLR (randomize_va_space)" "ok" "full (value=2)"
    else
        check_status "ASLR (randomize_va_space)" "warn" "value=${aslr} (expected 2)"
    fi

    local kptr; kptr=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null || echo "?")
    if [[ "${kptr}" == "2" ]]; then
        check_status "Kernel pointer restriction" "ok" "strict (value=2)"
    else
        check_status "Kernel pointer restriction" "warn" "value=${kptr} (expected 2)"
    fi

    local ipv6_redir; ipv6_redir=$(cat /proc/sys/net/ipv6/conf/all/accept_redirects 2>/dev/null || echo "?")
    if [[ "${ipv6_redir}" == "0" ]]; then
        check_status "IPv6 ICMP redirect rejection" "ok" "disabled"
    else
        check_status "IPv6 ICMP redirect rejection" "warn" "enabled (MITM risk)"
    fi

    local bpf_unpriv; bpf_unpriv=$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo "?")
    if [[ "${bpf_unpriv}" == "1" ]]; then
        check_status "Unprivileged BPF" "ok" "disabled"
    else
        check_status "Unprivileged BPF" "warn" "enabled (value=${bpf_unpriv})"
    fi

    # --- Storage & system ---
    if [[ -w "${PERSIST_ROOT}" ]]; then
        check_status "Persistent volume writable" "ok" "${PERSIST_ROOT}"
    else
        check_status "Persistent volume writable" "fail" "not writable!"
    fi

    if mount | grep -qE "^[^ ]+ on / .*\bro\b"; then
        check_status "Root filesystem (read-only)" "ok" "protected"
    else
        check_status "Root filesystem (read-only)" "warn" "may not be read-only"
    fi

    if [[ -f "${LOG_FILE}" ]]; then
        local log_size; log_size=$(stat -c%s "${LOG_FILE}" 2>/dev/null || echo 0)
        check_status "Audit log present" "ok" "$(( log_size / 1024 ))KB — ${LOG_FILE}"
    else
        check_status "Audit log present" "warn" "log file not created yet"
    fi

    echo ""
    info "Audit complete. Investigate any [!] or [✗] items above."
    echo ""
}

# ---------------------------------------------------------------------------
# 3G. FEATURE: BACKUP & RESTORE
# ---------------------------------------------------------------------------

manage_backups() {
    section "Configuration Backup & Restore"

    mkdir -p "${CONFIG_ARCHIVE_DIR}"

    echo ""
    echo "  ${BOLD}[c]${RESET} Create full configuration backup"
    echo "  ${BOLD}[l]${RESET} List existing backups"
    echo "  ${BOLD}[r]${RESET} Restore from a backup"
    echo "  ${BOLD}[d]${RESET} Delete backups older than 30 days"
    echo "  ${BOLD}[b]${RESET} Back"
    echo ""
    read -r -p "  Choice [c/l/r/d/b]: " bk_choice

    case "${bk_choice,,}" in
        c)
            local archive="${CONFIG_ARCHIVE_DIR}/tasa_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
            info "Creating backup archive: ${archive}"

            local items=()
            [[ -d "${FIREWALL_DIR}" ]]  && items+=("${FIREWALL_DIR}")
            [[ -d "${ASP_DIR}" ]]       && items+=("${ASP_DIR}")
            [[ -d "${MAC_DIR}" ]]       && items+=("${MAC_DIR}")
            [[ -d "${TOR_DIR}" ]]       && items+=("${TOR_DIR}")
            [[ -d "${SYSCTL_DIR}" ]]    && items+=("${SYSCTL_DIR}")
            [[ -f "${PERSIST_CONF}" ]]  && items+=("${PERSIST_CONF}")

            if [[ ${#items[@]} -eq 0 ]]; then
                warn "Nothing to back up — no TASA configuration found."; return
            fi

            execute tar -czf "${archive}" "${items[@]}" 2>/dev/null \
                && info "Backup created: ${archive}" \
                || error "Backup failed — check permissions and disk space."
            ;;

        l)
            echo ""
            if ls "${CONFIG_ARCHIVE_DIR}"/*.tar.gz &>/dev/null 2>&1; then
                ls -lh "${CONFIG_ARCHIVE_DIR}"/*.tar.gz \
                    | awk '{printf "  %-50s %s\n", $9, $5}'
            else
                warn "No backups found in ${CONFIG_ARCHIVE_DIR}."
            fi
            ;;

        r)
            if ! ls "${CONFIG_ARCHIVE_DIR}"/*.tar.gz &>/dev/null 2>&1; then
                warn "No backups found."; return
            fi
            echo ""
            ls "${CONFIG_ARCHIVE_DIR}"/*.tar.gz | nl -ba
            echo ""
            read -r -p "  Enter the full path of the backup to restore: " restore_file
            if [[ ! -f "${restore_file}" ]]; then
                error "File not found: ${restore_file}"; return
            fi

            warn "This will OVERWRITE current configuration with backup contents."
            read -r -p "  Confirm restore? [y/N]: " confirm
            if [[ "${confirm,,}" == "y" ]]; then
                execute tar -xzf "${restore_file}" -C / \
                    && info "Restore complete. Verify configuration and restart services." \
                    || error "Restore failed — archive may be corrupt."
            else
                info "Restore cancelled."
            fi
            ;;

        d)
            local old
            old=$(find "${CONFIG_ARCHIVE_DIR}" -name "*.tar.gz" -mtime +30 2>/dev/null || true)
            if [[ -z "${old}" ]]; then
                info "No backups older than 30 days found."; return
            fi
            echo ""
            echo "  Backups older than 30 days:"
            echo "${old}" | sed 's/^/    /'
            echo ""
            read -r -p "  Delete these? [y/N]: " confirm_del
            if [[ "${confirm_del,,}" == "y" ]]; then
                execute find "${CONFIG_ARCHIVE_DIR}" -name "*.tar.gz" -mtime +30 -delete
                info "Old backups deleted."
            else
                info "Deletion cancelled."
            fi
            ;;

        b) return ;;
        *) warn "Invalid choice." ;;
    esac
}

# ---------------------------------------------------------------------------
# 4. STATUS OVERVIEW
# ---------------------------------------------------------------------------

show_status() {
    section "Current Configuration Status"
    echo ""

    printf "  ${BOLD}%-28s${RESET} %s\n" "Persistent Volume:" "${PERSIST_ROOT}"
    echo ""

    # --- persistence.conf active entries ---
    echo -e "  ${BOLD}persistence.conf features:${RESET}"
    if [[ -f "${PERSIST_CONF}" ]]; then
        grep -v '^#' "${PERSIST_CONF}" | grep '[[:alnum:]]' | sed 's/^/    /'
    else
        echo "    (file not found)"
    fi

    # --- Firewall ---
    echo ""
    echo -e "  ${BOLD}Firewall (nftables):${RESET}"
    if [[ -f "${FIREWALL_RULES_FILE}" ]]; then
        local fw_count
        fw_count=$(grep -cv '^[[:space:]]*#\|^[[:space:]]*$' "${FIREWALL_RULES_FILE}" || true)
        echo "    Active rules : ${fw_count}"
        echo "    Rules file   : ${FIREWALL_RULES_FILE}"
    else
        echo "    Not configured."
    fi

    # --- Additional Software ---
    echo ""
    echo -e "  ${BOLD}Additional Software:${RESET}"
    if [[ -f "${ASP_PACKAGES_FILE}" ]]; then
        local pkg_count
        pkg_count=$(grep -cv '^[[:space:]]*#\|^[[:space:]]*$' "${ASP_PACKAGES_FILE}" || true)
        echo "    Packages persisted : ${pkg_count}"
        if [[ "${pkg_count}" -gt 0 ]]; then
            grep -v '^#' "${ASP_PACKAGES_FILE}" | grep '[[:alnum:]]' | sed 's/^/      • /'
        fi
    else
        echo "    Not configured."
    fi

    # --- MAC ---
    echo ""
    echo -e "  ${BOLD}MAC Randomization:${RESET}"
    if [[ -f "${MAC_CONF_FILE}" ]]; then
        local mac_mode
        mac_mode=$(grep -oE 'random|stable' "${MAC_CONF_FILE}" | head -1 || echo "custom")
        echo "    Policy   : ${mac_mode}"
        echo "    Config   : ${MAC_CONF_FILE}"
        if [[ -f "${MAC_NM_CONF}" ]]; then
            echo "    Session  : applied"
        else
            echo "    Session  : not applied (run MAC Randomization to activate)"
        fi
    else
        echo "    Not configured."
    fi

    # --- Tor ---
    echo ""
    echo -e "  ${BOLD}Tor Configuration:${RESET}"
    if [[ -f "${TOR_CUSTOM_FILE}" ]]; then
        local tor_count
        tor_count=$(grep -cv '^#\|^[[:space:]]*$\|TASA-CUSTOM' "${TOR_CUSTOM_FILE}" 2>/dev/null || true)
        echo "    Directives : ${tor_count}"
        echo "    Config     : ${TOR_CUSTOM_FILE}"
        if [[ -f "${TOR_APPLIED_MARKER}" ]]; then
            echo "    Session    : applied"
        else
            echo "    Session    : not applied"
        fi
    else
        echo "    Not configured."
    fi

    # --- Kernel Hardening ---
    echo ""
    echo -e "  ${BOLD}Kernel Hardening (sysctl):${RESET}"
    if [[ -f "${SYSCTL_CONF_FILE}" ]]; then
        local sk_count
        sk_count=$(grep -cv '^#\|^[[:space:]]*$' "${SYSCTL_CONF_FILE}" || true)
        echo "    Parameters : ${sk_count}"
        echo "    Config     : ${SYSCTL_CONF_FILE}"
        local aslr; aslr=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo "?")
        echo "    ASLR live  : ${aslr} (2=full)"
    else
        echo "    Not configured."
    fi

    # --- Backups ---
    echo ""
    echo -e "  ${BOLD}Configuration Archives:${RESET} ${CONFIG_ARCHIVE_DIR}"
    if ls "${CONFIG_ARCHIVE_DIR}"/*.tar.gz &>/dev/null 2>&1; then
        local bk_count
        bk_count=$(ls "${CONFIG_ARCHIVE_DIR}"/*.tar.gz 2>/dev/null | wc -l)
        echo "    ${bk_count} archive(s) available"
    else
        echo "    No archives."
    fi

    # --- Live nftables summary ---
    echo ""
    echo -e "  ${BOLD}Live nftables tables (kernel):${RESET}"
    nft list tables 2>/dev/null | sed 's/^/    /' || echo "    (nft unavailable)"
    echo ""
}

# ---------------------------------------------------------------------------
# 5. MAIN
# ---------------------------------------------------------------------------

main() {
    parse_args "$@"

    clear
    echo -e "${BOLD}${CYAN}"
    echo " ______     _ __    ____  ____    ____                 _ __           ___       __                  __  _         "
    echo "/_  __/__ _(_) /__ / __ \/ __/   / __/__ ______ ______(_) /___ __    / _ |__ __/ /____  __ _  ___ _/ /_(_)__  ___ "
    echo " / / / _ \`/ / (_-</ /_/ /\ \    _\ \/ -_) __/ // / __/ / __/ // /   / __ / // / __/ _ \/  ' \/ _ \`/ __/ / _ \/ _ \\"
    echo "/_/  \_,_/_/_/___/\____/___/   /___/\__/\__/\_,_/_/ /_/\__/\_, /   /_/ |_\_,_/\__/\___/_/_/_/\_,_/\__/_/\___/_//_/"
    echo "                                                          /___/                                                    "
    echo -e "${RESET}"
    echo -e "  ${DIM}v${VERSION}  ·  Advanced Security Automation for TailsOS${RESET}"
    echo ""

    validate_tails_environment

    while true; do
        show_menu
        case "${MENU_CHOICE,,}" in
            1) configure_firewall ;;
            2) configure_additional_software ;;
            3) configure_mac_randomization ;;
            4) configure_tor ;;
            5) configure_kernel_hardening ;;
            6) run_security_audit ;;
            7) manage_backups ;;
            8) show_status ;;
            q) info "Exiting. Audit log: ${LOG_FILE}"; exit 0 ;;
            *) warn "Invalid choice '${MENU_CHOICE}'. Enter 1–8 or q." ;;
        esac
    done
}

main "$@"
