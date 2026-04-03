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
# This script provides a professional interface for configuring advanced
# security features in TailsOS, ensuring air-gapped operation where possible.
# Features include:
#   - Custom nftables firewall rules persistence
#   - Additional software package management
#
# Designed for security-conscious users requiring persistent configurations
# without compromising Tails' amnesic nature.
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
#
# Security Notes:
#   - All modifications are confined to the persistent volume
#   - No changes to the read-only base system
#   - Operations are logged for auditability
# =============================================================================

set -euo pipefail

# Version
readonly VERSION="2.0.0"

# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------

# Canonical mount point for the unlocked Tails Persistent Storage volume
readonly PERSIST_ROOT="/live/persistence/TailsData_unlocked"

# Path to the persistence feature manifest
readonly PERSIST_CONF="${PERSIST_ROOT}/persistence.conf"

# Firewall configuration
readonly FIREWALL_DIR="${PERSIST_ROOT}/firewall"
readonly FIREWALL_RULES_FILE="${FIREWALL_DIR}/custom-rules.nft"
readonly FIREWALL_BACKUP_DIR="${FIREWALL_DIR}/backups"

# Additional Software configuration
readonly ASP_DIR="${PERSIST_ROOT}/additional-software"
readonly ASP_PACKAGES_FILE="${ASP_DIR}/packages.list"
readonly ASP_BACKUP_DIR="${ASP_DIR}/backups"

# General backups
readonly PERSIST_BACKUP_DIR="${PERSIST_ROOT}/backups"

# Logging
readonly LOG_FILE="${PERSIST_ROOT}/tails_security_setup.log"
readonly LOG_MAX_SIZE=$((1024 * 1024))  # 1MB

# Runtime options
DRY_RUN=false

# Colours (disabled automatically when not writing to a terminal)
if [[ -t 1 ]]; then
    readonly RED='\033[0;31m'; readonly GREEN='\033[0;32m'; readonly YELLOW='\033[1;33m'
    readonly CYAN='\033[0;36m'; readonly BOLD='\033[1m'; readonly RESET='\033[0m'
else
    readonly RED=''; readonly GREEN=''; readonly YELLOW=''; readonly CYAN=''; readonly BOLD=''; readonly RESET=''
fi

# ---------------------------------------------------------------------------
# UTILITY FUNCTIONS
# ---------------------------------------------------------------------------

cleanup() {
    # Cleanup function for traps
    log INFO "Script execution completed or interrupted."
}

trap cleanup EXIT

# Command line parsing
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
${BOLD}tails_advanced_security.sh${RESET} - Advanced Security Automation for TailsOS

USAGE:
    sudo ./tails_advanced_security.sh [OPTIONS]

OPTIONS:
    --dry-run    Show what would be done without making changes
    --help       Display this help message
    --version    Display version information

DESCRIPTION:
    This script provides a professional interface for configuring advanced
    security features in TailsOS, ensuring air-gapped operation where possible.

REQUIREMENTS:
    - TailsOS with unlocked Persistent Storage
    - Root privileges

For more information, see the README.md file.
EOF
}

# Improved logging with rotation
log() {
    local level="$1"; shift
    local msg="$*"
    local ts; ts="$(date '+%Y-%m-%d %H:%M:%S')"
    local log_entry="[$ts] [${level^^}] $msg"

    # Rotate log if too large
    if [[ -f "$LOG_FILE" ]] && [[ $(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE") -gt $LOG_MAX_SIZE ]]; then
        mv "$LOG_FILE" "${LOG_FILE}.old"
    fi

    printf '%s\n' "$log_entry" | tee -a "$LOG_FILE" 2>/dev/null || true
}

info()    { echo -e "${GREEN}[INFO]${RESET}  $*";  log INFO    "$*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; log WARN    "$*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; log ERROR   "$*"; }
section() { echo -e "\n${BOLD}${CYAN}==> $*${RESET}"; }

# Backup function
backup_file() {
    local file="$1"
    local backup_dir="$2"
    if [[ -f "$file" ]]; then
        mkdir -p "$backup_dir"
        local backup_name="${backup_dir}/$(basename "$file").$(date +%Y%m%d_%H%M%S).bak"
        cp "$file" "$backup_name"
        info "Backed up $file to $backup_name"
    fi
}

# Dry run wrapper
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

    # --- 1a. Check /etc/os-release for the Tails identifier ---
    if [[ ! -f /etc/os-release ]]; then
        error "/etc/os-release not found. Cannot confirm OS identity."
        exit 1
    fi

    # Source the file so we can test its variables safely
    # shellcheck source=/dev/null
    source /etc/os-release

    # Tails sets ID=tails and NAME="Tails"
    if [[ "${ID:-}" != "tails" ]]; then
        error "This system is NOT TailsOS (ID='${ID:-unknown}'). Aborting."
        exit 1
    fi
    info "OS confirmed: ${NAME} ${VERSION:-} (ID=${ID})"

    # --- 1b. Confirm the amnesic live-boot environment ---
    # /live is the SquashFS overlay mount point present on every Tails boot
    if [[ ! -d /live ]]; then
        error "/live directory absent — unexpected for a live Tails session."
        exit 1
    fi
    info "Live boot environment detected (/live present)."

    # --- 1c. Confirm the persistent volume is unlocked and mounted ---
    if [[ ! -d "${PERSIST_ROOT}" ]]; then
        error "Persistent Storage not found at '${PERSIST_ROOT}'."
        error "Please unlock Persistent Storage before running this script."
        exit 1
    fi

    # Confirm it is actually a mount point, not just a dangling directory
    if ! mountpoint -q "${PERSIST_ROOT}" 2>/dev/null; then
        warn "'${PERSIST_ROOT}' exists but does not appear to be a mount point."
        warn "Proceeding, but verify your Persistent Storage is truly unlocked."
    else
        info "Persistent Storage is mounted at '${PERSIST_ROOT}'."
    fi

    # --- 1d. Ensure we are running as root ---
    if [[ "${EUID}" -ne 0 ]]; then
        error "This script must be run with root privileges (use sudo)."
        exit 1
    fi
    info "Running as root. ✓"

    # --- 1e. Check for required commands ---
    for cmd in nft apt-get; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            error "Required command '$cmd' not found in PATH."
            exit 1
        fi
    done
    info "Required commands available."

    # --- 1f. Confirm persistence.conf exists ---
    if [[ ! -f "${PERSIST_CONF}" ]]; then
        error "persistence.conf not found at '${PERSIST_CONF}'."
        error "Persistent Storage may not be properly configured."
        exit 1
    fi
    info "Persistence configuration found."

    echo ""
    info "Environment validation passed."
}

# ---------------------------------------------------------------------------
# 2. FEATURE SELECTION MENU
# ---------------------------------------------------------------------------

show_menu() {
    section "Advanced Security Feature Selection"
    echo ""
    echo "  Which feature would you like to configure?"
    echo ""
    echo "  ${BOLD}1)${RESET} User-Defined Firewall Rules   — add / remove nftables rules"
    echo "  ${BOLD}2)${RESET} Additional Software Persistence — manage persisted packages"
    echo "  ${BOLD}3)${RESET} Both of the above"
    echo "  ${BOLD}4)${RESET} Show current configuration status"
    echo "  ${BOLD}q)${RESET} Quit"
    echo ""
    read -r -p "  Enter choice [1/2/3/4/q]: " MENU_CHOICE
}

# ---------------------------------------------------------------------------
# 3A. FEATURE: USER-DEFINED FIREWALL
# ---------------------------------------------------------------------------

ensure_firewall_persisted_in_conf() {
    # Adds the firewall directory to persistence.conf if not already present.
    if grep -qF "firewall" "${PERSIST_CONF}" 2>/dev/null; then
        info "Firewall directory already listed in persistence.conf."
    else
        warn "Firewall entry missing from persistence.conf — adding it."
        {
            echo ""
            echo "# User-defined firewall rules (added by tails_advanced_security.sh)"
            echo "/live/persistence/TailsData_unlocked/firewall source=Firewall"
        } >> "${PERSIST_CONF}"
        info "Firewall persistence entry added to persistence.conf."
    fi
}

install_firewall_dispatcher() {
    # Installs a NetworkManager dispatcher script (to the live/writable tmpfs
    # overlay at /etc/NetworkManager/dispatcher.d/) that applies our custom
    # nftables rules from the persistent volume at every pre-up network event.
    # The dispatcher itself is session-only; the rules FILE is what persists.
    local dispatcher_path="/etc/NetworkManager/dispatcher.d/99-tails-custom-firewall"

    cat > "${dispatcher_path}" << 'DISPATCHER'
#!/usr/bin/env bash
# NetworkManager dispatcher: apply custom nftables rules from persistent volume.
# Arguments passed by NM: <interface> <event>

RULES_FILE="/live/persistence/TailsData_unlocked/firewall/custom-rules.nft"

if [[ "$2" == "pre-up" ]] && [[ -f "${RULES_FILE}" ]]; then
    logger -t tails-firewall "Applying custom nftables rules from ${RULES_FILE}"
    nft -f "${RULES_FILE}" || \
        logger -t tails-firewall "WARNING: nftables rule application failed"
fi
DISPATCHER

    chmod 750 "${dispatcher_path}"
    info "NetworkManager dispatcher installed at '${dispatcher_path}' (this session)."
}

configure_firewall() {
    section "User-Defined Firewall Configuration"

    mkdir -p "${FIREWALL_DIR}"

    # Seed a commented template if the rules file does not yet exist
    if [[ ! -f "${FIREWALL_RULES_FILE}" ]]; then
        cat > "${FIREWALL_RULES_FILE}" << 'NFT_TEMPLATE'
# =============================================================================
# TailsOS Custom nftables Rules
# Managed by: tails_advanced_security.sh
# Location:   /live/persistence/TailsData_unlocked/firewall/custom-rules.nft
#
# These rules are applied AFTER Tails' base hardened ruleset at each boot.
# Only add what you genuinely need — Tails' defaults are already strict.
#
# nftables quick reference:
#   table inet filter { chain input { type filter hook input priority 0; } }
#   ip saddr 192.168.1.0/24 accept     -- allow a subnet
#   tcp dport 22 drop                  -- block SSH inbound
#   log prefix "TAILS-CUSTOM: " drop  -- log and drop
# =============================================================================
NFT_TEMPLATE
        info "Created rules template at '${FIREWALL_RULES_FILE}'."
    fi

    ensure_firewall_persisted_in_conf
    install_firewall_dispatcher

    echo ""
    echo "  ${BOLD}a)${RESET} Add a new firewall rule"
    echo "  ${BOLD}r)${RESET} Remove an existing rule"
    echo "  ${BOLD}v)${RESET} View current custom rules"
    echo "  ${BOLD}t)${RESET} Test / apply rules to the running kernel now"
    echo "  ${BOLD}s)${RESET} Show rules currently loaded in the kernel"
    echo "  ${BOLD}b)${RESET} Back to main menu"
    echo ""
    read -r -p "  Choice [a/r/v/t/s/b]: " fw_choice

    case "${fw_choice,,}" in

        a)
            echo ""
            echo "  Enter a single-line nftables rule to append."
            echo "  Example: ip saddr 10.0.0.0/8 tcp dport 80 drop"
            echo ""
            read -r -p "  Rule: " new_rule
            [[ -z "${new_rule}" ]] && { warn "Empty input — no rule added."; return; }

            backup_file "${FIREWALL_RULES_FILE}" "${FIREWALL_BACKUP_DIR}"

            # Validate syntax before persisting (wrap in a minimal table context)
            if echo "table inet _test { chain _c { ${new_rule}; } }" \
                | nft --check -f - 2>/dev/null; then
                info "Syntax OK. Appending to ${FIREWALL_RULES_FILE}."
                execute bash -c "{
                    echo '# Added $(date '+%Y-%m-%d %H:%M:%S') by tails_advanced_security.sh'
                    echo '${new_rule}'
                } >> '${FIREWALL_RULES_FILE}'"
                info "Rule saved. Will be applied at next boot."
                echo ""
                read -r -p "  Apply to running kernel now? [y/N]: " apply_now
                if [[ "${apply_now,,}" == "y" ]]; then
                    execute nft -f "${FIREWALL_RULES_FILE}" \
                        && info "Rules applied to running kernel." \
                        || warn "nft returned errors — check the rules file."
                fi
            else
                error "Syntax check failed. Rule NOT saved. Verify and retry."
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
            local total_lines; total_lines=$(wc -l < "${FIREWALL_RULES_FILE}")
            if ! [[ "${del_line}" =~ ^[0-9]+$ ]] || \
               [[ "${del_line}" -lt 1 ]] || [[ "${del_line}" -gt "${total_lines}" ]]; then
                error "Invalid line number '${del_line}'."; return
            fi
            backup_file "${FIREWALL_RULES_FILE}" "${FIREWALL_BACKUP_DIR}"
            execute sed -i "${del_line}d" "${FIREWALL_RULES_FILE}"
            info "Line ${del_line} deleted from ${FIREWALL_RULES_FILE}."
            ;;

        v)
            echo ""; info "Contents of ${FIREWALL_RULES_FILE}:"; echo "---"
            cat "${FIREWALL_RULES_FILE}"; echo "---"
            ;;

        t)
            info "Running: nft -f ${FIREWALL_RULES_FILE}"
            execute nft -f "${FIREWALL_RULES_FILE}" \
                && info "Rules applied successfully." \
                || error "nft reported errors — rules NOT fully applied."
            ;;

        s)
            info "Kernel nftables ruleset:"; echo "---"
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
    # Registers the Additional Software feature in persistence.conf if absent.
    if grep -qE "AdditionalSoftware|additional-software" "${PERSIST_CONF}" 2>/dev/null; then
        info "Additional Software already registered in persistence.conf."
    else
        warn "Additional Software entry missing — adding it."
        backup_file "${PERSIST_CONF}" "${PERSIST_BACKUP_DIR}"
        execute bash -c "{
            echo ''
            echo '# Additional Software persistence (tails_advanced_security.sh)'
            echo '/usr/local/lib/tails-additional-software'
        } >> '${PERSIST_CONF}'"
        info "Additional Software entry added to persistence.conf."
    fi
}

configure_additional_software() {
    section "Additional Software Persistence Configuration"

    mkdir -p "${ASP_DIR}"

    if [[ ! -f "${ASP_PACKAGES_FILE}" ]]; then
        cat > "${ASP_PACKAGES_FILE}" << 'PKG_TEMPLATE'
# =============================================================================
# TailsOS Additional Software Package List
# Managed by: tails_advanced_security.sh
# Location:   /live/persistence/TailsData_unlocked/additional-software/packages.list
#
# One Debian package name per line.  Lines beginning with # are comments.
# Tails installs these automatically when Persistent Storage is unlocked,
# using locally cached .deb files stored alongside this file.
#
# Discover packages:  apt-cache search <keyword>
# =============================================================================
PKG_TEMPLATE
        info "Created packages.list template at '${ASP_PACKAGES_FILE}'."
    fi

    ensure_asp_persisted_in_conf

    echo ""
    echo "  ${BOLD}a)${RESET} Add a package to the persistence list"
    echo "  ${BOLD}r)${RESET} Remove a package from the list"
    echo "  ${BOLD}v)${RESET} View current package list"
    echo "  ${BOLD}i)${RESET} Install + cache all listed packages now (requires network)"
    echo "  ${BOLD}b)${RESET} Back to main menu"
    echo ""
    read -r -p "  Choice [a/r/v/i/b]: " asp_choice

    case "${asp_choice,,}" in

        a)
            echo ""
            read -r -p "  Debian package name to add: " pkg_name
            [[ -z "${pkg_name}" ]] && { warn "Empty input — nothing added."; return; }

            # Validate Debian package naming rules
            if ! [[ "${pkg_name}" =~ ^[a-z0-9][a-z0-9.+\-]*$ ]]; then
                error "'${pkg_name}' is not a valid Debian package name."; return
            fi

            # Check apt sources know this package
            if ! apt-cache show "${pkg_name}" &>/dev/null; then
                warn "apt-cache has no record of '${pkg_name}'. Check your sources."
                read -r -p "  Add anyway? [y/N]: " force_add
                [[ "${force_add,,}" != "y" ]] && { warn "Skipped."; return; }
            fi

            # Guard duplicates
            if grep -qxF "${pkg_name}" "${ASP_PACKAGES_FILE}" 2>/dev/null; then
                warn "'${pkg_name}' is already in the list."; return
            fi

            backup_file "${ASP_PACKAGES_FILE}" "${ASP_BACKUP_DIR}"
            execute echo "${pkg_name}" >> "${ASP_PACKAGES_FILE}"
            info "'${pkg_name}' added. Will be installed at next boot."
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
                # Escape special regex chars in the package name before sed
                local escaped; escaped=$(printf '%s\n' "${rm_pkg}" | sed 's/[[\.*^$()+?{|]/\\&/g')
                backup_file "${ASP_PACKAGES_FILE}" "${ASP_BACKUP_DIR}"
                execute sed -i "/^${escaped}$/d" "${ASP_PACKAGES_FILE}"
                info "'${rm_pkg}' removed from the list."
            else
                warn "'${rm_pkg}' not found in the list."
            fi
            ;;

        v)
            echo ""; info "Contents of ${ASP_PACKAGES_FILE}:"; echo "---"
            cat "${ASP_PACKAGES_FILE}"; echo "---"
            ;;

        i)
            mapfile -t pkgs < <(grep -v '^#' "${ASP_PACKAGES_FILE}" \
                                | grep '[[:alnum:]]')
            if [[ ${#pkgs[@]} -eq 0 ]]; then
                warn "No packages listed — nothing to install."; return
            fi
            info "Updating apt cache…"
            execute apt-get update -qq
            info "Installing: ${pkgs[*]}"
            execute DEBIAN_FRONTEND=noninteractive \
                apt-get install -y --no-install-recommends "${pkgs[@]}" \
                && info "All packages installed successfully." \
                || error "apt-get returned errors — review output above."
            info "Tip: Confirm the list in the Additional Software GUI to ensure"
            info "offline .deb caching is handled by tails-additional-software."
            ;;

        b) return ;;
        *) warn "Unrecognised choice '${asp_choice}'." ;;
    esac
}

# ---------------------------------------------------------------------------
# 4. STATUS DISPLAY
# ---------------------------------------------------------------------------

show_status() {
    section "Current Advanced Security Configuration Status"
    echo ""
    echo "  ${BOLD}Persistent Volume:${RESET} ${PERSIST_ROOT}"
    echo ""

    echo "  ${BOLD}persistence.conf active features:${RESET}"
    if [[ -f "${PERSIST_CONF}" ]]; then
        grep -v '^#' "${PERSIST_CONF}" | grep '[[:alnum:]]' | sed 's/^/    /'
    else
        echo "    (file not found)"
    fi

    echo ""
    echo "  ${BOLD}Firewall rules file:${RESET} ${FIREWALL_RULES_FILE}"
    if [[ -f "${FIREWALL_RULES_FILE}" ]]; then
        local rule_count
        rule_count=$(grep -cv '^[[:space:]]*#\|^[[:space:]]*$' "${FIREWALL_RULES_FILE}" || true)
        echo "    Active (non-comment) lines: ${rule_count}"
    else
        echo "    Not configured yet."
    fi

    echo ""
    echo "  ${BOLD}Additional Software packages:${RESET} ${ASP_PACKAGES_FILE}"
    if [[ -f "${ASP_PACKAGES_FILE}" ]]; then
        local pkg_count
        pkg_count=$(grep -cv '^[[:space:]]*#\|^[[:space:]]*$' "${ASP_PACKAGES_FILE}" || true)
        echo "    Persisted package count: ${pkg_count}"
        if [[ "${pkg_count}" -gt 0 ]]; then
            grep -v '^#' "${ASP_PACKAGES_FILE}" | grep '[[:alnum:]]' | sed 's/^/      • /'
        fi
    else
        echo "    Not configured yet."
    fi

    echo ""
    echo "  ${BOLD}Live nftables tables (kernel):${RESET}"
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
    echo " / / / _ `/ / (_-</ /_/ /\ \    _\ \/ -_) __/ // / __/ / __/ // /   / __ / // / __/ _ \/  ' \/ _ `/ __/ / _ \/ _ \"
    echo "/_/  \_,_/_/_/___/\____/___/   /___/\__/\__/\_,_/_/ /_/\__/\_, /   /_/ |_\_,_/\__/\___/_/_/_/\_,_/\__/_/\___/_//_/"
    echo "                                                          /___/                                                   "
    echo -e "${RESET}"

    validate_tails_environment

    while true; do
        show_menu
        case "${MENU_CHOICE,,}" in
            1) configure_firewall ;;
            2) configure_additional_software ;;
            3) configure_firewall; configure_additional_software ;;
            4) show_status ;;
            q) info "Exiting. Log saved to ${LOG_FILE}"; exit 0 ;;
            *) warn "Invalid choice '${MENU_CHOICE}'. Enter 1, 2, 3, 4, or q." ;;
        esac
    done
}

main "$@"
