# TailsOS Advanced Security Automation (TASA)

This script `tails_advanced_security.sh` (v2.0.0) is a hardened Bash utility designed for power users who need to bridge the gap between Tails' **amnesic nature** and the requirement for **persistent security configurations**. 

## Before Starting, Visit These:

[![TailsOS](https://img.shields.io/badge/Tails_OS-563D7C?logo=tails&logoColor=white)](https://tails.net)
[![Tor Project](https://img.shields.io/badge/Tor_Project-7D4698?logo=torproject&logoColor=white)](https://www.torproject.org)
[![Debian](https://img.shields.io/badge/Debian-D70A53?logo=debian&logoColor=white)](https://www.debian.org)
[![Privacy Guides](https://img.shields.io/badge/Privacy_Guides-00ADFF?logo=shield&logoColor=white)](https://www.privacyguides.org)

---

## Core Capabilities

| Feature | Description | Mechanism |
| :--- | :--- | :--- |
| **Custom Firewall** | Persistent `nftables` rules applied at every boot. | NetworkManager `pre-up` dispatcher. |
| **Software Persistence** | Automated Debian package management. | `persistence.conf` + `packages.list` integration. |
| **Syntax Guard** | Prevents broken rules from locking you out. | Real-time `nft --check` validation. |
| **Audit Logging** | Full traceability of all security changes. | Rotated logs in Persistent Storage. |
| **Safety First** | No-touch approach to the base system. | Changes limited to `/live/persistence/`. |

---

## Requirements & Environment

To ensure the script operates correctly, your environment must meet the following:

* **Operating System:** TailsOS (Verified via `/etc/os-release`).
* **Storage:** Unlocked **Persistent Storage** (mounted at `/live/persistence/TailsData_unlocked`).
* **Privileges:** Root access via `sudo`.
* **Dependencies:** `nftables`, `apt-get`, and `NetworkManager`.

---

## Installation

1.  **Move the script** to your Persistent folder:
    ```bash
    mv tails_advanced_security.sh /live/persistence/TailsData_unlocked/
    ```
2.  **Apply executable permissions:**
    ```bash
    chmod +x /live/persistence/TailsData_unlocked/tails_advanced_security.sh
    ```

---

## Usage Guide

### Standard Execution
Launch the interactive menu to manage your security profile:
```bash
sudo ./tails_advanced_security.sh
```

### Command Line Flags
| Flag | Effect |
| :--- | :--- |
| `--dry-run` | Simulates operations without writing to disk or applying rules. |
| `--help` | Displays the help manifest and usage examples. |
| `--version` | Outputs current script version ($2.0.0$). |

---

## Feature Deep-Dive

### 1. User-Defined Firewall (`nftables`)
Tails' default firewall is extremely restrictive. This script allows you to append custom logic (e.g., specific LAN access or custom logging) without manually editing system files every session.
* **Location:** `/live/persistence/TailsData_unlocked/firewall/custom-rules.nft`
* **Validation:** The script wraps your input in a temporary test table. If the kernel rejects the syntax, the rule is **not** saved.

### 2. Additional Software (ASP)
Streamlines the "Additional Software" feature of Tails by managing the underlying `packages.list` and triggering cached installations.
* **Location:** `/live/persistence/TailsData_unlocked/additional-software/packages.list`
* **Intelligence:** It checks `apt-cache` to ensure a package exists before you commit it to the persistence list.

---

## Security & Persistence Model

> [!IMPORTANT]
> This script operates on a "Layered Security" principle. It does not replace Tails' defaults; it extends them.

* **Non-Persistent Dispatcher:** The NetworkManager dispatcher script is written to `/etc/` (tmpfs) each time you run the configuration. This ensures that if you stop using the script, the system reverts to default behavior after a reboot unless the dispatcher is re-initialized.
* **Backup Logic:** Every time a configuration file is edited, a timestamped backup is created in the respective `backups/` directory.
* **Log Rotation:** Logs are capped at **1MB** to prevent the persistent volume from filling up due to audit trails.

---

## File Structure
Within your Persistent Storage, the following hierarchy is maintained:
```text
TailsData_unlocked/
├── firewall/
│   ├── custom-rules.nft    # Your active nftables rules
│   └── backups/            # Timestamped .bak files
├── additional-software/
│   ├── packages.list       # List of persisted Debian packages
│   └── backups/            # Package list backups
├── tails_security_setup.log # Audit log
└── persistence.conf        # Modified to include new features
```

---

## ⚖️ Disclaimer
*This script is provided "as-is." While it includes safety checks, manual modification of firewall rules can lead to network leaks or de-anonymization if used improperly. Always verify your rules with `nft list ruleset`.*

[![GnuPG](https://img.shields.io/badge/PGP_Verified-0033CC?logo=gnupg&logoColor=white)](https://gnupg.org)
[![Bash](https://img.shields.io/badge/Shell_Script-4EAA25?logo=gnubash&logoColor=white)](https://www.gnu.org/software/bash/)
[![VPN](https://img.shields.io/badge/VPN_Security-000000?logo=wireguard&logoColor=white)](https://en.wikipedia.org/wiki/Virtual_private_network)
[![Proton](https://img.shields.io/badge/Proton-6D4AFF?logo=proton&logoColor=white)](https://proton.me)

**Developed for the TailsOS Community.** *Stay safe, stay amnesic.*
