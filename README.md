# TailsOS Integrity Audit (TAIA)

`tails_integrity_audit.sh` (v1.0.0) is a **read-only** diagnostic tool for TailsOS power users who want to verify their system's security properties without altering the system itself.

[![TailsOS](https://img.shields.io/badge/Tails_OS-563D7C?logo=tails&logoColor=white)](https://tails.net)
[![Tor Project](https://img.shields.io/badge/Tor_Project-7D4698?logo=torproject&logoColor=white)](https://www.torproject.org)
[![Debian](https://img.shields.io/badge/Debian-D70A53?logo=debian&logoColor=white)](https://www.debian.org)
[![Privacy Guides](https://img.shields.io/badge/Privacy_Guides-00ADFF?logo=shield&logoColor=white)](https://www.privacyguides.org)

---

## Design Philosophy

> **"Anonymity Loves Company."**

The most powerful anonymity property of Tails is not any individual security feature  it is the fact that every Tails user looks identical to every other Tails user. The Tor Browser is the same. The kernel flags are the same. The network fingerprint is the same.

The moment you run a script that modifies `sysctl` values, patches `torrc`, or installs extra packages, your system diverges from that shared baseline. You are no longer *one in a million*. You are *one of one*. That uniqueness is itself a fingerprint, and it defeats anonymity more reliably than the problems you were trying to solve.

**This tool follows a strict "Observe, Never Touch" contract:**

- It reads system state and reports findings.
- It never writes to the root filesystem.
- It never modifies kernel parameters, network configuration, or Tor settings.
- The only write it ever performs is appending to an optional log file you explicitly request.

If this tool finds something wrong, the correct response is to **boot a fresh Tails session from a verified image**  not to patch around the problem in-place.

---

## OpSec Warning

> [!WARNING]
> **Custom hardening scripts are dangerous for Tails users.**

This is not a disclaimer. It is an operational security fact backed by the Tails threat model.

**Why custom hardening backfires:**

| Hardening Action | Actual Risk |
| :--- | :--- |
| Modifying `sysctl` values | Creates a measurable kernel fingerprint via `/proc` timing attacks. |
| Patching `torrc` | Alters the circuit-build behaviour observed by Tor relays and guard nodes. |
| Randomising the MAC on a schedule different from Tails' default | Makes the device identifiable by MAC-change timing on the local network. |
| Installing extra packages via `apt` | Changes the installed package list, package signatures, and binary timestamps  all observable. |
| Writing dispatcher scripts to `/etc/` | Leaves traces in `inotify` event logs and process accounting even on tmpfs. |

**The correct mental model:** Tails is a product, not a platform. Its security properties are the result of a carefully designed, audited, and coordinated whole. Replacing individual components with custom logic does not *add* to that security  it *subtracts* from it by breaking the assumptions the rest of the system was built on.

If Tails does not meet your requirements out of the box, the correct path is to [contribute to the Tails project](https://tails.net/contribute/) or evaluate a different threat model  not to script around it.

---

## Audit Modules

| # | Module | What It Checks | Severity if Failed |
| :- | :--- | :--- | :--- |
| 1 | **Network Leak Test** | ICMP to `8.8.8.8` is dropped by the Tor firewall | Critical |
| 2 | **Forensic Swap Scan** | No active or available swap on any attached drive | Critical |
| 3 | **Memory Wipe Audit** | `slub_debug=P` and `page_poison=1` (or `init_on_free=1`) are armed | High |
| 4 | **Filesystem Integrity** | Root is `ro`, Tor binary checksum matches expected value | High |
| 5 | **Metadata Audit** | Files in Persistent/ are free of identifying metadata (via `mat2`) | Medium |

---

## Requirements

- **OS:** TailsOS (verified via `/etc/os-release`)
- **Privileges:** Root (`sudo`)
- **Persistent Storage:** Unlocked at `/live/persistence/TailsData_unlocked` (metadata module only)
- **Dependencies:** All native to Tails  `ping`, `lsblk`, `sha256sum`, `mat2`. No `apt install` required.

---

## Usage

### Run all audit modules

```bash
sudo ./tails_integrity_audit.sh
```

### Run a single module

```bash
sudo ./tails_integrity_audit.sh --module network
sudo ./tails_integrity_audit.sh --module swap
sudo ./tails_integrity_audit.sh --module memory
sudo ./tails_integrity_audit.sh --module filesystem
sudo ./tails_integrity_audit.sh --module metadata
```

### Save audit output to a log file

```bash
sudo ./tails_integrity_audit.sh --log /live/persistence/TailsData_unlocked/audit.log
```

### Verify the Tor binary against a known checksum

```bash
export TOR_AUDIT_CHECKSUM="<sha256 from trusted source>"
sudo ./tails_integrity_audit.sh --module filesystem
```

### Disable color output (for piping or scripting)

```bash
sudo ./tails_integrity_audit.sh --no-color | tee report.txt
```

---

## Understanding Audit Results

Each finding is prefixed with a status marker:

| Marker | Meaning |
| :--- | :--- |
| `[PASS]` | The check passed  the expected security property is confirmed. |
| `[WARN]` | The check could not be fully completed, or a non-critical issue was found. Review the detail. |
| `[FAIL]` | A security property is violated. Treat this seriously. |
| `[INFO]` | Informational context  no action required. |

The script exits `0` if all checks pass or warn, and exits `1` if any `[FAIL]` result is recorded. This makes it safe to use in scripts:

```bash
sudo ./tails_integrity_audit.sh || echo "Audit found failures  do not proceed."
```

### Module 1  Network Leak Test

A `[PASS]` means the Tor firewall is dropping clearnet ICMP as expected. A `[FAIL]` means direct internet traffic is reaching the network  your traffic is **not** being routed through Tor. Stop what you are doing and reboot.

### Module 2  Forensic Swap Scan

A `[PASS]` means no swap space is active and no swap partitions were found. A `[FAIL]` on **active swap** is critical: pages of decrypted memory may be written to disk in plaintext. Reboot immediately.

### Module 3  Memory Wipe Audit

A `[PASS]` on both flags confirms the kernel will poison freed memory before it can be reused or read after shutdown. A `[FAIL]` means a cold-boot or live-forensics attack could recover plaintext data from RAM.

### Module 4  Filesystem Integrity

A `[PASS]` on root-read-only confirms the live system is behaving as expected. The Tor checksum check requires you to supply `TOR_AUDIT_CHECKSUM` from a trusted source; without it, this check emits `[WARN]` and records the current value for your reference.

### Module 5  Metadata Audit

A `[FAIL]` lists files in your Persistent Storage that carry embedded metadata (EXIF, author fields, GPS coordinates, etc.) that could de-anonymise you if those files are ever shared. To clean them, run `mat2 <file>` manually. **This audit tool will never modify your files.**

---

## File Structure

```text
Tails Hardening/
├── tails_integrity_audit.sh   # Audit tool (this script)
├── README.md                  # This document
└── LICENSE.md                 # Personal use license
```

---

## Disclaimer

*This tool is provided as-is. It observes and reports  it does not guarantee security. A passing audit result confirms the checked properties at the moment of the scan; it does not certify the overall security of the system. Always boot from a verified Tails image.*

[![GnuPG](https://img.shields.io/badge/PGP_Verified-0033CC?logo=gnupg&logoColor=white)](https://gnupg.org)
[![Bash](https://img.shields.io/badge/Shell_Script-4EAA25?logo=gnubash&logoColor=white)](https://www.gnu.org/software/bash/)

**Developed for the TailsOS Community.** *Stay safe, stay amnesic.*
