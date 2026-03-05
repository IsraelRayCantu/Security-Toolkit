# Security Toolkit v2.0

A dynamic, metadata-driven security toolkit built in Python covering
network analysis, offensive attack tools, and defensive log analysis.
Built as a portfolio project demonstrating practical security knowledge
across the full offensive/defensive spectrum.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows%2011%20%7C%20Kali%20Linux-lightgrey?style=flat-square)
![Modules](https://img.shields.io/badge/Modules-16-green?style=flat-square)
![License](https://img.shields.io/badge/License-Educational-orange?style=flat-square)

---

## Overview

The toolkit auto-discovers all `.py` files in its directory, reads
metadata from each file's header, and builds a grouped interactive
menu — no manual configuration required. Adding a new module is as
simple as dropping a `.py` file in the folder with the correct headers.
```
# topic: Web Security
# title: My New Tool
# priority: 2
```

---

## Modules

### Network Analysis
| Module | Description |
|---|---|
| **Network Mapper** | ARP + ICMP host discovery, MAC/IP/hostname/OS fingerprinting, NetBIOS names, gateway detection, SSID detection, port probing |
| **Packet Sniffer** | Live traffic capture across Ethernet, IP, TCP, UDP, ICMP, DNS layers with BPF filter support and timestamped log files |
| **Port Scanner** | Four scan modes: TCP Connect, SYN half-open, UDP, and Banner Grabbing with threaded execution and report saving |

### Network Attacks
| Module | Description |
|---|---|
| **ARP Spoofer** | Bidirectional ARP cache poisoning for MITM positioning. Enables IP forwarding automatically, restores ARP tables and forwarding state on exit |
| **MAC Flooder** | CAM table overflow via random-source Ethernet frame flooding. Forces switches into fail-open hub mode. Batch sending for maximum throughput |

### Networking
| Module | Description |
|---|---|
| **TCP Client** | Connects to any TCP service, sends raw payloads, reads response. Supports custom payloads and HTTP probing |
| **TCP Server** | Multi-threaded TCP listener. Each client handled in its own daemon thread |
| **TCP Proxy** | Bidirectional forwarding proxy with hexdump display and request/response modification hooks |
| **UDP Client** | Sends UDP datagrams and reads responses. Demonstrates connectionless protocol behaviour |

### SSH Tools
| Module | Description |
|---|---|
| **SSH Command Executor** | Connects to remote SSH server and executes commands. Separates stdout and stderr |
| **SSH Command Handler** | Reverse SSH channel — server sends commands, this client executes them locally |
| **SSH Server** | Custom SSH server using Paramiko ServerInterface with host key management and shell relay |
| **Reverse SSH Tunnel** | Requests port forwarding on a remote SSH server to bypass inbound firewall rules |

### Web Security
| Module | Description |
|---|---|
| **HTTP Directory Brute Forcer** | Discovers hidden paths using wordlists. Tracks 200, 301, 403, 500 responses including forbidden paths. Multi-threaded with extension support |

### Password Security
| Module | Description |
|---|---|
| **Password Cracking Demo** | Five attack techniques against SHA-256 hashes: brute force, dictionary, rainbow table, hybrid, and rule-based leet speak substitution |

### Defensive Security
| Module | Description |
|---|---|
| **Log Analyser** | Parses Linux auth logs, Apache/Nginx access logs, and Windows Security Event Logs. Detects brute force, SQLi, path traversal, scanners. Severity-classified findings |

---

## Security Design Decisions

These decisions are intentional and demonstrate security-aware development:

**`sys.executable` instead of `'python'`**
Hardcoding the string `python` in subprocess calls means the first
binary named `python` in PATH gets executed. On a compromised system
this could be a malicious binary. `sys.executable` always resolves to
the exact interpreter running the launcher.

**`shell=False` throughout**
Every subprocess call uses list-form arguments and `shell=False`.
With `shell=True`, the OS passes the command to `/bin/sh` which
interprets metacharacters like `;`, `|`, and `$()` enabling command
injection. `shell=False` means the OS exec's the binary directly.

**Path traversal protection in module discovery**
Each discovered module path is resolved with `Path.resolve()` and
validated with `relative_to()` to confirm it lives inside the toolkit
directory. This blocks symlink-based attacks.

**ARP table restoration on exit**
The ARP spoofer sends corrective packets to both target and gateway
on exit, restoring their caches to the correct state. Standard practice
in professional penetration testing.

**IP forwarding state preservation**
The ARP spoofer reads and saves the current IP forwarding state before
enabling it, then restores the exact original value on exit.

---

## Requirements
```bash
pip install -r requirements.txt
```

| Package | Version | Used by |
|---|---|---|
| `paramiko` | 3.5.0 | All SSH modules |
| `scapy` | 2.6.1 | Packet Sniffer, Port Scanner (SYN/UDP), ARP Spoofer, MAC Flooder, Network Mapper |
| `pywin32` | 311 | Log Analyser (Windows Event Log mode) |

**Windows users** also need Npcap for raw socket modules:
- Download from [https://npcap.com](https://npcap.com)
- Install with **WinPcap API-compatible mode** checked
- Affected modules: Packet Sniffer, ARP Spoofer, MAC Flooder, Port Scanner SYN/UDP, Network Mapper

---

## Privileges

| Module | Requires Elevation |
|---|---|
| Packet Sniffer | Yes - raw socket capture |
| ARP Spoofer | Yes - raw frame injection |
| MAC Flooder | Yes - raw frame injection |
| Network Mapper | Yes - ARP + ICMP raw packets |
| Port Scanner (SYN/UDP) | Yes - raw packet crafting |
| Port Scanner (TCP Connect) | No |
| All SSH modules | No |
| TCP / UDP modules | No |
| HTTP Brute Forcer | No |
| Log Analyser | No (may need elevation to read `/var/log/`) |
| Password Cracking | No |

---

## Quick Start
```bash
# Clone the repository
git clone https://github.com/IsraelRayCantu/security-toolkit.git
cd security-toolkit

# Install dependencies
pip install -r requirements.txt

# Windows: install Npcap from https://npcap.com

# Run the toolkit
# Windows (Administrator PowerShell for raw socket modules):
python Toolkit.py

# Linux/Kali:
sudo python toolkit.py
```

---

## Lab Setup

To safely test the offensive modules use an isolated virtual network:
```
Host machine
└── Host-only network (192.168.56.0/24)
    ├── Attacker VM  - runs this toolkit
    └── Target VM    - Metasploitable2, DVWA, or plain Ubuntu
```

**Recommended targets per module:**

| Module | Target |
|---|---|
| Port Scanner | Metasploitable2 |
| HTTP Brute Forcer | DVWA, Metasploitable2 web server |
| Network Mapper | Any VM on host-only network |
| Packet Sniffer | Any HTTP traffic on local interface |
| ARP Spoofer | Two VMs on same host-only network |
| MAC Flooder | Unmanaged virtual switch |
| SSH modules | Any Linux VM with SSH enabled |
| Log Analyser | `/var/log/auth.log` on attacker VM |
| Password Cracking | Self-contained, no target needed |

---

## Output Files
```
security-toolkit/
├── toolkit.py
├── requirements.txt
├── README.md
├── toolkit.log
├── capture_logs/
│   └── capture_20260304_143022.log
└── scan_results/
    ├── scan_192_168_1_1_20260304_143512.txt
    ├── dirbrute_192_168_1_10_20260304_150211.txt
    └── log_analysis_auth_20260304_151043.txt
```

---

## Skills Demonstrated
```
Network fundamentals    Raw socket programming (TCP, UDP, ICMP, Ethernet)
SSH internals           Paramiko ServerInterface, host keys, tunnelling
Attack techniques       ARP spoofing, CAM overflow, port scanning, MITM
Traffic analysis        Protocol parsing, BPF filters, hexdump
Web reconnaissance      Directory brute forcing, HTTP status analysis
Password security       Hashing, salting, five cracking techniques
Defensive analysis      Log parsing, SIEM-style severity classification
Network discovery       ARP/ICMP scanning, OS fingerprinting, NetBIOS
Cross-platform dev      Windows 11 + Kali Linux, privilege handling
Secure coding           shell=False, path validation, resource cleanup
```

---

## Legal Notice

This toolkit is built for **educational purposes only**.

Every module that interacts with a network or system requires explicit
written authorisation from the owner before use. Unauthorised use may
violate the Computer Fraud and Abuse Act (CFAA), Computer Misuse Act
(CMA), and equivalent laws in your jurisdiction.

The techniques demonstrated are covered in CEH, OSCP, and CompTIA
Security+ certifications and taught in university network security
courses. Understanding how attacks work is a prerequisite for
defending against them.

**Always get written permission. Always use an isolated lab.**

---

## Platform

Tested on **Windows 11** and **Kali Linux 2024**.
Python 3.8+ required.

---

*Built as a university project and security portfolio piece.*