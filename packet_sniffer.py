# topic: Network Analysis
# title: Packet Sniffer
# priority: 1

"""
packet_sniffer.py - Live Packet Capture and Protocol Analyser
==============================================================
Captures live network traffic using Scapy, decodes each packet
through multiple protocol layers, displays results in real time,
and writes a timestamped log file for post-capture analysis.

PROTOCOL STACK COVERED
-----------------------
Layer 2 - Ethernet : source/destination MAC addresses, EtherType
Layer 3 - IP       : source/destination IPs, TTL, protocol number
Layer 4 - TCP      : ports, flags, sequence/acknowledgement numbers
Layer 4 - UDP      : ports, payload length
Layer 3 - ICMP     : type, code, human-readable description
Layer 7 - DNS      : query names, record types

PLATFORM SUPPORT
-----------------
Linux (Kali, Ubuntu):
    Requires root:  sudo python packet_sniffer.py
    No extra install needed beyond Scapy.

Windows 11:
    Requires Npcap: https://npcap.com
    Install with WinPcap API-compatible mode checked.
    Run as Administrator.
    Interface names appear as GUIDs e.g.:
        \\Device\\NPF_{4DC81B-...}
    Use the numbered selection to avoid typing them manually.

CAPTURE WORKFLOW
-----------------
1. Select a network interface
2. Optionally apply a BPF filter
3. Capture runs until Ctrl+C or packet count reached
4. Every packet displayed in real time AND written to a log file
5. Summary printed on exit

BPF FILTER EXAMPLES
--------------------
  tcp port 80       - HTTP traffic only
  udp port 53       - DNS queries only
  host 192.168.1.1  - all traffic to/from a specific host
  icmp              - ping traffic only
  not port 22       - everything except SSH

EDUCATIONAL USE ONLY.
Only capture on networks you own or have explicit written permission
to monitor. Unauthorised packet capture is illegal in most
jurisdictions.

Requirements:
    pip install scapy
    Windows: Npcap from https://npcap.com
"""

import logging
import os
import sys
import threading
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------
IS_WINDOWS = os.name == "nt"
IS_LINUX   = sys.platform.startswith("linux")

# ---------------------------------------------------------------------------
# Scapy import
# ---------------------------------------------------------------------------
try:
    from scapy.all import (
        sniff,
        get_if_list,
        Ether,
        IP,
        TCP,
        UDP,
        ICMP,
        DNS,
        DNSQR,
        Raw,
        conf as scapy_conf,
    )
    scapy_conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOG_DIR          = Path(__file__).resolve().parent / "capture_logs"
PACKET_SEPARATOR = "-" * 60
DEFAULT_COUNT    = 0       # 0 = capture indefinitely
DEFAULT_FILTER   = ""      # Empty = capture all traffic

ICMP_TYPES = {
    0:  ("Echo Reply",              {0: "Echo reply"}),
    3:  ("Destination Unreachable", {
            0: "Net unreachable",       1: "Host unreachable",
            2: "Protocol unreachable",  3: "Port unreachable",
            4: "Fragmentation needed",  5: "Source route failed",
        }),
    4:  ("Source Quench",           {0: "Source quench"}),
    5:  ("Redirect",                {
            0: "Redirect for network",  1: "Redirect for host",
        }),
    8:  ("Echo Request",            {0: "Echo request (ping)"}),
    11: ("Time Exceeded",           {
            0: "TTL exceeded in transit",
            1: "Fragment reassembly time exceeded",
        }),
    12: ("Parameter Problem",       {0: "Pointer indicates the error"}),
}

TCP_FLAGS = {
    "F": "FIN", "S": "SYN", "R": "RST", "P": "PSH",
    "A": "ACK", "U": "URG", "E": "ECE", "C": "CWR",
}

DNS_QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
}


# ---------------------------------------------------------------------------
# Privilege check
# ---------------------------------------------------------------------------

def check_privileges() -> bool:
    """
    Verify the process has privileges required for raw packet capture.

    Linux/macOS : requires root (UID 0)
    Windows     : requires Administrator
    """
    try:
        return os.getuid() == 0
    except AttributeError:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Windows Npcap check
# ---------------------------------------------------------------------------

def check_npcap() -> bool:
    """
    On Windows, verify Npcap is installed before attempting capture.

    Returns True if Npcap is present or we are not on Windows.
    """
    if not IS_WINDOWS:
        return True

    try:
        result = subprocess.run(
            ["sc", "query", "npcap"],
            capture_output=True,
            text=True,
            shell=False,
            timeout=5,
        )
        if result.returncode == 0:
            return True
    except Exception:
        pass

    print("\n  [!] Npcap does not appear to be installed.")
    print("      Scapy requires Npcap for packet capture on Windows.")
    print("\n      Install steps:")
    print("      1. Download from: https://npcap.com")
    print("      2. Run installer as Administrator")
    print("      3. Check WinPcap API-compatible mode during install")
    print("      4. Restart this toolkit after installation\n")
    return False


# ---------------------------------------------------------------------------
# Interface helpers
# ---------------------------------------------------------------------------

def get_friendly_interface_name(iface: str) -> str:
    """
    Return a human-readable interface description alongside the raw name.

    On Windows, Scapy returns GUID-style names which are unreadable.
    We look up the friendly adapter description from Scapy's ifaces dict.

    Parameters
    ----------
    iface : str   Raw interface name from get_if_list().

    Returns
    -------
    String combining raw name and friendly description if available.
    """
    if not IS_WINDOWS:
        return iface

    try:
        from scapy.all import ifaces as scapy_ifaces
        iface_obj = scapy_ifaces.get(iface)
        if iface_obj:
            friendly = (
                getattr(iface_obj, "description", None) or
                getattr(iface_obj, "name", None)
            )
            if friendly and friendly != iface:
                return f"{friendly}  ({iface})"
    except Exception:
        pass

    return iface


def list_interfaces() -> list:
    """
    Return available network interfaces and display them to the user.

    On Windows shows friendly adapter names alongside GUIDs so the
    user can identify which interface to capture on.
    """
    try:
        interfaces = get_if_list()
    except Exception as exc:
        print(f"  [!] Could not list interfaces: {exc}")
        if IS_WINDOWS:
            print("  [*] Make sure Npcap is installed and you are running "
                  "as Administrator.")
        return []

    print("\n  Available network interfaces:\n")
    for i, iface in enumerate(interfaces, start=1):
        friendly = get_friendly_interface_name(iface)
        print(f"    {i:>2}.  {friendly}")
    print()

    return interfaces


# ---------------------------------------------------------------------------
# Log file setup
# ---------------------------------------------------------------------------

def create_log_file() -> Optional[Path]:
    """
    Create a timestamped log file in the capture_logs directory.

    Returns
    -------
    Path to the created log file, or None on failure.
    """
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_path  = LOG_DIR / f"capture_{timestamp}.log"

        with log_path.open("w", encoding="utf-8") as fh:
            fh.write("Packet Capture Log\n")
            fh.write(f"Platform : {sys.platform}\n")
            fh.write(
                f"Started  : "
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            )
            fh.write("=" * 60 + "\n\n")

        logger.info("Log file created: %s", log_path)
        return log_path

    except OSError as exc:
        print(f"  [!] Could not create log file: {exc}")
        logger.error("Log file creation failed: %s", exc)
        return None


def write_to_log(log_path: Path, content: str) -> None:
    """Append content to the capture log file."""
    try:
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(content + "\n")
    except OSError as exc:
        logger.error("Log write error: %s", exc)


# ---------------------------------------------------------------------------
# Protocol parsers
# ---------------------------------------------------------------------------

def parse_ethernet(packet) -> str:
    """Extract and format Ethernet frame header fields."""
    if not packet.haslayer(Ether):
        return ""
    eth = packet[Ether]
    return (
        f"  [Ethernet]\n"
        f"    Source MAC : {eth.src}\n"
        f"    Dest MAC   : {eth.dst}\n"
        f"    EtherType  : 0x{eth.type:04X}"
    )


def parse_ip(packet) -> str:
    """
    Extract and format IPv4 header fields.

    TTL heuristic OS fingerprinting:
        TTL <= 64  : likely Linux/macOS
        TTL <= 128 : likely Windows
        TTL > 128  : likely network device
    """
    if not packet.haslayer(IP):
        return ""
    ip = packet[IP]

    if ip.ttl <= 64:
        os_hint = "Linux/macOS"
    elif ip.ttl <= 128:
        os_hint = "Windows"
    else:
        os_hint = "Network device"

    proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(ip.proto, "Other")

    return (
        f"  [IPv4]\n"
        f"    Source IP  : {ip.src}\n"
        f"    Dest IP    : {ip.dst}\n"
        f"    TTL        : {ip.ttl}  (likely {os_hint})\n"
        f"    Protocol   : {ip.proto} ({proto_name})"
    )


def parse_tcp(packet) -> str:
    """Extract and format TCP segment fields."""
    if not packet.haslayer(TCP):
        return ""
    tcp = packet[TCP]

    flags_str      = str(tcp.flags) if tcp.flags else "None"
    flags_expanded = " ".join(TCP_FLAGS.get(f, f) for f in flags_str)

    result = (
        f"  [TCP]\n"
        f"    Source Port : {tcp.sport}\n"
        f"    Dest Port   : {tcp.dport}\n"
        f"    Flags       : {flags_str} ({flags_expanded})\n"
        f"    Seq         : {tcp.seq}\n"
        f"    Ack         : {tcp.ack}"
    )

    if packet.haslayer(Raw):
        raw = packet[Raw].load
        try:
            preview = raw[:80].decode(
                "utf-8", errors="replace"
            ).replace("\n", "\\n")
            result += (
                f"\n    Payload     : "
                f"{preview}{'...' if len(raw) > 80 else ''}"
            )
        except Exception:
            result += f"\n    Payload     : [{len(raw)} bytes binary]"

    return result


def parse_udp(packet) -> str:
    """Extract and format UDP datagram fields."""
    if not packet.haslayer(UDP):
        return ""
    udp = packet[UDP]

    result = (
        f"  [UDP]\n"
        f"    Source Port : {udp.sport}\n"
        f"    Dest Port   : {udp.dport}\n"
        f"    Length      : {udp.len} bytes"
    )

    if packet.haslayer(Raw) and not packet.haslayer(DNS):
        raw = packet[Raw].load
        try:
            preview = raw[:80].decode(
                "utf-8", errors="replace"
            ).replace("\n", "\\n")
            result += (
                f"\n    Payload     : "
                f"{preview}{'...' if len(raw) > 80 else ''}"
            )
        except Exception:
            result += f"\n    Payload     : [{len(raw)} bytes binary]"

    return result


def parse_icmp(packet) -> str:
    """Extract and format ICMP message fields."""
    if not packet.haslayer(ICMP):
        return ""
    icmp = packet[ICMP]

    type_info = ICMP_TYPES.get(icmp.type, ("Unknown", {}))
    type_name = type_info[0]
    code_name = type_info[1].get(icmp.code, f"Code {icmp.code}")

    return (
        f"  [ICMP]\n"
        f"    Type : {icmp.type} ({type_name})\n"
        f"    Code : {icmp.code} ({code_name})"
    )


def parse_dns(packet) -> str:
    """Extract and format DNS query/response fields."""
    if not packet.haslayer(DNS):
        return ""
    dns = packet[DNS]

    direction = "Response" if dns.qr else "Query"
    result    = f"  [DNS] {direction}\n"

    if dns.qdcount > 0 and packet.haslayer(DNSQR):
        qr    = packet[DNSQR]
        qname = qr.qname.decode("utf-8", errors="replace").rstrip(".")
        qtype = DNS_QTYPES.get(qr.qtype, f"Type {qr.qtype}")
        result += f"    Query   : {qname} ({qtype})"

    if dns.qr and dns.ancount > 0:
        result += f"\n    Answers : {dns.ancount} record(s)"

    return result


# ---------------------------------------------------------------------------
# Packet formatter
# ---------------------------------------------------------------------------

_packet_counter = 0
_counter_lock   = threading.Lock()


def format_packet(packet) -> str:
    """
    Decode a captured packet through all protocol layers and return
    a formatted multi-line string for display and logging.
    """
    global _packet_counter
    with _counter_lock:
        _packet_counter += 1
        count = _packet_counter

    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    lines = [
        PACKET_SEPARATOR,
        f"  Packet #{count}  |  {timestamp}",
        PACKET_SEPARATOR,
    ]

    for parser in (
        parse_ethernet, parse_ip, parse_tcp,
        parse_udp, parse_icmp, parse_dns,
    ):
        section = parser(packet)
        if section:
            lines.append(section)

    if len(lines) == 3:
        lines.append(f"  [Raw] {len(packet)} bytes - unknown protocol")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Packet callback factory
# ---------------------------------------------------------------------------

def make_packet_callback(log_path: Optional[Path]):
    """
    Return a per-packet callback that displays and logs each capture.

    Factory pattern used so the callback closes over log_path without
    needing a global variable.
    """
    def callback(packet) -> None:
        formatted = format_packet(packet)
        print(formatted)
        if log_path:
            write_to_log(log_path, formatted)
        logger.debug("Packet #%d captured.", _packet_counter)

    return callback


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Interactive entry point - configure and start the packet capture.
    """
    print("\n  Packet Sniffer")
    print("  " + "-" * 14)
    print(f"  Platform : {sys.platform}")
    print("  [!] Requires root (Linux) or Administrator (Windows).")
    print("  [!] Only capture on networks you own or are authorised to monitor.")
    print("  [*] Enter 0 at any prompt to cancel.\n")

    if not SCAPY_AVAILABLE:
        print("  [!] Scapy is not installed: pip install scapy")
        if IS_WINDOWS:
            print("  [!] Also install Npcap from https://npcap.com")
        return

    # Privilege check
    if not check_privileges():
        print("  [!] This module requires elevated privileges.")
        if IS_WINDOWS:
            print("  [*] Right-click your terminal and select "
                  "Run as Administrator.")
        else:
            print("  [*] Run with: sudo python packet_sniffer.py")
        print()
        return

    # Windows Npcap check
    if IS_WINDOWS:
        if not check_npcap():
            return
        print("  [*] Windows detected - interface names may appear as GUIDs.")
        print("      Use the number selection to choose your interface.\n")

    # Interface selection
    interfaces = list_interfaces()
    if not interfaces:
        return

    raw = input(
        "  Select interface number (or type name directly): "
    ).strip()
    if raw == "0":
        return

    if raw.isdigit():
        idx = int(raw) - 1
        if not (0 <= idx < len(interfaces)):
            print("  [!] Invalid selection.")
            return
        interface = interfaces[idx]
    else:
        if raw not in interfaces:
            print(f"  [!] Interface '{raw}' not found.")
            return
        interface = raw

    friendly = get_friendly_interface_name(interface)
    print(f"  [+] Selected: {friendly}")

    # BPF filter
    print("\n  BPF filter examples:")
    print("    tcp port 80  |  udp port 53  |  host 192.168.1.1  |  icmp")
    bpf_filter = input("  BPF filter (press Enter for none): ").strip()
    if bpf_filter == "0":
        return

    # Packet count
    raw_count = input(
        "  Max packets to capture (press Enter for unlimited): "
    ).strip()
    if raw_count == "0":
        return
    if raw_count:
        if not raw_count.isdigit():
            print("  [!] Please enter a number.")
            return
        packet_count = int(raw_count)
    else:
        packet_count = DEFAULT_COUNT

    # Log file
    log_path = create_log_file()
    if log_path:
        print(f"\n  [*] Logging to: {log_path}")
    else:
        print("  [*] File logging unavailable - terminal output only.")

    # Start capture
    filter_desc = f"filter='{bpf_filter}'" if bpf_filter else "no filter"
    count_desc  = f"{packet_count} packets" if packet_count else "unlimited"
    print(f"\n  [*] Starting capture on {friendly}")
    print(f"  [*] {filter_desc} | {count_desc}")
    print("  [*] Press Ctrl+C to stop\n")
    print(PACKET_SEPARATOR)

    logger.info(
        "Capture started: iface=%s filter='%s' count=%d platform=%s",
        interface, bpf_filter, packet_count, sys.platform,
    )

    callback = make_packet_callback(log_path)

    try:
        sniff(
            iface=interface,
            filter=bpf_filter if bpf_filter else None,
            prn=callback,
            count=packet_count,
            store=False,
        )
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print(f"\n  [!] Permission denied.")
        if IS_WINDOWS:
            print("  [*] Run as Administrator and ensure Npcap is installed.")
        else:
            print("  [*] Run with sudo.")
        logger.error("Permission denied during capture.")
    except Exception as exc:
        print(f"\n  [!] Capture error: {exc}")
        logger.error("Capture error: %s", exc)

    # Summary
    print(f"\n{PACKET_SEPARATOR}")
    print(f"  Capture complete.")
    print(f"  Total packets captured : {_packet_counter}")
    if log_path:
        print(f"  Log saved to           : {log_path}")
        write_to_log(log_path, "\n" + "=" * 60)
        write_to_log(
            log_path,
            f"Capture ended  : "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        )
        write_to_log(log_path, f"Total packets  : {_packet_counter}")
    print(f"{PACKET_SEPARATOR}\n")
    logger.info("Capture ended. Total packets: %d", _packet_counter)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()