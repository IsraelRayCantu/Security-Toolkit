# topic: Network Analysis
# title: Port Scanner
# priority: 2

"""
port_scanner.py - Multi-Mode Port Scanner with Banner Grabbing
===============================================================
Scans a target host for open ports using four distinct techniques,
identifies running services, grabs service banners, and saves
results to a timestamped report file.

SCAN TYPES
-----------
TCP Connect Scan
    Completes the full TCP three-way handshake.
    Most reliable - if connect() succeeds the port is open.
    Logged by target applications.
    Does NOT require root/Administrator.

SYN Scan (Half-Open)
    Sends SYN, waits for response:
      SYN-ACK -> port OPEN    (send RST, never complete handshake)
      RST     -> port CLOSED
      No response -> port FILTERED
    Not logged by most application-layer logs.
    REQUIRES root/Administrator + Npcap on Windows.

UDP Scan
    Sends empty UDP datagram:
      ICMP port unreachable -> CLOSED
      UDP response          -> OPEN
      No response           -> OPEN|FILTERED
    REQUIRES root/Administrator + Npcap on Windows.

Banner Grabbing
    Connects to open TCP ports and reads the service response.
    Reveals software name and version for vulnerability research.

PLATFORM SUPPORT
-----------------
Windows 11:
    TCP Connect : works without elevation
    SYN/UDP     : requires Administrator + Npcap
    Banner grab : works without elevation

Linux/Kali:
    TCP Connect : works without root
    SYN/UDP     : requires sudo
    Banner grab : works without root

EDUCATIONAL USE ONLY.
Port scanning without authorisation may be illegal.
Only scan hosts you own or have explicit written permission to test.

Requirements:
    pip install scapy  (for SYN and UDP scans only)
"""

import concurrent.futures
import logging
import os
import random
import socket
import sys
import time
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Optional

IS_WINDOWS = os.name == "nt"
IS_LINUX   = sys.platform.startswith("linux")

try:
    from scapy.all import (
        IP,
        TCP,
        UDP,
        ICMP,
        sr1,
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
RESULTS_DIR       = Path(__file__).resolve().parent / "scan_results"
CONNECT_TIMEOUT   = 1.0
BANNER_TIMEOUT    = 2.0
SYN_TIMEOUT       = 1.0
UDP_TIMEOUT       = 2.0
MAX_WORKERS       = 100
BANNER_READ_BYTES = 1024

COMMON_SERVICES = {
    21: "FTP",        22: "SSH",         23: "Telnet",
    25: "SMTP",       53: "DNS",         67: "DHCP",
    80: "HTTP",       110: "POP3",       111: "RPC",
    135: "MSRPC",     139: "NetBIOS",    143: "IMAP",
    443: "HTTPS",     445: "SMB",        465: "SMTPS",
    587: "SMTP",      993: "IMAPS",      995: "POP3S",
    1433: "MSSQL",    1521: "Oracle",    3306: "MySQL",
    3389: "RDP",      5432: "PostgreSQL",5900: "VNC",
    6379: "Redis",    8080: "HTTP-Alt",  8443: "HTTPS-Alt",
    8888: "HTTP-Alt", 27017: "MongoDB",  6443: "K8s-API",
}

BANNER_PROBES = {
    80:   b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\n\r\n",
    443:  b"HEAD / HTTP/1.0\r\n\r\n",
}


# ---------------------------------------------------------------------------
# Port status enum
# ---------------------------------------------------------------------------

class PortStatus(Enum):
    OPEN             = auto()
    CLOSED           = auto()
    FILTERED         = auto()
    OPEN_OR_FILTERED = auto()


# ---------------------------------------------------------------------------
# Port result
# ---------------------------------------------------------------------------

class PortResult:
    """
    Holds the scan result for a single port.
    """
    __slots__ = ("port", "status", "service", "banner", "proto")

    def __init__(
        self,
        port: int,
        status: PortStatus,
        proto: str = "TCP",
        banner: str = "",
    ) -> None:
        self.port    = port
        self.status  = status
        self.proto   = proto
        self.service = COMMON_SERVICES.get(port, "")
        self.banner  = banner.strip()


# ---------------------------------------------------------------------------
# Privilege check
# ---------------------------------------------------------------------------

def check_privileges() -> bool:
    """Check for root (Linux) or Administrator (Windows) privileges."""
    try:
        return os.getuid() == 0
    except AttributeError:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Banner grabbing
# ---------------------------------------------------------------------------

def grab_banner(host: str, port: int) -> str:
    """
    Connect to an open TCP port and read its service banner.

    Most services send identifying information immediately on
    connection or in response to a simple probe. This banner
    typically includes the software name and version - critical
    for vulnerability research.

    Parameters
    ----------
    host : str   Target hostname or IP.
    port : int   Open TCP port to grab banner from.

    Returns
    -------
    Decoded banner string, or empty string if nothing received.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(BANNER_TIMEOUT)
            sock.connect((host, port))

            probe = BANNER_PROBES.get(port)
            if probe:
                sock.sendall(probe)

            banner = sock.recv(BANNER_READ_BYTES)
            return banner.decode("utf-8", errors="replace").strip()

    except (socket.timeout, ConnectionRefusedError, OSError):
        return ""


# ---------------------------------------------------------------------------
# TCP Connect scan
# ---------------------------------------------------------------------------

def tcp_connect_scan_port(host: str, port: int) -> PortResult:
    """
    Scan a single port using a full TCP connect.

    connect_ex() returns 0 on success (port open) and a non-zero
    error code on failure - faster than exception handling in a
    tight loop scanning many ports.

    Parameters
    ----------
    host : str   Target hostname or IP.
    port : int   Port to probe.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(CONNECT_TIMEOUT)
        result = sock.connect_ex((host, port))
        status = PortStatus.OPEN if result == 0 else PortStatus.CLOSED
        return PortResult(port, status, proto="TCP")


def tcp_connect_scan(
    host: str,
    ports: list,
    grab_banners: bool = False,
) -> list:
    """
    Scan multiple ports concurrently using TCP connect.

    ThreadPoolExecutor parallelises the scan - instead of scanning
    ports sequentially (slow due to timeout waits), we scan
    MAX_WORKERS ports simultaneously.

    Parameters
    ----------
    host         : str    Target to scan.
    ports        : list   Port numbers to scan.
    grab_banners : bool   Grab banners from open ports if True.

    Returns
    -------
    List of PortResult objects sorted by port number.
    """
    results = []

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:
        futures = {
            executor.submit(tcp_connect_scan_port, host, port): port
            for port in ports
        }
        completed = 0
        total     = len(ports)

        for future in concurrent.futures.as_completed(futures):
            completed += 1
            print(
                f"\r  [*] TCP Connect: {completed}/{total} ports scanned  ",
                end="",
                flush=True,
            )
            try:
                result = future.result()
                if result.status == PortStatus.OPEN and grab_banners:
                    result.banner = grab_banner(host, result.port)
                results.append(result)
            except Exception as exc:
                port = futures[future]
                logger.warning("TCP connect error on port %d: %s", port, exc)

    print()
    return sorted(results, key=lambda r: r.port)


# ---------------------------------------------------------------------------
# SYN scan
# ---------------------------------------------------------------------------

def syn_scan_port(host: str, port: int) -> PortResult:
    """
    Scan a single port using a SYN (half-open) scan.

    Sends a TCP SYN packet and analyses the response:
      SYN-ACK (flags 0x12) -> port OPEN  (reply with RST)
      RST     (flags 0x14) -> port CLOSED
      No response          -> port FILTERED

    The RST we send after SYN-ACK prevents the OS from sending its
    own RST and avoids leaving half-open connections on the target.

    Requires root/Administrator + Npcap on Windows.

    Parameters
    ----------
    host : str   Target IP address.
    port : int   Port to probe.
    """
    syn_packet = IP(dst=host) / TCP(
        sport=random.randint(1024, 65535),
        dport=port,
        flags="S",
    )

    response = sr1(syn_packet, timeout=SYN_TIMEOUT, verbose=False)

    if response is None:
        return PortResult(port, PortStatus.FILTERED, proto="TCP")

    if response.haslayer(TCP):
        tcp_layer = response[TCP]

        if tcp_layer.flags == 0x12:
            # SYN-ACK - port is open - send RST to clean up
            rst = IP(dst=host) / TCP(
                sport=tcp_layer.dport,
                dport=port,
                flags="R",
                seq=tcp_layer.ack,
            )
            sr1(rst, timeout=1, verbose=False)
            return PortResult(port, PortStatus.OPEN, proto="TCP")

        if tcp_layer.flags == 0x14:
            return PortResult(port, PortStatus.CLOSED, proto="TCP")

    if response.haslayer(ICMP):
        return PortResult(port, PortStatus.FILTERED, proto="TCP")

    return PortResult(port, PortStatus.FILTERED, proto="TCP")


def syn_scan(
    host: str,
    ports: list,
    grab_banners: bool = False,
) -> list:
    """
    Run a SYN scan across all ports sequentially.

    Sequential (not threaded) to avoid flooding the network and
    triggering IDS rate-based detection. Slower but stealthier.

    Parameters
    ----------
    host         : str   Target IP.
    ports        : list  Ports to scan.
    grab_banners : bool  Grab banners from open ports if True.
    """
    results = []
    total   = len(ports)

    for i, port in enumerate(ports, start=1):
        print(
            f"\r  [*] SYN scanning: {i}/{total} "
            f"(current: {port})          ",
            end="",
            flush=True,
        )
        result = syn_scan_port(host, port)

        if result.status == PortStatus.OPEN and grab_banners:
            result.banner = grab_banner(host, port)

        if result.status != PortStatus.CLOSED:
            results.append(result)

    print()
    return sorted(results, key=lambda r: r.port)


# ---------------------------------------------------------------------------
# UDP scan
# ---------------------------------------------------------------------------

def udp_scan_port(host: str, port: int) -> PortResult:
    """
    Probe a single UDP port.

    UDP scanning is ambiguous - silence means open OR filtered.
    Only an ICMP port unreachable definitively means closed.

    Requires root/Administrator + Npcap on Windows.

    Parameters
    ----------
    host : str   Target IP.
    port : int   UDP port to probe.
    """
    udp_packet = IP(dst=host) / UDP(dport=port)
    response   = sr1(udp_packet, timeout=UDP_TIMEOUT, verbose=False)

    if response is None:
        return PortResult(port, PortStatus.OPEN_OR_FILTERED, proto="UDP")

    if response.haslayer(UDP):
        return PortResult(port, PortStatus.OPEN, proto="UDP")

    if response.haslayer(ICMP):
        icmp = response[ICMP]
        if int(icmp.type) == 3 and int(icmp.code) == 3:
            return PortResult(port, PortStatus.CLOSED, proto="UDP")
        return PortResult(port, PortStatus.FILTERED, proto="UDP")

    return PortResult(port, PortStatus.OPEN_OR_FILTERED, proto="UDP")


def udp_scan(host: str, ports: list) -> list:
    """
    Run a UDP scan across all specified ports.

    Parameters
    ----------
    host  : str   Target IP.
    ports : list  UDP ports to scan.
    """
    results = []
    total   = len(ports)

    for i, port in enumerate(ports, start=1):
        print(
            f"\r  [*] UDP scanning: {i}/{total} "
            f"(current: {port})          ",
            end="",
            flush=True,
        )
        result = udp_scan_port(host, port)

        if result.status != PortStatus.CLOSED:
            results.append(result)

    print()
    return sorted(results, key=lambda r: r.port)


# ---------------------------------------------------------------------------
# Port range parser
# ---------------------------------------------------------------------------

def parse_port_range(port_input: str) -> Optional[list]:
    """
    Parse a port specification string into a list of integers.

    Supported formats:
      80              -> [80]
      80,443,8080     -> [80, 443, 8080]
      1-1024          -> [1, 2, ..., 1024]
      22,80,1000-2000 -> combined list
      top100          -> top 100 common ports
      top1000         -> ports 1-1024 plus common high ports

    Parameters
    ----------
    port_input : str   Raw user input string.

    Returns
    -------
    Sorted list of unique port integers, or None on parse error.
    """
    port_input = port_input.strip().lower()

    if port_input == "top100":
        return sorted(list(COMMON_SERVICES.keys()))[:100]
    if port_input == "top1000":
        return list(range(1, 1025)) + sorted(
            [p for p in COMMON_SERVICES if p > 1024]
        )

    ports = set()
    try:
        for part in port_input.split(","):
            part = part.strip()
            if "-" in part:
                start, _, end = part.partition("-")
                start, end = int(start), int(end)
                if not (1 <= start <= 65535 and 1 <= end <= 65535
                        and start <= end):
                    raise ValueError(f"Invalid range: {start}-{end}")
                ports.update(range(start, end + 1))
            else:
                port = int(part)
                if not (1 <= port <= 65535):
                    raise ValueError(f"Invalid port: {port}")
                ports.add(port)
    except ValueError as exc:
        print(f"  [!] Port parse error: {exc}")
        return None

    return sorted(ports)


# ---------------------------------------------------------------------------
# Results display and saving
# ---------------------------------------------------------------------------

def display_results(
    results: list,
    scan_type: str,
    host: str,
) -> None:
    """Print scan results in a formatted table."""
    open_ports = [r for r in results if r.status != PortStatus.CLOSED]

    print(f"\n  {'-' * 58}")
    print(f"  Scan Results - {scan_type} - {host}")
    print(f"  {'-' * 58}")
    print(f"  {'PROTO':<6}{'PORT':<8}{'STATUS':<18}{'SERVICE'}")
    print(f"  {'-' * 58}")

    if not open_ports:
        print("  No open or filtered ports found.")
    else:
        for result in open_ports:
            status_str  = result.status.name.replace("_", "|")
            service_str = result.service or "unknown"
            banner_line = (
                f"\n    Banner: {result.banner[:100]}"
                if result.banner else ""
            )
            print(
                f"  {result.proto:<6}{result.port:<8}"
                f"{status_str:<18}{service_str}"
                f"{banner_line}"
            )

    print(f"  {'-' * 58}")
    print(f"  Total open/filtered: {len(open_ports)}")


def save_results(
    results: list,
    scan_type: str,
    host: str,
    ports_scanned: int,
    elapsed: float,
) -> Optional[Path]:
    """
    Write scan results to a timestamped text file.

    Parameters
    ----------
    results       : list   PortResult objects from the scan.
    scan_type     : str    Human-readable scan type name.
    host          : str    Target that was scanned.
    ports_scanned : int    Total number of ports probed.
    elapsed       : float  Scan duration in seconds.

    Returns
    -------
    Path to the saved file, or None on failure.
    """
    try:
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename  = RESULTS_DIR / (
            f"scan_{host.replace('.', '_')}_{timestamp}.txt"
        )

        open_results = [r for r in results if r.status != PortStatus.CLOSED]

        with filename.open("w", encoding="utf-8") as fh:
            fh.write("Port Scan Report\n")
            fh.write("=" * 60 + "\n")
            fh.write(f"Target      : {host}\n")
            fh.write(f"Scan type   : {scan_type}\n")
            fh.write(
                f"Date/time   : "
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            )
            fh.write(f"Ports probed: {ports_scanned:,}\n")
            fh.write(f"Duration    : {elapsed:.2f}s\n")
            fh.write(f"Open/filter : {len(open_results)}\n")
            fh.write("=" * 60 + "\n\n")
            fh.write(f"{'PROTO':<6}{'PORT':<8}{'STATUS':<18}{'SERVICE'}\n")
            fh.write("-" * 60 + "\n")

            for result in open_results:
                status_str  = result.status.name.replace("_", "|")
                service_str = result.service or "unknown"
                fh.write(
                    f"{result.proto:<6}{result.port:<8}"
                    f"{status_str:<18}{service_str}\n"
                )
                if result.banner:
                    fh.write(f"  Banner: {result.banner[:200]}\n")

            fh.write("\n" + "-" * 60 + "\n")
            fh.write("Scan complete.\n")

        logger.info("Results saved to %s", filename)
        return filename

    except OSError as exc:
        print(f"  [!] Could not save results: {exc}")
        logger.error("Save error: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

SCAN_MENU = {
    "1": "TCP Connect Scan",
    "2": "SYN Scan (Half-Open)",
    "3": "UDP Scan",
    "4": "Banner Grab Only",
}


def main() -> None:
    """
    Interactive port scanner entry point.

    Collects target host, scan type, port range, and banner grab
    preference. Validates privileges for raw socket scan types.
    Displays live progress, results table, and saves to file.
    """
    print("\n  Port Scanner")
    print("  " + "-" * 12)
    print("  [!] EDUCATIONAL USE ONLY.")
    print("  [!] Only scan hosts you own or are authorised to test.")
    print("  [*] Enter 0 at any prompt to cancel.\n")

    # --- Target host ---
    target = input("  Target host (IP or hostname): ").strip()
    if not target or target == "0":
        return

    # Resolve hostname to IP
    try:
        target_ip = socket.gethostbyname(target)
        if target_ip != target:
            print(f"  [+] Resolved: {target} -> {target_ip}")
    except socket.gaierror:
        print(f"  [!] Could not resolve hostname: {target}")
        return

    # --- Scan type ---
    print("\n  Scan types:")
    for key, name in SCAN_MENU.items():
        needs_root = (
            " (requires root/Admin + Npcap on Windows)"
            if key in ("2", "3") else ""
        )
        print(f"    {key}. {name}{needs_root}")

    scan_choice = input("\n  Select scan type: ").strip()
    if scan_choice == "0":
        return
    if scan_choice not in SCAN_MENU:
        print("  [!] Invalid choice.")
        return

    scan_name = SCAN_MENU[scan_choice]

    # Privilege check for raw socket scans
    if scan_choice in ("2", "3"):
        if not SCAPY_AVAILABLE:
            print("  [!] Scapy is required: pip install scapy")
            if IS_WINDOWS:
                print("  [!] Also requires Npcap from https://npcap.com")
            return
        if not check_privileges():
            print(f"  [!] {scan_name} requires root/Administrator.")
            if IS_WINDOWS:
                print("  [*] Run VS Code or your terminal as Administrator.")
                print("  [*] Also ensure Npcap is installed from https://npcap.com")
            else:
                print("  [*] Run with: sudo python port_scanner.py")
            print("  [*] TCP Connect Scan works without elevation.")
            return

    # --- Port range ---
    print("\n  Port range examples:")
    print("    80        - single port")
    print("    1-1024    - range")
    print("    22,80,443 - list")
    print("    top100    - 100 most common ports")
    print("    top1000   - ports 1-1024 plus common high ports")
    raw_ports = input("\n  Ports to scan [top100]: ").strip()
    if raw_ports == "0":
        return
    raw_ports = raw_ports or "top100"

    ports = parse_port_range(raw_ports)
    if not ports:
        return

    # --- Banner grabbing ---
    grab_banners = False
    if scan_choice in ("1", "2"):
        banner_input = input(
            "\n  Grab banners from open ports? (y/n) [y]: "
        ).strip().lower()
        grab_banners = banner_input != "n"

    # --- Confirm ---
    print(f"\n  Scan summary:")
    print(f"    Target    : {target} ({target_ip})")
    print(f"    Scan type : {scan_name}")
    print(f"    Ports     : {len(ports):,}")
    print(f"    Banners   : {'yes' if grab_banners else 'no'}")

    confirm = input("\n  Start scan? (y/n): ").strip().lower()
    if confirm != "y":
        print("  Cancelled.")
        return

    # --- Run scan ---
    print(f"\n  [*] Starting {scan_name} on {target_ip}...\n")
    logger.info(
        "Scan started: target=%s type=%s ports=%d",
        target_ip, scan_name, len(ports),
    )

    start_time = time.perf_counter()
    results    = []

    try:
        if scan_choice == "1":
            results = tcp_connect_scan(target_ip, ports, grab_banners)

        elif scan_choice == "2":
            results = syn_scan(target_ip, ports, grab_banners)

        elif scan_choice == "3":
            results = udp_scan(target_ip, ports)

        elif scan_choice == "4":
            known = input(
                "  Enter known open ports (comma-separated): "
            ).strip()
            known_ports = parse_port_range(known)
            if known_ports:
                for port in known_ports:
                    banner = grab_banner(target_ip, port)
                    results.append(
                        PortResult(port, PortStatus.OPEN, banner=banner)
                    )

    except KeyboardInterrupt:
        print("\n\n  [*] Scan interrupted.")

    elapsed = time.perf_counter() - start_time

    # --- Display results ---
    display_results(results, scan_name, target_ip)
    print(f"\n  Scan duration: {elapsed:.2f}s")

    # --- Save results ---
    saved = save_results(
        results, scan_name, target_ip, len(ports), elapsed
    )
    if saved:
        print(f"  Results saved to: {saved}")

    logger.info(
        "Scan complete: %s - %d ports in %.2fs",
        target_ip, len(ports), elapsed,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()