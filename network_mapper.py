# topic: Network Analysis
# title: Network Mapper
# priority: 3

"""
network_mapper.py - Network Host Discovery and Mapping
=======================================================
Discovers all live hosts on a network using ARP and ICMP,
resolves hostnames, fingerprints operating systems from TTL
values, detects the gateway, probes common ports, and
attempts to identify device names/SSIDs where possible.

DISCOVERY METHODS
------------------
ARP Scan (Layer 2):
    Sends ARP who-has requests to every IP in the subnet.
    Only works on the local network segment (same LAN).
    Very reliable - devices must respond to ARP to function.
    Fast - typically completes in 2-5 seconds.
    Requires Scapy + Npcap on Windows.

ICMP Ping Sweep (Layer 3):
    Sends ICMP echo requests to every IP in the subnet.
    Works across subnets if routing allows.
    Some hosts block ICMP - may miss firewalled devices.
    Requires Administrator/root.

Combined:
    Runs both methods and merges results.
    A host appearing in either scan is marked as live.
    Most thorough approach - catches hosts that block one method.

WHAT IT DETECTS
----------------
  IP Address      : IPv4 address of each live host
  MAC Address     : Hardware address (ARP only - LAN hosts)
  Hostname        : Reverse DNS lookup of IP address
  OS Fingerprint  : Heuristic from TTL value in ICMP response
                    TTL 64  -> Linux/macOS
                    TTL 128 -> Windows
                    TTL 255 -> Network device/router
  Vendor          : Network card manufacturer from MAC OUI
                    (first 3 bytes of MAC address)
  Gateway         : Default router for this machine
  Open Ports      : Quick probe of 10 common ports per host
  Device Name     : NetBIOS name query (Windows devices)
  SSID            : Wireless network name (Windows only,
                    requires netsh - shows AP SSID for
                    wireless interfaces)

PLATFORM SUPPORT
-----------------
Windows 11:
    ARP scan    : requires Administrator + Npcap
    ICMP sweep  : requires Administrator + Npcap
    NetBIOS     : works without elevation
    SSID        : works without elevation (netsh)
    Gateway     : works without elevation

Linux/Kali:
    ARP scan    : requires root
    ICMP sweep  : requires root
    NetBIOS     : works without elevation
    SSID        : requires iwconfig/nmcli
    Gateway     : works without elevation

EDUCATIONAL USE ONLY.
Network scanning without authorisation may be illegal.
Only scan networks you own or have explicit written permission
to map.

Requirements:
    pip install scapy
    Windows: Npcap from https://npcap.com
"""

import concurrent.futures
import ipaddress
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

IS_WINDOWS = os.name == "nt"
IS_LINUX   = sys.platform.startswith("linux")

try:
    from scapy.all import (
        ARP,
        Ether,
        ICMP,
        IP,
        srp,
        sr1,
        conf as scapy_conf,
        get_if_list,
        get_if_addr,
        get_if_hwaddr,
    )
    scapy_conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
ARP_TIMEOUT      = 3       # Seconds to wait for ARP replies
ICMP_TIMEOUT     = 2       # Seconds to wait for ping replies
PORT_TIMEOUT     = 0.5     # Seconds per port probe
NETBIOS_TIMEOUT  = 2       # Seconds to wait for NetBIOS reply
MAX_WORKERS      = 50      # Concurrent threads for port scanning

# Common ports to probe on each discovered host
QUICK_PORTS = [21, 22, 23, 80, 135, 139, 443, 445, 3389, 8080]

# MAC OUI vendor database - first 3 bytes of MAC -> manufacturer
# A small subset of the full IEEE OUI registry for common vendors
MAC_VENDORS = {
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "00:1a:a0": "Dell",
    "00:14:22": "Dell",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
    "00:1b:21": "Intel",
    "8c:8d:28": "Intel",
    "00:1c:bf": "Apple",
    "00:23:df": "Apple",
    "a4:83:e7": "Apple",
    "00:50:ba": "D-Link",
    "1c:7e:e5": "D-Link",
    "00:18:e7": "Cisco",
    "00:1a:2f": "Cisco",
    "fc:fb:fb": "Cisco",
    "00:23:69": "Linksys",
    "00:14:bf": "Linksys",
    "00:90:4c": "Epson",
    "00:13:d4": "HP",
    "3c:d9:2b": "HP",
    "00:26:b9": "Dell",
    "f8:bc:12": "Samsung",
    "00:16:32": "Samsung",
    "00:1d:25": "Asus",
    "04:d4:c4": "Asus",
    "74:d4:35": "Netgear",
    "00:14:6c": "Netgear",
    "c0:ff:d4": "TP-Link",
    "50:c7:bf": "TP-Link",
    "00:0f:66": "TP-Link",
}


# ---------------------------------------------------------------------------
# Host dataclass
# ---------------------------------------------------------------------------

@dataclass
class Host:
    """
    Represents a single discovered network host.
    """
    ip          : str
    mac         : str  = "N/A"
    hostname    : str  = "N/A"
    os_hint     : str  = "Unknown"
    ttl         : int  = 0
    vendor      : str  = "Unknown"
    open_ports  : list = field(default_factory=list)
    device_name : str  = "N/A"
    is_gateway  : bool = False
    discovery   : str  = ""     # ARP, ICMP, or ARP+ICMP


# ---------------------------------------------------------------------------
# Privilege check
# ---------------------------------------------------------------------------

def check_privileges() -> bool:
    """Check for root/Administrator privileges."""
    try:
        return os.getuid() == 0
    except AttributeError:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Gateway detection
# ---------------------------------------------------------------------------

def get_default_gateway() -> Optional[str]:
    """
    Detect the default gateway (router) IP address.

    Windows : parses 'route print' output
    Linux   : parses /proc/net/route or 'ip route' output

    Returns
    -------
    Gateway IP string, or None if not detected.
    """
    if IS_WINDOWS:
        try:
            result = subprocess.run(
                ["route", "print", "0.0.0.0"],
                capture_output=True,
                text=True,
                shell=False,
                timeout=5,
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[0] == "0.0.0.0":
                    gateway = parts[2]
                    try:
                        ipaddress.ip_address(gateway)
                        return gateway
                    except ValueError:
                        continue
        except Exception as exc:
            logger.debug("Gateway detection error (Windows): %s", exc)
        return None

    # Linux - parse /proc/net/route
    try:
        with open("/proc/net/route") as fh:
            for line in fh:
                parts = line.strip().split()
                if len(parts) >= 3 and parts[1] == "00000000":
                    gateway_hex = parts[2]
                    gateway_int = int(gateway_hex, 16)
                    gateway_ip  = socket.inet_ntoa(
                        struct.pack("<L", gateway_int)
                    )
                    return gateway_ip
    except Exception:
        pass

    # Fallback - ip route
    try:
        result = subprocess.run(
            ["ip", "route"],
            capture_output=True,
            text=True,
            shell=False,
            timeout=5,
        )
        for line in result.stdout.splitlines():
            if line.startswith("default"):
                parts = line.split()
                if "via" in parts:
                    return parts[parts.index("via") + 1]
    except Exception as exc:
        logger.debug("Gateway detection error (Linux): %s", exc)

    return None


# ---------------------------------------------------------------------------
# SSID detection
# ---------------------------------------------------------------------------

def get_current_ssid() -> Optional[str]:
    """
    Get the SSID of the currently connected wireless network.

    Windows : uses 'netsh wlan show interfaces'
    Linux   : uses 'iwconfig' or 'nmcli'

    Returns
    -------
    SSID string, or None if not on WiFi or not detectable.
    """
    if IS_WINDOWS:
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True,
                text=True,
                shell=False,
                timeout=5,
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("SSID") and "BSSID" not in line:
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        ssid = parts[1].strip()
                        if ssid:
                            return ssid
        except Exception as exc:
            logger.debug("SSID detection error (Windows): %s", exc)
        return None

    # Linux - try iwconfig
    try:
        result = subprocess.run(
            ["iwconfig"],
            capture_output=True,
            text=True,
            shell=False,
            timeout=5,
        )
        m = re.search(r'ESSID:"([^"]+)"', result.stdout)
        if m:
            return m.group(1)
    except Exception:
        pass

    # Linux - try nmcli
    try:
        result = subprocess.run(
            ["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"],
            capture_output=True,
            text=True,
            shell=False,
            timeout=5,
        )
        for line in result.stdout.splitlines():
            if line.startswith("yes:"):
                return line.split(":", 1)[1].strip()
    except Exception as exc:
        logger.debug("SSID detection error (Linux): %s", exc)

    return None


# ---------------------------------------------------------------------------
# Subnet detection
# ---------------------------------------------------------------------------

def get_local_subnet() -> Optional[str]:
    """
    Detect the local machine's IP and subnet in CIDR notation.

    Uses socket to get the local IP, then attempts to determine
    the subnet mask from the network interface.

    Returns
    -------
    CIDR string e.g. '192.168.1.0/24', or None on failure.
    """
    try:
        # Connect to a public IP to determine which interface is used
        # for outbound traffic. No data is actually sent.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]

        # Assume /24 subnet as default - most home/office networks
        # We try to get the real mask but fall back to /24
        network = ipaddress.IPv4Network(
            f"{local_ip}/24", strict=False
        )
        return str(network)

    except Exception as exc:
        logger.debug("Subnet detection error: %s", exc)
        return None


def get_local_ip() -> Optional[str]:
    """Return the local machine's primary IP address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return None


# ---------------------------------------------------------------------------
# MAC vendor lookup
# ---------------------------------------------------------------------------

def lookup_vendor(mac: str) -> str:
    """
    Look up the network card manufacturer from the MAC OUI prefix.

    The first 3 bytes (6 hex chars) of a MAC address identify the
    manufacturer - this is the Organizationally Unique Identifier (OUI).
    IEEE assigns OUI prefixes to hardware manufacturers.

    Parameters
    ----------
    mac : str   MAC address string e.g. 'aa:bb:cc:dd:ee:ff'

    Returns
    -------
    Vendor name string, or 'Unknown'.
    """
    if not mac or mac == "N/A":
        return "Unknown"

    oui = mac.lower()[:8]    # First 3 bytes e.g. 'aa:bb:cc'
    return MAC_VENDORS.get(oui, "Unknown")


# ---------------------------------------------------------------------------
# OS fingerprinting
# ---------------------------------------------------------------------------

def fingerprint_os(ttl: int) -> str:
    """
    Estimate the operating system from the ICMP TTL value.

    TTL is set by the sender's OS and decremented by each router hop.
    Common initial TTL values:
      64  : Linux, macOS, Android, iOS
      128 : Windows (all versions)
      255 : Cisco IOS, network equipment, some BSD variants

    We add a small buffer (+5) to account for router hops between
    the target and this machine.

    Parameters
    ----------
    ttl : int   TTL value from ICMP echo reply.

    Returns
    -------
    OS hint string.
    """
    if ttl <= 0:
        return "Unknown"
    elif ttl <= 69:
        return "Linux / macOS"
    elif ttl <= 133:
        return "Windows"
    elif ttl <= 260:
        return "Network Device"
    else:
        return "Unknown"


# ---------------------------------------------------------------------------
# Hostname resolution
# ---------------------------------------------------------------------------

def resolve_hostname(ip: str) -> str:
    """
    Perform a reverse DNS lookup on an IP address.

    gethostbyaddr() queries the DNS PTR record for the IP.
    Many LAN devices (routers, printers, IoT) register PTR records
    with the local DNS server (usually the router).

    Times out after 2 seconds to avoid slowing the scan.

    Parameters
    ----------
    ip : str   IPv4 address to resolve.

    Returns
    -------
    Hostname string, or 'N/A' if not resolvable.
    """
    try:
        socket.setdefaulttimeout(2)
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror, socket.timeout):
        return "N/A"
    finally:
        socket.setdefaulttimeout(None)


# ---------------------------------------------------------------------------
# NetBIOS name query
# ---------------------------------------------------------------------------

def get_netbios_name(ip: str) -> str:
    """
    Query the NetBIOS name of a Windows host.

    Sends a NetBIOS Name Service (NBNS) query to UDP port 137.
    Windows machines broadcast their computer name via NetBIOS
    which lets us identify devices by their Windows hostname
    even if DNS is not configured.

    This is the same protocol used by Network Neighbourhood in
    older Windows versions to discover computers on the LAN.

    Parameters
    ----------
    ip : str   Target IP to query.

    Returns
    -------
    NetBIOS name string, or 'N/A' if not available.
    """
    # NBNS query packet - standard NetBIOS status request
    netbios_query = (
        b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41"
        b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
        b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00"
        b"\x21\x00\x01"
    )

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(NETBIOS_TIMEOUT)
        sock.sendto(netbios_query, (ip, 137))
        response, _ = sock.recvfrom(1024)
        sock.close()

        # Parse the NetBIOS name from the response
        # Name starts at offset 57, is 15 bytes, space-padded
        if len(response) > 72:
            name = response[57:72].decode(
                "ascii", errors="ignore"
            ).strip()
            if name:
                return name

    except Exception:
        pass

    return "N/A"


# ---------------------------------------------------------------------------
# Quick port scan
# ---------------------------------------------------------------------------

def quick_port_scan(ip: str) -> list:
    """
    Probe QUICK_PORTS on a host using TCP connect.

    Uses connect_ex() which returns 0 on success (port open) and
    an error code on failure - faster than exception handling in
    a tight loop.

    Parameters
    ----------
    ip : str   Target IP to scan.

    Returns
    -------
    List of open port numbers.
    """
    open_ports = []
    for port in QUICK_PORTS:
        try:
            with socket.socket(
                socket.AF_INET, socket.SOCK_STREAM
            ) as sock:
                sock.settimeout(PORT_TIMEOUT)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
        except OSError:
            continue
    return open_ports


# ---------------------------------------------------------------------------
# ARP scan
# ---------------------------------------------------------------------------

def arp_scan(subnet: str) -> dict:
    """
    Discover live hosts using ARP requests.

    Sends an Ethernet broadcast containing ARP who-has for every
    IP in the subnet. Hosts that are online MUST respond to ARP
    to function on the network - this makes ARP scanning very
    reliable for local network discovery.

    srp() operates at Layer 2 and returns (answered, unanswered)
    pairs. Each answered pair contains the request and response.

    Parameters
    ----------
    subnet : str   CIDR notation e.g. '192.168.1.0/24'

    Returns
    -------
    Dict mapping IP string to MAC string for all responding hosts.
    """
    print(f"  [*] ARP scan on {subnet}...")

    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)

    try:
        answered, _ = srp(
            arp_request,
            timeout=ARP_TIMEOUT,
            verbose=False,
        )
    except Exception as exc:
        print(f"  [!] ARP scan error: {exc}")
        if IS_WINDOWS:
            print("  [*] Ensure Npcap is installed and running as Administrator.")
        return {}

    results = {}
    for sent, received in answered:
        results[received.psrc] = received.hwsrc

    print(f"  [+] ARP scan found {len(results)} host(s).")
    return results


# ---------------------------------------------------------------------------
# ICMP ping sweep
# ---------------------------------------------------------------------------

def ping_host(ip: str) -> Optional[int]:
    """
    Send a single ICMP echo request and return the TTL if alive.

    sr1() sends one packet and waits for one reply.
    Returns the TTL from the response for OS fingerprinting.

    Parameters
    ----------
    ip : str   Target IP to ping.

    Returns
    -------
    TTL integer if host responds, None if no response.
    """
    try:
        packet   = IP(dst=ip) / ICMP()
        response = sr1(packet, timeout=ICMP_TIMEOUT, verbose=False)
        if response and response.haslayer(ICMP):
            if response[ICMP].type == 0:    # Echo reply
                return response[IP].ttl
    except Exception:
        pass
    return None


def icmp_sweep(subnet: str) -> dict:
    """
    Ping every host in the subnet and return TTL values.

    Uses ThreadPoolExecutor to parallelise the pings - instead of
    waiting ICMP_TIMEOUT seconds per host sequentially, we ping
    all hosts concurrently.

    Parameters
    ----------
    subnet : str   CIDR notation e.g. '192.168.1.0/24'

    Returns
    -------
    Dict mapping IP string to TTL int for all responding hosts.
    """
    network = ipaddress.IPv4Network(subnet, strict=False)
    hosts   = [str(ip) for ip in network.hosts()]

    print(f"  [*] ICMP sweep on {subnet} ({len(hosts)} addresses)...")

    results  = {}
    done     = 0
    total    = len(hosts)
    lock     = threading.Lock()

    def ping_and_track(ip):
        nonlocal done
        ttl = ping_host(ip)
        with lock:
            done += 1
            print(
                f"\r  [*] Pinging: {done}/{total}  "
                f"(responding: {len(results)})  ",
                end="",
                flush=True,
            )
            if ttl is not None:
                results[ip] = ttl

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:
        list(executor.map(ping_and_track, hosts))

    print()
    print(f"  [+] ICMP sweep found {len(results)} host(s).")
    return results


# ---------------------------------------------------------------------------
# Host enrichment
# ---------------------------------------------------------------------------

def enrich_host(
    host: Host,
    scan_ports: bool,
) -> Host:
    """
    Enrich a discovered host with additional details.

    Performs in parallel where possible:
      - Reverse DNS hostname lookup
      - NetBIOS name query
      - Quick port scan (if requested)

    Parameters
    ----------
    host       : Host   The host object to enrich.
    scan_ports : bool   Whether to probe common ports.

    Returns
    -------
    Enriched Host object.
    """
    # Reverse DNS
    host.hostname = resolve_hostname(host.ip)

    # NetBIOS name (Windows device names)
    netbios = get_netbios_name(host.ip)
    if netbios != "N/A":
        host.device_name = netbios

    # MAC vendor lookup
    host.vendor = lookup_vendor(host.mac)

    # Quick port scan
    if scan_ports:
        host.open_ports = quick_port_scan(host.ip)

    return host


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP",
    135: "RPC", 139: "NetBIOS", 443: "HTTPS",
    445: "SMB", 3389: "RDP", 8080: "HTTP-Alt",
}


def display_results(
    hosts: list,
    gateway: Optional[str],
    ssid: Optional[str],
    subnet: str,
    elapsed: float,
) -> None:
    """
    Display discovered hosts in a formatted table.

    Parameters
    ----------
    hosts   : list           Discovered Host objects.
    gateway : str or None    Default gateway IP.
    ssid    : str or None    Current WiFi SSID.
    subnet  : str            Scanned subnet.
    elapsed : float          Scan duration in seconds.
    """
    local_ip = get_local_ip()

    # Network summary header
    print(f"\n  {'=' * 72}")
    print(f"  Network Map - {subnet}")
    print(f"  {'=' * 72}")
    print(f"  Local IP  : {local_ip or 'Unknown'}")
    print(f"  Gateway   : {gateway or 'Not detected'}")
    print(f"  SSID      : {ssid or 'Not on WiFi / Not detected'}")
    print(f"  Hosts     : {len(hosts)} discovered")
    print(f"  Duration  : {elapsed:.2f}s")
    print(f"  {'=' * 72}\n")

    if not hosts:
        print("  No hosts discovered.")
        return

    # Sort: gateway first, then by IP
    def sort_key(h):
        try:
            return (
                0 if h.is_gateway else 1,
                ipaddress.IPv4Address(h.ip),
            )
        except ValueError:
            return (1, ipaddress.IPv4Address("0.0.0.0"))

    hosts_sorted = sorted(hosts, key=sort_key)

    # Column headers
    print(
        f"  {'IP':<16} {'MAC':<18} {'HOSTNAME':<22} "
        f"{'OS':<16} {'VENDOR':<12} {'DEVICE':<16} {'PORTS'}"
    )
    print("  " + "-" * 110)

    for host in hosts_sorted:
        gateway_marker = " [GW]" if host.is_gateway else ""
        local_marker   = " [YOU]" if host.ip == local_ip else ""
        marker         = gateway_marker or local_marker

        ports_str = (
            ", ".join(
                f"{p}({SERVICE_NAMES.get(p, '?')})"
                for p in host.open_ports
            ) if host.open_ports else "-"
        )

        # Truncate long fields for table alignment
        hostname_display = (
            host.hostname[:20] + ".."
            if len(host.hostname) > 22
            else host.hostname
        )
        vendor_display = (
            host.vendor[:10] + ".."
            if len(host.vendor) > 12
            else host.vendor
        )
        device_display = (
            host.device_name[:14] + ".."
            if len(host.device_name) > 16
            else host.device_name
        )

        print(
            f"  {host.ip + marker:<16} "
            f"{host.mac:<18} "
            f"{hostname_display:<22} "
            f"{host.os_hint:<16} "
            f"{vendor_display:<12} "
            f"{device_display:<16} "
            f"{ports_str}"
        )

    print("  " + "-" * 110)
    print(
        f"\n  Discovery method: {hosts_sorted[0].discovery if hosts_sorted else 'N/A'}"
        f" | [GW] = Gateway | [YOU] = This machine\n"
    )


# ---------------------------------------------------------------------------
# Main scan orchestrator
# ---------------------------------------------------------------------------

def run_network_map(
    subnet: str,
    scan_ports: bool,
) -> list:
    """
    Run the full network mapping scan.

    Flow:
      1. ARP scan - gets IP + MAC for all LAN hosts
      2. ICMP sweep - gets TTL for OS fingerprinting,
                      catches hosts that don't respond to ARP
      3. Merge results
      4. Enrich each host concurrently:
           - Reverse DNS
           - NetBIOS name
           - Port scan (optional)
           - OS fingerprint from TTL
           - Vendor from MAC OUI

    Parameters
    ----------
    subnet     : str    CIDR subnet to scan.
    scan_ports : bool   Probe common ports on each host.

    Returns
    -------
    List of enriched Host objects.
    """
    # Step 1 - ARP scan
    arp_results  = arp_scan(subnet)

    # Step 2 - ICMP sweep
    icmp_results = icmp_sweep(subnet)

    # Step 3 - Merge results
    # Union of all IPs found by either method
    all_ips = set(arp_results.keys()) | set(icmp_results.keys())

    hosts = []
    for ip in all_ips:
        mac = arp_results.get(ip, "N/A")
        ttl = icmp_results.get(ip, 0)

        # Determine discovery method
        in_arp  = ip in arp_results
        in_icmp = ip in icmp_results
        if in_arp and in_icmp:
            discovery = "ARP+ICMP"
        elif in_arp:
            discovery = "ARP"
        else:
            discovery = "ICMP"

        host = Host(
            ip        = ip,
            mac       = mac,
            ttl       = ttl,
            os_hint   = fingerprint_os(ttl) if ttl else "Unknown",
            discovery = discovery,
        )
        hosts.append(host)

    print(
        f"\n  [*] Total unique hosts: {len(hosts)}. "
        f"Enriching (DNS, NetBIOS, ports)...\n"
    )

    # Step 4 - Enrich hosts concurrently
    gateway = get_default_gateway()
    enriched = []
    done     = 0
    total    = len(hosts)
    lock     = threading.Lock()

    def enrich_and_track(host):
        nonlocal done
        result = enrich_host(host, scan_ports)
        if gateway and result.ip == gateway:
            result.is_gateway = True
        with lock:
            done += 1
            print(
                f"\r  [*] Enriching hosts: {done}/{total}  ",
                end="",
                flush=True,
            )
        return result

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:
        enriched = list(executor.map(enrich_and_track, hosts))

    print()
    return enriched


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Interactive network mapper entry point.
    """
    print("\n  Network Mapper")
    print("  " + "-" * 14)
    print(f"  Platform : {sys.platform}")
    print("  [!] Requires Administrator (Windows) or root (Linux).")
    print("  [!] EDUCATIONAL USE ONLY.")
    print("  [!] Only scan networks you own or are authorised to map.")
    print("  [*] Enter 0 at any prompt to cancel.\n")

    if not SCAPY_AVAILABLE:
        print("  [!] Scapy is not installed: pip install scapy")
        if IS_WINDOWS:
            print("  [!] Also requires Npcap from https://npcap.com")
        return

    if not check_privileges():
        print("  [!] This module requires elevated privileges.")
        if IS_WINDOWS:
            print("  [*] Right-click your terminal and "
                  "select Run as Administrator.")
        else:
            print("  [*] Run with: sudo python network_mapper.py")
        return

    # Detect current SSID
    ssid = get_current_ssid()
    if ssid:
        print(f"  [*] Connected to WiFi: {ssid}")

    # Detect local subnet
    detected_subnet = get_local_subnet()
    if detected_subnet:
        print(f"  [*] Detected subnet: {detected_subnet}")

    # Subnet input
    if detected_subnet:
        raw_subnet = input(
            f"\n  Subnet to scan [{detected_subnet}]: "
        ).strip()
        if raw_subnet == "0":
            return
        subnet = raw_subnet or detected_subnet
    else:
        raw_subnet = input(
            "\n  Subnet to scan (e.g. 192.168.1.0/24): "
        ).strip()
        if not raw_subnet or raw_subnet == "0":
            return
        subnet = raw_subnet

    # Validate subnet
    try:
        network      = ipaddress.IPv4Network(subnet, strict=False)
        host_count   = network.num_addresses - 2
        print(f"  [+] Scanning {network} ({host_count} host addresses)")
    except ValueError as exc:
        print(f"  [!] Invalid subnet: {exc}")
        return

    # Warn for large subnets
    if host_count > 254:
        print(
            f"  [!] Large subnet ({host_count} addresses). "
            f"Scan may take several minutes."
        )
        confirm = input("  Continue? (y/n): ").strip().lower()
        if confirm != "y":
            return

    # Port scanning option
    port_input = input(
        "\n  Probe common ports on each host? (y/n) [y]: "
    ).strip().lower()
    if port_input == "0":
        return
    scan_ports = port_input != "n"

    # Detect gateway
    gateway = get_default_gateway()
    if gateway:
        print(f"  [*] Gateway detected: {gateway}")
    else:
        print("  [*] Gateway not detected.")

    # Run scan
    print(f"\n  [*] Starting network map of {subnet}...\n")
    logger.info(
        "Network map started: subnet=%s ports=%s",
        subnet, scan_ports,
    )

    start_time = time.perf_counter()

    try:
        hosts = run_network_map(subnet, scan_ports)
    except KeyboardInterrupt:
        print("\n\n  [*] Scan interrupted.")
        return

    elapsed = time.perf_counter() - start_time

    # Display results
    display_results(hosts, gateway, ssid, subnet, elapsed)

    logger.info(
        "Network map complete: %d hosts in %.2fs",
        len(hosts), elapsed,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()