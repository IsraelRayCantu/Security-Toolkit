# topic: Networking
# title: UDP Client
# priority: 8

"""
udp_client.py - UDP Client
============================
Sends data to a remote host over UDP and optionally receives a response.

UDP vs TCP - the key difference
---------------------------------
TCP (used by the TCP Client module) is connection-oriented:
  - A connection is established before data is sent (three-way handshake)
  - Delivery is guaranteed - lost packets are retransmitted automatically
  - Order is preserved - data arrives in the sequence it was sent
  - Higher overhead due to connection state and acknowledgements

UDP is connectionless:
  - Data is sent directly with no handshake
  - No delivery guarantee - packets can be lost, duplicated, or reordered
  - No retransmission - if a packet is lost it is gone
  - Lower overhead - faster for time-sensitive or high-volume applications

USE CASES
----------
UDP is used by protocols where speed matters more than reliability:
  - DNS  (port 53)    - name resolution queries
  - DHCP (port 67/68) - IP address assignment
  - SNMP (port 161)   - network device monitoring
  - VoIP / video      - real-time media streams
  - Game servers      - position updates

IN SECURITY
-----------
UDP services are frequently overlooked in security assessments because
many port scanners default to TCP-only scans. UDP services can expose:
  - DNS amplification attack vectors (open resolvers)
  - SNMP community strings (default public/private)
  - Outdated unpatched UDP services on non-standard ports

This client is useful for manually probing UDP services, testing
firewall rules on UDP ports, and verifying DNS/SNMP responses.

EDUCATIONAL USE ONLY.
Only send traffic to hosts you own or have explicit permission to test.

Requirements: Python standard library only
"""

import socket
import os
import sys
from typing import Optional

IS_WINDOWS = os.name == "nt"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_HOST  = "127.0.0.1"
DEFAULT_PORT  = 9997
BUFFER_SIZE   = 4096    # Bytes per recvfrom() call
RECV_TIMEOUT  = 5       # Seconds to wait for a UDP response


# ---------------------------------------------------------------------------
# Core function
# ---------------------------------------------------------------------------

def send_udp_message(
    target_host: str,
    target_port: int,
    data: bytes,
) -> Optional[str]:
    """
    Send data to target_host:target_port over UDP and return the response.

    Why no connect() call?
        TCP requires connect() to establish a session before sending.
        UDP is connectionless - sendto() transmits the datagram directly
        to the destination without any prior handshake. No connection
        state is maintained - each sendto() is an independent packet.

    Why might recvfrom() time out?
        UDP has no acknowledgement mechanism. If the server is not
        running, a firewall silently drops the packet, or the server
        ignores the message, recvfrom() will block forever without a
        timeout. RECV_TIMEOUT ensures we always regain control.

    Why does UDP not guarantee a response?
        Some UDP services (e.g. DNS) always reply. Others (e.g. syslog)
        are fire-and-forget - the sender never expects a response.
        A timeout is the correct way to handle both cases.

    Parameters
    ----------
    target_host : str     Hostname or IP address to send to.
    target_port : int     Destination UDP port.
    data        : bytes   The payload to transmit.

    Returns
    -------
    Decoded response string if a reply is received, or None.
    """
    # SOCK_DGRAM selects UDP - compare with SOCK_STREAM for TCP
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(RECV_TIMEOUT)

    try:
        print(f"  [*] Sending {len(data)} bytes to {target_host}:{target_port}...")
        client.sendto(data, (target_host, target_port))

        # Wait for a response - may time out if the server does not reply
        try:
            response, server_addr = client.recvfrom(BUFFER_SIZE)
            print(f"  [+] Response from {server_addr[0]}:{server_addr[1]} "
                  f"({len(response)} bytes)")
            return response.decode("utf-8", errors="replace")

        except socket.timeout:
            print(f"  [*] No response within {RECV_TIMEOUT}s.")
            print(f"      This is normal for fire-and-forget protocols like syslog.")
            return None

    except OSError as exc:
        print(f"  [!] UDP error: {exc}")
        return None

    finally:
        # UDP has no connection to close but we still release the
        # socket file descriptor
        client.close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Interactively prompt for a target and send a UDP datagram.

    Loops so the user can send multiple messages without restarting,
    useful for testing different payloads against the same service.
    """
    print("\n  UDP Client")
    print("  " + "-" * 10)
    print("  [!] Only send traffic to hosts you own or are authorised to test.")
    print("  [*] Enter 0 at any prompt to cancel.\n")

    while True:
        # --- Target host ---
        target_host = input(f"  Target host [{DEFAULT_HOST}]: ").strip()
        if target_host == "0":
            print("  Returning to menu...")
            break
        target_host = target_host or DEFAULT_HOST

        # --- Target port ---
        raw_port = input(f"  Target port [{DEFAULT_PORT}]: ").strip()
        if raw_port == "0":
            print("  Returning to menu...")
            break
        if raw_port:
            if not raw_port.isdigit():
                print("  [!] Port must be a number.")
                continue
            target_port = int(raw_port)
            if not (1 <= target_port <= 65535):
                print("  [!] Port must be between 1 and 65535.")
                continue
        else:
            target_port = DEFAULT_PORT

        # --- Payload ---
        data_input = input("  Data to send: ").strip()
        if data_input == "0":
            print("  Returning to menu...")
            break
        if not data_input:
            print("  [!] Payload cannot be empty.")
            continue

        # --- Send ---
        print()
        response = send_udp_message(
            target_host,
            target_port,
            data_input.encode("utf-8"),
        )

        if response:
            display = (
                response if len(response) <= 2000
                else response[:2000] + "\n  [...truncated]"
            )
            print(f"\n  [*] Response:\n")
            print("  " + "-" * 40)
            for line in display.splitlines():
                print(f"  {line}")
            print("  " + "-" * 40)

        # --- Again? ---
        again = input("\n  Send another message? (y/n): ").strip().lower()
        if again != "y":
            break


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()