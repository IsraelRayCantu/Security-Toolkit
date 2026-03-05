# topic: Networking
# title: TCP Client
# priority: 5

"""
tcp_client.py - Interactive TCP Client
=======================================
Connects to a remote host over TCP, sends a custom payload,
and reads the response. Useful for banner grabbing, protocol
testing, and verifying firewall rules.

HOW IT WORKS
-------------
TCP (Transmission Control Protocol) is connection-oriented:
  1. Three-way handshake establishes the connection
     (SYN -> SYN-ACK -> ACK)
  2. Data is sent and received reliably in order
  3. Connection is closed gracefully (FIN -> FIN-ACK)

This client completes the full handshake before sending data,
which means the connection WILL appear in server logs.

USE CASES IN SECURITY
----------------------
  - Banner grabbing    : read service version from open ports
  - Protocol testing   : send raw data to any TCP service
  - Firewall testing   : verify a port is reachable end-to-end
  - CTF challenges     : interact with custom TCP services

EXAMPLE INTERACTIONS
---------------------
  HTTP server (port 80):
    Send: HEAD / HTTP/1.0\r\n\r\n
    Gets: HTTP/1.1 200 OK / Server: Apache/2.4.41 ...

  SMTP server (port 25):
    Connect and read banner: 220 mail.example.com ESMTP

  SSH server (port 22):
    Connect and read banner: SSH-2.0-OpenSSH_8.2p1

EDUCATIONAL USE ONLY.
Only connect to hosts you own or have permission to test.

Requirements: Python standard library only
"""

import socket
import os
import sys

IS_WINDOWS = os.name == "nt"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_HOST        = "127.0.0.1"
DEFAULT_PORT        = 9999
CONNECT_TIMEOUT     = 5       # Seconds to wait for connection
RECEIVE_TIMEOUT     = 5       # Seconds to wait for response
MAX_RESPONSE_BYTES  = 65536   # 64KB max response to prevent memory issues
BUFFER_SIZE         = 4096    # Bytes per recv() call

# HTTP probe sent to web servers to elicit a response
DEFAULT_HTTP_PROBE  = "HEAD / HTTP/1.0\r\n\r\n"


# ---------------------------------------------------------------------------
# Core function
# ---------------------------------------------------------------------------

def send_tcp_message(
    host: str,
    port: int,
    payload: str,
) -> None:
    """
    Connect to host:port, send payload, and print the response.

    Uses a context manager (with statement) to guarantee the socket
    is closed when the function returns - even if an exception is
    raised mid-communication. This is equivalent to a try/finally
    block and is the recommended pattern for socket lifetime management.

    Two timeouts are set:
      CONNECT_TIMEOUT : how long to wait for the TCP handshake
      RECEIVE_TIMEOUT : how long to wait for data after connecting

    Parameters
    ----------
    host    : str   Target hostname or IP address.
    port    : int   Target TCP port number.
    payload : str   Data to send to the server.
    """
    print(f"\n  [*] Connecting to {host}:{port}...")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Set connect timeout before attempting connection
        sock.settimeout(CONNECT_TIMEOUT)

        try:
            sock.connect((host, port))
        except socket.timeout:
            print(f"  [!] Connection timed out after {CONNECT_TIMEOUT}s.")
            print(f"      Is the host reachable and the port open?")
            return
        except ConnectionRefusedError:
            print(f"  [!] Connection refused - port {port} is closed or filtered.")
            return
        except OSError as exc:
            print(f"  [!] Connection error: {exc}")
            return

        print(f"  [+] Connected to {host}:{port}")

        # Switch to receive timeout after successful connection
        sock.settimeout(RECEIVE_TIMEOUT)

        # Send the payload
        try:
            sock.sendall(payload.encode("utf-8"))
            print(f"  [*] Sent {len(payload)} bytes.")
        except OSError as exc:
            print(f"  [!] Send error: {exc}")
            return

        # Read the full response in chunks
        # A single recv() may only return part of the data if the
        # server sends more than BUFFER_SIZE bytes or the TCP stack
        # splits the transmission into multiple segments.
        response     = b""
        chunks_read  = 0

        try:
            while len(response) < MAX_RESPONSE_BYTES:
                chunk = sock.recv(BUFFER_SIZE)
                if not chunk:
                    break   # Server closed the connection
                response    += chunk
                chunks_read += 1

                # Stop reading when we receive less than a full buffer -
                # heuristic that works for most request/response protocols
                if len(chunk) < BUFFER_SIZE:
                    break

        except socket.timeout:
            if not response:
                print(f"  [*] No response received within {RECEIVE_TIMEOUT}s.")
                return

        except OSError as exc:
            print(f"  [!] Receive error: {exc}")
            return

        # Display the response
        if response:
            print(f"\n  [+] Response ({len(response)} bytes):\n")
            print("  " + "-" * 56)
            try:
                decoded = response.decode("utf-8", errors="replace")
                for line in decoded.splitlines():
                    print(f"  {line}")
            except Exception:
                print(f"  [Binary data - {len(response)} bytes]")
            print("  " + "-" * 56)
        else:
            print("  [*] Empty response received.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Interactively prompt for connection details and send a TCP message.

    Loops so the user can send multiple messages to the same or
    different hosts without restarting - useful for testing multiple
    ports or payloads in sequence.
    """
    print("\n  TCP Client")
    print("  " + "-" * 10)
    print("  [!] Only connect to hosts you own or are authorised to test.")
    print("  [*] Enter 0 at any prompt to cancel.\n")

    while True:
        # --- Target host ---
        host = input(f"  Target host [{DEFAULT_HOST}]: ").strip()
        if host == "0":
            print("  Returning to menu...")
            break
        host = host or DEFAULT_HOST

        # --- Target port ---
        raw_port = input(f"  Target port [{DEFAULT_PORT}]: ").strip()
        if raw_port == "0":
            print("  Returning to menu...")
            break
        if raw_port:
            if not raw_port.isdigit():
                print("  [!] Port must be a number.")
                continue
            port = int(raw_port)
            if not (1 <= port <= 65535):
                print("  [!] Port must be between 1 and 65535.")
                continue
        else:
            port = DEFAULT_PORT

        # --- Payload ---
        print(f"\n  Payload to send. Press Enter to use default HTTP probe.")
        print(f"  Default: HEAD / HTTP/1.0\\r\\n\\r\\n")
        raw_payload = input("  Payload: ").strip()
        if raw_payload == "0":
            print("  Returning to menu...")
            break

        # Handle escape sequences in payload
        if raw_payload:
            payload = raw_payload.replace("\\r\\n", "\r\n").replace("\\n", "\n")
        else:
            payload = DEFAULT_HTTP_PROBE

        # --- Send ---
        send_tcp_message(host, port, payload)

        # --- Again? ---
        again = input("\n  Send another message? (y/n): ").strip().lower()
        if again != "y":
            break


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()