# topic: Networking
# title: TCP Proxy
# priority: 6

"""
tcp_proxy.py - TCP Proxy with Hexdump
======================================
A bidirectional TCP proxy that sits between a client and a remote
server, forwarding traffic in both directions while displaying a
hexdump of every packet passing through.

HOW IT WORKS
-------------
1. The proxy binds to a local port and waits for a client connection
2. When a client connects, the proxy opens a second connection to
   the real remote server
3. Two threads relay data in both directions simultaneously:
      Client -> Proxy -> Remote Server
      Remote Server -> Proxy -> Client
4. Every packet is hexdumped to the terminal before forwarding

USE CASES IN SECURITY
----------------------
  - Protocol analysis      : inspect raw bytes of any TCP protocol
  - MITM testing           : intercept and modify traffic in transit
  - Debugging              : see exactly what bytes an app sends
  - CTF challenges         : decode custom binary protocols
  - Firewall bypass testing: relay traffic through an allowed port

HEXDUMP FORMAT
---------------
Each line shows 16 bytes in three columns:
  Offset   | Hex bytes (space separated)  | ASCII printable chars
  00000000 | 48 65 6c 6c 6f 20 57 6f 72   | Hello Wor

Non-printable characters are shown as a dot (.) in the ASCII column.

MODIFICATION HOOKS
-------------------
request_handler()  - called on every client->server packet
response_handler() - called on every server->client packet
Modify these functions to inspect or alter traffic in transit.

EDUCATIONAL USE ONLY.
Only proxy traffic on networks you own or have permission to test.
Intercepting traffic without authorisation is illegal in most
jurisdictions.

Requirements: Python standard library only
"""

import socket
import threading
import sys
import os

IS_WINDOWS = os.name == "nt"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
BUFFER_SIZE      = 4096    # Bytes per recv() call
SOCKET_TIMEOUT   = 10      # Seconds before idle connection closes
HEX_CHARS        = 16      # Bytes per hexdump line


# ---------------------------------------------------------------------------
# Hexdump
# ---------------------------------------------------------------------------

# Lookup table mapping each byte value to its printable ASCII character
# or a dot for non-printable bytes. Built once at module load for speed.
HEX_FILTER = "".join(
    chr(i) if 32 <= i < 127 else "."
    for i in range(256)
)


def hexdump(data: bytes, label: str = "") -> None:
    """
    Print a formatted hexdump of raw bytes to the terminal.

    Format mirrors classic tools like xxd and Wireshark's hex view:
      00000000  48 65 6c 6c 6f  Hello

    Non-printable bytes are shown as dots in the ASCII column.
    This makes it easy to spot protocol structures, magic bytes,
    and embedded strings in binary data.

    Parameters
    ----------
    data  : bytes   Raw bytes to display.
    label : str     Optional label printed above the hexdump.
    """
    if label:
        print(f"\n  [{label}]")

    if not data:
        print("  (empty)")
        return

    for i in range(0, len(data), HEX_CHARS):
        chunk     = data[i:i + HEX_CHARS]

        # Hex column - space separated byte values
        hex_part  = " ".join(f"{b:02x}" for b in chunk)

        # ASCII column - printable chars or dots
        # HEX_FILTER is indexed by byte value to get the display char
        ascii_part = "".join(HEX_FILTER[b] for b in chunk)

        # Pad hex column to consistent width for alignment
        print(f"  {i:08x}  {hex_part:<{HEX_CHARS * 3}}  {ascii_part}")

    print()


# ---------------------------------------------------------------------------
# Modification hooks
# ---------------------------------------------------------------------------

def request_handler(data: bytes) -> bytes:
    """
    Called on every packet travelling from client to remote server.

    Modify this function to inspect or alter outbound traffic.
    Return the data unchanged to act as a transparent proxy.
    Return modified bytes to alter what the server receives.

    Example - log all requests to a file:
        with open("requests.log", "ab") as f:
            f.write(data)
        return data

    Parameters
    ----------
    data : bytes   Raw packet bytes from the client.

    Returns
    -------
    bytes to forward to the remote server.
    """
    # Transparent by default - return data unmodified
    return data


def response_handler(data: bytes) -> bytes:
    """
    Called on every packet travelling from remote server to client.

    Modify this function to inspect or alter inbound traffic.
    Return the data unchanged to act as a transparent proxy.

    Parameters
    ----------
    data : bytes   Raw packet bytes from the remote server.

    Returns
    -------
    bytes to forward to the client.
    """
    # Transparent by default - return data unmodified
    return data


# ---------------------------------------------------------------------------
# Relay threads
# ---------------------------------------------------------------------------

def relay(
    source: socket.socket,
    destination: socket.socket,
    handler,
    label: str,
    stop_event: threading.Event,
) -> None:
    """
    Relay data from source socket to destination socket.

    Runs in a thread. Reads data from source, passes it through
    the handler function (for optional modification), hexdumps it,
    then forwards to destination.

    Stops when:
      - The source closes the connection (recv returns empty bytes)
      - A socket error occurs
      - stop_event is set by the other relay thread

    Parameters
    ----------
    source      : socket   Read data from this socket.
    destination : socket   Write data to this socket.
    handler     : callable  request_handler or response_handler.
    label       : str       Direction label for hexdump display.
    stop_event  : Event     Signals both threads to stop.
    """
    while not stop_event.is_set():
        try:
            data = source.recv(BUFFER_SIZE)
            if not data:
                break   # Connection closed cleanly

            # Pass through modification hook
            data = handler(data)

            # Display hexdump
            hexdump(data, label)

            # Forward to destination
            destination.sendall(data)

        except socket.timeout:
            continue    # No data yet - keep waiting

        except OSError:
            break       # Socket closed or error - stop relay

    stop_event.set()    # Signal the other relay thread to stop too


# ---------------------------------------------------------------------------
# Connection handler
# ---------------------------------------------------------------------------

def handle_connection(
    client_socket: socket.socket,
    remote_host: str,
    remote_port: int,
    receive_first: bool,
) -> None:
    """
    Handle a single proxied connection.

    Opens a connection to the remote server, optionally reads the
    server's banner first, then starts two relay threads for
    bidirectional forwarding.

    Parameters
    ----------
    client_socket : socket   The connected client socket.
    remote_host   : str      Hostname or IP of the real server.
    remote_port   : int      Port of the real server.
    receive_first : bool     If True, read server banner before
                             relaying - useful for protocols that
                             send a greeting on connect (FTP, SMTP,
                             SSH, POP3).
    """
    # Connect to the real remote server
    try:
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.settimeout(SOCKET_TIMEOUT)
        remote_socket.connect((remote_host, remote_port))
        print(f"  [+] Connected to remote {remote_host}:{remote_port}")
    except OSError as exc:
        print(f"  [!] Could not connect to {remote_host}:{remote_port} - {exc}")
        client_socket.close()
        return

    client_socket.settimeout(SOCKET_TIMEOUT)

    # Some protocols send a banner immediately on connect
    # (FTP: 220 ready, SMTP: 220 mail server, SSH: SSH-2.0-...)
    # Read this before starting the relay so the client sees it
    if receive_first:
        try:
            banner = remote_socket.recv(BUFFER_SIZE)
            if banner:
                hexdump(banner, "Server -> Client (banner)")
                client_socket.sendall(response_handler(banner))
        except OSError as exc:
            print(f"  [!] Could not read banner: {exc}")

    # Shared event to stop both relay threads when either side closes
    stop_event = threading.Event()

    # Client -> Server relay thread
    client_thread = threading.Thread(
        target=relay,
        args=(
            client_socket,
            remote_socket,
            request_handler,
            "Client -> Server",
            stop_event,
        ),
        daemon=True,
    )

    # Server -> Client relay thread
    server_thread = threading.Thread(
        target=relay,
        args=(
            remote_socket,
            client_socket,
            response_handler,
            "Server -> Client",
            stop_event,
        ),
        daemon=True,
    )

    client_thread.start()
    server_thread.start()

    # Wait for either side to close
    stop_event.wait()

    # Clean up both sockets
    try:
        client_socket.close()
    except OSError:
        pass
    try:
        remote_socket.close()
    except OSError:
        pass

    print(f"  [*] Connection to {remote_host}:{remote_port} closed.")


# ---------------------------------------------------------------------------
# Proxy server
# ---------------------------------------------------------------------------

def run_proxy(
    local_host: str,
    local_port: int,
    remote_host: str,
    remote_port: int,
    receive_first: bool,
) -> None:
    """
    Bind to local_host:local_port and proxy all connections to
    remote_host:remote_port.

    SO_REUSEADDR prevents address already in use errors when
    restarting the proxy quickly after stopping it.

    Parameters
    ----------
    local_host    : str    Local address to bind to.
    local_port    : int    Local port to listen on.
    remote_host   : str    Real server hostname or IP.
    remote_port   : int    Real server port.
    receive_first : bool   Read server banner before relaying.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((local_host, local_port))
    except OSError as exc:
        print(f"  [!] Could not bind to {local_host}:{local_port} - {exc}")
        return

    server.listen(5)
    print(f"\n  [*] Proxy listening on {local_host}:{local_port}")
    print(f"  [*] Forwarding to {remote_host}:{remote_port}")
    print(f"  [*] Ctrl+C to stop\n")

    try:
        while True:
            client_socket, address = server.accept()
            print(f"\n  [+] Incoming connection from {address[0]}:{address[1]}")

            proxy_thread = threading.Thread(
                target=handle_connection,
                args=(
                    client_socket,
                    remote_host,
                    remote_port,
                    receive_first,
                ),
                daemon=True,
            )
            proxy_thread.start()

    except KeyboardInterrupt:
        print("\n\n  [*] Proxy stopped.")
    finally:
        server.close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Collect proxy configuration and start the proxy server.

    Prompts for:
      - Local bind address and port
      - Remote host and port to forward to
      - Whether to read the server banner before relaying
    """
    print("\n  TCP Proxy")
    print("  " + "-" * 9)
    print("  [!] EDUCATIONAL USE ONLY.")
    print("  [!] Only proxy traffic on networks you own or are authorised to test.")
    print("  [*] Enter 0 at any prompt to cancel.\n")

    # --- Local bind address ---
    local_host = input("  Local bind address [0.0.0.0]: ").strip()
    if local_host == "0":
        return
    local_host = local_host or "0.0.0.0"

    # --- Local port ---
    raw_local_port = input("  Local port [9999]: ").strip()
    if raw_local_port == "0":
        return
    if raw_local_port:
        if not raw_local_port.isdigit():
            print("  [!] Port must be a number.")
            return
        local_port = int(raw_local_port)
        if not (1 <= local_port <= 65535):
            print("  [!] Port must be between 1 and 65535.")
            return
    else:
        local_port = 9999

    # --- Remote host ---
    remote_host = input("  Remote host to forward to: ").strip()
    if not remote_host or remote_host == "0":
        return

    # --- Remote port ---
    raw_remote_port = input("  Remote port: ").strip()
    if raw_remote_port == "0":
        return
    if not raw_remote_port.isdigit():
        print("  [!] Port must be a number.")
        return
    remote_port = int(raw_remote_port)
    if not (1 <= remote_port <= 65535):
        print("  [!] Port must be between 1 and 65535.")
        return

    # --- Receive first ---
    print("\n  Receive banner first?")
    print("  Say yes for protocols that greet on connect:")
    print("  FTP (21), SMTP (25), SSH (22), POP3 (110)")
    raw_rf = input("  Receive server banner first? (y/n) [n]: ").strip().lower()
    if raw_rf == "0":
        return
    receive_first = raw_rf == "y"

    # --- Summary ---
    print(f"\n  Proxy summary:")
    print(f"    Listen  : {local_host}:{local_port}")
    print(f"    Forward : {remote_host}:{remote_port}")
    print(f"    Banner  : {'yes' if receive_first else 'no'}")

    confirm = input("\n  Start proxy? (y/n): ").strip().lower()
    if confirm != "y":
        print("  Cancelled.")
        return

    run_proxy(local_host, local_port, remote_host, remote_port, receive_first)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()