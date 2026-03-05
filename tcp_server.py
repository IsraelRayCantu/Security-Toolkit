# topic: Networking
# title: TCP Server
# priority: 7

"""
tcp_server.py - Multi-Threaded TCP Server
==========================================
A general-purpose TCP server that accepts multiple concurrent client
connections, each handled in its own thread.

This is the server-side counterpart to the TCP Client module. Together
they demonstrate the full client-server communication model at the raw
socket level - the foundation that every networked application is built on.

HOW IT WORKS
-------------
1. A listening socket is bound to an IP address and port.
2. The main thread loops calling accept(), which blocks until a client
   connects.
3. Each accepted connection is handed off to a new daemon thread running
   handle_client(), so the main thread immediately returns to accept()
   and can handle the next incoming connection without waiting.
4. handle_client() reads the full message, prints it, and sends back
   an ACK.

USE CASES IN SECURITY
----------------------
  - Catching reverse shells    : a compromised machine connects back
  - Receiving exfiltrated data : capture data sent from a target
  - Firewall rule testing      : verify inbound traffic reaches a port
  - C2 listener demo           : simple command and control listener
  - Protocol testing           : pair with TCP Client module

EDUCATIONAL USE ONLY.
Only run on networks and systems you own or have permission to test.

Requirements: Python standard library only
"""

import socket
import threading
import logging
import os
import sys

IS_WINDOWS = os.name == "nt"

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_HOST   = "0.0.0.0"   # Listen on all interfaces
DEFAULT_PORT   = 9998
BACKLOG        = 5            # Max queued incoming connections
RECV_TIMEOUT   = 30           # Seconds before idle client is disconnected
BUFFER_SIZE    = 4096         # Bytes per recv() call


# ---------------------------------------------------------------------------
# Client handler
# ---------------------------------------------------------------------------

def handle_client(client_socket: socket.socket, address: tuple) -> None:
    """
    Handle communication with a single connected client.

    Reads the complete message from the client, prints it, then
    sends an ACK back.

    The with statement ensures the socket is closed when this function
    returns - even if an exception is raised mid-communication.

    A recv() timeout is set so a client that connects but never sends
    data cannot hold this thread open indefinitely.

    Parameters
    ----------
    client_socket : socket.socket
        The connected socket for this specific client.
    address : tuple
        (ip, port) of the connecting client.
    """
    with client_socket:
        client_socket.settimeout(RECV_TIMEOUT)
        data = b""

        try:
            while True:
                chunk = client_socket.recv(BUFFER_SIZE)
                if not chunk:
                    break
                data += chunk

                # Stop reading when we have less than a full buffer -
                # heuristic that works for most request/response protocols
                if len(chunk) < BUFFER_SIZE:
                    break

        except socket.timeout:
            if not data:
                print(f"  [!] {address[0]}:{address[1]} connected but sent no data.")
                logger.warning("Client %s:%d timed out with no data.", *address)
                return

        except OSError as exc:
            print(f"  [!] Receive error from {address[0]}: {exc}")
            logger.error("Recv error from %s:%d: %s", *address, exc)
            return

        if not data:
            return

        # Display received message
        try:
            decoded = data.decode("utf-8", errors="replace")
            print(f"\n  [+] Received from {address[0]}:{address[1]} "
                  f"({len(data)} bytes):")
            print("  " + "-" * 40)
            for line in decoded.splitlines():
                print(f"  {line}")
            print("  " + "-" * 40)
        except Exception:
            print(f"  [*] Received {len(data)} bytes from {address[0]}:{address[1]}")

        logger.info("Received %d bytes from %s:%d", len(data), *address)

        # Send acknowledgement
        try:
            client_socket.sendall(b"ACK\n")
            logger.info("ACK sent to %s:%d", *address)
        except OSError as exc:
            print(f"  [!] Failed to send ACK to {address[0]}: {exc}")
            logger.error("Send error to %s:%d: %s", *address, exc)


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

def run_server(host: str, port: int) -> None:
    """
    Bind to host:port and accept incoming connections until Ctrl+C.

    Each accepted connection is dispatched to handle_client() in a
    daemon thread. daemon=True means threads are killed automatically
    when the main program exits.

    SO_REUSEADDR lets the port be reused immediately after the server
    stops, avoiding the address already in use error that occurs when
    the OS holds the port in TIME_WAIT state after a socket closes.

    Parameters
    ----------
    host : str
        IP address to bind to. 0.0.0.0 listens on all interfaces.
    port : int
        Port number to listen on.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((host, port))
    except OSError as exc:
        print(f"  [!] Could not bind to {host}:{port} - {exc}")
        if IS_WINDOWS and "10048" in str(exc):
            print("  [*] Port is already in use. Try a different port.")
        logger.error("Bind failed on %s:%d: %s", host, port, exc)
        return

    server.listen(BACKLOG)
    print(f"\n  [*] TCP server listening on {host}:{port}")
    print(f"  [*] Waiting for connections - Ctrl+C to stop\n")
    logger.info("TCP server started on %s:%d", host, port)

    try:
        while True:
            try:
                client_socket, address = server.accept()
                print(f"  [+] Connection from {address[0]}:{address[1]}")
                logger.info("Accepted connection from %s:%d", *address)

                thread = threading.Thread(
                    target=handle_client,
                    args=(client_socket, address),
                    daemon=True,
                )
                thread.start()

            except socket.timeout:
                continue

    except KeyboardInterrupt:
        print("\n\n  [*] Server stopped.")
        logger.info("TCP server stopped by user.")
    finally:
        server.close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Prompt for bind address and port, then start the server.

    0.0.0.0 binds to all network interfaces simultaneously - the server
    will accept connections on any IP address assigned to this machine.
    Use a specific IP to restrict to one interface only.
    """
    print("\n  TCP Server")
    print("  " + "-" * 10)
    print("  [!] Only run on networks you own or are authorised to test.")
    print("  [*] Enter 0 at any prompt to cancel.\n")

    # --- Bind address ---
    host = input(f"  Bind address [{DEFAULT_HOST}]: ").strip()
    if host == "0":
        return
    host = host or DEFAULT_HOST

    # --- Port ---
    raw_port = input(f"  Port [{DEFAULT_PORT}]: ").strip()
    if raw_port == "0":
        return
    if raw_port:
        if not raw_port.isdigit():
            print("  [!] Port must be a number.")
            return
        port = int(raw_port)
        if not (1 <= port <= 65535):
            print("  [!] Port must be between 1 and 65535.")
            return
    else:
        port = DEFAULT_PORT

    run_server(host, port)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()