# topic: SSH Tools
# title: Reverse SSH Tunnel
# priority: 4

"""
reverse_ssh_tunnel.py - Reverse SSH Port Forwarding Tunnel
============================================================
Connects to a remote SSH server and requests reverse port forwarding,
tunnelling traffic from a port on the remote server back through the
SSH connection to a local service.

HOW IT WORKS
-------------
Normal SSH port forwarding (local):
  ssh -L 8080:localhost:80 user@server
  Opens port 8080 locally, forwards to port 80 on the server.
  Useful for accessing remote services locally.

Reverse SSH port forwarding (what this module does):
  ssh -R 8080:localhost:80 user@server
  Opens port 8080 on the SERVER, forwards back to port 80 locally.
  Useful for exposing local services through a remote server.

ATTACK / PENTEST USE CASES
----------------------------
Scenario: You have code execution on a target behind a firewall.
The firewall blocks all inbound connections but allows outbound SSH.

  1. Target runs this module, connecting outbound to your server
  2. Your server now has a port open that forwards to the target
  3. You connect to that port on your server
  4. Traffic is tunnelled back through SSH to the target's local network
  5. You now have access to internal services behind the firewall

This is called a reverse tunnel or reverse port forward and is
a standard technique in penetration testing for pivoting into
internal networks.

LEGITIMATE USE CASES
---------------------
  - Expose a local development server to a remote tester
  - Access a home machine behind NAT/firewall from anywhere
  - Provide temporary remote access without opening firewall ports
  - Bypass CGNAT (carrier-grade NAT) that blocks inbound connections

DEFENCES
---------
  - Disable GatewayPorts on SSH servers (prevents remote forwarding)
  - Egress filtering on outbound SSH
  - Network monitoring for unusual SSH connections
  - Jump host / bastion host controls

WINDOWS NOTE
-------------
Works identically on Windows and Linux - Paramiko handles the
SSH transport layer cross-platform.

EDUCATIONAL USE ONLY.
Only use against systems and networks you own or have explicit
written permission to test.

Requirements:
    pip install paramiko
"""

import os
import sys
import socket
import select
import threading
import getpass
from typing import Optional

IS_WINDOWS = os.name == "nt"

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_SSH_PORT    = 22
DEFAULT_REMOTE_PORT = 8080    # Port opened on the remote SSH server
DEFAULT_LOCAL_HOST  = "127.0.0.1"
DEFAULT_LOCAL_PORT  = 80      # Local service to forward to
CONNECT_TIMEOUT     = 10      # SSH connection timeout in seconds
TUNNEL_TIMEOUT      = 1.0     # select() timeout for clean shutdown
BUFFER_SIZE         = 1024    # Bytes per relay read


# ---------------------------------------------------------------------------
# Port forwarding handler
# ---------------------------------------------------------------------------

def handle_forward(
    channel: paramiko.Channel,
    local_host: str,
    local_port: int,
    stop_event: threading.Event,
) -> None:
    """
    Relay data between an SSH channel and a local TCP service.

    Called in a thread for each incoming connection on the remote
    forwarded port. Opens a connection to the local service and
    relays data bidirectionally until either side closes.

    select() is used with TUNNEL_TIMEOUT so the loop checks
    stop_event regularly and exits cleanly when the tunnel stops.

    Parameters
    ----------
    channel    : paramiko.Channel   Incoming channel from remote server.
    local_host : str                Local service hostname.
    local_port : int                Local service port.
    stop_event : threading.Event    Signals this thread to stop.
    """
    # Connect to the local service being exposed
    try:
        local_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        local_sock.connect((local_host, local_port))
    except OSError as exc:
        print(f"  [!] Could not connect to local {local_host}:{local_port} - {exc}")
        channel.close()
        return

    print(f"  [+] Forwarding connection to {local_host}:{local_port}")

    try:
        while not stop_event.is_set():
            # select() monitors both sockets simultaneously with a timeout
            # so we can check stop_event without blocking forever
            readable, _, _ = select.select(
                [channel, local_sock],
                [],
                [],
                TUNNEL_TIMEOUT,
            )

            if channel in readable:
                data = channel.recv(BUFFER_SIZE)
                if not data:
                    break
                local_sock.sendall(data)

            if local_sock in readable:
                data = local_sock.recv(BUFFER_SIZE)
                if not data:
                    break
                channel.sendall(data)

    except OSError:
        pass    # Socket closed - normal exit

    finally:
        local_sock.close()
        channel.close()


# ---------------------------------------------------------------------------
# Tunnel listener
# ---------------------------------------------------------------------------

def run_tunnel_listener(
    transport: paramiko.Transport,
    local_host: str,
    local_port: int,
    remote_port: int,
    stop_event: threading.Event,
) -> None:
    """
    Accept incoming channels on the remote forwarded port and
    spawn a handler thread for each one.

    transport.accept() blocks until a new channel arrives or the
    transport closes. Each accepted channel represents one incoming
    connection to the remote forwarded port.

    Parameters
    ----------
    transport   : paramiko.Transport   Active SSH transport.
    local_host  : str                  Local service to forward to.
    local_port  : int                  Local service port.
    remote_port : int                  Port opened on remote server.
    stop_event  : threading.Event      Signals this thread to stop.
    """
    while not stop_event.is_set():
        channel = transport.accept(timeout=1)
        if channel is None:
            continue    # Timeout - check stop_event and loop

        print(f"  [+] Incoming connection on remote port {remote_port}")

        handler = threading.Thread(
            target=handle_forward,
            args=(channel, local_host, local_port, stop_event),
            daemon=True,
        )
        handler.start()


# ---------------------------------------------------------------------------
# Core tunnel
# ---------------------------------------------------------------------------

def run_reverse_tunnel(
    ssh_host: str,
    ssh_port: int,
    username: str,
    password: str,
    remote_port: int,
    local_host: str,
    local_port: int,
) -> None:
    """
    Connect to an SSH server and establish a reverse port forward.

    Uses Paramiko's request_port_forward() to ask the SSH server to
    open remote_port and forward all connections back to us through
    the SSH transport.

    This is equivalent to running:
        ssh -R remote_port:local_host:local_port user@ssh_host

    The tunnel runs until Ctrl+C. On exit, cancel_port_forward()
    tells the server to close the remote port cleanly.

    Parameters
    ----------
    ssh_host    : str   SSH server hostname or IP.
    ssh_port    : int   SSH server port.
    username    : str   SSH username.
    password    : str   SSH password.
    remote_port : int   Port to open on the remote SSH server.
    local_host  : str   Local service hostname to forward to.
    local_port  : int   Local service port to forward to.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        print(f"  [*] Connecting to SSH server {ssh_host}:{ssh_port}...")
        client.connect(
            hostname=ssh_host,
            port=ssh_port,
            username=username,
            password=password,
            timeout=CONNECT_TIMEOUT,
            allow_agent=False,
            look_for_keys=False,
        )
        print(f"  [+] Connected.")

    except paramiko.AuthenticationException:
        print(f"  [!] Authentication failed for {username}@{ssh_host}")
        return

    except paramiko.SSHException as exc:
        print(f"  [!] SSH error: {exc}")
        return

    except OSError as exc:
        print(f"  [!] Network error: {exc}")
        if IS_WINDOWS and "10061" in str(exc):
            print(f"      Connection refused - is SSH running on {ssh_host}:{ssh_port}?")
        return

    transport = client.get_transport()

    # Request the server to open remote_port and forward connections back
    try:
        transport.request_port_forward("", remote_port)
        print(f"  [+] Reverse tunnel established.")
        print(f"  [*] Remote port {remote_port} on {ssh_host} forwards to "
              f"{local_host}:{local_port}")
        print(f"  [*] Ctrl+C to stop\n")

    except paramiko.SSHException as exc:
        print(f"  [!] Port forwarding request failed: {exc}")
        print(f"      Check that GatewayPorts is enabled on the SSH server.")
        client.close()
        return

    stop_event = threading.Event()

    # Start listener thread to accept incoming forwarded connections
    listener = threading.Thread(
        target=run_tunnel_listener,
        args=(transport, local_host, local_port, remote_port, stop_event),
        daemon=True,
    )
    listener.start()

    try:
        # Keep the main thread alive while the tunnel runs
        while transport.is_active():
            import time
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n\n  [*] Stopping tunnel...")

    finally:
        stop_event.set()

        # Cancel the remote port forward cleanly
        try:
            transport.cancel_port_forward("", remote_port)
            print(f"  [*] Remote port {remote_port} closed.")
        except Exception:
            pass

        client.close()
        print("  [*] Tunnel closed.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Collect tunnel configuration and establish the reverse SSH tunnel.
    """
    print("\n  Reverse SSH Tunnel")
    print("  " + "-" * 18)
    print("  [!] EDUCATIONAL USE ONLY.")
    print("  [!] Only use on networks you own or are authorised to test.")
    print("  [*] Enter 0 at any prompt to cancel.\n")

    if not PARAMIKO_AVAILABLE:
        print("  [!] Paramiko is not installed.")
        print("      Run: pip install paramiko")
        return

    print("  This module connects to a remote SSH server and opens a port")
    print("  on that server that forwards traffic back to a local service.\n")

    # --- SSH server ---
    ssh_host = input("  SSH server host (IP or hostname): ").strip()
    if not ssh_host or ssh_host == "0":
        return

    raw_ssh_port = input(f"  SSH server port [{DEFAULT_SSH_PORT}]: ").strip()
    if raw_ssh_port == "0":
        return
    if raw_ssh_port:
        if not raw_ssh_port.isdigit():
            print("  [!] Port must be a number.")
            return
        ssh_port = int(raw_ssh_port)
        if not (1 <= ssh_port <= 65535):
            print("  [!] Port must be between 1 and 65535.")
            return
    else:
        ssh_port = DEFAULT_SSH_PORT

    # --- SSH credentials ---
    username = input("  SSH username: ").strip()
    if not username or username == "0":
        return

    try:
        password = getpass.getpass("  SSH password: ")
    except (KeyboardInterrupt, EOFError):
        print("\n  Cancelled.")
        return

    if not password:
        print("  [!] Password cannot be empty.")
        return

    # --- Remote port ---
    print(f"\n  Remote port: port to open on the SSH server.")
    raw_remote = input(f"  Remote port [{DEFAULT_REMOTE_PORT}]: ").strip()
    if raw_remote == "0":
        return
    if raw_remote:
        if not raw_remote.isdigit():
            print("  [!] Port must be a number.")
            return
        remote_port = int(raw_remote)
        if not (1 <= remote_port <= 65535):
            print("  [!] Port must be between 1 and 65535.")
            return
    else:
        remote_port = DEFAULT_REMOTE_PORT

    # --- Local service ---
    print(f"\n  Local service: the service on this machine to expose.")
    local_host = input(f"  Local host [{DEFAULT_LOCAL_HOST}]: ").strip()
    if local_host == "0":
        return
    local_host = local_host or DEFAULT_LOCAL_HOST

    raw_local = input(f"  Local port [{DEFAULT_LOCAL_PORT}]: ").strip()
    if raw_local == "0":
        return
    if raw_local:
        if not raw_local.isdigit():
            print("  [!] Port must be a number.")
            return
        local_port = int(raw_local)
        if not (1 <= local_port <= 65535):
            print("  [!] Port must be between 1 and 65535.")
            return
    else:
        local_port = DEFAULT_LOCAL_PORT

    # --- Summary ---
    print(f"\n  Tunnel summary:")
    print(f"    SSH server  : {ssh_host}:{ssh_port}")
    print(f"    Remote port : {remote_port} (opened on {ssh_host})")
    print(f"    Local target: {local_host}:{local_port}")
    print(f"\n  Traffic flow:")
    print(f"    {ssh_host}:{remote_port} -> SSH tunnel -> {local_host}:{local_port}")

    confirm = input("\n  Start tunnel? (y/n): ").strip().lower()
    if confirm != "y":
        print("  Cancelled.")
        return

    run_reverse_tunnel(
        ssh_host, ssh_port,
        username, password,
        remote_port,
        local_host, local_port,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()