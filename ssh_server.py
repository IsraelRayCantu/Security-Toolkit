# topic: SSH Tools
# title: SSH Server with Authentication
# priority: 3

"""
ssh_server.py - Custom SSH Server
===================================
Runs a custom SSH server using Paramiko's ServerInterface.
Accepts incoming SSH client connections, handles authentication,
and provides an interactive shell channel.

HOW IT WORKS
-------------
1. Generate or load an RSA host key (identifies this server)
2. Bind a TCP socket and wait for incoming connections
3. For each connection, start an SSH Transport in server mode
4. Handle the SSH handshake and key exchange automatically
5. Validate credentials in check_auth_password()
6. Accept shell channel requests
7. Relay data between the channel and a subprocess shell

WHY BUILD A CUSTOM SSH SERVER
--------------------------------
Understanding SSH from the server side is valuable for:
  - Honeypots      : capture attacker credentials and commands
  - Protocol research : understand exactly how SSH works
  - CTF challenges : some require custom SSH server interaction
  - Security testing : test how SSH clients behave

PARAMIKO ServerInterface
--------------------------
Paramiko's ServerInterface is an abstract class that defines
callbacks the SSH transport calls during the connection lifecycle:
  check_auth_password()      - validate username/password
  check_channel_request()    - approve/deny channel open requests
  check_channel_shell_request() - approve/deny shell requests
  check_channel_pty_request()   - approve/deny PTY requests

HOST KEY
---------
The server needs an RSA host key to identify itself to clients.
If no key file exists this module generates one automatically.
The key is saved to ssh_host_key in the toolkit directory.

On first connection, SSH clients will show:
  "The authenticity of host can't be established"
This is normal for a new server - clients can accept and save
the key to their known_hosts file.

WINDOWS NOTE
-------------
Interactive shell on Windows uses cmd.exe instead of /bin/bash.
Some SSH clients may behave differently with Windows shells.

EDUCATIONAL USE ONLY.
Only run this server on networks you own or are authorised to test.
Running an SSH server on a shared network without permission may
violate network policies.

Requirements:
    pip install paramiko
"""

import os
import sys
import socket
import threading
import subprocess
import getpass
from pathlib import Path
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
DEFAULT_HOST     = "0.0.0.0"
DEFAULT_PORT     = 2222       # Use 2222 to avoid needing root for port 22
HOST_KEY_FILE    = Path(__file__).resolve().parent / "ssh_host_key"
RSA_KEY_BITS     = 2048
SHELL_TIMEOUT    = 300        # Seconds before idle shell closes
BUFFER_SIZE      = 1024       # Bytes per channel read


# ---------------------------------------------------------------------------
# SSH Server Interface
# ---------------------------------------------------------------------------

class ToolkitSSHServer(paramiko.ServerInterface):
    """
    Custom SSH server interface implementing credential validation
    and channel management.

    Paramiko calls these methods during the SSH handshake and
    session setup. We override only what we need - the base class
    denies everything by default.
    """

    def __init__(self, valid_username: str, valid_password: str) -> None:
        """
        Parameters
        ----------
        valid_username : str   Accepted SSH username.
        valid_password : str   Accepted SSH password.
        """
        self.valid_username = valid_username
        self.valid_password = valid_password
        self.shell_event    = threading.Event()

    def check_channel_request(
        self,
        kind: str,
        chanid: int,
    ) -> int:
        """
        Called when the client requests to open a channel.

        We only accept session channels - the standard channel type
        for interactive shells, command execution, and file transfer.
        Other channel types (direct-tcpip, forwarded-tcpip) are denied.

        Parameters
        ----------
        kind   : str   Channel type requested by client.
        chanid : int   Channel ID assigned by the transport.
        """
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(
        self,
        username: str,
        password: str,
    ) -> int:
        """
        Validate username and password credentials.

        Called by Paramiko when a client attempts password
        authentication. Returns AUTH_SUCCESSFUL if credentials
        match, AUTH_FAILED otherwise.

        In a real honeypot you would log all attempts here -
        both successful and failed - to capture attacker credentials.

        Parameters
        ----------
        username : str   Username provided by the client.
        password : str   Password provided by the client.
        """
        if username == self.valid_username and password == self.valid_password:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        """
        Return the authentication methods this server accepts.

        We only support password authentication - not public key,
        GSSAPI, or other methods. This simplifies the server
        implementation for educational purposes.
        """
        return "password"

    def check_channel_shell_request(self, channel) -> bool:
        """
        Called when the client requests an interactive shell.

        Setting shell_event signals the connection handler that
        the client is ready to receive shell output.
        """
        self.shell_event.set()
        return True

    def check_channel_pty_request(
        self,
        channel,
        term: str,
        width: int,
        height: int,
        pixelwidth: int,
        pixelheight: int,
        modes: bytes,
    ) -> bool:
        """
        Called when the client requests a pseudo-terminal (PTY).

        A PTY makes the shell behave as if connected to a real
        terminal - enabling interactive programs, colour output,
        and proper line editing. We accept all PTY requests.
        """
        return True


# ---------------------------------------------------------------------------
# Host key management
# ---------------------------------------------------------------------------

def load_or_generate_host_key() -> Optional[paramiko.RSAKey]:
    """
    Load the server's RSA host key from disk, or generate a new one.

    The host key is the server's identity - SSH clients use it to
    verify they are connecting to the same server on subsequent
    connections (stored in ~/.ssh/known_hosts).

    Generating the key at runtime means each fresh install gets a
    unique key. Saving it to disk means the key stays consistent
    across restarts - clients won't see a "host key changed" warning.

    Returns
    -------
    RSAKey object ready to use as the server host key, or None on error.
    """
    if HOST_KEY_FILE.exists():
        try:
            key = paramiko.RSAKey(filename=str(HOST_KEY_FILE))
            print(f"  [+] Loaded host key from {HOST_KEY_FILE.name}")
            return key
        except Exception as exc:
            print(f"  [!] Could not load host key: {exc}")
            print(f"      Generating a new one...")

    # Generate a new RSA key
    try:
        print(f"  [*] Generating {RSA_KEY_BITS}-bit RSA host key...")
        key = paramiko.RSAKey.generate(RSA_KEY_BITS)
        key.write_private_key_file(str(HOST_KEY_FILE))
        print(f"  [+] Host key saved to {HOST_KEY_FILE.name}")
        return key
    except Exception as exc:
        print(f"  [!] Could not generate host key: {exc}")
        return None


# ---------------------------------------------------------------------------
# Shell relay
# ---------------------------------------------------------------------------

def relay_shell(channel: paramiko.Channel) -> None:
    """
    Relay data between the SSH channel and a local shell process.

    Spawns a shell subprocess (cmd.exe on Windows, /bin/bash on Linux)
    and relays data bidirectionally:
      SSH channel -> shell stdin
      Shell stdout/stderr -> SSH channel

    Two daemon threads handle each direction concurrently.

    Parameters
    ----------
    channel : paramiko.Channel   The authenticated SSH session channel.
    """
    # Select shell based on platform
    shell_cmd = "cmd.exe" if IS_WINDOWS else "/bin/bash"

    try:
        shell = subprocess.Popen(
            shell_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
    except OSError as exc:
        channel.send(f"[!] Could not start shell: {exc}\n".encode())
        channel.close()
        return

    stop_event = threading.Event()

    def channel_to_shell():
        """Read from SSH channel, write to shell stdin."""
        while not stop_event.is_set():
            try:
                if channel.recv_ready():
                    data = channel.recv(BUFFER_SIZE)
                    if not data:
                        break
                    shell.stdin.write(data)
                    shell.stdin.flush()
            except OSError:
                break
        stop_event.set()

    def shell_to_channel():
        """Read from shell stdout, write to SSH channel."""
        while not stop_event.is_set():
            try:
                output = shell.stdout.read(BUFFER_SIZE)
                if not output:
                    break
                channel.send(output)
            except OSError:
                break
        stop_event.set()

    # Start relay threads
    t1 = threading.Thread(target=channel_to_shell, daemon=True)
    t2 = threading.Thread(target=shell_to_channel, daemon=True)
    t1.start()
    t2.start()

    # Wait for either side to close
    stop_event.wait(timeout=SHELL_TIMEOUT)

    # Clean up
    try:
        shell.terminate()
    except OSError:
        pass
    channel.close()


# ---------------------------------------------------------------------------
# Connection handler
# ---------------------------------------------------------------------------

def handle_connection(
    client_socket: socket.socket,
    address: tuple,
    host_key: paramiko.RSAKey,
    valid_username: str,
    valid_password: str,
) -> None:
    """
    Handle a single incoming SSH connection.

    Creates a Paramiko Transport in server mode, performs the SSH
    handshake, authenticates the client, and starts the shell relay.

    Parameters
    ----------
    client_socket  : socket    The raw TCP socket from accept().
    address        : tuple     (ip, port) of the connecting client.
    host_key       : RSAKey    Server's host key for identification.
    valid_username : str       Accepted username.
    valid_password : str       Accepted password.
    """
    print(f"  [+] Connection from {address[0]}:{address[1]}")

    transport = paramiko.Transport(client_socket)
    transport.add_server_key(host_key)

    server = ToolkitSSHServer(valid_username, valid_password)

    try:
        transport.start_server(server=server)
    except paramiko.SSHException as exc:
        print(f"  [!] SSH handshake failed with {address[0]}: {exc}")
        return

    # Wait for the client to open a channel
    channel = transport.accept(timeout=20)
    if channel is None:
        print(f"  [!] No channel opened by {address[0]}")
        transport.close()
        return

    print(f"  [+] Channel opened by {address[0]}")

    # Wait for shell request
    server.shell_event.wait(timeout=10)
    if not server.shell_event.is_set():
        print(f"  [!] Client did not request a shell.")
        channel.close()
        transport.close()
        return

    print(f"  [+] Shell requested - starting relay for {address[0]}")

    try:
        relay_shell(channel)
    finally:
        transport.close()
        print(f"  [*] Connection from {address[0]} closed.")


# ---------------------------------------------------------------------------
# Main server loop
# ---------------------------------------------------------------------------

def run_server(
    host: str,
    port: int,
    valid_username: str,
    valid_password: str,
    host_key: paramiko.RSAKey,
) -> None:
    """
    Bind to host:port and accept SSH connections until Ctrl+C.

    Each connection is handled in a daemon thread so multiple
    clients can connect simultaneously.

    Parameters
    ----------
    host           : str      Bind address.
    port           : int      Listen port.
    valid_username : str      Accepted SSH username.
    valid_password : str      Accepted SSH password.
    host_key       : RSAKey   Server host key.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((host, port))
    except OSError as exc:
        print(f"  [!] Could not bind to {host}:{port} - {exc}")
        if IS_WINDOWS and "10048" in str(exc):
            print(f"      Port {port} is already in use. Try a different port.")
        return

    server_socket.listen(5)
    print(f"\n  [*] SSH server listening on {host}:{port}")
    print(f"  [*] Connect with: ssh {valid_username}@localhost -p {port}")
    print(f"  [*] Ctrl+C to stop\n")

    try:
        while True:
            client_socket, address = server_socket.accept()

            thread = threading.Thread(
                target=handle_connection,
                args=(
                    client_socket,
                    address,
                    host_key,
                    valid_username,
                    valid_password,
                ),
                daemon=True,
            )
            thread.start()

    except KeyboardInterrupt:
        print("\n\n  [*] SSH server stopped.")
    finally:
        server_socket.close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Collect server configuration and credentials, then start the server.
    """
    print("\n  SSH Server with Authentication")
    print("  " + "-" * 30)
    print("  [!] EDUCATIONAL USE ONLY.")
    print("  [!] Only run on networks you own or are authorised to test.")
    print("  [*] Enter 0 at any prompt to cancel.\n")

    if not PARAMIKO_AVAILABLE:
        print("  [!] Paramiko is not installed.")
        print("      Run: pip install paramiko")
        return

    if IS_WINDOWS:
        print("  [*] Windows detected - shell will use cmd.exe")
        print("  [*] Some SSH clients may behave differently with Windows shells.\n")

    # --- Load or generate host key ---
    host_key = load_or_generate_host_key()
    if not host_key:
        print("  [!] Cannot start server without a host key.")
        return

    # --- Bind address ---
    host = input(f"\n  Bind address [{DEFAULT_HOST}]: ").strip()
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

    # Warn about ports below 1024 on Linux
    if not IS_WINDOWS and port < 1024:
        print(f"  [!] Ports below 1024 require root on Linux.")
        print(f"      Consider using port 2222 instead.")

    # --- Credentials ---
    print(f"\n  Set credentials for incoming SSH connections.")
    username = input("  Username: ").strip()
    if not username or username == "0":
        return

    try:
        password = getpass.getpass("  Password: ")
        confirm  = getpass.getpass("  Confirm password: ")
    except (KeyboardInterrupt, EOFError):
        print("\n  Cancelled.")
        return

    if password != confirm:
        print("  [!] Passwords do not match.")
        return

    if not password:
        print("  [!] Password cannot be empty.")
        return

    # --- Summary ---
    print(f"\n  Server summary:")
    print(f"    Bind    : {host}:{port}")
    print(f"    User    : {username}")
    print(f"    Shell   : {'cmd.exe' if IS_WINDOWS else '/bin/bash'}")
    print(f"    Key     : {HOST_KEY_FILE.name}")

    confirm_start = input("\n  Start server? (y/n): ").strip().lower()
    if confirm_start != "y":
        print("  Cancelled.")
        return

    run_server(host, port, username, password, host_key)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()