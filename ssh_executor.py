# topic: SSH Tools
# title: SSH Command Executor
# priority: 2

"""
ssh_executor.py - SSH Command Executor
========================================
Connects to a remote SSH server and executes a single command,
returning the output to the local terminal.

HOW IT WORKS
-------------
1. Connect to the remote host using Paramiko's SSHClient
2. Authenticate with username and password
3. Execute a single command via exec_command()
4. Read stdout and stderr and display the results
5. Close the connection cleanly

This is the standard SSH client pattern - the same thing that
happens when you run:
    ssh user@host "command"

USE CASES IN SECURITY
----------------------
  - Remote enumeration   : gather system info from a target
  - Post-exploitation    : run commands after gaining credentials
  - Automated admin      : run commands across multiple hosts
  - CTF challenges       : interact with remote SSH services

PARAMIKO vs SUBPROCESS
-----------------------
We use Paramiko (a pure Python SSH implementation) rather than
subprocess(['ssh', ...]) for several reasons:
  - Works on Windows without OpenSSH installed
  - Gives programmatic access to stdout/stderr separately
  - Allows credential handling without shell interaction
  - Enables building more complex SSH tooling (see other modules)

KNOWN SECURITY RISK - AutoAddPolicy
-------------------------------------
AutoAddPolicy() automatically accepts any host key without
verification. This is vulnerable to man-in-the-middle attacks -
an attacker could intercept the connection and present a fake
host key. In production use RejectPolicy and maintain a known
hosts file. AutoAddPolicy is acceptable in isolated lab
environments where MITM is not a concern.

EDUCATIONAL USE ONLY.
Only connect to hosts you own or have explicit permission to access.
Unauthorised SSH access is illegal in most jurisdictions.

Requirements:
    pip install paramiko
"""

import os
import sys
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
CONNECT_TIMEOUT = 10    # Seconds before connection attempt times out
RECV_TIMEOUT    = 30    # Seconds to wait for command output


# ---------------------------------------------------------------------------
# Core function
# ---------------------------------------------------------------------------

def execute_ssh_command(
    host: str,
    port: int,
    username: str,
    password: str,
    command: str,
) -> Optional[str]:
    """
    Connect to an SSH server and execute a single command.

    exec_command() opens a new channel on the existing SSH transport
    and runs the command in a non-interactive shell. It returns three
    streams: stdin, stdout, stderr. We read stdout and stderr
    separately so we can display them distinctly.

    rstrip() is used instead of strip() on command output to preserve
    leading whitespace in output (e.g. indented code or formatted
    tables) while removing trailing newlines.

    Parameters
    ----------
    host     : str   Target hostname or IP address.
    port     : int   SSH port (default 22).
    username : str   SSH username.
    password : str   SSH password.
    command  : str   Shell command to execute on the remote host.

    Returns
    -------
    Command output as a string, or None on failure.
    """
    client = paramiko.SSHClient()

    # AutoAddPolicy accepts any host key - see module docstring for risk
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        print(f"  [*] Connecting to {host}:{port} as {username}...")
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=CONNECT_TIMEOUT,
            allow_agent=False,      # Don't use local SSH agent
            look_for_keys=False,    # Don't look for local key files
        )
        print(f"  [+] Connected.")

    except paramiko.AuthenticationException:
        print(f"  [!] Authentication failed for {username}@{host}")
        print(f"      Check username and password.")
        return None

    except paramiko.SSHException as exc:
        print(f"  [!] SSH error: {exc}")
        return None

    except OSError as exc:
        print(f"  [!] Network error: {exc}")
        if IS_WINDOWS and "10061" in str(exc):
            print(f"      Connection refused - is SSH running on port {port}?")
        return None

    try:
        print(f"  [*] Executing: {command}")
        stdin, stdout, stderr = client.exec_command(
            command,
            timeout=RECV_TIMEOUT,
        )

        # Read output streams
        # rstrip() preserves leading whitespace (indentation)
        # while removing trailing newlines
        output = stdout.read().decode("utf-8", errors="replace").rstrip()
        errors = stderr.read().decode("utf-8", errors="replace").rstrip()

        return output, errors

    except paramiko.SSHException as exc:
        print(f"  [!] Command execution error: {exc}")
        return None

    finally:
        client.close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Prompt for SSH credentials and command, execute, display output.
    """
    print("\n  SSH Command Executor")
    print("  " + "-" * 20)
    print("  [!] EDUCATIONAL USE ONLY.")
    print("  [!] Only connect to hosts you own or are authorised to access.")
    print("  [*] Enter 0 at any prompt to cancel.\n")

    if not PARAMIKO_AVAILABLE:
        print("  [!] Paramiko is not installed.")
        print("      Run: pip install paramiko")
        return

    # --- Host ---
    host = input("  Target host (IP or hostname): ").strip()
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

    # --- Command loop ---
    print(f"\n  [*] Connected to {host}:{port} as {username}")
    print(f"  [*] Enter commands to execute. Enter 0 to disconnect.\n")

    while True:
        command = input("  Command: ").strip()
        if not command or command == "0":
            print("  Disconnecting...")
            break

        result = execute_ssh_command(
            host, port, username, password, command
        )

        if result is not None:
            output, errors = result

            if output:
                print(f"\n  [+] Output:\n")
                print("  " + "-" * 40)
                for line in output.splitlines():
                    print(f"  {line}")
                print("  " + "-" * 40)

            if errors:
                print(f"\n  [!] Stderr:\n")
                for line in errors.splitlines():
                    print(f"  {line}")

            if not output and not errors:
                print("  [*] Command executed with no output.")

        print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()