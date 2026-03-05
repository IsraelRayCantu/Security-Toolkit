"""
toolkit.py - Security Toolkit Launcher
=======================================
A dynamic, metadata-driven module loader for a mixed security toolkit.
Modules are discovered automatically, grouped by topic, and ordered by
priority - all defined in each module's header comments.

Author : Israel Cantu
Version: 2.0.0
Python : 3.8+
Platform: Windows 11, Kali Linux, Ubuntu, macOS

HOW TO ADD A NEW MODULE
-----------------------
Create a .py file in the same directory and add these three header lines:

    # topic: Cryptography
    # title: Caesar Cipher Tool
    # priority: 2

The launcher will pick it up automatically on the next run.

WINDOWS USERS
-------------
Raw socket modules (Packet Sniffer, ARP Spoofer, MAC Flooder, Port
Scanner SYN/UDP) require Npcap installed:
    https://npcap.com
    Install with WinPcap API-compatible mode checked.

Run the launcher from an Administrator PowerShell or Command Prompt
for any module that requires elevated privileges.
"""

import importlib.util
import os
import sys
import logging
import subprocess
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    filename="toolkit.log",
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)s]  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------
IS_WINDOWS = os.name == "nt"

def get_base_dir() -> Path:
    """
    Return the correct base directory whether running as a
    script or as a PyInstaller bundled exe.

    When bundled with --onefile, sys._MEIPASS points to the
    temporary extraction directory where bundled files live.
    When running as a normal script, use the script's directory.
    """
    if getattr(sys, "frozen", False):
        # Running as PyInstaller exe
        return Path(sys._MEIPASS)
    else:
        # Running as normal Python script
        return Path(__file__).resolve().parent
    
IS_LINUX   = sys.platform.startswith("linux")
IS_MACOS   = sys.platform == "darwin"

# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------

def _enable_windows_ansi() -> bool:
    """
    Enable ANSI escape code processing on Windows 10+.

    Windows console does not process ANSI codes by default.
    We enable virtual terminal processing via the Win32 API.
    Returns True if successful, False if unavailable.
    """
    if not IS_WINDOWS:
        return True
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(
            kernel32.GetStdHandle(-11),
            7,
        )
        return True
    except Exception:
        return False

_USE_COLOUR = sys.stdout.isatty() and _enable_windows_ansi()

GREEN  = "\033[92m" if _USE_COLOUR else ""
YELLOW = "\033[93m" if _USE_COLOUR else ""
CYAN   = "\033[96m" if _USE_COLOUR else ""
BOLD   = "\033[1m"  if _USE_COLOUR else ""
RESET  = "\033[0m"  if _USE_COLOUR else ""

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
EXIT_CODE          = 99
DEFAULT_PRIORITY   = 99
SUBPROCESS_TIMEOUT = 300
REQUIREMENTS_FILE  = Path(__file__).resolve().parent / "requirements.txt"

PACKAGE_DESCRIPTIONS = {
    "paramiko": "SSH client and server implementation",
    "scapy":    "Packet crafting, sniffing, and network analysis",
    "pywin32":  "Windows Event Log access (Log Analyser - Windows only)",
}

NPCAP_URL = "https://npcap.com"


# ---------------------------------------------------------------------------
# Console helpers
# ---------------------------------------------------------------------------

def clear_console() -> None:
    """Clear the terminal on both Windows and Unix-based systems."""
    os.system("cls" if IS_WINDOWS else "clear")


def print_banner() -> None:
    """Print the toolkit banner with platform indicator."""
    platform_str = (
        "Windows 11" if IS_WINDOWS else
        "Kali Linux" if IS_LINUX   else
        "macOS"      if IS_MACOS   else
        "Unknown OS"
    )
    print(f"""
{BOLD}{GREEN}\
  +======================================+
  |        Security Toolkit  v2.0        |
  |        Platform: {platform_str:<20}|
  +======================================+\
{RESET}
""")


# ---------------------------------------------------------------------------
# Dependency management
# ---------------------------------------------------------------------------

def parse_requirements(requirements_path: Path) -> list:
    """
    Read requirements.txt and return a list of (package_name, version) tuples.

    Skips blank lines, comment lines, and platform-specific entries that
    do not apply to the current platform.

    Parameters
    ----------
    requirements_path : Path
        Path to the requirements.txt file.

    Returns
    -------
    List of (package_name, version_string) tuples for this platform.
    """
    if not requirements_path.exists():
        logger.warning("requirements.txt not found at %s", requirements_path)
        return []

    packages = []

    with requirements_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            original = line

            line = line.split("#")[0].strip()
            if not line:
                continue

            lower_original = original.lower()
            if "[windows-only]" in lower_original and not IS_WINDOWS:
                continue
            if "[linux-only]" in lower_original and not IS_LINUX:
                continue

            if "==" in line:
                name, _, version = line.partition("==")
                packages.append((name.strip(), version.strip()))
            else:
                packages.append((line.strip(), ""))

    return packages


def check_npcap_windows() -> None:
    """
    On Windows, check if Npcap is installed and warn if not.

    Npcap is required for raw socket modules. This is advisory only -
    we do not block the toolkit if Npcap is missing since most modules
    work fine without it.
    """
    if not IS_WINDOWS:
        return

    npcap_installed = False

    try:
        result = subprocess.run(
            ["sc", "query", "npcap"],
            capture_output=True,
            text=True,
            shell=False,
            timeout=5,
        )
        npcap_installed = result.returncode == 0
    except Exception:
        pass

    if not npcap_installed:
        print(f"\n  {YELLOW}[!] Npcap does not appear to be installed.{RESET}")
        print(f"      Raw socket modules require Npcap on Windows:")
        print(f"      {CYAN}{NPCAP_URL}{RESET}")
        print(f"      Install with WinPcap API-compatible mode checked.\n")
        print(f"      Affected modules: Packet Sniffer, ARP Spoofer,")
        print(f"      MAC Flooder, Port Scanner (SYN/UDP modes)\n")
        input("      Press Enter to continue anyway...")
    else:
        logger.info("Npcap detected on Windows.")


def check_and_install_dependencies() -> bool:
    """
    Check all packages in requirements.txt and offer to install missing ones.

    Flow:
      1. Parse requirements.txt with platform awareness
      2. Check each package with importlib.util.find_spec()
      3. If nothing missing, continue silently
      4. Display missing packages and ask user whether to install
      5. Install via pip using sys.executable
      6. On Windows, additionally check for Npcap

    Returns
    -------
    True to continue launching the toolkit.
    False if user chose to abort.
    """
    packages = parse_requirements(REQUIREMENTS_FILE)
    if not packages:
        check_npcap_windows()
        return True

    missing = []
    for name, version in packages:
        check_name = "win32api" if name == "pywin32" else name
        spec = importlib.util.find_spec(check_name)
        if spec is None:
            missing.append((name, version))

    if not missing:
        logger.info("All dependencies satisfied.")
        check_npcap_windows()
        return True

    print(f"  {YELLOW}[*] Checking dependencies...{RESET}\n")
    print(f"  {YELLOW}The following packages are not installed:{RESET}\n")

    for name, version in missing:
        description = PACKAGE_DESCRIPTIONS.get(name, "required library")
        pin         = f"=={version}" if version else ""
        print(f"    {CYAN}*  {name}{pin}{RESET}  -  {description}")

    print()

    try:
        answer = input("  Install them now? (y/n): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\n  Skipping install.")
        check_npcap_windows()
        return True

    if answer != "y":
        print(
            f"\n  {YELLOW}[!] Skipping install. Some modules may not work "
            f"without their dependencies.{RESET}\n"
        )
        input("  Press Enter to continue to the toolkit anyway...")
        check_npcap_windows()
        return True

    print()
    success = []
    failed  = []

    for name, version in missing:
        pin     = f"=={version}" if version else ""
        package = f"{name}{pin}"
        print(f"  [*] Installing {package}...")

        try:
            result = subprocess.run(
                [
                    sys.executable, "-m", "pip", "install",
                    package,
                    "--quiet",
                    "--disable-pip-version-check",
                ],
                shell=False,
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode == 0:
                print(f"  {GREEN}[+] {name} installed successfully.{RESET}")
                logger.info("Installed: %s", package)
                success.append(name)
            else:
                print(f"  {YELLOW}[!] Failed to install {name}:{RESET}")
                print(f"      {result.stderr.strip()}")
                logger.error("pip failed for %s: %s", package, result.stderr.strip())
                failed.append(name)

        except subprocess.TimeoutExpired:
            print(f"  {YELLOW}[!] Install timed out for {name}.{RESET}")
            logger.warning("Install timeout for %s", name)
            failed.append(name)

        except Exception as exc:
            print(f"  {YELLOW}[!] Unexpected error installing {name}: {exc}{RESET}")
            logger.error("Install error for %s: %s", name, exc)
            failed.append(name)

    print()
    if failed:
        print(
            f"  {YELLOW}[!] {len(failed)} package(s) could not be installed: "
            f"{', '.join(failed)}{RESET}"
        )
        print("      Modules that depend on them will not work correctly.\n")
    if success:
        print(f"  {GREEN}[+] {len(success)} package(s) installed successfully.{RESET}\n")

    input("  Press Enter to continue...")
    check_npcap_windows()
    return True


# ---------------------------------------------------------------------------
# Module discovery and metadata parsing
# ---------------------------------------------------------------------------

def parse_module_headers(filepath: Path) -> dict:
    """
    Read the metadata header from a module file and return it as a dict.

    Expected format - first lines of the file must be comments:
        # topic: Network Recon
        # title: Port Scanner
        # priority: 1

    Any missing or malformed field falls back to a safe default so the
    launcher never crashes because of a badly written module.

    Parameters
    ----------
    filepath : Path
        Path to the .py module file to read.

    Returns
    -------
    dict with keys: topic, title, priority, file
    """
    metadata = {
        "topic":    "Uncategorised",
        "title":    filepath.stem.replace("_", " ").title(),
        "priority": DEFAULT_PRIORITY,
        "file":     filepath,
    }

    try:
        with filepath.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line.startswith("#"):
                    break
                if ": " not in line:
                    continue

                _, _, rest = line.partition("# ")
                key, _, value = rest.partition(": ")
                key   = key.strip().lower()
                value = value.strip()

                if key == "topic":
                    metadata["topic"] = value
                elif key == "title":
                    metadata["title"] = value
                elif key == "priority":
                    try:
                        metadata["priority"] = int(value)
                    except ValueError:
                        logger.warning(
                            "Non-integer priority in %s - using default (%d).",
                            filepath.name, DEFAULT_PRIORITY,
                        )

    except OSError as exc:
        logger.error("Could not read %s: %s", filepath.name, exc)

    return metadata


def discover_modules(directory: Path) -> list:
    """
    Find all .py files in directory (excluding the launcher itself) and
    return a list of their parsed metadata dicts.

    Security note: each path is resolved and checked to confirm it lives
    inside the toolkit directory - blocks symlink-based path traversal.

    Parameters
    ----------
    directory : Path
        The folder to scan - typically the toolkit's own directory.

    Returns
    -------
    List of metadata dicts, one per valid module found.
    """
    launcher_name = Path(__file__).resolve().name
    resolved_dir  = directory.resolve()
    modules       = []

    for entry in directory.iterdir():
        if entry.suffix != ".py" or entry.name == launcher_name:
            continue

        try:
            resolved_entry = entry.resolve()
            resolved_entry.relative_to(resolved_dir)
        except ValueError:
            logger.warning(
                "Skipping %s - resolves outside toolkit directory.",
                entry.name,
            )
            continue

        modules.append(parse_module_headers(resolved_entry))
        logger.info("Discovered module: %s", entry.name)

    return modules


def group_and_sort_modules(modules: list) -> dict:
    """
    Group modules by topic and sort each group by (priority, title).

    Parameters
    ----------
    modules : list of dicts returned by discover_modules()

    Returns
    -------
    dict mapping topic name to sorted list of module metadata dicts.
    """
    topics: dict = {}

    for module in modules:
        topic = module["topic"]
        topics.setdefault(topic, []).append(module)

    for topic in topics:
        topics[topic].sort(key=lambda m: (m["priority"], m["title"].lower()))

    return dict(sorted(topics.items()))


# ---------------------------------------------------------------------------
# Menu rendering
# ---------------------------------------------------------------------------

def render_menu(topics: dict) -> dict:
    """
    Print the numbered interactive menu and return an option to Path mapping.

    Parameters
    ----------
    topics : dict from group_and_sort_modules()

    Returns
    -------
    dict mapping displayed option number (int) to the module Path.
    """
    option_number = 1
    menu_map: dict = {}

    for topic, modules in topics.items():
        print(f"  {GREEN}{BOLD}{topic}{RESET}")
        for module in modules:
            print(f"    {CYAN}{option_number:>2}.{RESET}  {module['title']}")
            menu_map[option_number] = module["file"]
            option_number += 1
        print()

    refresh_number = option_number
    print(f"  {YELLOW}{refresh_number:>2}.  Refresh / Back{RESET}")
    print(f"  {YELLOW}{EXIT_CODE:>2}.  Exit{RESET}\n")

    return menu_map


# ---------------------------------------------------------------------------
# Module execution
# ---------------------------------------------------------------------------

def run_module(module_path: Path) -> None:
    """
    Execute a toolkit module as a subprocess.

    Security decisions:
    - sys.executable prevents PATH hijacking
    - shell=False with list args prevents shell injection
    - timeout prevents hung modules locking the launcher
    - check=False allows non-zero exit codes

    Parameters
    ----------
    module_path : Path
        Absolute path to the .py module to execute.
    """
    logger.info("Launching module: %s", module_path.name)
    print(f"\n{BOLD}Running: {module_path.name}{RESET}")
    print("-" * 42 + "\n")

    try:
        result = subprocess.run(
            [sys.executable, str(module_path)],
            shell=False,
            timeout=SUBPROCESS_TIMEOUT,
            check=False,
        )
        if result.returncode not in (0, 1):
            logger.warning(
                "Module %s finished with exit code %d.",
                module_path.name, result.returncode,
            )

    except subprocess.TimeoutExpired:
        print(
            f"\n{YELLOW}[!] Module timed out after "
            f"{SUBPROCESS_TIMEOUT // 60} minutes and was stopped.{RESET}"
        )
        logger.warning("Module %s timed out.", module_path.name)

    except FileNotFoundError:
        print(f"\n[!] Python interpreter not found at: {sys.executable}")
        logger.error("Python interpreter missing: %s", sys.executable)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Entry point. Runs the interactive menu loop until the user exits.

    The directory is re-scanned on every iteration so newly added modules
    appear without restarting the launcher.

    Startup sequence:
      1. Clear console and show banner
      2. Check and install pip dependencies once
      3. On Windows check for Npcap
      4. Enter menu loop
    """
    toolkit_dir = get_base_dir()

    clear_console()
    print_banner()
    if not check_and_install_dependencies():
        return

    while True:
        clear_console()
        print_banner()

        raw_modules = discover_modules(toolkit_dir)

        if not raw_modules:
            print("[!] No module files found in:", toolkit_dir)
            print("    Add .py files with the required header comments to get started.\n")
            input("Press Enter to exit...")
            logger.info("Exiting - no modules found.")
            break

        topics   = group_and_sort_modules(raw_modules)
        menu_map = render_menu(topics)

        try:
            raw    = input("Select an option: ").strip()
            choice = int(raw)
        except ValueError:
            continue
        except (EOFError, KeyboardInterrupt):
            print("\n\nExiting toolkit. Stay secure!")
            logger.info("Toolkit exited via keyboard interrupt.")
            break

        if choice == EXIT_CODE:
            print("\nExiting toolkit. Stay secure!")
            logger.info("Toolkit exited normally.")
            break

        elif choice in menu_map:
            run_module(menu_map[choice])
            input("\nPress Enter to return to the menu...")

        elif choice == max(menu_map.keys(), default=0) + 1:
            continue

        else:
            print(
                f"{YELLOW}[!] Invalid choice. "
                f"Please pick a number shown in the menu.{RESET}"
            )
            import time
            time.sleep(1)


# ---------------------------------------------------------------------------
# Entry guard
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logger.info("Toolkit started on %s.", sys.platform)
    main()