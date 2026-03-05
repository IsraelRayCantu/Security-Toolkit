# topic: Defensive Security
# title: Log Analyser
# priority: 1

"""
log_analyser.py - Security Log Analysis Tool
=============================================
Parses Linux auth logs, web server access logs, and Windows
Security Event Logs. Identifies suspicious patterns and
produces severity-classified security findings.

This is a blue team / SOC analyst tool demonstrating defensive
security concepts - the counterpart to the offensive modules.

LOG TYPES SUPPORTED
--------------------
1. Linux Auth Log (/var/log/auth.log or /var/log/secure)
   Detects:
     - Brute force attacks (repeated failed logins per IP)
     - Successful logins with source IP tracking
     - Root login attempts
     - Invalid user enumeration
     - New user account creation (persistence indicator)
     - Sudo usage (privilege escalation audit)

2. Web Server Access Log (Apache/Nginx combined log format)
   Detects:
     - Directory scanning (404 flood from single IP)
     - SQL injection attempts in request URLs
     - Path traversal attempts (../ sequences)
     - Suspicious user agents (scanners, exploit tools)
     - Server error spikes (exploitation indicators)
     - Large responses (potential data exfiltration)

3. Windows Security Event Log (Windows only)
   Detects:
     - Failed logon attempts (Event ID 4625)
     - Successful logons (Event ID 4624)
     - New user accounts (Event ID 4720)
     - Group membership changes (Event ID 4732)
     - Explicit credential use (Event ID 4648)
     - Audit log cleared (Event ID 1102) - CRITICAL

SEVERITY LEVELS
----------------
CRITICAL : Active exploitation likely
HIGH     : Strong attack indicator
MEDIUM   : Suspicious activity worth investigating
LOW      : Informational / audit trail

These mirror industry SIEM standards (Splunk, QRadar, ELK).

PLATFORM SUPPORT
-----------------
Windows 11 : Web log analysis + Windows Event Log
             Auth log analysis works if log file provided
Linux/Kali : Auth log + Web log analysis
             Windows Event Log not available

EDUCATIONAL USE ONLY.
Log files may contain sensitive personal information.
Only analyse logs from systems you own or are authorised to audit.

Requirements:
    Standard library only (Windows Event Log requires pywin32)
"""

import logging
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

IS_WINDOWS = os.name == "nt"
IS_LINUX   = sys.platform.startswith("linux")

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
RESULTS_DIR             = Path(__file__).resolve().parent / "scan_results"
BRUTE_FORCE_THRESHOLD   = 10    # Failed logins before flagging as brute force
SCAN_404_THRESHOLD      = 20    # 404s from one IP before flagging as scanner
ERROR_SPIKE_THRESHOLD   = 10    # Server errors before flagging
LARGE_RESPONSE_BYTES    = 10 * 1024 * 1024    # 10MB


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """
    Represents a single security finding from log analysis.
    """
    severity    : str
    category    : str
    description : str
    detail      : str  = ""
    count       : int  = 1
    source_ips  : list = field(default_factory=list)

    SEVERITY_ORDER = {
        "CRITICAL": 0,
        "HIGH":     1,
        "MEDIUM":   2,
        "LOW":      3,
    }

    def severity_rank(self) -> int:
        return self.SEVERITY_ORDER.get(self.severity, 99)


# ---------------------------------------------------------------------------
# Auth log patterns
# ---------------------------------------------------------------------------

AUTH_PATTERNS = {
    "failed_password": re.compile(
        r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)"
    ),
    "accepted_password": re.compile(
        r"Accepted (?:password|publickey) for (\S+) from ([\d.]+)"
    ),
    "invalid_user": re.compile(
        r"Invalid user (\S+) from ([\d.]+)"
    ),
    "root_attempt": re.compile(
        r"(?:Failed|Invalid).+for root from ([\d.]+)"
    ),
    "new_user": re.compile(
        r"new user: name=(\S+)"
    ),
    "sudo": re.compile(
        r"sudo:\s+(\S+) : .+ COMMAND=(.+)"
    ),
}

# ---------------------------------------------------------------------------
# Web log patterns
# ---------------------------------------------------------------------------

# Combined Log Format used by Apache and Nginx
# Example: 192.168.1.1 - - [01/Jan/2024:12:00:00 +0000]
#          "GET /admin HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
ACCESS_LOG_PATTERN = re.compile(
    r'([\d.]+) \S+ \S+ \[([^\]]+)\] '
    r'"(\S+) (\S+) \S+" (\d+) (\d+|-) '
    r'"[^"]*" "([^"]*)"'
)

# SQL injection detection patterns
SQLI_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"union\s+select",
        r"select\s+.+\s+from",
        r"'\s*or\s+'?\d",
        r"1=1",
        r"drop\s+table",
        r"--\s*$",
        r"/\*.*\*/",
        r"xp_cmdshell",
        r"exec\s*\(",
        r"cast\s*\(",
    ]
]

# Path traversal patterns
TRAVERSAL_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"\.\./",
        r"%2e%2e%2f",
        r"%2e%2e/",
        r"\.\.%2f",
        r"%252e%252e",
    ]
]

# Suspicious user agents - scanners and exploit tools
SUSPICIOUS_AGENTS = [
    "nikto", "sqlmap", "nmap", "gobuster", "dirbuster",
    "masscan", "zmap", "metasploit", "hydra", "medusa",
    "burpsuite", "zaproxy", "acunetix", "nessus", "openvas",
    "wfuzz", "ffuf", "nuclei", "whatweb", "wpscan",
]


# ---------------------------------------------------------------------------
# Auth log analyser
# ---------------------------------------------------------------------------

def analyse_auth_log(log_path: Path) -> list:
    """
    Parse a Linux auth log and extract security findings.

    Reads the log line by line to handle large files efficiently.
    Uses Counter for per-IP event aggregation.

    Detection logic:
      Brute force: count failed logins per source IP. Legitimate
      users fail 2-3 times. Automated tools fail hundreds or
      thousands of times. Threshold of 10 is conservative.

    Parameters
    ----------
    log_path : Path   Path to auth.log or secure log file.

    Returns
    -------
    List of Finding objects sorted by severity.
    """
    findings = []

    failed_per_ip    : Counter = Counter()
    accepted_per_ip  : Counter = Counter()
    invalid_users    : Counter = Counter()
    root_attempts    : Counter = Counter()
    new_users        : list    = []
    sudo_events      : list    = []

    try:
        with log_path.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                # Failed password attempts
                m = AUTH_PATTERNS["failed_password"].search(line)
                if m:
                    failed_per_ip[m.group(2)] += 1

                # Successful logins
                m = AUTH_PATTERNS["accepted_password"].search(line)
                if m:
                    accepted_per_ip[m.group(2)] += 1

                # Invalid user probing
                m = AUTH_PATTERNS["invalid_user"].search(line)
                if m:
                    invalid_users[m.group(2)] += 1

                # Root attempts
                m = AUTH_PATTERNS["root_attempt"].search(line)
                if m:
                    root_attempts[m.group(1)] += 1

                # New user creation
                m = AUTH_PATTERNS["new_user"].search(line)
                if m:
                    new_users.append(m.group(1))

                # Sudo usage
                m = AUTH_PATTERNS["sudo"].search(line)
                if m:
                    sudo_events.append((m.group(1), m.group(2).strip()))

    except OSError as exc:
        print(f"  [!] Could not read log file: {exc}")
        logger.error("Auth log read error: %s", exc)
        return []

    # Generate findings from aggregated data

    # Brute force detection
    for ip, count in failed_per_ip.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            findings.append(Finding(
                severity    = "HIGH",
                category    = "Brute Force",
                description = (
                    f"Possible SSH brute force from {ip} "
                    f"({count:,} failed attempts)"
                ),
                detail      = f"Source IP: {ip}",
                count       = count,
                source_ips  = [ip],
            ))

    # Successful logins
    for ip, count in accepted_per_ip.items():
        findings.append(Finding(
            severity    = "LOW",
            category    = "Successful Login",
            description = (
                f"Successful authentication from {ip} "
                f"({count} session(s))"
            ),
            detail      = f"Source IP: {ip}",
            count       = count,
            source_ips  = [ip],
        ))

    # Invalid user probing - username enumeration
    for ip, count in invalid_users.items():
        if count >= 3:
            findings.append(Finding(
                severity    = "MEDIUM",
                category    = "Username Enumeration",
                description = (
                    f"Invalid username probing from {ip} "
                    f"({count} attempts)"
                ),
                detail      = f"Source IP: {ip}",
                count       = count,
                source_ips  = [ip],
            ))

    # Root login attempts
    for ip, count in root_attempts.items():
        findings.append(Finding(
            severity    = "HIGH",
            category    = "Root Login Attempt",
            description = (
                f"Direct root login attempted from {ip} "
                f"({count} attempt(s))"
            ),
            detail      = "Direct root login is a high-risk indicator",
            count       = count,
            source_ips  = [ip],
        ))

    # New user creation - possible persistence
    for username in set(new_users):
        findings.append(Finding(
            severity    = "MEDIUM",
            category    = "New User Created",
            description = f"New user account created: {username}",
            detail      = "Could indicate attacker persistence mechanism",
        ))

    # Sudo usage audit
    for user, command in sudo_events[:10]:    # Cap at 10 for readability
        findings.append(Finding(
            severity    = "LOW",
            category    = "Privilege Escalation (sudo)",
            description = f"sudo used by {user}",
            detail      = f"Command: {command[:80]}",
        ))

    if not findings:
        findings.append(Finding(
            severity    = "LOW",
            category    = "Summary",
            description = "No significant security events detected.",
            detail      = f"Log file: {log_path.name}",
        ))

    return sorted(findings, key=lambda f: f.severity_rank())


# ---------------------------------------------------------------------------
# Web access log analyser
# ---------------------------------------------------------------------------

def analyse_access_log(log_path: Path) -> list:
    """
    Parse an Apache/Nginx combined format access log.

    Aggregates events per IP and URL to detect patterns that
    individual events would not reveal.

    Detection logic:
      404 flood:   automated scanners request hundreds of paths
                   that don't exist. Count 404s per IP.
      SQLi:        regex match suspicious URL patterns
      Traversal:   detect ../ and encoded variants in URLs
      Bad agents:  known scanner/exploit tool signatures
      Error spike: many 500s may indicate exploitation attempts

    Parameters
    ----------
    log_path : Path   Path to access.log file.

    Returns
    -------
    List of Finding objects sorted by severity.
    """
    findings = []

    ip_404_count     : Counter = Counter()
    ip_500_count     : Counter = Counter()
    ip_request_count : Counter = Counter()
    sqli_attempts    : list    = []
    traversal_hits   : list    = []
    bad_agents       : list    = []
    large_responses  : list    = []
    total_lines      = 0

    try:
        with log_path.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                total_lines += 1
                m = ACCESS_LOG_PATTERN.match(line)
                if not m:
                    continue

                ip         = m.group(1)
                method     = m.group(3)
                path       = m.group(4)
                status     = int(m.group(5))
                size_str   = m.group(6)
                user_agent = m.group(7).lower()

                size = int(size_str) if size_str != "-" else 0

                ip_request_count[ip] += 1

                # 404 tracking - directory scanning
                if status == 404:
                    ip_404_count[ip] += 1

                # 500 tracking - error spikes
                if status == 500:
                    ip_500_count[ip] += 1

                # SQL injection detection
                for pattern in SQLI_PATTERNS:
                    if pattern.search(path):
                        sqli_attempts.append((ip, path[:100], status))
                        break

                # Path traversal detection
                for pattern in TRAVERSAL_PATTERNS:
                    if pattern.search(path):
                        traversal_hits.append((ip, path[:100], status))
                        break

                # Suspicious user agent detection
                for agent in SUSPICIOUS_AGENTS:
                    if agent in user_agent:
                        bad_agents.append((ip, agent, path[:80]))
                        break

                # Large response - possible data exfiltration
                if size > LARGE_RESPONSE_BYTES:
                    large_responses.append((
                        ip, path[:80], size, status
                    ))

    except OSError as exc:
        print(f"  [!] Could not read log file: {exc}")
        logger.error("Access log read error: %s", exc)
        return []

    # Generate findings

    # Directory scanning - 404 flood
    for ip, count in ip_404_count.items():
        if count >= SCAN_404_THRESHOLD:
            findings.append(Finding(
                severity    = "HIGH",
                category    = "Directory Scanning",
                description = (
                    f"Possible directory scan from {ip} "
                    f"({count:,} 404 responses)"
                ),
                detail      = (
                    f"Total requests from {ip}: "
                    f"{ip_request_count[ip]:,}"
                ),
                count       = count,
                source_ips  = [ip],
            ))

    # Server error spikes
    for ip, count in ip_500_count.items():
        if count >= ERROR_SPIKE_THRESHOLD:
            findings.append(Finding(
                severity    = "MEDIUM",
                category    = "Server Error Spike",
                description = (
                    f"High server error rate from {ip} "
                    f"({count} errors)"
                ),
                detail      = "May indicate exploitation attempts",
                count       = count,
                source_ips  = [ip],
            ))

    # SQL injection attempts
    if sqli_attempts:
        ips = list({a[0] for a in sqli_attempts})
        findings.append(Finding(
            severity    = "CRITICAL",
            category    = "SQL Injection Attempt",
            description = (
                f"SQL injection patterns detected "
                f"({len(sqli_attempts)} request(s))"
            ),
            detail      = (
                f"Sample: {sqli_attempts[0][1]} "
                f"[status {sqli_attempts[0][2]}]"
            ),
            count       = len(sqli_attempts),
            source_ips  = ips[:5],
        ))

    # Path traversal
    if traversal_hits:
        ips = list({t[0] for t in traversal_hits})
        findings.append(Finding(
            severity    = "HIGH",
            category    = "Path Traversal Attempt",
            description = (
                f"Path traversal patterns detected "
                f"({len(traversal_hits)} request(s))"
            ),
            detail      = (
                f"Sample: {traversal_hits[0][1]} "
                f"[status {traversal_hits[0][2]}]"
            ),
            count       = len(traversal_hits),
            source_ips  = ips[:5],
        ))

    # Suspicious user agents
    if bad_agents:
        ips = list({a[0] for a in bad_agents})
        agent_names = list({a[1] for a in bad_agents})
        findings.append(Finding(
            severity    = "HIGH",
            category    = "Suspicious User Agent",
            description = (
                f"Known scanner/tool detected: "
                f"{', '.join(agent_names[:5])}"
            ),
            detail      = f"Source IPs: {', '.join(ips[:5])}",
            count       = len(bad_agents),
            source_ips  = ips[:5],
        ))

    # Large responses
    for ip, path, size, status in large_responses[:5]:
        size_mb = size / (1024 * 1024)
        findings.append(Finding(
            severity    = "MEDIUM",
            category    = "Large Response",
            description = (
                f"Unusually large response to {ip}: "
                f"{size_mb:.1f} MB"
            ),
            detail      = f"Path: {path} [status {status}]",
            count       = 1,
            source_ips  = [ip],
        ))

    # Request summary
    findings.append(Finding(
        severity    = "LOW",
        category    = "Summary",
        description = (
            f"Processed {total_lines:,} log lines from "
            f"{len(ip_request_count):,} unique IPs"
        ),
        detail      = f"Log file: {log_path.name}",
    ))

    if len(findings) == 1:
        findings.append(Finding(
            severity    = "LOW",
            category    = "Summary",
            description = "No significant attack patterns detected.",
        ))

    return sorted(findings, key=lambda f: f.severity_rank())


# ---------------------------------------------------------------------------
# Windows Event Log analyser
# ---------------------------------------------------------------------------

def analyse_windows_event_log() -> list:
    """
    Read the Windows Security Event Log and extract security findings.

    Uses the pywin32 library (win32evtlog) to access the Event Log.
    Only available on Windows - returns empty list on Linux/macOS.

    Event IDs monitored:
      4625 - Failed logon
      4624 - Successful logon
      4720 - New user account created
      4732 - User added to privileged group
      4648 - Logon with explicit credentials
      4672 - Special privileges assigned (admin logon)
      4698 - Scheduled task created
      1102 - Audit log cleared (CRITICAL - anti-forensics)

    Returns
    -------
    List of Finding objects sorted by severity.
    """
    if not IS_WINDOWS:
        print("  [!] Windows Event Log analysis is only available on Windows.")
        return []

    try:
        import win32evtlog
        import win32evtlogutil
    except ImportError:
        print("  [!] pywin32 is required for Windows Event Log analysis.")
        print("      Run: pip install pywin32")
        return []

    findings = []

    SECURITY_EVENT_IDS = {
        4625: ("HIGH",     "Failed Logon",
               "Failed authentication attempt"),
        4624: ("LOW",      "Successful Logon",
               "User logged on successfully"),
        4720: ("MEDIUM",   "User Account Created",
               "New user account was created"),
        4732: ("HIGH",     "Group Membership Change",
               "User added to privileged group"),
        4648: ("HIGH",     "Explicit Credentials",
               "Logon using explicit credentials"),
        4672: ("LOW",      "Special Privileges",
               "Admin-level logon occurred"),
        4698: ("MEDIUM",   "Scheduled Task Created",
               "New scheduled task registered"),
        1102: ("CRITICAL", "Audit Log Cleared",
               "Security event log was cleared"),
    }

    event_counts : Counter = Counter()
    total_read = 0

    try:
        hand  = win32evtlog.OpenEventLog(None, "Security")
        flags = (
            win32evtlog.EVENTLOG_BACKWARDS_READ
            | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        )

        while True:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            if not events:
                break
            for event in events:
                total_read += 1
                event_id = event.EventID & 0xFFFF
                if event_id in SECURITY_EVENT_IDS:
                    event_counts[event_id] += 1

        win32evtlog.CloseEventLog(hand)

    except Exception as exc:
        print(f"  [!] Could not read Windows Event Log: {exc}")
        print("  [*] Make sure you are running as Administrator.")
        logger.error("Windows Event Log error: %s", exc)
        return []

    for event_id, count in event_counts.items():
        severity, category, description = SECURITY_EVENT_IDS[event_id]

        if event_id == 4625 and count >= BRUTE_FORCE_THRESHOLD:
            severity    = "HIGH"
            description = (
                f"Possible brute force - "
                f"{count:,} failed logon events"
            )

        findings.append(Finding(
            severity    = severity,
            category    = category,
            description = f"{description} ({count:,} event(s))",
            detail      = f"Event ID: {event_id}",
            count       = count,
        ))

    findings.append(Finding(
        severity    = "LOW",
        category    = "Summary",
        description = (
            f"Read {total_read:,} Windows Security events"
        ),
    ))

    logger.info("Read %d Windows Security events.", total_read)

    return sorted(findings, key=lambda f: f.severity_rank())


# ---------------------------------------------------------------------------
# Results display
# ---------------------------------------------------------------------------

SEVERITY_LABELS = {
    "CRITICAL": "[CRITICAL]",
    "HIGH":     "[HIGH]    ",
    "MEDIUM":   "[MEDIUM]  ",
    "LOW":      "[LOW]     ",
}


def display_findings(findings: list) -> None:
    """
    Print findings to the terminal grouped by severity.

    Parameters
    ----------
    findings : list   Finding objects to display.
    """
    if not findings:
        print("  No findings to display.")
        return

    current_severity = None

    for finding in findings:
        if finding.severity != current_severity:
            current_severity = finding.severity
            print(f"\n  {'=' * 56}")
            print(f"  {finding.severity} FINDINGS")
            print(f"  {'=' * 56}")

        label = SEVERITY_LABELS.get(finding.severity, "[INFO]    ")
        print(f"\n  {label} {finding.category}")
        print(f"             {finding.description}")
        if finding.detail:
            print(f"             {finding.detail}")
        if finding.source_ips:
            print(
                f"             Source IPs: "
                f"{', '.join(finding.source_ips[:3])}"
                f"{'...' if len(finding.source_ips) > 3 else ''}"
            )


# ---------------------------------------------------------------------------
# Results saving
# ---------------------------------------------------------------------------

def save_findings(
    findings: list,
    log_type: str,
    source: str,
) -> Optional[Path]:
    """
    Write findings to a timestamped text file.

    Parameters
    ----------
    findings : list   Finding objects to save.
    log_type : str    Log type label (auth/web/windows).
    source   : str    Source log file path or description.

    Returns
    -------
    Path to saved file, or None on failure.
    """
    try:
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename  = RESULTS_DIR / f"log_analysis_{log_type}_{timestamp}.txt"

        with filename.open("w", encoding="utf-8") as fh:
            fh.write("Security Log Analysis Report\n")
            fh.write("=" * 60 + "\n")
            fh.write(f"Log type  : {log_type}\n")
            fh.write(f"Source    : {source}\n")
            fh.write(
                f"Date/Time : "
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            )
            fh.write(f"Findings  : {len(findings)}\n")
            fh.write("=" * 60 + "\n\n")

            current_severity = None

            for finding in findings:
                if finding.severity != current_severity:
                    current_severity = finding.severity
                    fh.write(f"\n{'=' * 60}\n")
                    fh.write(f"{finding.severity} FINDINGS\n")
                    fh.write(f"{'=' * 60}\n\n")

                fh.write(
                    f"[{finding.severity}] {finding.category}\n"
                )
                fh.write(f"  {finding.description}\n")
                if finding.detail:
                    fh.write(f"  {finding.detail}\n")
                if finding.source_ips:
                    fh.write(
                        f"  Source IPs: "
                        f"{', '.join(finding.source_ips)}\n"
                    )
                fh.write("\n")

        logger.info("Findings saved to %s", filename)
        return filename

    except OSError as exc:
        print(f"  [!] Could not save findings: {exc}")
        logger.error("Save error: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Log type menu
# ---------------------------------------------------------------------------

LOG_TYPE_MENU = {
    "1": ("SSH / Auth Log (Linux)",               "auth"),
    "2": ("Web Server Access Log (Apache/Nginx)",  "web"),
    "3": ("Windows Security Event Log",            "windows"),
}


# ---------------------------------------------------------------------------
# Default log paths
# ---------------------------------------------------------------------------

DEFAULT_AUTH_PATHS = [
    Path("/var/log/auth.log"),     # Debian/Ubuntu
    Path("/var/log/secure"),       # RHEL/CentOS/Kali
]

DEFAULT_WEB_PATHS = [
    Path("/var/log/apache2/access.log"),
    Path("/var/log/nginx/access.log"),
    Path("/var/log/httpd/access_log"),
]


def find_default_log(paths: list) -> Optional[Path]:
    """
    Return the first path from the list that exists.

    Parameters
    ----------
    paths : list   Path objects to check in order.
    """
    for path in paths:
        if path.exists():
            return path
    return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Interactive log analysis entry point.

    Prompts for log type, file path (with defaults), runs the
    appropriate analyser, displays findings, and saves report.
    """
    print("\n  Security Log Analyser")
    print("  " + "-" * 21)
    print(f"  Platform : {sys.platform}")
    print("  [!] Only analyse logs from systems you own or are")
    print("      authorised to audit.")
    print("  [*] Enter 0 at any prompt to cancel.\n")

    # Log type selection
    print("  Select log type:\n")
    for key, (label, _) in LOG_TYPE_MENU.items():
        available = ""
        if key == "3" and not IS_WINDOWS:
            available = "  (Windows only)"
        print(f"    {key}. {label}{available}")
    print()

    choice = input("  Select log type: ").strip()
    if choice == "0":
        return
    if choice not in LOG_TYPE_MENU:
        print("  [!] Invalid selection.")
        return

    log_label, log_type = LOG_TYPE_MENU[choice]
    print(f"  [+] Selected: {log_label}\n")

    # Windows Event Log - no file path needed
    if log_type == "windows":
        if not IS_WINDOWS:
            print("  [!] Windows Event Log is only available on Windows.")
            return
        print("  [*] Reading Windows Security Event Log...")
        print("  [*] This may take a moment for large logs.\n")
        findings = analyse_windows_event_log()
        source   = "Windows Security Event Log"

    else:
        # Get log file path
        if log_type == "auth":
            default_path = find_default_log(DEFAULT_AUTH_PATHS)
            type_hint    = "/var/log/auth.log"
        else:
            default_path = find_default_log(DEFAULT_WEB_PATHS)
            type_hint    = "/var/log/apache2/access.log"

        if default_path:
            print(f"  [*] Default log found: {default_path}")
            use_default = input(
                "  Use this file? (y/n) [y]: "
            ).strip().lower()
            if use_default == "0":
                return
            if use_default != "n":
                log_path = default_path
            else:
                log_path = None
        else:
            log_path = None

        if log_path is None:
            raw_path = input(
                f"  Path to log file [{type_hint}]: "
            ).strip()
            if not raw_path or raw_path == "0":
                return
            log_path = Path(raw_path)

        if not log_path.exists():
            print(f"  [!] File not found: {log_path}")
            print(f"      Check the path and try again.")
            return

        file_size = log_path.stat().st_size / (1024 * 1024)
        print(
            f"  [+] File: {log_path.name} "
            f"({file_size:.1f} MB)"
        )
        print(f"  [*] Analysing log - please wait...\n")

        if log_type == "auth":
            findings = analyse_auth_log(log_path)
        else:
            findings = analyse_access_log(log_path)

        source = str(log_path)

    # Display findings
    if not findings:
        print("  [*] No findings generated.")
        return

    critical = sum(1 for f in findings if f.severity == "CRITICAL")
    high     = sum(1 for f in findings if f.severity == "HIGH")
    medium   = sum(1 for f in findings if f.severity == "MEDIUM")
    low      = sum(1 for f in findings if f.severity == "LOW")

    print(f"  Analysis complete.")
    print(f"  {'=' * 40}")
    print(f"  CRITICAL : {critical}")
    print(f"  HIGH     : {high}")
    print(f"  MEDIUM   : {medium}")
    print(f"  LOW      : {low}")
    print(f"  {'=' * 40}")

    display_findings(findings)

    # Save findings
    print()
    save_choice = input(
        "  Save findings to file? (y/n) [y]: "
    ).strip().lower()
    if save_choice != "n":
        saved = save_findings(findings, log_type, source)
        if saved:
            print(f"\n  Report saved to: {saved}")

    logger.info(
        "Log analysis complete: type=%s findings=%d",
        log_type, len(findings),
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()