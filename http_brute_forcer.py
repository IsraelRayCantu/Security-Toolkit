# topic: Web Security
# title: HTTP Directory Brute Forcer
# priority: 1

"""
http_brute_forcer.py - HTTP Directory and File Brute Forcer
============================================================
Discovers hidden directories and files on web servers by
requesting paths from a wordlist and analysing HTTP response
codes. Mirrors the functionality of gobuster, dirb, and
feroxbuster.

HOW IT WORKS
-------------
1. Read a wordlist of common directory and file names
2. For each word, send an HTTP GET request to /word
3. Analyse the response code:
     200        - path exists and is accessible
     301/302    - redirect (path exists, moved)
     403        - forbidden (path EXISTS but access denied)
     500        - server error (path may trigger a bug)
     404        - not found (skip)
4. Report everything except 404

WHY 403 IS INTERESTING
-----------------------
A 403 Forbidden response confirms the resource EXISTS even
though we cannot access it. Finding /admin returning 403 tells
us the admin panel is there - a real finding in a pentest report.
The client may be misconfigured, or we may find a bypass later.

THREADING MODEL
----------------
HTTP requests are I/O bound - the bottleneck is waiting for
the server to respond, not CPU computation. ThreadPoolExecutor
with multiple workers parallelises the wait time - while one
thread waits for a response, others are sending new requests.

For CPU-bound work (hashing, compression) you would use
multiprocessing instead - threads cannot bypass the GIL for
CPU-bound Python code. But for network I/O, threads are ideal.

STATUS CODES TRACKED
---------------------
  200/201/204 - success (accessible)
  301/302/307/308 - redirect (exists, moved)
  401 - unauthorised (exists, needs credentials)
  403 - forbidden (exists, access denied)
  405 - method not allowed (exists, GET not permitted)
  500/503 - server error (may indicate vulnerability)

WORDLISTS
----------
This module works with any newline-separated wordlist.
Recommended sources:
  - SecLists: https://github.com/danielmiessler/SecLists
    common.txt, big.txt, directory-list-2.3-medium.txt
  - Built-in preset: top50 (included in this module)

PLATFORM SUPPORT
-----------------
Works identically on Windows 11 and Linux/Kali.
No elevated privileges required.
Uses only the Python standard library - no pip packages needed.

EDUCATIONAL USE ONLY.
Only scan web servers you own or have explicit written
permission to test. Unauthorised scanning may violate the
Computer Fraud and Abuse Act and equivalent laws.

Requirements: Python standard library only
"""

import concurrent.futures
import logging
import os
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import urljoin, urlparse

IS_WINDOWS = os.name == "nt"
IS_LINUX   = sys.platform.startswith("linux")

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
RESULTS_DIR      = Path(__file__).resolve().parent / "scan_results"
DEFAULT_THREADS  = 20
DEFAULT_TIMEOUT  = 5
DEFAULT_EXTENSIONS = ["php", "html", "txt", "asp", "aspx", "jsp"]
USER_AGENT       = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

# Status codes worth reporting (everything except 404)
INTERESTING_CODES = {
    200: "OK",
    201: "Created",
    204: "No Content",
    301: "Moved Permanently",
    302: "Found (Redirect)",
    307: "Temporary Redirect",
    308: "Permanent Redirect",
    401: "Unauthorised",
    403: "Forbidden (exists!)",
    405: "Method Not Allowed",
    500: "Internal Server Error",
    503: "Service Unavailable",
}

# Built-in top-50 wordlist for quick scans without a wordlist file
TOP50_WORDLIST = [
    "admin", "administrator", "login", "wp-admin", "dashboard",
    "backup", "config", "test", "dev", "staging",
    "api", "v1", "v2", "uploads", "files",
    "images", "img", "css", "js", "static",
    "assets", "media", "download", "downloads", "data",
    "db", "database", "sql", "logs", "log",
    "temp", "tmp", "cache", "public", "private",
    "secret", "hidden", "old", "archive", "bak",
    "robots.txt", "sitemap.xml", ".git", ".env", "readme",
    "index", "home", "main", "portal", "panel",
]


# ---------------------------------------------------------------------------
# Scan result
# ---------------------------------------------------------------------------

class ScanResult:
    """
    Holds the result for a single probed URL.
    """
    __slots__ = ("url", "status_code", "status_text",
                 "content_length", "redirect_url")

    def __init__(
        self,
        url: str,
        status_code: int,
        content_length: int = 0,
        redirect_url: str = "",
    ) -> None:
        self.url            = url
        self.status_code    = status_code
        self.status_text    = INTERESTING_CODES.get(
            status_code, str(status_code)
        )
        self.content_length = content_length
        self.redirect_url   = redirect_url


# ---------------------------------------------------------------------------
# Live progress counter
# ---------------------------------------------------------------------------

class ScanProgress:
    """
    Thread-safe progress tracker with live terminal display.

    Tracks requests sent, findings, elapsed time, and rate.
    Runs in a daemon thread so it does not block the scan.
    """

    def __init__(self, total: int) -> None:
        self._total    = total
        self._done     = 0
        self._found    = 0
        self._lock     = threading.Lock()
        self._running  = False
        self._thread   = None
        self._start    = time.time()

    def increment(self) -> None:
        with self._lock:
            self._done += 1

    def found(self) -> None:
        with self._lock:
            self._found += 1

    def start(self) -> None:
        self._running = True
        self._start   = time.time()
        self._thread  = threading.Thread(
            target=self._display_loop,
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        print()

    def _display_loop(self) -> None:
        while self._running:
            with self._lock:
                done  = self._done
                found = self._found

            elapsed = time.time() - self._start
            rate    = done / elapsed if elapsed > 0 else 0.0
            pct     = (done / self._total * 100) if self._total else 0

            print(
                f"\r  [*] Progress: {done:>6}/{self._total}  "
                f"({pct:>5.1f}%)  |  "
                f"Found: {found:>4}  |  "
                f"Rate: {rate:>6.0f} req/s  "
                "  (Ctrl+C to stop)",
                end="",
                flush=True,
            )
            time.sleep(0.5)


# ---------------------------------------------------------------------------
# HTTP probe
# ---------------------------------------------------------------------------

def probe_url(url: str, timeout: int) -> Optional[ScanResult]:
    """
    Send an HTTP GET request to url and return the result.

    Uses urllib from the standard library - no external dependencies.
    urllib raises HTTPError for 4xx/5xx responses rather than
    returning them - we catch HTTPError to extract the status code.

    A 404 returns None to signal the caller to skip it.
    All other status codes return a ScanResult.

    Parameters
    ----------
    url     : str   Full URL to probe.
    timeout : int   Seconds before the request times out.

    Returns
    -------
    ScanResult if the response is interesting, None for 404/error.
    """
    request = Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
            "Connection": "close",
        },
    )

    try:
        with urlopen(request, timeout=timeout) as response:
            status  = response.status
            length  = int(response.headers.get("Content-Length", 0))
            return ScanResult(url, status, content_length=length)

    except HTTPError as exc:
        # HTTPError is raised for 4xx/5xx responses
        if exc.code == 404:
            return None     # Not found - skip silently

        redirect = ""
        if exc.code in (301, 302, 307, 308):
            redirect = exc.headers.get("Location", "")

        return ScanResult(
            url,
            exc.code,
            redirect_url=redirect,
        )

    except URLError:
        return None     # Network error - skip

    except Exception:
        return None     # Any other error - skip


# ---------------------------------------------------------------------------
# Wordlist loader
# ---------------------------------------------------------------------------

def load_wordlist(path: Path) -> list:
    """
    Read a wordlist file and return a list of non-empty, stripped words.

    Reads line by line to handle large files efficiently without
    loading the entire file into memory at once.

    Parameters
    ----------
    path : Path   Path to the wordlist file.

    Returns
    -------
    List of word strings.
    """
    words = []
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                word = line.strip()
                if word and not word.startswith("#"):
                    words.append(word)
    except OSError as exc:
        print(f"  [!] Could not read wordlist: {exc}")

    return words


# ---------------------------------------------------------------------------
# URL builder
# ---------------------------------------------------------------------------

def build_urls(
    base_url: str,
    words: list,
    extensions: Optional[list],
) -> list:
    """
    Build the full list of URLs to probe from a wordlist.

    For each word we build:
      - The bare path:             /word
      - With each extension:       /word.php, /word.html etc.

    This tests both directories and files in a single pass.

    Parameters
    ----------
    base_url   : str          Target base URL (scheme + host).
    words      : list         Words from the wordlist.
    extensions : list or None File extensions to append.

    Returns
    -------
    Deduplicated list of full URLs to probe.
    """
    urls = []
    seen = set()

    def add(url: str) -> None:
        if url not in seen:
            seen.add(url)
            urls.append(url)

    for word in words:
        word = word.lstrip("/")

        # Bare path
        add(urljoin(base_url.rstrip("/") + "/", word))

        # With extensions
        if extensions:
            for ext in extensions:
                add(urljoin(
                    base_url.rstrip("/") + "/",
                    f"{word}.{ext}",
                ))

    return urls


# ---------------------------------------------------------------------------
# Results saving
# ---------------------------------------------------------------------------

def save_results(
    results: list,
    target: str,
    wordlist_name: str,
    elapsed: float,
) -> Optional[Path]:
    """
    Write scan findings to a timestamped results file.

    Parameters
    ----------
    results      : list   ScanResult objects to save.
    target       : str    Target URL that was scanned.
    wordlist_name: str    Name of the wordlist used.
    elapsed      : float  Scan duration in seconds.

    Returns
    -------
    Path to saved file, or None on failure.
    """
    try:
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        host      = urlparse(target).netloc.replace(":", "_")
        filename  = RESULTS_DIR / f"dirbrute_{host}_{timestamp}.txt"

        # Group results by status code
        by_status: dict = {}
        for result in results:
            by_status.setdefault(result.status_code, []).append(result)

        with filename.open("w", encoding="utf-8") as fh:
            fh.write("HTTP Directory Brute Force Report\n")
            fh.write("=" * 60 + "\n")
            fh.write(f"Target    : {target}\n")
            fh.write(f"Wordlist  : {wordlist_name}\n")
            fh.write(
                f"Date/Time : "
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            )
            fh.write(f"Duration  : {elapsed:.2f}s\n")
            fh.write(f"Findings  : {len(results)}\n")
            fh.write("=" * 60 + "\n\n")

            for code in sorted(by_status.keys()):
                status_text = INTERESTING_CODES.get(code, str(code))
                fh.write(f"[{code} - {status_text}]\n")
                for result in by_status[code]:
                    size_str = (
                        f" ({result.content_length} bytes)"
                        if result.content_length else ""
                    )
                    redirect_str = (
                        f" -> {result.redirect_url}"
                        if result.redirect_url else ""
                    )
                    fh.write(
                        f"  {result.url}"
                        f"{size_str}{redirect_str}\n"
                    )
                fh.write("\n")

        logger.info("Results saved to %s", filename)
        return filename

    except OSError as exc:
        print(f"  [!] Could not save results: {exc}")
        logger.error("Save error: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Main scan runner
# ---------------------------------------------------------------------------

def run_scan(
    base_url: str,
    urls: list,
    threads: int,
    timeout: int,
) -> list:
    """
    Probe all URLs concurrently using a thread pool.

    ThreadPoolExecutor manages the thread lifecycle automatically.
    submit() dispatches each URL to an available worker thread.
    as_completed() yields futures in completion order (not submission
    order) so we can display results as soon as they arrive.

    Parameters
    ----------
    base_url : str   Target base URL (for display only).
    urls     : list  Full list of URLs to probe.
    threads  : int   Number of concurrent worker threads.
    timeout  : int   Per-request timeout in seconds.

    Returns
    -------
    List of ScanResult objects for interesting responses.
    """
    results  = []
    progress = ScanProgress(len(urls))
    progress.start()

    try:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=threads
        ) as executor:
            futures = {
                executor.submit(probe_url, url, timeout): url
                for url in urls
            }

            for future in concurrent.futures.as_completed(futures):
                progress.increment()
                try:
                    result = future.result()
                    if result is not None:
                        results.append(result)
                        progress.found()

                        # Print finding immediately
                        size_str = (
                            f" [{result.content_length} bytes]"
                            if result.content_length else ""
                        )
                        redirect_str = (
                            f" -> {result.redirect_url}"
                            if result.redirect_url else ""
                        )
                        print(
                            f"\n  [{result.status_code}] "
                            f"{result.url}"
                            f"{size_str}{redirect_str}"
                        )

                except Exception as exc:
                    logger.warning(
                        "Future error for %s: %s",
                        futures[future], exc,
                    )

    except KeyboardInterrupt:
        print("\n\n  [*] Scan interrupted.")

    finally:
        progress.stop()

    return sorted(results, key=lambda r: (r.status_code, r.url))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Interactive HTTP directory brute forcer entry point.

    Collects target URL, wordlist, thread count, and extensions.
    Runs the concurrent scan and saves results.
    """
    print("\n  HTTP Directory Brute Forcer")
    print("  " + "-" * 27)
    print(f"  Platform : {sys.platform}")
    print("  [!] EDUCATIONAL USE ONLY.")
    print("  [!] Only scan servers you own or are authorised to test.")
    print("  [*] Enter 0 at any prompt to cancel.\n")

    # Target URL
    target_url = input(
        "  Target URL (e.g. http://192.168.1.10): "
    ).strip()
    if not target_url or target_url == "0":
        return

    # Normalise URL
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url
        print(f"  [*] Normalised to: {target_url}")

    # Verify target is reachable before scanning
    print(f"  [*] Checking target is reachable...")
    test = probe_url(target_url, timeout=5)
    if test is None:
        # None could mean 404 (reachable) or connection error
        # Try again and check for connection error specifically
        try:
            Request(target_url)
            urlopen(
                Request(
                    target_url,
                    headers={"User-Agent": USER_AGENT}
                ),
                timeout=5,
            )
            print(f"  [+] Target is reachable.")
        except HTTPError:
            print(f"  [+] Target is reachable (got HTTP error response).")
        except URLError as exc:
            print(f"  [!] Could not reach target: {exc}")
            print(f"      Check the URL and try again.")
            return
        except Exception:
            print(f"  [*] Could not verify - proceeding anyway.")
    else:
        print(f"  [+] Target reachable - status {test.status_code}")

    # Wordlist selection
    print("\n  Wordlist options:")
    print("    1. Built-in top50  (50 common paths - quick)")
    print("    2. Custom file     (provide path to wordlist)")
    wl_choice = input("\n  Select wordlist [1]: ").strip() or "1"
    if wl_choice == "0":
        return

    if wl_choice == "2":
        wl_path_str = input("  Path to wordlist file: ").strip()
        if not wl_path_str or wl_path_str == "0":
            return
        wl_path = Path(wl_path_str)
        if not wl_path.exists():
            print(f"  [!] File not found: {wl_path}")
            return
        wordlist = load_wordlist(wl_path)
        wl_name  = wl_path.name
        if not wordlist:
            print("  [!] Wordlist is empty.")
            return
        print(f"  [+] Loaded {len(wordlist):,} words from {wl_name}")
    else:
        wordlist = TOP50_WORDLIST
        wl_name  = "built-in top50"
        print(f"  [+] Using built-in wordlist ({len(wordlist)} words)")

    # Extensions
    print("\n  File extensions to test alongside each word.")
    print(f"  Default: {', '.join(DEFAULT_EXTENSIONS)}")
    print("  Enter comma-separated list, or press Enter for defaults.")
    print("  Type 'none' to test paths only (no extensions).")
    ext_input = input("  Extensions: ").strip().lower()
    if ext_input == "0":
        return

    if ext_input == "none":
        extensions = None
    elif ext_input:
        extensions = [e.strip().lstrip(".") for e in ext_input.split(",")]
    else:
        extensions = DEFAULT_EXTENSIONS

    # Thread count
    raw_threads = input(
        f"\n  Threads [{DEFAULT_THREADS}]: "
    ).strip()
    if raw_threads == "0":
        return
    if raw_threads:
        if not raw_threads.isdigit():
            print("  [!] Must be a number.")
            return
        threads = max(1, min(int(raw_threads), 50))
    else:
        threads = DEFAULT_THREADS

    # Request timeout
    raw_timeout = input(
        f"  Request timeout in seconds [{DEFAULT_TIMEOUT}]: "
    ).strip()
    if raw_timeout == "0":
        return
    if raw_timeout:
        if not raw_timeout.isdigit():
            print("  [!] Must be a number.")
            return
        timeout = int(raw_timeout)
    else:
        timeout = DEFAULT_TIMEOUT

    # Build URL list
    urls = build_urls(target_url, wordlist, extensions)

    # Summary
    print(f"\n  Scan summary:")
    print(f"    Target      : {target_url}")
    print(f"    Wordlist    : {wl_name}")
    print(f"    Extensions  : "
          f"{', '.join(extensions) if extensions else 'none'}")
    print(f"    Total URLs  : {len(urls):,}")
    print(f"    Threads     : {threads}")
    print(f"    Timeout     : {timeout}s per request")

    confirm = input("\n  Start scan? (y/n): ").strip().lower()
    if confirm != "y":
        print("  Cancelled.")
        return

    # Run
    print(f"\n  [*] Starting scan on {target_url}...\n")
    logger.info(
        "Dir scan started: target=%s words=%d threads=%d",
        target_url, len(urls), threads,
    )

    start_time = time.perf_counter()

    results = run_scan(target_url, urls, threads, timeout)

    elapsed = time.perf_counter() - start_time

    # Display results summary
    print(f"\n  {'=' * 56}")
    print(f"  Scan complete - {target_url}")
    print(f"  {'=' * 56}")
    print(f"  Duration       : {elapsed:.2f}s")
    print(f"  URLs probed    : {len(urls):,}")
    print(f"  Findings       : {len(results)}")

    if results:
        print(f"\n  Findings by status code:")
        by_status: dict = {}
        for r in results:
            by_status.setdefault(r.status_code, []).append(r)

        for code in sorted(by_status.keys()):
            status_text = INTERESTING_CODES.get(code, str(code))
            print(f"\n  [{code} - {status_text}]")
            for r in by_status[code]:
                print(f"    {r.url}")

    print(f"  {'=' * 56}")

    # Save results
    if results:
        saved = save_results(results, target_url, wl_name, elapsed)
        if saved:
            print(f"\n  Results saved to: {saved}")
    else:
        print("\n  No interesting paths found.")
        print("  Try a larger wordlist or different extensions.")

    logger.info(
        "Dir scan complete: %s - %d findings in %.2fs",
        target_url, len(results), elapsed,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()