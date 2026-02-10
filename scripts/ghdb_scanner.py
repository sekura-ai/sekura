#!/usr/bin/env python3
"""
GHDB Dork Scanner — converts Google Hacking Database dorks into direct HTTP probes.

Self-contained script designed to run inside the Kali container.
Uses only Python stdlib + curl subprocess calls.

Usage:
    python3 /pentest/ghdb_scanner.py \
        --target-url http://10.0.0.1:8080 \
        --intensity standard \
        --cookie "PHPSESSID=abc123; security=low"
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class GHDBEntry:
    id: int
    category: str
    query: str
    short_description: str
    date: str = ""


@dataclass
class DorkProbe:
    ghdb_id: int
    category: str
    description: str
    original_query: str
    paths: list
    title_pattern: str = ""
    body_pattern: str = ""
    filetype_paths: set = field(default_factory=set)


@dataclass
class ProbeResult:
    probe: DorkProbe
    url: str
    path: str
    http_status: int
    response_size: int
    content_type: str
    body_preview: str = ""
    matched: bool = False
    from_filetype: bool = False


# ---------------------------------------------------------------------------
# Built-in file extension to path mapping
# ---------------------------------------------------------------------------
FILETYPE_PATHS = {
    "sql": ["/backup.sql", "/dump.sql", "/database.sql", "/db.sql"],
    "env": ["/.env", "/.env.local", "/.env.production", "/.env.backup"],
    "log": ["/error.log", "/debug.log", "/logs/error.log", "/access.log"],
    "bak": ["/web.config.bak", "/.htaccess.bak", "/index.php.bak"],
    "git": ["/.git/HEAD", "/.git/config"],
    "php": ["/phpinfo.php", "/info.php", "/config.php", "/test.php"],
    "json": ["/package.json", "/composer.json", "/appsettings.json"],
    "yml": ["/docker-compose.yml", "/swagger.yml", "/.travis.yml"],
    "yaml": ["/docker-compose.yaml", "/swagger.yaml", "/openapi.yaml"],
    "zip": ["/backup.zip", "/www.zip", "/site.zip", "/archive.zip"],
    "tar": ["/backup.tar", "/backup.tar.gz", "/www.tar.gz"],
    "gz": ["/backup.gz", "/dump.gz", "/database.sql.gz"],
    "txt": ["/robots.txt", "/security.txt", "/readme.txt", "/changelog.txt"],
    "xml": ["/sitemap.xml", "/crossdomain.xml", "/web.config"],
    "conf": ["/httpd.conf", "/nginx.conf", "/.htaccess"],
    "cfg": ["/setup.cfg", "/app.cfg"],
    "ini": ["/php.ini", "/config.ini", "/settings.ini"],
    "old": ["/index.php.old", "/config.php.old", "/.htaccess.old"],
    "csv": ["/users.csv", "/export.csv", "/data.csv"],
    "key": ["/server.key", "/private.key", "/.ssh/id_rsa"],
    "pem": ["/server.pem", "/cert.pem", "/ca-bundle.pem"],
}

# Google-only operators that cannot be converted to HTTP probes
GOOGLE_ONLY_OPS = {"cache:", "info:", "related:", "define:", "link:"}


# ---------------------------------------------------------------------------
# Category constants and intensity presets
# ---------------------------------------------------------------------------
CATEGORY_MAP = {
    "quick": [
        "Files Containing Passwords",
        "Footholds",
        "Sensitive Directories",
        "Pages Containing Login Portals",
    ],
    "standard": [
        "Files Containing Passwords",
        "Footholds",
        "Sensitive Directories",
        "Pages Containing Login Portals",
        "Files Containing Usernames",
        "Vulnerable Files",
        "Error Messages",
        "Web Server Detection",
    ],
    "thorough": None,  # All categories
}

INTENSITY_CONFIG = {
    "quick":    {"max_probes": 100,  "concurrency": 5,  "timeout": 3},
    "standard": {"max_probes": 500,  "concurrency": 10, "timeout": 5},
    "thorough": {"max_probes": 2000, "concurrency": 20, "timeout": 5},
}

# Severity hint per category
SEVERITY_MAP = {
    "Files Containing Passwords": "high",
    "Footholds": "high",
    "Sensitive Directories": "medium",
    "Files Containing Usernames": "medium",
    "Pages Containing Login Portals": "low",
    "Error Messages": "low",
    "Web Server Detection": "low",
    "Vulnerable Files": "high",
    "Vulnerable Servers": "high",
    "Files Containing Juicy Info": "medium",
    "Various Online Devices": "medium",
    "Network or Vulnerability Data": "medium",
    "Advisories and Vulnerabilities": "medium",
    "Sensitive Online Shopping Info": "high",
}

SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}


# ---------------------------------------------------------------------------
# GHDBDatabase — parse and filter ghdb.xml
# ---------------------------------------------------------------------------
class GHDBDatabase:
    def __init__(self, xml_path: str):
        self.entries: list[GHDBEntry] = []
        self._parse(xml_path)

    def _parse(self, xml_path: str) -> None:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        for elem in root.findall("entry"):
            entry = GHDBEntry(
                id=int(elem.findtext("id", "0")),
                category=elem.findtext("category", ""),
                query=elem.findtext("query", ""),
                short_description=elem.findtext("shortDescription", ""),
                date=elem.findtext("date", ""),
            )
            if entry.query:
                self.entries.append(entry)

    def filter_entries(self, categories: list[str] | None = None) -> list[GHDBEntry]:
        filtered = []
        for entry in self.entries:
            # Skip entries with Google-only operators
            query_lower = entry.query.lower()
            if any(op in query_lower for op in GOOGLE_ONLY_OPS):
                continue
            # Must have at least one convertible operator
            if not any(op in query_lower for op in ["inurl:", "filetype:", "intitle:", "intext:"]):
                continue
            # Category filter
            if categories is not None and entry.category not in categories:
                continue
            filtered.append(entry)
        return filtered


# ---------------------------------------------------------------------------
# DorkConverter — convert GHDBEntry to DorkProbe
# ---------------------------------------------------------------------------
class DorkConverter:
    @staticmethod
    def convert(entry: GHDBEntry) -> DorkProbe | None:
        query = entry.query
        paths = []
        ft_paths: set[str] = set()
        title_pattern = ""
        body_pattern = ""

        # Extract inurl: paths
        for match in re.finditer(r'inurl:\s*["\']?([^\s"\']+)["\']?', query, re.IGNORECASE):
            path = match.group(1)
            if not path.startswith("/"):
                path = "/" + path
            paths.append(path)

        # Extract filetype: and map to known paths — track separately
        for match in re.finditer(r'filetype:\s*["\']?(\w+)["\']?', query, re.IGNORECASE):
            ext = match.group(1).lower()
            if ext in FILETYPE_PATHS:
                for p in FILETYPE_PATHS[ext]:
                    paths.append(p)
                    ft_paths.add(p)

        # Extract intitle: pattern
        for match in re.finditer(r'intitle:\s*"([^"]+)"', query, re.IGNORECASE):
            title_pattern = match.group(1)
        if not title_pattern:
            for match in re.finditer(r'intitle:\s*(\S+)', query, re.IGNORECASE):
                title_pattern = match.group(1)

        # Extract intext: pattern
        for match in re.finditer(r'intext:\s*"([^"]+)"', query, re.IGNORECASE):
            body_pattern = match.group(1)
        if not body_pattern:
            for match in re.finditer(r'intext:\s*(\S+)', query, re.IGNORECASE):
                body_pattern = match.group(1)

        # If we only have a title/body pattern but no paths, probe the root
        if not paths and (title_pattern or body_pattern):
            paths = ["/"]

        if not paths:
            return None

        # Deduplicate paths
        seen: set[str] = set()
        unique_paths = []
        for p in paths:
            if p not in seen:
                seen.add(p)
                unique_paths.append(p)

        return DorkProbe(
            ghdb_id=entry.id,
            category=entry.category,
            description=entry.short_description,
            original_query=entry.query,
            paths=unique_paths,
            title_pattern=title_pattern,
            body_pattern=body_pattern,
            filetype_paths=ft_paths,
        )


# ---------------------------------------------------------------------------
# Probe execution via curl — with soft-404 baseline detection
# ---------------------------------------------------------------------------
class ProbeExecutor:
    def __init__(self, target_url: str, cookie: str = "", timeout: int = 5, concurrency: int = 10):
        self.target_url = target_url.rstrip("/")
        self.cookie = cookie
        self.timeout = timeout
        self.concurrency = concurrency
        self.baseline_size: int = -1

    def _fetch_baseline(self) -> None:
        """Fetch a random non-existent path to fingerprint soft-404 responses.

        If the server returns HTTP 200 for a path that cannot exist, record
        its response size.  Any later 200 within ±100 bytes of that size
        (with no content-pattern match) is treated as a soft-404.

        Redirects are NOT followed — a 3xx response from the canary means
        the server properly redirects unknown paths (handled separately).
        """
        canary = f"/ghdb_baseline_{uuid.uuid4().hex[:12]}"
        url = self.target_url + canary
        body_file = tempfile.mktemp(prefix="ghdb_bl_", suffix=".html")
        try:
            cmd = [
                "curl", "-s", "-o", body_file,
                "-w", "%{http_code}|%{size_download}",
                "--connect-timeout", str(self.timeout),
                "--max-time", str(self.timeout + 2),
            ]
            if self.cookie:
                cmd.extend(["-b", self.cookie])
            cmd.append(url)
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self.timeout + 5,
            )
            output = proc.stdout.strip()
            if not output:
                return
            parts = output.split("|", 1)
            status = int(parts[0]) if parts[0].isdigit() else 0
            size = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            if status == 200:
                self.baseline_size = size
        except Exception:
            pass
        finally:
            if os.path.exists(body_file):
                try:
                    os.remove(body_file)
                except OSError:
                    pass

    def _is_soft_404(self, response_size: int) -> bool:
        """Return True if the response size is within ±100 bytes of the baseline."""
        if self.baseline_size < 0:
            return False
        return abs(response_size - self.baseline_size) <= 100

    def execute_probes(self, probes: list[DorkProbe], max_probes: int) -> list[ProbeResult]:
        # Establish soft-404 baseline before scanning
        self._fetch_baseline()

        # Flatten probes into (probe, path) pairs
        tasks = []
        for probe in probes:
            for path in probe.paths:
                tasks.append((probe, path))
                if len(tasks) >= max_probes:
                    break
            if len(tasks) >= max_probes:
                break

        results = []
        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = {
                executor.submit(self._probe_path, probe, path): (probe, path)
                for probe, path in tasks
            }
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    results.append(result)

        return results

    def _probe_path(self, probe: DorkProbe, path: str) -> ProbeResult | None:
        url = self.target_url + path
        body_file = tempfile.mktemp(prefix="ghdb_", suffix=".html")

        try:
            cmd = [
                "curl", "-s",
                "-o", body_file,
                "-w", "%{http_code}|%{size_download}|%{content_type}",
                "--connect-timeout", str(self.timeout),
                "--max-time", str(self.timeout + 2),
            ]
            if self.cookie:
                cmd.extend(["-b", self.cookie])
            cmd.append(url)

            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self.timeout + 5,
            )

            output = proc.stdout.strip()
            if not output:
                return None

            parts = output.split("|", 2)
            http_status = int(parts[0]) if parts[0].isdigit() else 0
            response_size = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            content_type = parts[2] if len(parts) > 2 else ""

            # Skip non-results: connection failures, 404, and redirects.
            # Redirects (3xx) mean the path doesn't serve content directly —
            # following them would land on a login/error page and cause
            # false positives.
            if http_status == 0 or http_status == 404 or 300 <= http_status < 400:
                return None

            # Read body for pattern matching
            body = ""
            if os.path.exists(body_file):
                try:
                    with open(body_file, "r", errors="replace") as f:
                        body = f.read(8192)
                except Exception:
                    pass

            matched = False
            has_content_pattern = bool(probe.title_pattern or probe.body_pattern)

            # Title pattern check
            if probe.title_pattern and http_status == 200:
                title_match = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
                if title_match and probe.title_pattern.lower() in title_match.group(1).lower():
                    matched = True
                elif probe.title_pattern:
                    # Title pattern specified but not matched — skip unless body pattern matches
                    if not probe.body_pattern:
                        return None

            # Body pattern check
            if probe.body_pattern and http_status == 200:
                if probe.body_pattern.lower() in body.lower():
                    matched = True
                elif not matched:
                    # Body pattern specified but not matched
                    return None

            # No pattern specified — path existence is the finding,
            # but filter out soft-404 responses first (Fix 1).
            if not has_content_pattern and http_status == 200:
                if self._is_soft_404(response_size):
                    return None
                matched = True

            # 403 is informational (path exists but forbidden)
            if http_status == 403:
                matched = True

            if not matched and http_status not in (200, 403):
                return None

            body_preview = body[:300].replace("\n", " ").strip() if body else ""
            from_filetype = path in probe.filetype_paths

            return ProbeResult(
                probe=probe,
                url=url,
                path=path,
                http_status=http_status,
                response_size=response_size,
                content_type=content_type,
                body_preview=body_preview,
                matched=matched,
                from_filetype=from_filetype,
            )

        except (subprocess.TimeoutExpired, Exception):
            return None
        finally:
            if os.path.exists(body_file):
                try:
                    os.remove(body_file)
                except OSError:
                    pass


# ---------------------------------------------------------------------------
# Result post-processing
# ---------------------------------------------------------------------------
def _deduplicate_by_url(results: list[ProbeResult]) -> list[ProbeResult]:
    """Keep the highest-severity result per unique URL (Fix 3)."""
    by_url: dict[str, ProbeResult] = {}
    for r in results:
        if r.url not in by_url:
            by_url[r.url] = r
        else:
            existing_sev = SEVERITY_MAP.get(by_url[r.url].probe.category, "info")
            new_sev = SEVERITY_MAP.get(r.probe.category, "info")
            if SEVERITY_RANK.get(new_sev, 3) < SEVERITY_RANK.get(existing_sev, 3):
                by_url[r.url] = r
    return list(by_url.values())


def _effective_description(result: ProbeResult) -> str:
    """Return an accurate description — generic label for filetype-expanded probes (Fix 4)."""
    if result.from_filetype:
        filename = result.path.rsplit("/", 1)[-1] if "/" in result.path else result.path
        return f"Exposed file: {filename} (generic filetype probe)"
    return result.probe.description


def _result_severity(result: ProbeResult) -> str:
    """Compute effective severity for a result."""
    if result.http_status == 403:
        return "info"
    sev = SEVERITY_MAP.get(result.probe.category, "info")
    # Filetype-expanded probes are generic path checks — cap at "low"
    # regardless of the original GHDB category (e.g. robots.txt should
    # not be "high" just because the dork was in "Files Containing Passwords").
    if result.from_filetype and SEVERITY_RANK.get(sev, 3) < SEVERITY_RANK.get("low", 3):
        return "low"
    return sev


# ---------------------------------------------------------------------------
# Output formatting — summary-first for LLM truncation resilience (Fix 2)
# ---------------------------------------------------------------------------
def format_results(
    target_url: str,
    intensity: str,
    total_entries: int,
    convertible_count: int,
    total_probes: int,
    results: list[ProbeResult],
    baseline_size: int,
) -> str:
    lines = [
        "=== GHDB Dork Scanner ===",
        f"Target: {target_url}",
        f"Intensity: {intensity}",
        f"GHDB entries loaded: {total_entries}",
        f"Convertible dorks: {convertible_count}",
        f"Total probes executed: {total_probes}",
    ]

    if baseline_size >= 0:
        lines.append(f"Soft-404 baseline: {baseline_size} bytes (responses within +/-100 bytes filtered)")
    else:
        lines.append("Soft-404 baseline: not detected (target returns proper 404s)")

    # Filter, deduplicate, and sort
    findings = [r for r in results if r.matched]
    findings = _deduplicate_by_url(findings)
    findings.sort(key=lambda r: SEVERITY_RANK.get(_result_severity(r), 3))

    lines.append("")
    lines.append("=== Scan Complete ===")
    lines.append(f"Findings: {len(findings)}")
    lines.append("")

    # --- Compact summary — one line per finding, highest severity first ---
    # This section is designed to survive LLM output truncation.
    if findings:
        lines.append("=== Summary (highest severity first) ===")
        for r in findings:
            sev = _result_severity(r)
            desc = _effective_description(r)
            lines.append(f"[{sev}] {r.url} -> {r.http_status} ({r.response_size} bytes) | {desc}")
        lines.append("")

    # --- Detailed findings ---
    for i, result in enumerate(findings, 1):
        severity = _result_severity(result)
        status_note = ""
        if result.http_status == 403:
            status_note = " (forbidden — path exists)"

        desc = _effective_description(result)

        lines.append(f"--- Finding {i} ---")
        lines.append(f"GHDB ID: {result.probe.ghdb_id}")
        lines.append(f"Category: {result.probe.category}")
        lines.append(f"Severity Hint: {severity}")
        lines.append(f"Description: {desc}")
        lines.append(f"Original Dork: {result.probe.original_query}")
        lines.append(f"URL: {result.url}{status_note}")
        lines.append(f"HTTP Status: {result.http_status}")
        lines.append(f"Response Size: {result.response_size} bytes")
        lines.append(f"Content-Type: {result.content_type}")
        if result.body_preview:
            lines.append(f"Body Preview: {result.body_preview}")
        lines.append("")

    lines.append("=== End GHDB Scan ===")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="GHDB Dork Scanner")
    parser.add_argument("--target-url", required=True, help="Target base URL (e.g. http://10.0.0.1:8080)")
    parser.add_argument("--intensity", choices=["quick", "standard", "thorough"], default="standard")
    parser.add_argument("--cookie", default="", help="Cookie string for authenticated scanning")
    parser.add_argument("--ghdb-path", default="/pentest/data/ghdb.xml", help="Path to ghdb.xml")
    args = parser.parse_args()

    # Locate ghdb.xml — try container path first, then local project path
    ghdb_path = args.ghdb_path
    if not os.path.exists(ghdb_path):
        local_path = os.path.join(os.path.dirname(__file__), "..", "data", "ghdb.xml")
        if os.path.exists(local_path):
            ghdb_path = local_path
        else:
            print(f"ERROR: ghdb.xml not found at {args.ghdb_path}", file=sys.stderr)
            sys.exit(1)

    # Load and filter database
    db = GHDBDatabase(ghdb_path)
    categories = CATEGORY_MAP.get(args.intensity)
    filtered = db.filter_entries(categories)

    # Convert to probes
    probes = []
    for entry in filtered:
        probe = DorkConverter.convert(entry)
        if probe is not None:
            probes.append(probe)

    config = INTENSITY_CONFIG[args.intensity]

    # Count total probe paths
    total_probe_count = 0
    for p in probes:
        total_probe_count += len(p.paths)
        if total_probe_count >= config["max_probes"]:
            total_probe_count = config["max_probes"]
            break

    # Execute probes
    executor = ProbeExecutor(
        target_url=args.target_url,
        cookie=args.cookie,
        timeout=config["timeout"],
        concurrency=config["concurrency"],
    )
    results = executor.execute_probes(probes, max_probes=config["max_probes"])

    # Format and print output
    output = format_results(
        target_url=args.target_url,
        intensity=args.intensity,
        total_entries=len(db.entries),
        convertible_count=len(probes),
        total_probes=total_probe_count,
        results=results,
        baseline_size=executor.baseline_size,
    )
    print(output)


if __name__ == "__main__":
    main()
