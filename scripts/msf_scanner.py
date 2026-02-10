#!/usr/bin/env python3
"""
Metasploit Auxiliary Scanner — maps open ports to MSF auxiliary modules,
generates a batched resource script, runs msfconsole once, and emits
structured findings for LLM analysis.

Self-contained script designed to run inside the Kali container.
Uses only Python stdlib + msfconsole subprocess.

Usage:
    python3 /pentest/msf_scanner.py \
        --target 10.0.0.1 \
        --ports 22,80,443,445,3306 \
        --intensity standard
"""

import argparse
import os
import re
import subprocess
import sys
import textwrap
import time


# ---------------------------------------------------------------------------
# Port-to-module mapping — auxiliary/scanner modules only (no exploitation)
# ---------------------------------------------------------------------------
# Each entry: (module_path, display_name, extra_options_dict, severity_hint)
MODULE_MAP: dict[int, list[tuple[str, str, dict, str]]] = {
    21: [
        ("auxiliary/scanner/ftp/ftp_version", "FTP Version Detection", {}, "info"),
        ("auxiliary/scanner/ftp/anonymous", "FTP Anonymous Login", {}, "high"),
    ],
    22: [
        ("auxiliary/scanner/ssh/ssh_version", "SSH Version Detection", {}, "info"),
        ("auxiliary/scanner/ssh/ssh_enumusers", "SSH User Enumeration", {
            "USER_FILE": "/usr/share/wordlists/metasploit/unix_users.txt",
            "THRESHOLD": "3",
        }, "medium"),
    ],
    23: [
        ("auxiliary/scanner/telnet/telnet_version", "Telnet Version Detection", {}, "info"),
    ],
    25: [
        ("auxiliary/scanner/smtp/smtp_version", "SMTP Version Detection", {}, "info"),
        ("auxiliary/scanner/smtp/smtp_enum", "SMTP User Enumeration", {}, "medium"),
    ],
    53: [
        ("auxiliary/scanner/dns/dns_amp", "DNS Amplification Check", {}, "medium"),
    ],
    80: [
        ("auxiliary/scanner/http/http_version", "HTTP Version Detection", {}, "info"),
        ("auxiliary/scanner/http/robots_txt", "HTTP robots.txt", {}, "low"),
        ("auxiliary/scanner/http/http_header", "HTTP Header Analysis", {}, "low"),
        ("auxiliary/scanner/http/dir_listing", "HTTP Directory Listing", {}, "medium"),
        ("auxiliary/scanner/http/http_put", "HTTP PUT Method", {}, "high"),
        ("auxiliary/scanner/http/webdav_scanner", "WebDAV Detection", {}, "medium"),
    ],
    110: [
        ("auxiliary/scanner/pop3/pop3_version", "POP3 Version Detection", {}, "info"),
    ],
    111: [
        ("auxiliary/scanner/nfs/nfsmount", "NFS Mount Enumeration", {}, "medium"),
    ],
    143: [
        ("auxiliary/scanner/imap/imap_version", "IMAP Version Detection", {}, "info"),
    ],
    443: [
        ("auxiliary/scanner/http/http_version", "HTTPS Version Detection", {
            "SSL": "true",
        }, "info"),
        ("auxiliary/scanner/http/ssl_version", "SSL/TLS Version Scan", {}, "medium"),
        ("auxiliary/scanner/http/http_header", "HTTPS Header Analysis", {
            "SSL": "true",
        }, "low"),
    ],
    445: [
        ("auxiliary/scanner/smb/smb_version", "SMB Version Detection", {}, "info"),
        ("auxiliary/scanner/smb/smb_enumshares", "SMB Share Enumeration", {}, "medium"),
        ("auxiliary/scanner/smb/smb_enumusers", "SMB User Enumeration", {}, "medium"),
        ("auxiliary/scanner/smb/smb_ms17_010", "MS17-010 EternalBlue Check", {}, "critical"),
    ],
    1433: [
        ("auxiliary/scanner/mssql/mssql_ping", "MSSQL Ping", {}, "info"),
        ("auxiliary/scanner/mssql/mssql_login", "MSSQL Default Login", {
            "USERNAME": "sa",
            "PASSWORD": "",
            "BLANK_PASSWORDS": "true",
        }, "high"),
    ],
    1521: [
        ("auxiliary/scanner/oracle/tnslsnr_version", "Oracle TNS Version", {}, "info"),
    ],
    2049: [
        ("auxiliary/scanner/nfs/nfsmount", "NFS Mount Enumeration", {}, "medium"),
    ],
    3306: [
        ("auxiliary/scanner/mysql/mysql_version", "MySQL Version Detection", {}, "info"),
        ("auxiliary/scanner/mysql/mysql_login", "MySQL Default Login", {
            "USERNAME": "root",
            "PASSWORD": "",
            "BLANK_PASSWORDS": "true",
        }, "high"),
    ],
    3389: [
        ("auxiliary/scanner/rdp/rdp_scanner", "RDP Detection", {}, "info"),
        ("auxiliary/scanner/rdp/cve_2019_0708_bluekeep", "BlueKeep CVE-2019-0708", {}, "critical"),
    ],
    5432: [
        ("auxiliary/scanner/postgres/postgres_version", "PostgreSQL Version Detection", {}, "info"),
        ("auxiliary/scanner/postgres/postgres_login", "PostgreSQL Default Login", {
            "USERNAME": "postgres",
            "PASSWORD": "postgres",
        }, "high"),
    ],
    5900: [
        ("auxiliary/scanner/vnc/vnc_none_auth", "VNC No Authentication", {}, "critical"),
    ],
    6379: [
        ("auxiliary/scanner/redis/redis_server", "Redis Open Instance", {}, "high"),
    ],
    8080: [
        ("auxiliary/scanner/http/http_version", "HTTP Proxy Version", {
            "RPORT": "8080",
        }, "info"),
        ("auxiliary/scanner/http/robots_txt", "HTTP Proxy robots.txt", {
            "RPORT": "8080",
        }, "low"),
        ("auxiliary/scanner/http/http_header", "HTTP Proxy Header Analysis", {
            "RPORT": "8080",
        }, "low"),
        ("auxiliary/scanner/http/dir_listing", "HTTP Proxy Directory Listing", {
            "RPORT": "8080",
        }, "medium"),
    ],
    8443: [
        ("auxiliary/scanner/http/http_version", "HTTPS Alt Version", {
            "RPORT": "8443",
            "SSL": "true",
        }, "info"),
    ],
    27017: [
        ("auxiliary/scanner/mongodb/mongodb_login", "MongoDB Open Instance", {}, "high"),
    ],
}

# Modules to always run regardless of ports (host-level checks)
GENERIC_MODULES: list[tuple[str, str, dict, str]] = [
    ("auxiliary/scanner/portscan/tcp", "TCP Port Verification", {
        "PORTS": "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,27017",
    }, "info"),
]

# ---------------------------------------------------------------------------
# Intensity presets
# ---------------------------------------------------------------------------
INTENSITY_CONFIG = {
    "quick": {
        "max_modules": 10,
        "timeout_per_module": 30,
        "total_timeout": 300,
        "skip_brute": True,
        "skip_generic": True,
    },
    "standard": {
        "max_modules": 30,
        "timeout_per_module": 60,
        "total_timeout": 600,
        "skip_brute": False,
        "skip_generic": True,
    },
    "thorough": {
        "max_modules": 80,
        "timeout_per_module": 90,
        "total_timeout": 900,
        "skip_brute": False,
        "skip_generic": False,
    },
}

BRUTE_KEYWORDS = {"login", "enumusers", "anonymous", "none_auth"}

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ---------------------------------------------------------------------------
# Module selection
# ---------------------------------------------------------------------------
def select_modules(
    ports: list[int],
    intensity: str,
) -> list[tuple[str, str, dict, str, int]]:
    """Select MSF modules based on open ports and intensity.

    Returns list of (module_path, display_name, options, severity_hint, port).
    """
    config = INTENSITY_CONFIG[intensity]
    selected: list[tuple[str, str, dict, str, int]] = []
    seen_modules: set[str] = set()

    # Port-specific modules
    for port in sorted(ports):
        candidates = MODULE_MAP.get(port, [])
        for module_path, name, opts, sev in candidates:
            if config["skip_brute"] and any(kw in module_path for kw in BRUTE_KEYWORDS):
                continue
            # Dedup by module+port (same module on different ports is OK)
            key = f"{module_path}:{port}"
            if key in seen_modules:
                continue
            seen_modules.add(key)
            # Merge port into options if not already set
            merged_opts = dict(opts)
            if "RPORT" not in merged_opts:
                merged_opts["RPORT"] = str(port)
            selected.append((module_path, name, merged_opts, sev, port))

    # Generic modules
    if not config["skip_generic"]:
        for module_path, name, opts, sev in GENERIC_MODULES:
            key = f"{module_path}:0"
            if key not in seen_modules:
                seen_modules.add(key)
                selected.append((module_path, name, opts, sev, 0))

    # Sort: critical/high first, then by port
    selected.sort(key=lambda m: (SEVERITY_RANK.get(m[3], 4), m[4]))

    # Cap at max_modules
    return selected[: config["max_modules"]]


# ---------------------------------------------------------------------------
# Resource script generation
# ---------------------------------------------------------------------------
def generate_resource_script(
    target: str,
    modules: list[tuple[str, str, dict, str, int]],
    timeout_per_module: int,
) -> str:
    """Generate a batched msfconsole resource script (.rc).

    Uses module timeouts and spool for output capture.
    """
    lines = [
        "# Auto-generated MSF resource script",
        "spool /tmp/msf_output.txt",
        "",
    ]

    for i, (module_path, name, opts, sev, port) in enumerate(modules):
        lines.append(f"# --- Module {i + 1}: {name} (port {port}, severity {sev}) ---")
        lines.append(f"echo \"=== MSF_MODULE_START: {module_path} | {name} | port={port} | severity={sev} ===\"")
        lines.append(f"use {module_path}")
        lines.append(f"set RHOSTS {target}")
        lines.append(f"set THREADS 1")

        for key, val in opts.items():
            lines.append(f"set {key} {val}")

        lines.append("run")
        lines.append(f"echo \"=== MSF_MODULE_END: {module_path} ===\"")
        lines.append("")

    lines.append("spool off")
    lines.append("exit")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Output parsing
# ---------------------------------------------------------------------------
# ANSI escape code stripper
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|\x1b\].*?\x07")


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def parse_msf_output(raw: str) -> list[dict]:
    """Parse MSF spool output into structured module results.

    Splits on MSF_MODULE_START/END markers, extracts module metadata
    and raw output per module.
    """
    clean = strip_ansi(raw)
    results = []

    # Split by module markers
    module_pattern = re.compile(
        r"=== MSF_MODULE_START: (.+?) \| (.+?) \| port=(\d+) \| severity=(\w+) ===\s*"
        r"(.*?)"
        r"=== MSF_MODULE_END: \1 ===",
        re.DOTALL,
    )

    for match in module_pattern.finditer(clean):
        module_path = match.group(1).strip()
        name = match.group(2).strip()
        port = int(match.group(3))
        severity = match.group(4).strip()
        body = match.group(5).strip()

        # Filter noise lines — strip resource script boilerplate,
        # set confirmations, and progress noise so only actual scan
        # results remain for LLM analysis.
        useful_lines = []
        for line in body.split("\n"):
            stripped = line.strip()
            if not stripped:
                continue
            # Resource script echo lines
            if stripped.startswith("resource ("):
                continue
            # Set confirmation lines (e.g. "RHOSTS => 127.0.0.1")
            if " => " in stripped and not stripped.startswith(("[", "+")):
                continue
            # MSF exec echo lines
            if stripped.startswith("[*] exec:"):
                continue
            # MSF [!] warnings (unknown options, deprecations, etc.)
            if stripped.startswith("[!]") or "Unknown datastore option" in stripped:
                continue
            # Module completion noise
            if stripped.startswith("[*] Auxiliary module execution completed"):
                continue
            # Progress lines (e.g. "[*] Scanned 1 of 1 hosts")
            if stripped.startswith("[*] Scanned") and "complete" in stripped:
                continue
            # MSF banners and loading noise
            if stripped.startswith(("msf", "[*] Starting", "[*] Nmap:")):
                continue
            useful_lines.append(stripped)

        body_clean = "\n".join(useful_lines)

        # Determine if this module found something interesting
        has_finding = _has_finding(body_clean, module_path, severity)

        results.append({
            "module": module_path,
            "name": name,
            "port": port,
            "severity": severity,
            "output": body_clean,
            "has_finding": has_finding,
        })

    return results


def _has_finding(output: str, module_path: str, severity: str) -> bool:
    """Heuristic: does this module output indicate something actionable?"""
    lower = output.lower()

    # Positive indicators
    positive = [
        "is vulnerable",
        "vulnerable to",
        "anonymous access",
        "anonymous login",
        "login successful",
        "authenticated successfully",
        "access allowed",
        "no authentication",
        "writable",
        "ms17-010",
        "eternalblue",
        "bluekeep",
        "cve-",
        "valid credentials",
        "password found",
        "[+]",  # MSF positive result marker
    ]
    if any(p in lower for p in positive):
        return True

    # For version detection, any version string is informational
    if "version" in module_path and any(c.isdigit() for c in output):
        return True

    # Share/user enumeration with results
    if "enum" in module_path and len(output.split("\n")) > 2:
        return True

    # robots.txt with content
    if "robots" in module_path and ("disallow" in lower or "allow" in lower):
        return True

    return False


# ---------------------------------------------------------------------------
# Output formatting — summary-first for LLM truncation resilience
# ---------------------------------------------------------------------------
def format_results(
    target: str,
    ports: list[int],
    intensity: str,
    modules_selected: int,
    module_results: list[dict],
    elapsed: float,
) -> str:
    lines = [
        "=== Metasploit Auxiliary Scanner ===",
        f"Target: {target}",
        f"Open ports scanned: {','.join(str(p) for p in sorted(ports))}",
        f"Intensity: {intensity}",
        f"Modules selected: {modules_selected}",
        f"Modules completed: {len(module_results)}",
        f"Scan duration: {elapsed:.1f}s",
        "",
    ]

    findings = [r for r in module_results if r["has_finding"]]
    informational = [r for r in module_results if not r["has_finding"] and r["output"]]

    lines.append("=== Scan Complete ===")
    lines.append(f"Modules with findings: {len(findings)}")
    lines.append(f"Informational modules: {len(informational)}")
    lines.append("")

    # --- Compact summary (survives truncation) ---
    if findings:
        findings.sort(key=lambda r: SEVERITY_RANK.get(r["severity"], 4))
        lines.append("=== Summary (highest severity first) ===")
        for r in findings:
            preview = r["output"].split("\n")[0][:120] if r["output"] else "no output"
            lines.append(f"[{r['severity']}] {r['name']} (port {r['port']}) | {preview}")
        lines.append("")

    # --- Detailed findings ---
    for i, r in enumerate(findings, 1):
        lines.append(f"--- Finding {i} ---")
        lines.append(f"Module: {r['module']}")
        lines.append(f"Name: {r['name']}")
        lines.append(f"Port: {r['port']}")
        lines.append(f"Severity Hint: {r['severity']}")
        lines.append(f"Output:")
        # Indent module output and cap per-module output
        output_lines = r["output"].split("\n")[:50]
        for line in output_lines:
            lines.append(f"  {line}")
        if len(r["output"].split("\n")) > 50:
            lines.append(f"  ... ({len(r['output'].split(chr(10)))} lines total)")
        lines.append("")

    # --- Informational results (version strings, etc.) ---
    if informational:
        lines.append("=== Informational Results ===")
        for r in informational:
            first_line = r["output"].split("\n")[0][:120] if r["output"] else ""
            lines.append(f"[info] {r['name']} (port {r['port']}): {first_line}")
        lines.append("")

    # --- Modules with no output ---
    no_output = [r for r in module_results if not r["output"]]
    if no_output:
        lines.append(f"Modules with no output: {len(no_output)}")
        for r in no_output:
            lines.append(f"  - {r['name']} ({r['module']}, port {r['port']})")
        lines.append("")

    lines.append("=== End Metasploit Scan ===")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Metasploit Auxiliary Scanner")
    parser.add_argument(
        "--target", required=True,
        help="Target IP or hostname",
    )
    parser.add_argument(
        "--ports", required=True,
        help="Comma-separated list of open ports (e.g. 22,80,443,445)",
    )
    parser.add_argument(
        "--intensity",
        choices=["quick", "standard", "thorough"],
        default="standard",
    )
    args = parser.parse_args()

    # Parse ports
    ports = []
    for p in args.ports.split(","):
        p = p.strip()
        if p.isdigit():
            ports.append(int(p))
    if not ports:
        print("ERROR: No valid ports provided", file=sys.stderr)
        sys.exit(1)

    config = INTENSITY_CONFIG[args.intensity]

    # Select modules
    modules = select_modules(ports, args.intensity)
    if not modules:
        print("=== Metasploit Auxiliary Scanner ===")
        print(f"Target: {args.target}")
        print(f"Open ports: {args.ports}")
        print(f"No applicable MSF modules for the discovered ports.")
        print("=== End Metasploit Scan ===")
        sys.exit(0)

    # Generate resource script
    rc_content = generate_resource_script(
        target=args.target,
        modules=modules,
        timeout_per_module=config["timeout_per_module"],
    )

    rc_path = "/tmp/msf_scan.rc"
    output_path = "/tmp/msf_output.txt"

    # Clean up any previous output
    for path in [rc_path, output_path]:
        if os.path.exists(path):
            os.remove(path)

    # Write resource script
    with open(rc_path, "w") as f:
        f.write(rc_content)

    # Run msfconsole with resource script
    start = time.time()
    try:
        proc = subprocess.run(
            ["msfconsole", "-q", "-r", rc_path],
            capture_output=True,
            text=True,
            timeout=config["total_timeout"],
            env={**os.environ, "TERM": "dumb"},  # Suppress color
        )
        elapsed = time.time() - start

        # Read spool file (preferred — cleaner output)
        raw_output = ""
        if os.path.exists(output_path):
            with open(output_path, "r", errors="replace") as f:
                raw_output = f.read()

        # Fall back to stdout if spool is empty
        if not raw_output.strip():
            raw_output = proc.stdout or ""

        if proc.stderr:
            # Append non-trivial stderr
            stderr_useful = "\n".join(
                l for l in proc.stderr.split("\n")
                if l.strip() and not l.strip().startswith(("[*]", "[-]", "Warning:"))
            )
            if stderr_useful.strip():
                raw_output += "\n" + stderr_useful

    except subprocess.TimeoutExpired:
        elapsed = time.time() - start
        raw_output = ""
        if os.path.exists(output_path):
            with open(output_path, "r", errors="replace") as f:
                raw_output = f.read()
        raw_output += f"\n\nWARNING: msfconsole timed out after {config['total_timeout']}s"

    # Parse module results
    module_results = parse_msf_output(raw_output)

    # Format and print
    output = format_results(
        target=args.target,
        ports=ports,
        intensity=args.intensity,
        modules_selected=len(modules),
        module_results=module_results,
        elapsed=elapsed,
    )
    print(output)

    # Cleanup
    for path in [rc_path, output_path]:
        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass


if __name__ == "__main__":
    main()
