<div align="center">

# Sekura

**Autonomous AI penetration testing agent written in Rust.**

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/sekura-ai/sekura)](https://github.com/sekura-ai/sekura/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/sekura-ai/sekura/release.yml?label=CI)](https://github.com/sekura-ai/sekura/actions)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

```
curl -fsSL https://sekura.ai/install.sh | bash
```

[Website](https://sekura.ai) · [GitHub](https://github.com/sekura-ai/sekura)

---
</div>

## What is Sekura?

Your team ships code every day. Your pentest happens once a year. Sekura closes that gap.

Sekura orchestrates **50+ security tools** inside a Kali Linux Docker container, drives vulnerability analysis and exploitation through **13 LLM agents**, and produces professional security assessment reports — all from a single command.

It combines **white-box source code analysis** with **black-box dynamic exploitation** across a 5-phase pipeline, giving you real exploits with proof-of-concept evidence, not just alerts.

## Features

- **5-phase scan pipeline** — white-box analysis, reconnaissance, vulnerability analysis, exploitation, and reporting
- **13 specialized AI agents** — 5 concurrent vuln analyzers + 5 concurrent exploit agents + whitebox, recon, and reporting agents
- **50+ tool techniques** across 9 OSI layers driven by declarative YAML definitions
- **OWASP WSTG v4.2 coverage tracking** — 97 test cases mapped to techniques with gap analysis
- **Multiple LLM providers** — Anthropic Claude, OpenAI, Google Gemini, OpenRouter, or self-hosted via Ollama
- **Three interfaces** — interactive REPL, direct CLI, and REST API with SQLite backend
- **Professional reporting** — HTML dashboard, executive summary, per-category evidence files, machine-readable JSON findings with CWE/CVSS scoring
- **Cost controls** — per-scan budget limits, real-time cost tracking, cost warnings
- **Crash-safe audit logging** — append-only JSONL event log, atomic session metrics, human-readable workflow log
- **Authenticated scanning** — form login with CSRF handling, cookie injection, TOTP 2FA support
- **Scope rules** — focus and avoid path patterns to control what gets tested

## Quick Start

### Install the binary

```bash
curl -fsSL https://sekura.ai/install.sh | bash
```

Or download a pre-built binary from [GitHub Releases](https://github.com/sekura-ai/sekura/releases).

### Build from source

```bash
git clone https://github.com/sekura-ai/sekura.git
cd sekura
cargo build --release
```

### Prerequisites

- **Docker** (Docker Desktop or Docker Engine)
- An LLM API key (Anthropic, OpenAI, etc.) — or a local Ollama instance

### Build the Kali Docker image

```bash
docker build -t sekura-kali:latest -f docker/Dockerfile.kali docker/
```

### Run

```bash
# Launch the interactive REPL
sekura

# Inside the REPL:
sekura> /init                          # Set up Docker + LLM provider
sekura> /scan --target http://target:8080
sekura> /report                        # Browse scan results
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  REPL / CLI / REST API                                  │
├─────────────────────────────────────────────────────────┤
│  Pipeline Orchestrator                                  │
│  ┌────────┐ ┌──────┐ ┌───────┐ ┌───────┐ ┌──────────┐ │
│  │Whitebox│→│Recon │→│ Vuln  │→│Exploit│→│ Reporting │ │
│  │Analysis│ │      │ │ (x5)  │ │ (x5)  │ │          │ │
│  └────────┘ └──────┘ └───────┘ └───────┘ └──────────┘ │
├─────────────────────────────────────────────────────────┤
│  Kali Linux Docker Container                            │
│  nmap · sqlmap · nikto · hydra · metasploit · 20+ more  │
├─────────────────────────────────────────────────────────┤
│  LLM Providers                                          │
│  Anthropic · OpenAI · Gemini · OpenRouter · Ollama      │
└─────────────────────────────────────────────────────────┘
```

## Pipeline

Sekura runs a 5-phase pipeline. Each phase builds on the outputs of the previous one.

### Phase 1 — White-Box Analysis

LLM-driven source code review. Identifies potential vulnerabilities from code patterns, SQL queries, authentication logic, input validation, and more. Skipped automatically if no `--repo` is provided.

### Phase 2 — Reconnaissance

Executes tool techniques inside the Kali container across 9 OSI layers — from ARP scanning and DNS enumeration through port scanning, service fingerprinting, TLS auditing, directory brute-forcing, and application-level probes.

### Phase 3 — Vulnerability Analysis

Five LLM agents run concurrently, each specializing in a vulnerability class:

| Agent | Focus |
|-------|-------|
| Injection | SQL injection, command injection, LDAP injection |
| XSS | Reflected, stored, and DOM-based cross-site scripting |
| Auth | Authentication bypass, weak credentials, session issues |
| SSRF | Server-side request forgery, open redirects |
| AuthZ | Authorization bypass, IDOR, privilege escalation |

Each agent correlates white-box findings, recon data, and tool output to produce a prioritized exploitation queue.

### Phase 4 — Exploitation

Five matching exploit agents attempt proof-of-concept exploitation against queued targets. Each finding receives a verdict:

| Verdict | Meaning |
|---------|---------|
| `EXPLOITED` | Successfully demonstrated impact |
| `BLOCKED_BY_SECURITY` | Valid vulnerability, blocked by WAF/controls |
| `POTENTIAL` | Code analysis suggests vulnerability, live test inconclusive |
| `FALSE_POSITIVE` | Not actually vulnerable after testing |
| `OUT_OF_SCOPE_INTERNAL` | Requires internal access, not pursued |

### Phase 5 — Reporting

Assembles all evidence into multiple deliverable formats, refined by LLM for professional presentation.

## Usage

### CLI Mode

```bash
# Direct scan without entering the REPL
sekura scan --target http://target:8080 --intensity standard

# With authentication
sekura scan --target http://target --cookie "session=abc123"

# With source code for white-box + black-box combined analysis
sekura scan --target http://target --repo /path/to/source

# With config file
sekura scan --config config.yaml

# Set a cost budget
sekura scan --target http://target --max-cost 2.00

# Start the REST API server
sekura serve --port 8080
```

### REPL Commands

| Command | Description |
|---------|-------------|
| `/init` | Set up Docker container and LLM provider interactively |
| `/scan --target <url>` | Start a penetration test |
| `/status` | Show pipeline progress, phase, cost, findings count |
| `/findings [--severity X]` | List discovered vulnerabilities |
| `/agents` | Show agent status (running, completed, failed) |
| `/report` | Browse scan results — interactive scan picker + summary dashboard |
| `/report findings` | Numbered findings list with severity, CWE, CVSS |
| `/report finding <N>` | Detailed view of finding N |
| `/report executive` | Executive summary with severity breakdown |
| `/report evidence <cat>` | Evidence for a category (injection, xss, auth, ssrf, authz) |
| `/report full` | Full markdown report |
| `/report html` | Open HTML report in browser |
| `/stop` | Cancel a running scan |
| `/config [key] [value]` | View or set defaults (provider, model, intensity, output) |
| `/container [action]` | Manage the Kali Docker container (status, start, stop, rebuild) |
| `/serve [--port N]` | Start the REST API server in the background |
| `/history` | Show past scan history |
| `/help [command]` | Show help |

### REST API

Start the API server with `sekura serve --port 8080` or `/serve` inside the REPL.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/scans` | Create a new scan |
| `GET` | `/api/v1/scans` | List all scans |
| `GET` | `/api/v1/scans/{id}` | Get scan details |
| `DELETE` | `/api/v1/scans/{id}` | Delete a scan |
| `POST` | `/api/v1/scans/{id}/stop` | Stop a running scan |
| `GET` | `/api/v1/scans/{id}/findings` | Get findings for a scan |
| `GET` | `/api/v1/reports/{id}` | Get the report for a scan |
| `GET` | `/api/v1/settings` | Get settings |
| `POST` | `/api/v1/settings` | Update settings |
| `GET` | `/health` | Health check |

### Configuration File

```yaml
# config.yaml
authentication:
  login_type: form
  login_url: http://target/login
  credentials:
    username: admin
    password: password123

rules:
  avoid:
    - description: "Don't scan admin panel"
      type: path
      url_path: /admin
  focus:
    - description: "Focus on API"
      type: path
      url_path: /api

scan:
  intensity: standard     # quick | standard | thorough
  layers:
    - network
    - application

llm:
  provider: anthropic
  model: claude-sonnet-4-5-20250929

container:
  image: sekura-kali:latest
  network_mode: host
```

### LLM Providers

| Provider | Default Model | Environment Variable |
|----------|--------------|---------------------|
| Anthropic | Claude Sonnet 4.5 | `ANTHROPIC_API_KEY` |
| OpenAI | GPT-4o | `OPENAI_API_KEY` |
| Google Gemini | Gemini 2.0 | `GOOGLE_API_KEY` |
| OpenRouter | Any | `OPENROUTER_API_KEY` |
| Local / Ollama | Configurable | None (default: `http://localhost:11434/v1`) |

## Output Structure

```
results/<scan-id>/
├── deliverables/
│   ├── findings.json                                # Machine-readable findings (CWE, CVSS, verdicts)
│   ├── session_metrics.json                         # Scan metadata (target, cost, duration)
│   ├── tool_findings_report.md                      # Raw tool output findings
│   ├── comprehensive_security_assessment_report.md  # Executive report (markdown)
│   ├── report.html                                  # HTML dashboard report
│   ├── wstg_coverage_report.md                      # OWASP WSTG coverage analysis
│   ├── code_analysis_deliverable.md                 # White-box analysis output
│   ├── recon_deliverable.md                         # Reconnaissance summary
│   ├── injection_exploitation_evidence.md           # Per-category evidence files
│   ├── xss_exploitation_evidence.md
│   ├── auth_exploitation_evidence.md
│   ├── ssrf_exploitation_evidence.md
│   └── authz_exploitation_evidence.md
├── audit-logs/
│   ├── audit_events.jsonl                           # Crash-safe event log
│   ├── session.json                                 # Atomic session summary
│   └── workflow.log                                 # Human-readable log
└── prompts/                                         # Saved prompt templates
```

## Disclaimers

> [!WARNING]
> **Do NOT run Sekura against production environments.**
> It actively executes exploits to confirm vulnerabilities. This can create users, modify data, and trigger unintended side effects. Use sandboxed, staging, or local development environments only.

> [!CAUTION]
> **Authorized use only.** You must have explicit written permission from the system owner before running Sekura. Unauthorized scanning and exploitation is illegal under laws such as the Computer Fraud and Abuse Act (CFAA).

LLM-generated findings require human review. While Sekura's "proof-by-exploitation" methodology minimizes false positives, the underlying models can still produce hallucinated or weakly-supported content. Verify all findings before acting on them.

## License

Sekura is released under the [GNU Affero General Public License v3.0 (AGPL-3.0)](LICENSE).

You may use and modify Sekura freely for internal security testing. The AGPL's sharing requirements apply primarily to organizations offering Sekura as a public or managed service — in those cases, modifications to the core software must be open-sourced.

## Community & Support

- Report bugs via [GitHub Issues](https://github.com/sekura-ai/sekura/issues)
- Feature requests via [GitHub Discussions](https://github.com/sekura-ai/sekura/discussions)

---

<p align="center">
  <b>Built by the Sekura team</b><br>
  <i>Making application security accessible to everyone</i>
</p>
