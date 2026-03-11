# snitch 🤫

A command-line tool for extracting and presenting structured intelligence from [Suricata](https://suricata.io/) EVE JSON logs. Designed for SOC analysts who need to quickly pull key details and IOCs from raw event data without parsing through noise.

---

## Overview

Suricata's EVE JSON output is verbose. `snitch` cuts through that verbosity and surfaces the fields that matter most for triage and reporting — alert signatures, network context, indicators of compromise, and more — in a clean, readable format.

---

## Features

- Parse Suricata EVE JSON from a file or stdin
- Extract structured **Key Details** per alert event:
  - Alert signature, category, and severity
  - CVE identifier (when present in rule metadata)
  - Time observed
  - Network direction
  - Source and destination IPs and ports
  - Protocol
- Extract **IOCs** where available (missing fields are silently skipped):
  - Suspicious IP — context-aware: source for inbound, destination for outbound; inferred from RFC1918 ranges when direction is absent
  - Protocol string (TLS SNI, DNS query name, HTTP hostname, or transport protocol)
  - URL path
  - HTTP User-Agent
  - GeoIP country and city (recovered from Elasticsearch enrichment fields when not present in native EVE)
- Accepts native Suricata EVE NDJSON **and** Elasticsearch/Kibana export format
- Handles single events or multi-event JSON arrays — paste directly from Kibana
- Output as human-readable text or JSON
- Filter by signature keyword or limit event count

---

## Installation

Requires Python 3.10+. No additional dependencies.

```bash
git clone https://github.com/yourusername/snitch.git
cd snitch
./install.sh
```

`install.sh` creates a symlink at `~/.local/bin/snitch`, which is in `$PATH` by default on most Linux distributions. After that, `snitch` works as a bare command from any directory.

If `~/.local/bin` is not in your PATH, the script will tell you and show the one line to add to your shell config.

### Optional: install as a package

```bash
pip install .          # standard install
pip install -e .       # editable/development install
```

---

## Usage

```text
snitch [OPTIONS] [FILE]
```

### Examples

Parse a local EVE log file:

```bash
snitch eve.json
```

Output as JSON:

```bash
snitch eve.json --format json
```

Filter by signature keyword (case-insensitive):

```bash
snitch eve.json --sig "ET MALWARE"
```

Limit output to the first N matching events:

```bash
snitch eve.json --limit 10
```

---

## Input Format Compatibility

`snitch` transparently handles multiple input shapes:

| Format | Description |
| --- | --- |
| Native EVE NDJSON | One JSON object per line from `/var/log/suricata/eve.json` |
| Elasticsearch hit | `{"_index": ..., "fields": {...}}` — raw EVE is extracted from `fields.message` |
| JSON array | Array of either of the above (e.g. copy-pasted from Kibana) |

---

## Output

### Text (default)

```text
------------------------------------------------------------
[alert]  2026-03-10T04:07:43.014112+0000
------------------------------------------------------------
KEY DETAILS
  Alert Signature:       ET EXPLOIT Apache HTTP Server 2.4.49 - Path Traversal Attempt (CVE-2021-41773) M2
  Category:              Attempted Administrator Privilege Gain
  Severity:              1
  CVE:                   CVE-2021-41773
  Time Observed:         2026-03-10T04:07:43.014112+0000
  Network Direction:     Inbound -> Server
  Source IP:             165.245.168.176
  Source Port:           37214
  Destination IP:        10.62.0.12
  Destination Port:      80
  Protocol:              TCP

IOCs
  Suspicious IP:         165.245.168.176
  Protocol String:       107.0.29.102
  URL Path:              /cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh
  User-Agent:            libredtail-http
  GeoIP Country:         United States
------------------------------------------------------------
```

### JSON (`--format json`)

```json
[
  {
    "event_type": "alert",
    "timestamp": "2026-03-10T04:07:43.014112+0000",
    "key_details": {
      "Alert Signature": "ET EXPLOIT Apache HTTP Server 2.4.49 - Path Traversal Attempt (CVE-2021-41773) M2",
      "Category": "Attempted Administrator Privilege Gain",
      "Severity": 1,
      "CVE": "CVE-2021-41773",
      "Time Observed": "2026-03-10T04:07:43.014112+0000",
      "Network Direction": "Inbound -> Server",
      "Source IP": "165.245.168.176",
      "Source Port": 37214,
      "Destination IP": "10.62.0.12",
      "Destination Port": 80,
      "Protocol": "TCP"
    },
    "iocs": {
      "Suspicious IP": "165.245.168.176",
      "Protocol String": "107.0.29.102",
      "URL Path": "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh",
      "User-Agent": "libredtail-http",
      "GeoIP Country": "United States"
    }
  }
]
```

---

## CLI Reference

| Flag | Description |
| --- | --- |
| `FILE` | Path to EVE JSON log file. |
| `--format` | Output format: `text` (default) or `json` |
| `--type TYPE` | Filter by event type (default: `alert`) |
| `--sig PATTERN` | Filter alerts by signature substring (case-insensitive) |
| `--limit N` | Show only the first N matching events |
| `--no-iocs` | Suppress the IOCs section |
| `--no-color` | Disable colored output |

---

## Project Structure

```text
snitch/
├── snitch                    # executable entry point (no install needed)
├── install.sh                # symlinks snitch into ~/.local/bin
├── src/
│   └── snitch/
│       ├── __init__.py       # version
│       ├── cli.py            # argument parsing and pipeline orchestration
│       ├── loader.py         # EVE JSON reader — handles native, ES, and array formats
│       ├── normalize.py      # field normalization across EVE variants
│       ├── formatter.py      # text and JSON rendering
│       └── extractors/
│           └── alert.py      # key details and IOC extraction for alert events
├── tests/
│   ├── samples/              # suricata export samples for testing
│   └── test_alert_extractor.py
├── pyproject.toml
└── README.md
```

---

## CI Workflows

| Workflow | Trigger | Purpose |
| --- | --- | --- |
| **CodeQL Analysis** | Push / PR to `main`, weekly (Mon 08:00 UTC) | Static analysis of Python source using GitHub's `security-extended` query suite. Flags injection, path traversal, insecure deserialization, and other CWEs. Results appear in the repo's Security → Code scanning tab. |
| **Gitleaks Secret Scan** | Push / PR to `main` | Scans the full git history for accidentally committed secrets — API keys, tokens, private keys, credentials — using Gitleaks' built-in ruleset (150+ detectors). Fails the check if a match is found. |

---

## License

MIT
