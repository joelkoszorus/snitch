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
  - Time observed
  - Network direction
  - Source and destination IPs and ports
  - Protocol
- Extract **IOCs** where available (missing fields are silently skipped):
  - Suspicious IP — context-aware: source for inbound, destination for outbound traffic
  - Protocol string (TLS SNI, DNS query name, HTTP hostname, or transport protocol)
  - URL path
  - HTTP User-Agent
  - GeoIP country and city
- Accepts native Suricata EVE NDJSON **and** Elasticsearch/Kibana export format
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
EVENT #1  [alert]  2026-03-07T02:45:27.711914+0000
------------------------------------------------------------
KEY DETAILS
  Alert Signature:       ET INFO Outgoing Basic Auth Base64 HTTP Password detected unencrypted
  Category:              Potential Corporate Privacy Violation
  Severity:              1
  Time Observed:         2026-03-07T02:45:27.711914+0000
  Network Direction:     Inbound -> Server
  Source IP:             192.168.11.15
  Source Port:           55842
  Destination IP:        192.168.20.25
  Destination Port:      80
  Protocol:              TCP

IOCs
  Suspicious IP:         192.168.11.15
  URL Path:              /lf/+LF/sess/cur
  User-Agent:            WebLink (11.0.2506.19) (LFRA/11.1.2409.553)
------------------------------------------------------------
```

### JSON (`--format json`)

```json
[
  {
    "event_type": "alert",
    "timestamp": "2026-03-07T02:45:27.711914+0000",
    "key_details": {
      "Alert Signature": "ET INFO Outgoing Basic Auth Base64 HTTP Password detected encrypted",
      "Category": "Potential Corporate Privacy Violation",
      "Severity": 1,
      "Time Observed": "2026-03-07T02:45:27.711914+0000",
      "Network Direction": "Inbound -> Server",
      "Source IP": "192.168.11.15",
      "Source Port": 55842,
      "Destination IP": "192.168.20.25",
      "Destination Port": 80,
      "Protocol": "TCP"
    },
    "iocs": {
      "Suspicious IP": "192.168.11.15",
      "URL Path": "/lf/+LF/sess/cur",
      "User-Agent": "WebLink (11.0.2506.19) (LFRA/11.1.2409.553)"
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
