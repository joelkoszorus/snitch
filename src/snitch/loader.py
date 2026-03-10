"""Load Suricata EVE JSON (NDJSON) from a file path or stdin.

Supports three input shapes:
  - Native EVE NDJSON (one JSON object per line from /var/log/suricata/eve.json)
  - Elasticsearch search hit  ({"_index":..., "fields":{...}})
  - JSON array of either of the above (e.g. copy-pasted from Kibana export)
"""
import json
import sys
from pathlib import Path
from typing import Iterator


def _iter_parsed(raw) -> Iterator[dict]:
    """Recursively yield native EVE dicts from any supported wrapper format."""
    if isinstance(raw, list):
        for item in raw:
            yield from _iter_parsed(item)
        return

    if not isinstance(raw, dict):
        return

    # Elasticsearch search hit: {"_index": "...", "fields": {"src_ip": ["..."], ...}}
    # The complete original EVE JSON is stored as a string in fields.message[0].
    if "_index" in raw and "fields" in raw:
        fields = raw["fields"]
        messages = fields.get("message")
        if messages and isinstance(messages, list):
            try:
                yield json.loads(messages[0])
                return
            except (json.JSONDecodeError, TypeError):
                pass
        # Fallback: unwrap array values from ES fields into a flat dict
        yield {k: (v[0] if isinstance(v, list) and v else v) for k, v in fields.items()}
        return

    # Native EVE JSON — yield as-is
    yield raw


def iter_events(source: str | None) -> Iterator[dict]:
    """Yield native EVE dicts from *source* path or stdin.

    Transparently handles native EVE NDJSON, Elasticsearch hit documents,
    and JSON arrays of either.
    """
    if source is None:
        if sys.stdin.isatty():
            print("Paste JSON below, then press Ctrl+D:", file=sys.stderr)
        lines = sys.stdin
    else:
        lines = Path(source).open(encoding="utf-8")

    try:
        for lineno, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"Warning: skipping malformed JSON on line {lineno}: {exc}", file=sys.stderr)
                continue
            yield from _iter_parsed(raw)
    finally:
        if source is not None:
            lines.close()
