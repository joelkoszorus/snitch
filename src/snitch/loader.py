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


def _iter_blob(content: str) -> Iterator[dict]:
    """Parse a string that may be a single JSON value or NDJSON (one object per line)."""
    content = content.strip()
    if not content:
        return

    # Try parsing the whole blob as one JSON value first (handles arrays and
    # single objects, including large pastes that span multiple lines).
    try:
        yield from _iter_parsed(json.loads(content))
        return
    except json.JSONDecodeError:
        pass

    # Fall back to NDJSON: parse line by line.
    for lineno, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            yield from _iter_parsed(json.loads(line))
        except json.JSONDecodeError as exc:
            print(f"Warning: skipping malformed JSON on line {lineno}: {exc}", file=sys.stderr)


def read_clipboard() -> str:
    """Return clipboard contents using the first available system utility.

    Tries xclip, xsel, and wl-paste in order. Raises RuntimeError if none
    are installed.
    """
    import subprocess

    candidates = [
        ["xclip", "-o", "-selection", "clipboard"],
        ["xsel", "--output", "--clipboard"],
        ["wl-paste"],
    ]
    for cmd in candidates:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return result.stdout
        except FileNotFoundError:
            continue
    raise RuntimeError(
        "No clipboard utility found. Install xclip, xsel, or wl-paste."
    )


def iter_events(source: str | None) -> Iterator[dict]:
    """Yield native EVE dicts from *source* path or stdin.

    Transparently handles native EVE NDJSON, Elasticsearch hit documents,
    and JSON arrays of either.
    """
    if source is None:
        if sys.stdin.isatty():
            print("Paste JSON below, then press Ctrl+D:", file=sys.stderr)
        # Read all stdin at once — avoids the ~4096-byte terminal line-buffer
        # limit that truncates large pastes when reading line by line.
        yield from _iter_blob(sys.stdin.read())
    else:
        path = Path(source)
        yield from _iter_blob(path.read_text(encoding="utf-8"))
