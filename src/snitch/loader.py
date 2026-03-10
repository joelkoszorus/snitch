"""Load Suricata EVE JSON (NDJSON) from a file path or stdin."""
import json
import sys
from pathlib import Path
from typing import Iterator


def iter_events(source: str | None) -> Iterator[dict]:
    """Yield parsed JSON objects one per line from *source* path or stdin."""
    if source is None:
        lines = sys.stdin
    else:
        lines = Path(source).open(encoding="utf-8")

    try:
        for lineno, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"Warning: skipping malformed JSON on line {lineno}: {exc}", file=sys.stderr)
    finally:
        if source is not None:
            lines.close()
