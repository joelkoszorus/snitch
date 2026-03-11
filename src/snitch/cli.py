"""Command-line interface for snitch."""
import argparse
import sys
from pathlib import Path

from snitch import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="snitch",
        description="Extract key details and IOCs from Suricata EVE JSON logs.",
    )
    parser.add_argument(
        "file",
        nargs="?",
        metavar="FILE",
        help="EVE JSON log file. Omit to read from stdin.",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--type",
        dest="event_type",
        metavar="TYPE",
        help="Filter by event type: alert, http, dns, tls, flow (default: alert)",
    )
    parser.add_argument(
        "--sig",
        metavar="PATTERN",
        help="Filter alerts by signature substring (case-insensitive)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        metavar="N",
        help="Show only the first N matching events",
    )
    parser.add_argument(
        "--no-iocs",
        action="store_true",
        help="Suppress the IOCs section",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"snitch {__version__}",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    from snitch.loader import iter_events
    from snitch.normalize import normalize
    from snitch.extractors.alert import extract as extract_alert
    from snitch.formatter import render_text, render_json

    # Validate file path before processing
    if args.file is not None:
        path = Path(args.file)
        if not path.is_file():
            print(f"snitch: file not found: {args.file}", file=sys.stderr)
            sys.exit(1)

    color = not args.no_color and sys.stdout.isatty()
    show_iocs = not args.no_iocs
    target_type = args.event_type or "alert"

    json_records = []
    text_buffer  = []  # (index, norm, result) — held until count is known
    count = 0

    for raw in iter_events(args.file):
        norm = normalize(raw)

        if norm.get("event_type") != target_type:
            continue

        if args.sig:
            sig = (norm.get("alert_signature") or "").lower()
            if args.sig.lower() not in sig:
                continue

        if args.limit is not None and count >= args.limit:
            break

        result = extract_alert(norm)
        count += 1

        if args.format == "json":
            json_records.append({
                "event_type": norm.get("event_type"),
                "timestamp":  norm.get("timestamp"),
                **result,
            })
        else:
            text_buffer.append((count, norm, result))

    if args.format == "json":
        print(render_json(json_records))
    else:
        show_index = len(text_buffer) > 1
        for index, norm, result in text_buffer:
            print(render_text(
                index=index,
                event_type=target_type,
                timestamp=norm.get("timestamp", "unknown"),
                key_details=result["key_details"],
                iocs=result["iocs"],
                show_iocs=show_iocs,
                color=color,
                show_index=show_index,
            ))

    if count == 0:
        print("No matching events found.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
