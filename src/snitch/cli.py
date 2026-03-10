"""Command-line interface for snitch."""
import argparse
import sys

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
        help="Filter by event type: alert, http, dns, tls, flow",
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

    # Placeholder — extraction logic not yet implemented
    print(f"snitch {__version__} — not yet implemented")
    print(f"args: {args}")


if __name__ == "__main__":
    main()
