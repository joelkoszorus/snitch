"""Render extracted event data as text or JSON."""
import json


DIVIDER = "-" * 60
YELLOW  = "\033[33m"
CYAN    = "\033[36m"
BOLD    = "\033[1m"
RESET   = "\033[0m"


def _label(key: str, value, color: bool, width: int = 22) -> str:
    label = f"{key}:".ljust(width)
    if color:
        return f"  {CYAN}{label}{RESET} {value}"
    return f"  {label} {value}"


def render_text(index: int, event_type: str, timestamp: str,
                key_details: dict, iocs: dict,
                show_iocs: bool = True, color: bool = True) -> str:
    lines = []

    header = f"EVENT #{index}  [{event_type}]  {timestamp}"
    if color:
        lines.append(f"{BOLD}{DIVIDER}{RESET}")
        lines.append(f"{BOLD}{header}{RESET}")
        lines.append(f"{BOLD}{DIVIDER}{RESET}")
    else:
        lines.append(DIVIDER)
        lines.append(header)
        lines.append(DIVIDER)

    if color:
        lines.append(f"{YELLOW}KEY DETAILS{RESET}")
    else:
        lines.append("KEY DETAILS")

    for key, val in key_details.items():
        if val is not None:
            lines.append(_label(key, val, color))

    if show_iocs and iocs:
        lines.append("")
        if color:
            lines.append(f"{YELLOW}IOCs{RESET}")
        else:
            lines.append("IOCs")
        for key, val in iocs.items():
            if val is not None:
                lines.append(_label(key, val, color))

    lines.append(DIVIDER)
    return "\n".join(lines)


def render_json(records: list[dict]) -> str:
    return json.dumps(records, indent=2)
