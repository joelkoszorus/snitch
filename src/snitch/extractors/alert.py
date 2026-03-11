"""Extract key details and IOCs from a normalized Suricata alert event."""
import ipaddress

# Maps Suricata flow direction values to human-readable labels
_DIRECTION_LABELS = {
    "to_server":  "Inbound -> Server",
    "toserver":   "Inbound -> Server",
    "to_client":  "Outbound -> Client",
    "toclient":   "Outbound -> Client",
}


def _is_private(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _format_cve(raw) -> str | None:
    """Format CVE metadata: list or string, underscores to hyphens."""
    if isinstance(raw, list):
        return ", ".join(c.replace("_", "-") for c in raw if c)
    if isinstance(raw, str):
        return raw.replace("_", "-")
    return None


def extract(norm: dict) -> dict:
    """Return ``{"key_details": {...}, "iocs": {...}}`` for a normalized alert event.

    All fields are best-effort: missing values are omitted from iocs and left
    as None in key_details (the formatter skips None values).
    """
    direction_raw = norm.get("flow_direction")

    # When direction is absent, infer from RFC1918 ranges:
    #   src private + dest public  → outbound (internal host hitting external)
    #   src public  + dest private → inbound  (external attacker hitting internal)
    if direction_raw is None:
        src_priv  = _is_private(norm.get("src_ip"))
        dest_priv = _is_private(norm.get("dest_ip"))
        if src_priv and not dest_priv:
            direction_raw = "to_client"   # outbound: suspicious IP is dest
        elif not src_priv and dest_priv:
            direction_raw = "to_server"   # inbound: suspicious IP is src

    direction = _DIRECTION_LABELS.get(direction_raw, direction_raw)

    # Choose which IP is "suspicious" for the IOC block based on traffic direction.
    # Inbound → attacker is the source; outbound (C2/exfil) → attacker is the dest.
    if direction_raw in ("to_server", "toserver"):
        ioc_ip      = norm.get("src_ip")
        ioc_country = norm.get("geoip_src_country")
        ioc_city    = norm.get("geoip_src_city")
    elif direction_raw in ("to_client", "toclient"):
        ioc_ip      = norm.get("dest_ip")
        ioc_country = norm.get("geoip_dest_country")
        ioc_city    = norm.get("geoip_dest_city")
    else:
        # Both IPs private or direction truly unknown — default to src
        ioc_ip      = norm.get("src_ip")
        ioc_country = norm.get("geoip_src_country") or norm.get("geoip_dest_country")
        ioc_city    = norm.get("geoip_src_city")    or norm.get("geoip_dest_city")

    # Best application-layer identifier for "suspicious protocol string"
    proto_string = (
        norm.get("tls_sni")
        or norm.get("dns_query_name")
        or norm.get("http_hostname")
        or norm.get("proto")
    )

    key_details = {
        "Alert Signature":   norm.get("alert_signature"),
        "Category":          norm.get("alert_category"),
        "Severity":          norm.get("alert_severity"),
        "CVE":               _format_cve(norm.get("alert_cve")),
        "Time Observed":     norm.get("timestamp"),
        "Network Direction": direction,
        "Source IP":         norm.get("src_ip"),
        "Source Port":       norm.get("src_port"),
        "Destination IP":    norm.get("dest_ip"),
        "Destination Port":  norm.get("dest_port"),
        "Protocol":          norm.get("proto"),
    }

    ioc_candidates = {
        "Suspicious IP":   ioc_ip,
        "Protocol String": proto_string,
        "URL Path":        norm.get("http_url"),
        "User-Agent":      norm.get("http_user_agent"),
        "GeoIP Country":   ioc_country,
        "GeoIP City":      ioc_city,
    }
    iocs = {k: v for k, v in ioc_candidates.items() if v is not None}

    return {"key_details": key_details, "iocs": iocs}
