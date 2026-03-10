"""Normalize a raw EVE JSON event into a stable flat dict."""


def _get(event: dict, *paths: str):
    """Return the first non-None value found across the given dot-notation paths."""
    for path in paths:
        obj = event
        for key in path.split("."):
            if not isinstance(obj, dict):
                obj = None
                break
            obj = obj.get(key)
        if obj is not None:
            return obj
    return None


def normalize(event: dict) -> dict:
    """Return a flat dict with stable keys regardless of EVE variant (native vs ECS/Filebeat)."""
    return {
        # Top-level metadata
        "event_type": _get(event, "event_type", "suricata.eve.event_type"),
        "timestamp":  _get(event, "timestamp",  "suricata.eve.timestamp", "@timestamp"),
        # Network 5-tuple
        "src_ip":    _get(event, "src_ip",   "suricata.eve.src_ip",   "source.ip"),
        "src_port":  _get(event, "src_port",  "suricata.eve.src_port",  "source.port"),
        "dest_ip":   _get(event, "dest_ip",   "suricata.eve.dest_ip",   "destination.ip"),
        "dest_port": _get(event, "dest_port", "suricata.eve.dest_port", "destination.port"),
        "proto":     _get(event, "proto",     "suricata.eve.proto",     "network.transport"),
        # Direction — top-level field in native EVE; also check legacy paths
        "flow_direction": _get(event, "direction", "flow.direction", "suricata.eve.flow.direction"),
        # Alert fields
        "alert_signature":  _get(event, "alert.signature",  "suricata.eve.alert.signature"),
        "alert_category":   _get(event, "alert.category",   "suricata.eve.alert.category"),
        "alert_severity":   _get(event, "alert.severity",   "suricata.eve.alert.severity"),
        # HTTP fields
        "http_hostname":   _get(event, "http.hostname",    "suricata.eve.http.hostname"),
        "http_url":        _get(event, "http.url",         "suricata.eve.http.url"),
        "http_method":     _get(event, "http.http_method", "suricata.eve.http.http_method"),
        "http_user_agent": _get(event, "http.http_user_agent", "suricata.eve.http.http_user_agent", "user_agent.original"),
        # DNS fields
        "dns_query_name": _get(event, "dns.query.0.rrname", "suricata.eve.dns.query.0.rrname"),
        "dns_query_type": _get(event, "dns.query.0.rrtype", "suricata.eve.dns.query.0.rrtype"),
        # TLS fields
        "tls_sni":     _get(event, "tls.sni",     "suricata.eve.tls.sni"),
        "tls_version": _get(event, "tls.version", "suricata.eve.tls.version"),
        "tls_ja3":     _get(event, "tls.ja3.hash", "suricata.eve.tls.ja3.hash"),
        "tls_subject": _get(event, "tls.subject",  "suricata.eve.tls.subject"),
        # GeoIP — populated by Suricata's geoip module or Logstash enrichment
        "geoip_src_country": _get(event, "src_ip_info.country_code", "source.geo.country_iso_code"),
        "geoip_src_city":    _get(event, "src_ip_info.city",         "source.geo.city_name"),
        "geoip_dest_country": _get(event, "dest_ip_info.country_code", "destination.geo.country_iso_code"),
        "geoip_dest_city":    _get(event, "dest_ip_info.city",          "destination.geo.city_name"),
        # Keep the original for any ad-hoc access
        "_raw": event,
    }
