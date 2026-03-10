"""Tests for the alert extractor."""
import pytest
from snitch.normalize import normalize
from snitch.extractors.alert import extract


# --- Fixtures ----------------------------------------------------------------

FULL_ALERT = {
    "event_type": "alert",
    "timestamp": "2024-01-15T10:23:45.123456+0000",
    "src_ip": "198.51.100.42",
    "src_port": 54321,
    "dest_ip": "10.0.0.5",
    "dest_port": 80,
    "proto": "TCP",
    "flow": {"direction": "to_server"},
    "alert": {
        "signature": "ET MALWARE Suspicious User-Agent",
        "category": "A Network Trojan was detected",
        "severity": 1,
    },
    "http": {
        "hostname": "malicious.example.com",
        "url": "/payload/download",
        "http_method": "GET",
        "http_user_agent": "curl/7.68.0",
    },
    "src_ip_info": {"country_code": "RU", "city": "Moscow"},
}

MINIMAL_ALERT = {
    "event_type": "alert",
    "timestamp": "2024-01-15T10:23:45.123456+0000",
    "src_ip": "203.0.113.1",
    "dest_ip": "192.168.1.10",
    "dest_port": 443,
    "proto": "TCP",
    "alert": {"signature": "ET SCAN Nmap"},
}

TLS_ALERT = {
    "event_type": "alert",
    "timestamp": "2024-01-15T11:00:00+0000",
    "src_ip": "10.0.0.2",
    "src_port": 49200,
    "dest_ip": "185.220.101.1",
    "dest_port": 443,
    "proto": "TCP",
    "flow": {"direction": "to_client"},
    "alert": {"signature": "ET TLS Suspicious SNI"},
    "tls": {"sni": "evil-c2.example.net"},
    "dest_ip_info": {"country_code": "NL", "city": "Amsterdam"},
}


# --- Key Details tests -------------------------------------------------------

def test_full_alert_key_details():
    result = extract(normalize(FULL_ALERT))
    kd = result["key_details"]

    assert kd["Alert Signature"] == "ET MALWARE Suspicious User-Agent"
    assert kd["Category"] == "A Network Trojan was detected"
    assert kd["Severity"] == 1
    assert kd["Source IP"] == "198.51.100.42"
    assert kd["Source Port"] == 54321
    assert kd["Destination IP"] == "10.0.0.5"
    assert kd["Destination Port"] == 80
    assert kd["Protocol"] == "TCP"
    assert kd["Network Direction"] == "Inbound -> Server"
    assert kd["Time Observed"] == "2024-01-15T10:23:45.123456+0000"


def test_minimal_alert_missing_fields_are_none():
    result = extract(normalize(MINIMAL_ALERT))
    kd = result["key_details"]

    assert kd["Alert Signature"] == "ET SCAN Nmap"
    assert kd["Source Port"] is None
    assert kd["Network Direction"] is None
    assert kd["Category"] is None


# --- IOC tests ---------------------------------------------------------------

def test_inbound_ioc_ip_is_source():
    """For to_server traffic the attacker is the source."""
    result = extract(normalize(FULL_ALERT))
    assert result["iocs"]["Suspicious IP"] == "198.51.100.42"


def test_outbound_ioc_ip_is_dest():
    """For to_client traffic the external host (dest) is the IOC."""
    result = extract(normalize(TLS_ALERT))
    assert result["iocs"]["Suspicious IP"] == "185.220.101.1"


def test_ioc_geoip_follows_direction():
    result = extract(normalize(FULL_ALERT))
    assert result["iocs"]["GeoIP Country"] == "RU"
    assert result["iocs"]["GeoIP City"] == "Moscow"


def test_outbound_ioc_geoip_from_dest():
    result = extract(normalize(TLS_ALERT))
    assert result["iocs"]["GeoIP Country"] == "NL"
    assert result["iocs"]["GeoIP City"] == "Amsterdam"


def test_tls_sni_used_as_protocol_string():
    result = extract(normalize(TLS_ALERT))
    assert result["iocs"]["Protocol String"] == "evil-c2.example.net"


def test_http_fields_in_iocs():
    result = extract(normalize(FULL_ALERT))
    assert result["iocs"]["URL Path"] == "/payload/download"
    assert result["iocs"]["User-Agent"] == "curl/7.68.0"


def test_missing_ioc_fields_excluded():
    """Fields absent from the event must not appear in iocs at all."""
    result = extract(normalize(MINIMAL_ALERT))
    assert "URL Path" not in result["iocs"]
    assert "User-Agent" not in result["iocs"]
    assert "GeoIP Country" not in result["iocs"]
    assert "GeoIP City" not in result["iocs"]


def test_no_direction_falls_back_to_src_ip():
    result = extract(normalize(MINIMAL_ALERT))
    assert result["iocs"]["Suspicious IP"] == "203.0.113.1"


# --- Protocol string priority ------------------------------------------------

def test_hostname_used_when_no_sni_or_dns():
    result = extract(normalize(FULL_ALERT))
    # FULL_ALERT has http.hostname but no tls.sni or dns — hostname should win
    assert result["iocs"]["Protocol String"] == "malicious.example.com"
