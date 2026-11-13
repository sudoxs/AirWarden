"""Tests for layer-7 cleartext exposure detection on open networks."""

from __future__ import annotations

from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, Raw

from airwarden.http_exposure import detect_http_exposure, frame_exposures
from airwarden.live_analyzer import LiveAnalyzer
from airwarden.pcap_analyzer import analyze_frames

OPEN_BSSID = "aa:bb:cc:00:00:09"
CLIENT = "11:22:33:44:55:66"
BCAST = "ff:ff:ff:ff:ff:ff"

_POST = (
    "POST /login HTTP/1.1\r\n"
    "Host: portal.local\r\n"
    "Cookie: PHPSESSID=abc123; theme=dark\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "\r\n"
    "username=free1&password=hunter2"
)
_BASIC = (
    "GET /admin HTTP/1.1\r\nHost: portal.local\r\n"
    "Authorization: Basic ZnJlZTE6cGFzcw==\r\n\r\n"
)


def _open_beacon() -> object:
    return (
        RadioTap()
        / Dot11(type=0, subtype=8, addr1=BCAST, addr2=OPEN_BSSID, addr3=OPEN_BSSID)
        / Dot11Beacon(cap="ESS")
        / Dot11Elt(ID="SSID", info=b"FreeWiFi")
        / Dot11Elt(ID="DSset", info=b"\x06")
    )


def _http(payload: str) -> object:
    return (
        RadioTap()
        / Dot11(type=2, subtype=0, addr1=OPEN_BSSID, addr2=CLIENT, addr3=OPEN_BSSID)
        / Raw(load=payload.encode())
    )


def _frames() -> list:
    return [_open_beacon(), _http(_POST), _http(_BASIC)]


def test_frame_exposures_flags_without_dumping_secret() -> None:
    pairs = frame_exposures(_http(_POST))
    codes = {k[0] for k, _v in pairs}
    assert "HTTP_CREDENTIAL" in codes
    assert "HTTP_COOKIE" in codes
    joined = " ".join(v.evidence for _k, v in pairs)
    assert "hunter2" not in joined  # the password value is never dumped
    assert "password" in joined and "username" in joined  # field names are shown
    assert "PHPSESSID" in joined  # cookie name is shown


def test_analyze_attaches_http_findings_to_open_ap() -> None:
    assessments, _ = analyze_frames(_frames())
    t = next(a for a in assessments if a.ap.bssid == OPEN_BSSID)
    codes = {f.code for f in t.findings}
    assert {"OPEN_NETWORK", "HTTP_CREDENTIAL", "HTTP_COOKIE", "HTTP_BASIC_AUTH"} <= codes


def test_http_exposure_dedupes_per_host_and_code() -> None:
    # Two identical POSTs collapse to one credential finding.
    exp = detect_http_exposure([_http(_POST), _http(_POST)])
    keys = list(exp[OPEN_BSSID])
    assert keys.count(("HTTP_CREDENTIAL", "portal.local")) == 1


def test_stream_matches_batch_with_http() -> None:
    frames = _frames()
    analyzer = LiveAnalyzer()
    for f in frames:
        analyzer.process(f)
    assert analyzer.snapshot() == analyze_frames(frames)
