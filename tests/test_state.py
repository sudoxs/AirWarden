"""Tests for confirmed/potential finding states and conditional findings."""

from __future__ import annotations

from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap

from wifiaudit.live_analyzer import LiveAnalyzer
from wifiaudit.models import Finding
from wifiaudit.pcap_analyzer import analyze_frames
from wifiaudit.state import CONFIRMED, POTENTIAL, finding_state, is_potential

BCAST = "ff:ff:ff:ff:ff:ff"
WPA2 = "aa:bb:cc:00:00:01"
SAE = "aa:bb:cc:00:00:02"
OWE = "aa:bb:cc:00:00:03"
ENT = "aa:bb:cc:00:00:04"

_RSN_WPA2 = b"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00"
_RSN_SAE = b"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x08\xc0\x00"
_RSN_OWE = b"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x12\xc0\x00"
_RSN_ENT = b"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x01\x00\x00"


def _beacon(bssid: str, ssid: bytes, rsn: bytes) -> object:
    return (
        RadioTap()
        / Dot11(type=0, subtype=8, addr1=BCAST, addr2=bssid, addr3=bssid)
        / Dot11Beacon(cap="ESS+privacy")
        / Dot11Elt(ID="SSID", info=ssid)
        / Dot11Elt(ID=48, info=rsn)
        / Dot11Elt(ID="DSset", info=b"\x06")
    )


def _frames() -> list:
    return [
        _beacon(WPA2, b"HomeNet", _RSN_WPA2),
        _beacon(SAE, b"SecureNet", _RSN_SAE),
        _beacon(OWE, b"FreeSecure", _RSN_OWE),
        _beacon(ENT, b"CorpNet", _RSN_ENT),
    ]


def _codes(assessments, bssid: str) -> set[str]:
    t = next(a for a in assessments if a.ap.bssid == bssid)
    return {f.code for f in t.findings}


def test_state_map_confirmed_vs_potential() -> None:
    assert finding_state(Finding("OPEN_NETWORK", "high", 1.0, "", ""))[0] == CONFIRMED
    assert finding_state(Finding("HANDSHAKE_CAPTURED", "high", 1.0, "", ""))[0] == CONFIRMED
    state, condition = finding_state(Finding("WPS_ENABLED", "high", 1.0, "", ""))
    assert state == POTENTIAL and condition  # has a non-empty "if ..." condition
    assert is_potential(Finding("PSK_OFFLINE_IF_CAPTURED", "medium", 0.6, "", ""))


def test_conditional_findings_per_category() -> None:
    assessments, _ = analyze_frames(_frames())
    assert "PSK_OFFLINE_IF_CAPTURED" in _codes(assessments, WPA2)
    assert "SAE_ONLINE_ONLY" in _codes(assessments, SAE)
    assert "OWE_EVIL_TWIN" in _codes(assessments, OWE)
    assert "ENTERPRISE_ROGUE_AP" in _codes(assessments, ENT)
    # OWE must not also be treated as a crackable PSK.
    assert "PSK_OFFLINE_IF_CAPTURED" not in _codes(assessments, OWE)


def test_conditional_findings_are_all_potential() -> None:
    assessments, _ = analyze_frames(_frames())
    conditional = {
        "PSK_OFFLINE_IF_CAPTURED",
        "SAE_ONLINE_ONLY",
        "OWE_EVIL_TWIN",
        "ENTERPRISE_ROGUE_AP",
    }
    for t in assessments:
        for f in t.findings:
            if f.code in conditional:
                assert is_potential(f)


def test_owe_detected_in_meta() -> None:
    _, meta = analyze_frames(_frames())
    assert meta["owe_bssids"] == [OWE]


def test_stream_matches_batch_states() -> None:
    frames = _frames()
    analyzer = LiveAnalyzer()
    for f in frames:
        analyzer.process(f)
    assert analyzer.snapshot() == analyze_frames(frames)
