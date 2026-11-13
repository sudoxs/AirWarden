"""Tests for the passive detectors added for Enterprise / WPA3 / DoS / evil-twin."""

from __future__ import annotations

from scapy.all import (
    EAPOL,
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    Dot11ProbeReq,
    RadioTap,
    Raw,
)

from airwarden.advisor import ACTION_DEAUTH, recommend_active_step
from airwarden.live_analyzer import LiveAnalyzer
from airwarden.models import Encryption
from airwarden.pcap_analyzer import (
    analyze_frames,
    collect_probe_ssids,
    count_80211_disconnects,
    detect_eap,
    detect_wpa3_transition,
)

WPA2 = "aa:bb:cc:00:00:01"
WPA3T = "aa:bb:cc:00:00:02"  # transition (SAE + PSK)
ENT = "aa:bb:cc:00:00:03"  # enterprise (EAP)
CLIENT = "11:22:33:44:55:66"
BCAST = "ff:ff:ff:ff:ff:ff"

_RSN_WPA2 = b"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00"
# AKM list = PSK (02) + SAE (08) -> transition.
_RSN_TRANS = (
    b"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04"
    b"\x02\x00\x00\x0f\xac\x02\x00\x0f\xac\x08\x00\x00"
)
# AKM = 802.1X (01) -> enterprise.
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


def _probe(ssid: bytes) -> object:
    return (
        RadioTap()
        / Dot11(type=0, subtype=4, addr1=BCAST, addr2=CLIENT, addr3=BCAST)
        / Dot11ProbeReq()
        / Dot11Elt(ID="SSID", info=ssid)
    )


def _eap(bssid: str, eap_bytes: bytes, to_client: bool) -> object:
    src, dst = (bssid, CLIENT) if to_client else (CLIENT, bssid)
    return (
        RadioTap()
        / Dot11(type=2, subtype=0, addr1=dst, addr2=src, addr3=bssid)
        / EAPOL(version=1, type=0)
        / Raw(load=eap_bytes)
    )


def _disassoc(bssid: str) -> object:
    return RadioTap() / Dot11(type=0, subtype=10, addr1=CLIENT, addr2=bssid, addr3=bssid)


# EAP: code,id,len,type,data
_EAP_ID_RESP = b"\x02\x01\x00\x11\x01" + b"CONTOSO\\juan"  # Response/Identity
_EAP_MD5_REQ = b"\x01\x02\x00\x06\x04\xaa"  # Request/MD5 (weak)
_EAP_PEAP_REQ = b"\x01\x03\x00\x06\x19\x20"  # Request/PEAP (type 25)


def _frames() -> list:
    return [
        _beacon(WPA2, b"HomeNet", _RSN_WPA2),
        _beacon(WPA3T, b"GuestNet", _RSN_TRANS),
        _beacon(ENT, b"CorpNet", _RSN_ENT),
        _eap(ENT, _EAP_ID_RESP, to_client=False),
        _eap(ENT, _EAP_MD5_REQ, to_client=True),
        _eap(ENT, _EAP_PEAP_REQ, to_client=True),
        _probe(b"HomeNet"),  # beaconed -> not evil-twin bait
        _probe(b"Starbucks"),  # not in range -> evil-twin bait
        _disassoc(WPA2),
        _disassoc(WPA2),
    ]


def test_transition_detection_and_encryption() -> None:
    frames = _frames()
    assert detect_wpa3_transition(frames) == {WPA3T}
    assessments, meta = analyze_frames(frames)
    assert meta["transition_bssids"] == [WPA3T]
    t = next(a for a in assessments if a.ap.bssid == WPA3T)
    assert t.ap.encryption == Encryption.WPA3  # strongest AKM wins
    assert any(f.code == "WPA3_DOWNGRADE_POSSIBLE" for f in t.findings)


def test_transition_advisor_recommends_downgrade_deauth() -> None:
    assessments, _ = analyze_frames(_frames())
    t = next(a for a in assessments if a.ap.bssid == WPA3T)
    rec = recommend_active_step(t)
    assert rec.action == ACTION_DEAUTH
    assert "downgrade" in rec.yields.lower()


def test_eap_methods_identity_and_weakness() -> None:
    eap = detect_eap(_frames())
    assert eap[ENT]["methods"] == {1, 4, 25}
    assert "CONTOSO\\juan" in eap[ENT]["identities"]

    assessments, _ = analyze_frames(_frames())
    t = next(a for a in assessments if a.ap.bssid == ENT)
    codes = {f.code for f in t.findings}
    assert "ENTERPRISE_EAP" in codes
    assert "WEAK_EAP" in codes  # MD5 offered
    assert "EAP_IDENTITY_LEAK" in codes


def test_disassoc_counted_as_disconnect() -> None:
    counts = count_80211_disconnects(_frames())
    assert counts[(WPA2, CLIENT)] == 2


def test_probe_and_evil_twin_ssids() -> None:
    assert collect_probe_ssids(_frames()) == {"HomeNet", "Starbucks"}
    _, meta = analyze_frames(_frames())
    assert meta["probed_ssids"] == ["HomeNet", "Starbucks"]
    assert meta["evil_twin_ssids"] == ["Starbucks"]  # HomeNet is beaconed


def test_stream_matches_batch_on_rich_frames() -> None:
    frames = _frames()
    analyzer = LiveAnalyzer()
    for f in frames:
        analyzer.process(f)
    assert analyzer.snapshot() == analyze_frames(frames)
