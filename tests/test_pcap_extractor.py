"""Tests for the scapy backend of pcap_extractor (no tshark required)."""

from __future__ import annotations

from pathlib import Path

import pytest
from scapy.all import EAPOL, Dot11, Dot11Elt, Dot11ProbeReq, RadioTap, Raw, wrpcap

import airwarden.pcap_extractor as px

BSSID = "aa:bb:cc:dd:ee:01"
CLIENT = "11:22:33:44:55:66"
BCAST = "ff:ff:ff:ff:ff:ff"

_POST = (
    "POST /login HTTP/1.1\r\nHost: portal.local\r\n"
    "Cookie: PHPSESSID=abc\r\n\r\nusername=free1&password=hunter2"
)
_EAP_ID = b"\x02\x01\x00\x11\x01" + b"CONTOSO\\juan"


def _key(msg: int) -> bytes:
    ki = {1: 0x0100, 2: 0x0200, 3: 0x0300, 4: 0x0600}[msg]
    return bytes([0, 3, 0, 0, 0, (ki >> 8) & 0xFF, ki & 0xFF])


def _frames() -> list:
    http = (
        RadioTap()
        / Dot11(type=2, subtype=0, addr1=BSSID, addr2=CLIENT, addr3=BSSID)
        / Raw(load=_POST.encode())
    )
    eap = (
        RadioTap()
        / Dot11(type=2, subtype=0, addr1=CLIENT, addr2=BSSID, addr3=BSSID)
        / EAPOL(version=1, type=0)
        / Raw(load=_EAP_ID)
    )
    probe = (
        RadioTap()
        / Dot11(type=0, subtype=4, addr1=BCAST, addr2=CLIENT, addr3=BCAST)
        / Dot11ProbeReq()
        / Dot11Elt(ID="SSID", info=b"Starbucks")
    )
    m1 = (
        RadioTap()
        / Dot11(type=2, subtype=0, addr1=CLIENT, addr2=BSSID, addr3=BSSID)
        / EAPOL(version=2, type=3)
        / Raw(load=_key(1))
    )
    deauth = RadioTap() / Dot11(type=0, subtype=12, addr1=CLIENT, addr2=BSSID, addr3=BSSID)
    return [http, eap, probe, m1, deauth, deauth]


def test_scapy_extraction() -> None:
    arts = px.extract_scapy_frames(_frames())
    kinds = {a.kind for a in arts}
    assert {"HTTP_POST", "HTTP_COOKIE", "EAP_IDENTITY", "EAP_TYPE", "PROBE_SSID",
            "DEAUTH", "WPA_HANDSHAKE"} <= kinds
    for a in arts:
        assert "frame.number ==" in a.wireshark_filter or "wlan.bssid ==" in a.wireshark_filter
    assert all("hunter2" not in a.snippet for a in arts)
    post = next(a for a in arts if a.kind == "HTTP_POST")
    assert "password" in post.snippet and isinstance(post.frame, int)
    deauth = next(a for a in arts if a.kind == "DEAUTH")
    assert deauth.extra["count"] == 2 and deauth.bssid == BSSID


def test_eap_identity_value() -> None:
    arts = px.extract_scapy_frames(_frames())
    ident = next(a for a in arts if a.kind == "EAP_IDENTITY")
    assert ident.extra["identity"] == "CONTOSO\\juan"


def _pcap(tmp_path: Path) -> str:
    path = tmp_path / "cap.pcap"
    wrpcap(str(path), _frames())
    return str(path)


def test_tshark_backend_degrades_without_binary(tmp_path: Path, monkeypatch) -> None:
    # No tshark installed -> tshark backend yields nothing, no crash.
    monkeypatch.setattr(px, "tshark_available", lambda: False)
    assert px.extract(_pcap(tmp_path), backend="tshark") == []
    # auto falls back to scapy when tshark is absent (finds at least something).
    assert px.extract(_pcap(tmp_path), backend="auto")


def test_unknown_backend(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        px.extract(_pcap(tmp_path), backend="nope")
