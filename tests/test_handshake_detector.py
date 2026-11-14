"""Tests for handshake / PMKID detection (presence only, no cracking)."""

from __future__ import annotations

from scapy.all import EAPOL, Dot11, RadioTap, Raw

from airwarden.handshake_detector import detect_frames

BSSID = "aa:bb:cc:dd:ee:01"
CLIENT = "11:22:33:44:55:66"
_PMKID_KDE = b"\xdd\x14\x00\x0f\xac\x04"


def _key(msg: int, pmkid: bool = False) -> bytes:
    ki = {1: 0x0100, 2: 0x0200, 3: 0x0300, 4: 0x0600}[msg]
    body = bytes([0, 3, 0, 0, 0, (ki >> 8) & 0xFF, ki & 0xFF])
    if pmkid:
        body += _PMKID_KDE + b"\x00" * 16
    return body


def _frame(msg: int, from_ap: bool, pmkid: bool = False) -> object:
    a1, a2 = (CLIENT, BSSID) if from_ap else (BSSID, CLIENT)
    return (
        RadioTap()
        / Dot11(type=2, subtype=0, addr1=a1, addr2=a2, addr3=BSSID)
        / EAPOL(version=2, type=3)
        / Raw(load=_key(msg, pmkid))
    )


def test_complete_handshake_detected() -> None:
    frames = [_frame(1, from_ap=True), _frame(2, from_ap=False)]
    ev = detect_frames(frames)
    assert len(ev) == 1
    e = ev[0]
    assert e.bssid == BSSID and e.client == CLIENT
    assert e.messages == [1, 2]
    assert e.complete_handshake
    assert e.frames == [1, 2]
    assert e.wireshark_filter == f"eapol && wlan.bssid == {BSSID}"
    assert not e.pmkid


def test_partial_handshake_not_complete() -> None:
    ev = detect_frames([_frame(1, from_ap=True)])
    assert ev and not ev[0].complete_handshake and ev[0].messages == [1]


def test_pmkid_detected() -> None:
    ev = detect_frames([_frame(1, from_ap=True, pmkid=True)])
    assert ev[0].pmkid is True


def test_no_eapol_no_evidence() -> None:
    plain = RadioTap() / Dot11(
        type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=BSSID, addr3=BSSID
    )
    assert detect_frames([plain]) == []
