"""The streaming LiveAnalyzer must produce exactly what the batch path produces."""

from __future__ import annotations

from scapy.all import (
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    Dot11ProbeReq,
    RadioTap,
)

from wifiaudit.live_analyzer import LiveAnalyzer
from wifiaudit.models import Encryption
from wifiaudit.pcap_analyzer import analyze_frames

_RSN_WPA2 = (
    b"\x01\x00\x00\x0f\xac\x04"  # group cipher
    b"\x01\x00\x00\x0f\xac\x04"  # pairwise cipher
    b"\x01\x00\x00\x0f\xac\x02"  # AKM: PSK
    b"\x00\x00"  # RSN capabilities (PMF off)
)


def _beacon(bssid: str, ssid: bytes, *, rsn: bytes | None) -> object:
    frame = (
        RadioTap()
        / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
        / Dot11Beacon(cap="ESS+privacy" if rsn else "ESS")
        / Dot11Elt(ID="SSID", info=ssid)
    )
    if rsn is not None:
        frame = frame / Dot11Elt(ID=48, info=rsn)
    return frame / Dot11Elt(ID="DSset", info=b"\x06")


def _probe(client: str, ssid: bytes) -> object:
    bcast = "ff:ff:ff:ff:ff:ff"
    return (
        RadioTap()
        / Dot11(type=0, subtype=4, addr1=bcast, addr2=client, addr3=bcast)
        / Dot11ProbeReq()
        / Dot11Elt(ID="SSID", info=ssid)
    )


def _frames() -> list:
    wpa2 = _beacon("aa:bb:cc:dd:ee:01", b"TestNet", rsn=_RSN_WPA2)
    openap = _beacon("de:ad:be:ef:00:02", b"OpenNet", rsn=None)
    return [
        wpa2,
        wpa2,
        wpa2,
        openap,
        _probe("11:22:33:44:55:66", b""),  # wildcard
        _probe("11:22:33:44:55:66", b"TestNet"),  # targeted
    ]


def test_stream_matches_batch() -> None:
    frames = _frames()

    analyzer = LiveAnalyzer()
    for f in frames:
        analyzer.process(f)

    assert analyzer.snapshot() == analyze_frames(frames)


def test_snapshot_grows_as_frames_arrive() -> None:
    analyzer = LiveAnalyzer()
    assert analyzer.snapshot()[1]["aps_total"] == 0

    frames = _frames()
    analyzer.process(frames[0])
    assert analyzer.snapshot()[1]["aps_total"] == 1

    for f in frames[1:]:
        analyzer.process(f)
    assessments, meta = analyzer.snapshot()
    assert meta["aps_total"] == 2
    assert meta["frames_total"] == len(frames)
    by_bssid = {t.ap.bssid: t for t in assessments}
    assert by_bssid["aa:bb:cc:dd:ee:01"].ap.encryption == Encryption.WPA2
    assert by_bssid["de:ad:be:ef:00:02"].ap.encryption == Encryption.OPEN


def test_process_ignores_malformed_frames() -> None:
    analyzer = LiveAnalyzer()
    analyzer.process(object())  # not a scapy packet; must not raise
    assert analyzer.snapshot()[1]["frames_total"] == 1
    assert analyzer.snapshot()[1]["aps_total"] == 0
