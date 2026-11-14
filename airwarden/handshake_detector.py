"""Detect WPA 4-way handshakes and PMKIDs in a pcap, per (BSSID, client) pair.

This reports *presence* and the relevant frames so a tester can confirm the
evidence by hand. It deliberately does NOT crack passwords and does NOT emit any
cracking command — it only says whether crackable material was captured.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, field
from typing import Any

from scapy.all import EAPOL, Dot11, rdpcap

from airwarden.pcap_analyzer import _classify_eapol_msg

_PMKID_KDE = b"\xdd\x14\x00\x0f\xac\x04"


@dataclass
class HandshakeEvidence:
    """Handshake/PMKID evidence for one (BSSID, client) pair."""

    bssid: str
    client: str
    messages: list[int] = field(default_factory=list)  # which of 1..4 were seen
    frames: list[int] = field(default_factory=list)  # EAPOL frame numbers (1-based)
    complete_handshake: bool = False  # a crackable pair: (M1&M2) or (M3&M4)
    pmkid: bool = False  # RSN PMKID KDE seen for this pair
    wireshark_filter: str = ""


def detect_frames(frames) -> list[HandshakeEvidence]:
    """Detect handshake/PMKID evidence from an in-memory frame iterable."""
    msgs: dict[tuple[str, str], set[int]] = defaultdict(set)
    fnos: dict[tuple[str, str], list[int]] = defaultdict(list)
    pmkid: dict[tuple[str, str], bool] = defaultdict(bool)

    for i, f in enumerate(frames, start=1):
        if not f.haslayer(EAPOL):
            continue
        try:
            d = f.getlayer(Dot11)
            bssid = d.addr3.lower()
            addr1 = d.addr1.lower()
            addr2 = d.addr2.lower()
        except Exception:
            continue
        raw = bytes(f[EAPOL].payload or b"")
        msg = _classify_eapol_msg(raw)
        if msg is None and _PMKID_KDE not in raw:
            continue
        # M1/M3 travel AP->client (client is the receiver); M2/M4 client->AP.
        client = addr1 if msg in (1, 3) else addr2
        key = (bssid, client)
        fnos[key].append(i)
        if msg is not None:
            msgs[key].add(msg)
        if _PMKID_KDE in raw:
            pmkid[key] = True

    out: list[HandshakeEvidence] = []
    for key in sorted(set(fnos)):
        bssid, client = key
        nums = msgs[key]
        complete = (1 in nums and 2 in nums) or (3 in nums and 4 in nums)
        out.append(
            HandshakeEvidence(
                bssid=bssid,
                client=client,
                messages=sorted(nums),
                frames=sorted(fnos[key]),
                complete_handshake=complete,
                pmkid=pmkid[key],
                wireshark_filter=f"eapol && wlan.bssid == {bssid}",
            )
        )
    return out


def detect(pcap_path: str) -> list[HandshakeEvidence]:
    """Read a pcap from disk and detect handshake/PMKID evidence."""
    return detect_frames(rdpcap(pcap_path))


def to_dicts(evidence: list[HandshakeEvidence]) -> list[dict[str, Any]]:
    return [asdict(e) for e in evidence]
