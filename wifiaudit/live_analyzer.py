"""Streaming analyzer: feed one 802.11 frame at a time, read results any time.

``LiveAnalyzer`` keeps the same state the batch pipeline derives from a whole
pcap (AP inventory, 4-way-handshake and PMKID tracking, disconnect counts, and
scan-classification counters) but updates it incrementally as frames arrive from
a live sniff. :meth:`snapshot` assembles the current findings with the exact same
helpers the file path uses (:func:`wifiaudit.pcap_analyzer.build_assessments` and
:func:`wifiaudit.scan_classifier.classify_counts`), so a live capture and the
pcap written from it yield identical results.

It is passive: it only reads frames handed to it and never transmits.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from scapy.all import EAPOL, Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp

from wifiaudit.models import AccessPoint, TargetAssessment
from wifiaudit.pcap_analyzer import (
    _channel_of,
    _classify_eapol_msg,
    _has_wps,
    _rank,
    _rsn_info,
    _ssid_of,
    build_assessments,
)
from wifiaudit.scan_classifier import classify_counts

_PMKID_KDE = b"\xdd\x14\x00\x0f\xac\x04"


class LiveAnalyzer:
    """Incremental 802.11 analyzer. Call :meth:`process` per frame, :meth:`snapshot` any time."""

    def __init__(self) -> None:
        self.aps: dict[str, AccessPoint] = {}
        self._eapol: dict[tuple[str, str], set[int]] = defaultdict(set)
        self._pmkids: set[str] = set()
        self._disconnects: dict[str, int] = defaultdict(int)
        self._frames = 0
        # scan-classification counters
        self._probe_total = 0
        self._wildcard = 0
        self._targeted: Counter[str] = Counter()
        self._channels: Counter[int] = Counter()

    def process(self, frame: Any) -> None:
        """Update all state from a single frame. Never raises on a malformed frame."""
        self._frames += 1
        try:
            self._process(frame)
        except Exception:
            return

    def _process(self, f: Any) -> None:
        if f.haslayer(Dot11Beacon) or f.haslayer(Dot11ProbeResp):
            self._update_ap(f)
        if f.haslayer(Dot11Beacon):
            ch = _channel_of(f)
            if ch:
                self._channels[ch] += 1
        if f.haslayer(Dot11ProbeReq):
            self._probe_total += 1
            ssid = _ssid_of(f)
            if ssid:
                self._targeted[ssid] += 1
            else:
                self._wildcard += 1
        if f.haslayer(EAPOL):
            self._update_eapol(f)
        self._update_disconnect(f)

    def _update_ap(self, f: Any) -> None:
        try:
            bssid = f[Dot11].addr3.lower()
        except Exception:
            return
        if not bssid:
            return
        ap = self.aps.get(bssid)
        if ap is None:
            ap = AccessPoint(bssid=bssid, ssid=_ssid_of(f) or "<hidden>", channel=_channel_of(f))
            self.aps[bssid] = ap
        ap.beacon_count += 1
        enc, pmf = _rsn_info(f)
        if _rank(enc) > _rank(ap.encryption):
            ap.encryption = enc
        ap.pmf_enabled = ap.pmf_enabled or pmf
        ap.wps_enabled = ap.wps_enabled or _has_wps(f)

    def _update_eapol(self, f: Any) -> None:
        try:
            bssid = f.getlayer(Dot11).addr3.lower()
        except Exception:
            return
        raw = bytes(f[EAPOL].payload or b"")
        if _PMKID_KDE in raw:
            self._pmkids.add(bssid)
        try:
            d = f.getlayer(Dot11)
            addr1 = d.addr1.lower()
            addr2 = d.addr2.lower()
        except Exception:
            return
        msg = _classify_eapol_msg(raw)
        if msg is None:
            return
        client = addr1 if msg in (1, 3) else addr2
        self._eapol[(bssid, client)].add(msg)

    def _update_disconnect(self, f: Any) -> None:
        try:
            d = f.getlayer(Dot11)
            if d is None or d.type != 0 or d.subtype != 12:
                return
            bssid = d.addr3.lower()
        except Exception:
            return
        self._disconnects[bssid] += 1

    def _complete_handshakes(self) -> set[str]:
        out: set[str] = set()
        for (bssid, _client), nums in self._eapol.items():
            if (1 in nums and 2 in nums) or (3 in nums and 4 in nums):
                out.add(bssid)
        return out

    def snapshot(self) -> tuple[list[TargetAssessment], dict]:
        """Return (assessments, meta) for the frames seen so far."""
        handshakes = self._complete_handshakes()
        assessments = build_assessments(
            self.aps, handshakes, set(self._pmkids), dict(self._disconnects)
        )
        channel_spread = len([c for c, n in self._channels.items() if n >= 3])
        scan_type, evidence = classify_counts(
            self._probe_total,
            self._wildcard,
            len(self._targeted),
            channel_spread,
            sum(self._channels.values()),
        )
        meta = {
            "scan_type": scan_type.value,
            "scan_evidence": evidence,
            "frames_total": self._frames,
            "aps_total": len(self.aps),
            "handshake_bssids": sorted(handshakes),
            "pmkid_bssids": sorted(self._pmkids),
        }
        return assessments, meta
