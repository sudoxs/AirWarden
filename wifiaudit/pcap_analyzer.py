"""Parse a pcap and produce TargetAssessment objects plus metadata."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator
from typing import Any

from scapy.all import EAPOL, Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp, rdpcap

from wifiaudit.models import AccessPoint, Encryption, Finding, TargetAssessment
from wifiaudit.scan_classifier import classify_scan

_RSN_IE_ID = 48
_VENDOR_IE_ID = 221
_MS_OUI = b"\x00\x50\xf2"
_WPS_TYPE = 4

_DISCONNECT_FIELD = "deauth_frames"


def _iter_elts(frame: Any) -> Iterator[Any]:
    try:
        first = frame.getlayer(Dot11Elt)
    except Exception:
        return
    elt = first
    guard = 0
    while elt is not None and guard < 64:
        yield elt
        try:
            nxt = elt.payload
        except Exception:
            return
        if not isinstance(nxt, Dot11Elt):
            return
        elt = nxt
        guard += 1


def _ssid_of(frame: Any) -> str:
    elt = frame.getlayer(Dot11Elt)
    if elt is None or not elt.info:
        return ""
    try:
        return elt.info.decode(errors="ignore")
    except Exception:
        return ""


def _channel_of(frame: Any) -> int:
    try:
        return int(getattr(frame.getlayer(Dot11), "channel", 0) or 0)
    except Exception:
        return 0


def _rsn_akm_encryption(info: bytes) -> Encryption:
    try:
        idx = 2
        idx += 4
        pc = int.from_bytes(info[idx : idx + 2], "little")
        idx += 2 + pc * 4
        ac = int.from_bytes(info[idx : idx + 2], "little")
        idx += 2
        for i in range(ac):
            akm = info[idx + i * 4 : idx + (i + 1) * 4]
            if akm[:3] == b"\x00\x0f\xac":
                t = akm[3]
                if t == 1:
                    return Encryption.ENTERPRISE
                if t == 2:
                    return Encryption.WPA2
                if t == 8:
                    return Encryption.WPA3
        return Encryption.WPA2
    except Exception:
        return Encryption.WPA2


def _rsn_pmf(info: bytes) -> bool:
    try:
        idx = 2
        idx += 4
        pc = int.from_bytes(info[idx : idx + 2], "little")
        idx += 2 + pc * 4
        ac = int.from_bytes(info[idx : idx + 2], "little")
        idx += 2 + ac * 4
        caps = int.from_bytes(info[idx : idx + 2], "little")
        return bool(caps & 0x80)
    except Exception:
        return False


def _rsn_info(frame: Any) -> tuple[Encryption, bool]:
    for elt in _iter_elts(frame):
        try:
            eid = int(elt.ID)
            info = bytes(elt.info or b"")
        except Exception:
            continue
        if eid == _RSN_IE_ID and len(info) >= 8:
            return _rsn_akm_encryption(info), _rsn_pmf(info)
        if eid == _VENDOR_IE_ID and info.startswith(_MS_OUI + b"\x01"):
            return Encryption.WPA, False
    return Encryption.OPEN, False


def _has_wps(frame: Any) -> bool:
    for elt in _iter_elts(frame):
        try:
            if int(elt.ID) != _VENDOR_IE_ID:
                continue
            info = bytes(elt.info or b"")
        except Exception:
            continue
        if info.startswith(_MS_OUI + bytes([_WPS_TYPE])):
            return True
    return False


def _rank(enc: Encryption) -> int:
    return {
        Encryption.UNKNOWN: 0,
        Encryption.OPEN: 1,
        Encryption.WEP: 2,
        Encryption.WPA: 3,
        Encryption.ENTERPRISE: 4,
        Encryption.WPA2: 4,
        Encryption.WPA3: 5,
    }.get(enc, 0)


def extract_aps(frames) -> dict[str, AccessPoint]:
    aps: dict[str, AccessPoint] = {}
    for f in frames:
        if not (f.haslayer(Dot11Beacon) or f.haslayer(Dot11ProbeResp)):
            continue
        try:
            bssid = f[Dot11].addr3.lower()
        except Exception:
            continue
        if not bssid:
            continue
        if bssid not in aps:
            aps[bssid] = AccessPoint(
                bssid=bssid,
                ssid=_ssid_of(f) or "<hidden>",
                channel=_channel_of(f),
            )
        ap = aps[bssid]
        ap.beacon_count += 1
        enc, pmf = _rsn_info(f)
        if _rank(enc) > _rank(ap.encryption):
            ap.encryption = enc
        ap.pmf_enabled = ap.pmf_enabled or pmf
        ap.wps_enabled = ap.wps_enabled or _has_wps(f)
    return aps


def _classify_eapol_msg(raw: bytes) -> int | None:
    if len(raw) < 7 or raw[1] != 3:
        return None
    key_info = int.from_bytes(raw[5:7], "big")
    ack = bool(key_info & 0x0100)
    mic = bool(key_info & 0x0200)
    secure = bool(key_info & 0x0400)
    if ack and not mic and not secure:
        return 1
    if not ack and mic and not secure:
        return 2
    if ack and mic:
        return 3
    if not ack and mic and secure:
        return 4
    return None


def detect_handshakes(frames) -> set[str]:
    """Return BSSIDs where a complete 4-way handshake was observed."""
    seen: dict[tuple[str, str], set[int]] = defaultdict(set)
    for f in frames:
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
        if msg is None:
            continue
        client = addr1 if msg in (1, 3) else addr2
        seen[(bssid, client)].add(msg)

    complete: set[str] = set()
    for (bssid, _client), nums in seen.items():
        if (1 in nums and 2 in nums) or (3 in nums and 4 in nums):
            complete.add(bssid)
    return complete


def detect_pmkid(frames) -> set[str]:
    """Return BSSIDs whose EAPOL payload contains an RSN PMKID KDE."""
    found: set[str] = set()
    for f in frames:
        if not f.haslayer(EAPOL):
            continue
        try:
            bssid = f.getlayer(Dot11).addr3.lower()
        except Exception:
            continue
        raw = bytes(f[EAPOL].payload or b"")
        if b"\xdd\x14\x00\x0f\xac\x04" in raw:
            found.add(bssid)
    return found


def count_80211_disconnects(frames) -> dict[tuple[str, str], int]:
    """Count 802.11 management subtype 12 frames per (bssid, client)."""
    counts: dict[tuple[str, str], int] = defaultdict(int)
    for f in frames:
        try:
            d = f.getlayer(Dot11)
            if d is None or d.type != 0 or d.subtype != 12:
                continue
            bssid = d.addr3.lower()
            client = d.addr1.lower()
        except Exception:
            continue
        counts[(bssid, client)] += 1
    return dict(counts)


def _findings_for(ap: AccessPoint) -> list[Finding]:
    out: list[Finding] = []
    if ap.encryption == Encryption.OPEN:
        out.append(
            Finding(
                "OPEN_NETWORK",
                "high",
                1.0,
                "AP advertises an open network",
                "Require WPA2/3 and rotate any shared secrets.",
            )
        )
    if ap.encryption == Encryption.WEP:
        out.append(
            Finding(
                "WEAK_CRYPTO",
                "high",
                1.0,
                "AP uses WEP encryption",
                "Migrate to WPA2/3 immediately.",
            )
        )
    if ap.encryption == Encryption.WPA:
        out.append(
            Finding("WEAK_CRYPTO", "medium", 0.9, "AP uses WPA1 encryption", "Migrate to WPA2/3.")
        )
    if ap.wps_enabled:
        out.append(
            Finding(
                "WPS_ENABLED",
                "high",
                0.9,
                "WPS Information Element is advertised",
                "Disable WPS or enforce lockout.",
            )
        )
    if ap.encryption in (Encryption.WPA2, Encryption.WPA3) and not ap.pmf_enabled:
        out.append(
            Finding(
                "NO_PMF",
                "medium",
                0.8,
                "802.11w (PMF) is not advertised",
                "Enable PMF to mitigate disconnect/flood abuse.",
            )
        )
    return out


def analyze_pcap(path: str) -> tuple[list[TargetAssessment], dict]:
    frames = rdpcap(path)
    aps = extract_aps(frames)
    handshakes = detect_handshakes(frames)
    pmkids = detect_pmkid(frames)
    disconnect_counts = count_80211_disconnects(frames)

    per_bssid_disconnects: dict[str, int] = defaultdict(int)
    for (bssid, _client), n in disconnect_counts.items():
        per_bssid_disconnects[bssid] += n

    assessments: list[TargetAssessment] = []
    for bssid, ap in aps.items():
        t = TargetAssessment(ap=ap, findings=_findings_for(ap))
        if bssid in handshakes:
            t.handshake_captured = True
            t.findings.append(
                Finding(
                    "HANDSHAKE_CAPTURED",
                    "high",
                    1.0,
                    "4-way handshake observed in pcap",
                    "Rotate the PSK; consider longer keys or WPA3.",
                )
            )
        if bssid in pmkids:
            t.pmkid_captured = True
            t.findings.append(
                Finding(
                    "PMKID_CAPTURED",
                    "critical",
                    1.0,
                    "PMKID KDE observed in EAPOL M1",
                    "Rotate the PSK; disable PMKID if not required.",
                )
            )
        setattr(t, _DISCONNECT_FIELD, per_bssid_disconnects.get(bssid, 0))
        if getattr(t, _DISCONNECT_FIELD, 0) >= 10:
            t.findings.append(
                Finding(
                    "DISCONNECT_FLOOD",
                    "medium",
                    0.7,
                    f"{getattr(t, _DISCONNECT_FIELD)} disconnect frames observed",
                    "Enable PMF; investigate the source of disconnect frames.",
                )
            )
        assessments.append(t)

    scan_type, scan_evidence = classify_scan(frames)
    meta = {
        "scan_type": scan_type.value,
        "scan_evidence": scan_evidence,
        "frames_total": len(frames),
        "aps_total": len(aps),
        "handshake_bssids": sorted(handshakes),
        "pmkid_bssids": sorted(pmkids),
    }
    return assessments, meta
