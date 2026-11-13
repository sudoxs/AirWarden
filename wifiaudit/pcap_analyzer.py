"""Parse a pcap and produce TargetAssessment objects plus metadata."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator
from typing import Any

from scapy.all import (
    EAPOL,
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    Dot11ProbeReq,
    Dot11ProbeResp,
    rdpcap,
)

from wifiaudit.http_exposure import detect_http_exposure
from wifiaudit.models import AccessPoint, Encryption, Finding, TargetAssessment
from wifiaudit.scan_classifier import classify_scan

_RSN_IE_ID = 48
_VENDOR_IE_ID = 221
_MS_OUI = b"\x00\x50\xf2"
_WPS_TYPE = 4

_DISCONNECT_FIELD = "deauth_frames"

# RSN AKM suite selector types (last byte of a 00-0F-AC-xx selector).
_PSK_AKMS = frozenset({2, 4, 6})  # PSK, FT-PSK, PSK-SHA256
_SAE_AKMS = frozenset({8, 9})  # SAE, FT-SAE
_ENT_AKMS = frozenset({1, 3, 5, 11, 12})  # 802.1X variants

# EAP method types worth flagging (RFC 3748 + common vendor).
_EAP_NAMES = {
    1: "Identity",
    4: "MD5",
    6: "GTC",
    13: "TLS",
    17: "LEAP",
    18: "SIM",
    21: "TTLS",
    23: "AKA",
    25: "PEAP",
    50: "AKA'",
}
_WEAK_EAP = frozenset({4, 5, 6, 17})  # MD5, OTP, GTC, LEAP — crackable / downgradable


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


def _rsn_akm_set(info: bytes) -> set[int]:
    """Return the set of RSN AKM selector types advertised in an RSN IE body."""
    out: set[int] = set()
    try:
        idx = 2 + 4  # version (2) + group cipher suite (4)
        pc = int.from_bytes(info[idx : idx + 2], "little")
        idx += 2 + pc * 4
        ac = int.from_bytes(info[idx : idx + 2], "little")
        idx += 2
        for i in range(ac):
            akm = info[idx + i * 4 : idx + (i + 1) * 4]
            if len(akm) == 4 and akm[:3] == b"\x00\x0f\xac":
                out.add(akm[3])
    except Exception:
        return set()
    return out


def _encryption_from_akms(akms: set[int]) -> Encryption:
    """Pick the strongest encryption implied by a set of AKM selector types."""
    if akms & _SAE_AKMS:
        return Encryption.WPA3
    if akms & _ENT_AKMS:
        return Encryption.ENTERPRISE
    if akms & _PSK_AKMS:
        return Encryption.WPA2
    return Encryption.WPA2  # RSN present but AKM unknown: assume WPA2


def _is_transition(akms: set[int]) -> bool:
    """True for a WPA3/WPA2 transition BSSID (both SAE and PSK AKMs advertised)."""
    return bool(akms & _SAE_AKMS) and bool(akms & _PSK_AKMS)


def _rsn_akm_encryption(info: bytes) -> Encryption:
    return _encryption_from_akms(_rsn_akm_set(info))


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


def _rsn_akm_set_of(frame: Any) -> set[int]:
    """Return the RSN AKM selector set from a frame's RSN IE (empty if none)."""
    for elt in _iter_elts(frame):
        try:
            eid = int(elt.ID)
            info = bytes(elt.info or b"")
        except Exception:
            continue
        if eid == _RSN_IE_ID and len(info) >= 8:
            return _rsn_akm_set(info)
    return set()


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
    """Count 802.11 deauth (subtype 12) and disassoc (subtype 10) per (bssid, client)."""
    counts: dict[tuple[str, str], int] = defaultdict(int)
    for f in frames:
        try:
            d = f.getlayer(Dot11)
            if d is None or d.type != 0 or d.subtype not in (10, 12):
                continue
            bssid = d.addr3.lower()
            client = d.addr1.lower()
        except Exception:
            continue
        counts[(bssid, client)] += 1
    return dict(counts)


def detect_wpa3_transition(frames) -> set[str]:
    """Return BSSIDs advertising WPA3/WPA2 transition mode (SAE + PSK AKMs)."""
    out: set[str] = set()
    for f in frames:
        if not (f.haslayer(Dot11Beacon) or f.haslayer(Dot11ProbeResp)):
            continue
        try:
            bssid = f[Dot11].addr3.lower()
        except Exception:
            continue
        if bssid and _is_transition(_rsn_akm_set_of(f)):
            out.add(bssid)
    return out


def _eap_from_frame(f: Any) -> tuple[int, int] | None:
    """Return (eap_code, eap_type) for an EAPOL EAP-Packet frame, else None."""
    try:
        eapol = bytes(f[EAPOL])
    except Exception:
        return None
    # EAPOL header: version(1) type(1) length(2); type 0 == EAP-Packet.
    if len(eapol) < 5 or eapol[1] != 0:
        return None
    eap = eapol[4:]
    if len(eap) < 5:
        return None
    return eap[0], eap[4]  # code, type


def detect_eap(frames) -> dict[str, dict[str, Any]]:
    """Map BSSID -> {"methods": set[int], "identities": set[str]} from EAP frames."""
    out: dict[str, dict[str, Any]] = {}
    for f in frames:
        if not f.haslayer(EAPOL):
            continue
        parsed = _eap_from_frame(f)
        if parsed is None:
            continue
        code, etype = parsed
        if code not in (1, 2):  # only Request/Response carry a method type
            continue
        try:
            bssid = f.getlayer(Dot11).addr3.lower()
        except Exception:
            continue
        entry = out.setdefault(bssid, {"methods": set(), "identities": set()})
        entry["methods"].add(etype)
        if etype == 1 and code == 2:  # EAP-Response/Identity (cleartext username)
            eapol = bytes(f[EAPOL])
            ident = eapol[9:].split(b"\x00", 1)[0].decode(errors="ignore").strip()
            if ident:
                entry["identities"].add(ident)
    return out


def collect_probe_ssids(frames) -> set[str]:
    """Return the set of directed (non-wildcard) SSIDs seen in probe requests."""
    out: set[str] = set()
    for f in frames:
        if not f.haslayer(Dot11ProbeReq):
            continue
        ssid = _ssid_of(f)
        if ssid:
            out.add(ssid)
    return out


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


def _eap_findings(info: dict[str, Any]) -> list[Finding]:
    """Build findings from one BSSID's EAP methods and leaked identities."""
    out: list[Finding] = []
    methods = sorted(info.get("methods") or set())
    identities = sorted(info.get("identities") or set())
    if methods:
        named = ", ".join(_EAP_NAMES.get(m, f"type {m}") for m in methods if m != 1)
        if named:
            out.append(
                Finding(
                    "ENTERPRISE_EAP",
                    "info",
                    0.9,
                    f"802.1X/EAP methods observed: {named}",
                    "Allow only strong EAP (e.g. EAP-TLS) with server-certificate validation.",
                )
            )
    weak = [_EAP_NAMES.get(m, str(m)) for m in methods if m in _WEAK_EAP]
    if weak:
        out.append(
            Finding(
                "WEAK_EAP",
                "high",
                0.9,
                f"Weak EAP method(s) offered: {', '.join(weak)}",
                "Disable MD5/LEAP/GTC; require EAP-TLS or PEAP/TTLS with strong inner auth.",
            )
        )
    if identities:
        shown = ", ".join(identities[:5])
        out.append(
            Finding(
                "EAP_IDENTITY_LEAK",
                "medium",
                0.8,
                f"EAP identities sent in the clear: {shown}",
                "Use anonymous outer identities to avoid leaking usernames/domains.",
            )
        )
    return out


def build_assessments(
    aps: dict[str, AccessPoint],
    handshakes: set[str],
    pmkids: set[str],
    per_bssid_disconnects: dict[str, int],
    transition: set[str] | None = None,
    eap: dict[str, dict[str, Any]] | None = None,
    http_exposure: dict[str, dict[tuple[str, str], Finding]] | None = None,
) -> list[TargetAssessment]:
    """Assemble TargetAssessment objects from inventory + detection results.

    Shared by the batch (:func:`analyze_frames`) and streaming
    (``LiveAnalyzer``) paths so both produce identical findings.
    """
    transition = transition or set()
    eap = eap or {}
    http_exposure = http_exposure or {}
    assessments: list[TargetAssessment] = []
    for bssid, ap in aps.items():
        t = TargetAssessment(ap=ap, findings=_findings_for(ap))
        if bssid in transition:
            t.findings.append(
                Finding(
                    "WPA3_DOWNGRADE_POSSIBLE",
                    "high",
                    0.9,
                    "AP advertises WPA3/WPA2 transition mode (SAE + PSK)",
                    "Disable transition mode; run WPA3-only so clients cannot be forced to WPA2.",
                )
            )
        if bssid in eap:
            t.findings.extend(_eap_findings(eap[bssid]))
        if bssid in http_exposure:
            t.findings.extend(v for _k, v in sorted(http_exposure[bssid].items()))
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
                    f"{getattr(t, _DISCONNECT_FIELD)} deauth/disassoc frames observed",
                    "Enable PMF; investigate the source of the disconnect frames.",
                )
            )
        assessments.append(t)
    return assessments


def _evil_twin_ssids(aps: dict[str, AccessPoint], probed: set[str]) -> list[str]:
    """SSIDs that clients probe for but that no AP in range beacons (evil-twin bait)."""
    beaconed = {ap.ssid for ap in aps.values() if ap.ssid and ap.ssid != "<hidden>"}
    return sorted(probed - beaconed)


def analyze_frames(frames) -> tuple[list[TargetAssessment], dict]:
    """Analyze an in-memory frame iterable (shared by file and live paths)."""
    aps = extract_aps(frames)
    handshakes = detect_handshakes(frames)
    pmkids = detect_pmkid(frames)
    transition = detect_wpa3_transition(frames)
    eap = detect_eap(frames)
    http = detect_http_exposure(frames)
    probed = collect_probe_ssids(frames)
    disconnect_counts = count_80211_disconnects(frames)

    per_bssid_disconnects: dict[str, int] = defaultdict(int)
    for (bssid, _client), n in disconnect_counts.items():
        per_bssid_disconnects[bssid] += n

    assessments = build_assessments(
        aps, handshakes, pmkids, dict(per_bssid_disconnects), transition, eap, http
    )

    scan_type, scan_evidence = classify_scan(frames)
    meta = {
        "scan_type": scan_type.value,
        "scan_evidence": scan_evidence,
        "frames_total": len(frames),
        "aps_total": len(aps),
        "handshake_bssids": sorted(handshakes),
        "pmkid_bssids": sorted(pmkids),
        "transition_bssids": sorted(transition),
        "probed_ssids": sorted(probed),
        "evil_twin_ssids": _evil_twin_ssids(aps, probed),
    }
    return assessments, meta


def analyze_pcap(path: str) -> tuple[list[TargetAssessment], dict]:
    """Read a pcap/pcapng file from disk and analyze it."""
    return analyze_frames(rdpcap(path))
