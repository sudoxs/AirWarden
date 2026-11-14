"""Advisory applicability matrix: which authorized test categories fit each AP.

Given a normalized AP (from scan_ingestor) and the evidence extracted from a
capture, this says *what is worth inspecting next* and *why*, with the
preconditions and the evidence still missing. It is advisory only: it never
executes an attack, sends a frame, spoofs a MAC, stands up a rogue AP, relays,
brute-forces WPS, or runs a DoS. It helps a tester prioritise inspection.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from airwarden.handshake_detector import HandshakeEvidence
from airwarden.pcap_extractor import Artifact
from airwarden.scan_ingestor import ScanAP

_WEAK_EAP = {4, 6, 17}  # MD5, GTC, LEAP
_PRIORITY_ORDER = {"high": 0, "medium": 1, "low": 2}


@dataclass
class ApEvidence:
    """What the capture actually shows for one BSSID."""

    has_handshake: bool = False
    has_pmkid: bool = False
    eap_identities: list[str] = field(default_factory=list)
    eap_types: set[int] = field(default_factory=set)
    http_credentials: bool = False
    cookies: bool = False
    deauth_seen: bool = False
    probe_ssids: list[str] = field(default_factory=list)


@dataclass
class Applicability:
    """One advisory row: a relevant, authorized test category for an AP."""

    category: str  # OPN | WEP | WPA2-PSK | WPA3-SAE | MGT | OWE | WPS
    priority: str  # high | medium | low
    reason: str
    preconditions: str
    missing_evidence: str


def evidence_for(
    bssid: str, artifacts: list[Artifact], handshakes: list[HandshakeEvidence]
) -> ApEvidence:
    """Summarise the evidence attributable to ``bssid``."""
    ev = ApEvidence()
    for h in handshakes:
        if h.bssid == bssid:
            ev.has_handshake = ev.has_handshake or h.complete_handshake
            ev.has_pmkid = ev.has_pmkid or h.pmkid
    for a in artifacts:
        if a.bssid not in (bssid, None):
            continue
        if a.kind in ("EAP_IDENTITY", "IMSI") and a.extra.get("identity"):
            ev.eap_identities.append(a.extra["identity"])
        elif a.kind == "EAP_TYPE" and "eap_type" in a.extra:
            ev.eap_types.add(a.extra["eap_type"])
        elif a.kind in ("HTTP_POST", "HTTP_BASIC_AUTH"):
            ev.http_credentials = True
        elif a.kind in ("HTTP_COOKIE", "SET_COOKIE"):
            ev.cookies = True
        elif a.kind in ("DEAUTH", "DISASSOC"):
            ev.deauth_seen = True
        elif a.kind == "PROBE_SSID" and a.extra.get("ssid"):
            ev.probe_ssids.append(a.extra["ssid"])
    return ev


def _classes(ap: ScanAP) -> dict[str, bool]:
    enc = (ap.enc or "").upper()
    auth = (ap.auth or "").upper()
    return {
        "open": enc in ("OPN", "OPEN", "") and auth in ("", "OPN"),
        "wep": enc == "WEP",
        "owe": auth == "OWE",
        "sae": auth == "SAE" or (enc == "WPA3" and auth in ("", "SAE")),
        "mgt": auth == "MGT",
        "psk": auth == "PSK" or (enc in ("WPA", "WPA2") and auth in ("", "PSK")),
        "wps": ap.wps_version is not None,
    }


def map_ap(ap: ScanAP, ev: ApEvidence) -> list[Applicability]:
    """Return the advisory applicability rows for one AP."""
    cls = _classes(ap)
    rows: list[Applicability] = []

    if cls["open"]:
        got = ev.http_credentials or ev.cookies
        rows.append(
            Applicability(
                "OPN",
                "high" if got else "medium",
                "Open network — client traffic is unencrypted and readable in the capture.",
                "Authorized passive capture on this AP's channel.",
                ""
                if got
                else "No cleartext HTTP credentials/cookies seen yet; capture more client traffic.",
            )
        )
    if cls["wep"]:
        rows.append(
            Applicability(
                "WEP",
                "high",
                "WEP is cryptographically broken; the key is recoverable offline from "
                "captured IVs.",
                "Authorized scope; enough data frames/IVs collected.",
                "",
            )
        )
    if cls["psk"]:
        got = ev.has_handshake or ev.has_pmkid
        rows.append(
            Applicability(
                "WPA2-PSK",
                "high" if got else "medium",
                "WPA/WPA2-PSK — the PSK is recoverable offline once a 4-way handshake or "
                "PMKID is captured.",
                "Authorized scope; a captured handshake or PMKID.",
                ""
                if got
                else "No handshake/PMKID captured yet (needs a client auth, or an "
                "authorized deauth to force one).",
            )
        )
    if cls["sae"]:
        if ap.wpa3_transition:
            rows.append(
                Applicability(
                    "WPA3-SAE",
                    "high",
                    "WPA3/WPA2 transition — a WPA2-capable client can be led to a "
                    "crackable WPA2 handshake (downgrade).",
                    "Authorized scope; a WPA2-capable client present.",
                    "" if ev.has_handshake else "No WPA2 handshake captured yet.",
                )
            )
        else:
            rows.append(
                Applicability(
                    "WPA3-SAE",
                    "low",
                    "WPA3-SAE resists offline cracking; only online guessing "
                    "(slow, rate-limited) applies.",
                    "Authorized scope.",
                    "SAE exposes no offline-crackable material.",
                )
            )
    if cls["mgt"]:
        weak = sorted(ev.eap_types & _WEAK_EAP)
        missing = []
        if not ev.eap_identities:
            missing.append("no EAP identity captured yet")
        if not ev.eap_types:
            missing.append("EAP method not yet observed")
        rows.append(
            Applicability(
                "MGT",
                "high" if weak else "medium",
                "802.1X/Enterprise — EAP identities leak in the clear; weak inner auth "
                "(MD5/GTC/LEAP) is crackable, and clients that skip server-cert "
                "validation can be drawn to a rogue AP.",
                "Authorized scope; for rogue-AP review, a client that does not validate "
                "the RADIUS cert.",
                "; ".join(missing),
            )
        )
    if cls["owe"]:
        rows.append(
            Applicability(
                "OWE",
                "medium",
                "Enhanced Open — traffic is encrypted but the AP is unauthenticated, so "
                "an evil-twin can MitM.",
                "Authorized scope.",
                "OWE has no PSK to recover.",
            )
        )
    if cls["wps"]:
        locked = ap.wps_locked
        rows.append(
            Applicability(
                "WPS",
                "low" if locked else "medium",
                f"WPS {ap.wps_version} advertised — the PIN may be brute-forceable "
                "(Pixie-Dust or online PIN).",
                "Authorized scope; WPS not locked.",
                "WPS reports locked."
                if locked
                else "Confirm WPS lock state before any authorized test.",
            )
        )

    rows.sort(key=lambda r: _PRIORITY_ORDER.get(r.priority, 9))
    return rows


def map_all(
    aps: dict[str, ScanAP],
    artifacts: list[Artifact] | None = None,
    handshakes: list[HandshakeEvidence] | None = None,
) -> dict[str, list[Applicability]]:
    """Build the applicability matrix for every AP."""
    artifacts = artifacts or []
    handshakes = handshakes or []
    out: dict[str, list[Applicability]] = {}
    for bssid, ap in aps.items():
        ev = evidence_for(bssid, artifacts, handshakes)
        out[bssid] = map_ap(ap, ev)
    return out


def to_dicts(matrix: dict[str, list[Applicability]]) -> dict[str, list[dict[str, Any]]]:
    return {bssid: [asdict(r) for r in rows] for bssid, rows in matrix.items()}
