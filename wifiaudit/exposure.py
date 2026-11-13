"""Classify each finding as a kind of exposure: what leaked, from where, how abusable.

This turns the flat list of findings into a structured data-leak view. It is a
pure mapping over finding codes — it reads nothing new from the capture, so it
works everywhere the findings do (file and live).
"""

from __future__ import annotations

from dataclasses import dataclass

from wifiaudit.models import Finding

# what-leaked categories, ordered from "actual secret/data" to "weakness only".
LEAK_KINDS = (
    "plaintext_credential",
    "credential_hash",
    "key_material",
    "session_cookie",
    "identity",
    "plaintext_data",
)


@dataclass
class Exposure:
    """One finding, seen through a leak/exposure lens."""

    code: str
    what: str  # a LEAK_KINDS value, or "config_weakness" / "availability"
    source: str  # which part of the capture it came from
    exploitability: str  # how an attacker would use it
    severity: str  # carried from the finding


# code -> (what, source, exploitability)
_MAP: dict[str, tuple[str, str, str]] = {
    "OPEN_NETWORK": ("plaintext_data", "open network (no link encryption)", "traffic-readable"),
    "WEAK_CRYPTO": ("key_material", "weak cipher (WEP/WPA1)", "offline-crackable"),
    "WPS_ENABLED": ("key_material", "WPS PIN", "online/offline-crackable"),
    "NO_PMF": ("config_weakness", "RSN capabilities (no 802.11w)", "enables-deauth"),
    "HANDSHAKE_CAPTURED": ("key_material", "RSN 4-way handshake", "offline-crackable"),
    "PMKID_CAPTURED": ("key_material", "RSN PMKID (EAPOL M1)", "offline-crackable"),
    "DISCONNECT_FLOOD": ("availability", "deauth/disassoc frames", "availability-impact"),
    "WPA3_DOWNGRADE_POSSIBLE": (
        "key_material",
        "RSN transition AKMs (SAE+PSK)",
        "downgrade-then-offline-crackable",
    ),
    "ENTERPRISE_EAP": ("config_weakness", "802.1X/EAP exchange", "informational"),
    "WEAK_EAP": ("credential_hash", "weak EAP method", "offline-crackable"),
    "EAP_IDENTITY_LEAK": ("identity", "EAP-Identity (cleartext)", "recon/targeting"),
    "HTTP_CREDENTIAL": ("plaintext_credential", "open-network HTTP POST", "directly-usable"),
    "HTTP_COOKIE": ("session_cookie", "open-network HTTP", "session-hijack"),
    "HTTP_BASIC_AUTH": ("plaintext_credential", "HTTP Basic header (base64)", "directly-usable"),
}


def classify_exposure(finding: Finding) -> Exposure | None:
    """Map one finding to an :class:`Exposure`, or None if it is not classified."""
    entry = _MAP.get(finding.code)
    if entry is None:
        return None
    what, source, exploitability = entry
    return Exposure(finding.code, what, source, exploitability, finding.severity)


def classify_exposures(findings: list[Finding]) -> list[Exposure]:
    """Classify a finding list, preserving order and dropping unmapped codes."""
    out: list[Exposure] = []
    for f in findings:
        exposure = classify_exposure(f)
        if exposure is not None:
            out.append(exposure)
    return out


def is_leak(exposure: Exposure) -> bool:
    """True when the exposure is an actual secret/data leak (not just a weakness)."""
    return exposure.what in LEAK_KINDS
