"""Weighted risk scoring for TargetAssessment objects (higher = riskier)."""

from __future__ import annotations

from airwarden.models import Encryption, TargetAssessment

_ENCRYPTION_STRENGTH = {
    Encryption.WPA3: 100,
    Encryption.WPA2: 85,
    Encryption.ENTERPRISE: 80,
    Encryption.WPA: 45,
    Encryption.WEP: 10,
    Encryption.OPEN: 0,
    Encryption.UNKNOWN: 40,
}

_SEVERITY_WEIGHT = {
    "critical": 40,
    "high": 25,
    "medium": 12,
    "low": 5,
    "info": 0,
}

_DISCONNECT_FIELD = "deauth_frames"


def score_target(t: TargetAssessment) -> float:
    """Return a 0..100 risk score (higher = riskier)."""
    enc_strength = _ENCRYPTION_STRENGTH.get(t.ap.encryption, 40)
    enc_component = (100 - enc_strength) * 0.30

    vuln_raw = sum(
        _SEVERITY_WEIGHT.get(f.severity, 0) * max(0.0, min(1.0, f.confidence)) for f in t.findings
    )
    vuln_component = min(vuln_raw, 100) * 0.50

    exposure = 0.0
    if t.handshake_captured:
        exposure += 10.0
    if t.pmkid_captured:
        exposure += 15.0
    if t.ap.wps_enabled:
        exposure += 5.0
    if not t.ap.pmf_enabled:
        exposure += 3.0
    if getattr(t, _DISCONNECT_FIELD, 0) > 5:
        exposure += 4.0
    exposure_component = min(exposure, 20.0)

    return round(min(enc_component + vuln_component + exposure_component, 100.0), 1)
