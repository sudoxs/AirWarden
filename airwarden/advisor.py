"""Active-step advisory for authorized follow-up.

Given a passively-derived :class:`TargetAssessment`, describe the single gated
action (if any) that would reveal the most additional information about that
target, and exactly what it would yield. This module only *describes*: it runs
nothing, touches no radio, and plans no broad attack. Every suggestion maps to
one of the single-target primitives the tool already gates behind a signed scope
file (``pmkid_capture``, ``deauth_targeted``) or to a configuration review.

Encryption and PMF status decide what, if anything, is worth doing. Targets whose
key material is already in the capture, open networks, and SAE/Enterprise
networks get no capture suggestion, because an active step would reveal nothing
new or nothing crackable. The least-disruptive primitive is always preferred: a
clientless PMKID request before any client-affecting deauth.
"""

from __future__ import annotations

from dataclasses import dataclass

from airwarden.models import Encryption, TargetAssessment

# Action identifiers mirror airwarden.bettercap_client / the scope 'active_actions' list.
ACTION_PMKID = "pmkid_capture"
ACTION_DEAUTH = "deauth_targeted"
ACTION_CONFIG = "config_review"
ACTION_NONE = "none"

_PERSONAL = (Encryption.WPA, Encryption.WPA2)


@dataclass
class ActiveRecommendation:
    """A single described follow-up step for one target (no action is taken)."""

    action: str  # none | config_review | pmkid_capture | deauth_targeted
    priority: str  # none | low | medium | high
    channel: int
    rationale: str  # why this target is called out
    yields: str  # what the step would reveal
    authorization_note: str  # preconditions, empty when no gated action applies


def _auth_note(action: str) -> str:
    if action in (ACTION_NONE, ACTION_CONFIG):
        return ""
    return (
        f"Authorized only: needs AIRWARDEN_AUTHORIZED=1, this BSSID in scope "
        f"'targets', and '{action}' in 'active_actions'. One single-client action, "
        f"with typed human confirmation."
    )


def _has_finding(t: TargetAssessment, code: str) -> bool:
    return any(f.code == code for f in t.findings)


def recommend_active_step(t: TargetAssessment) -> ActiveRecommendation:
    """Return the single most informative authorized follow-up step for ``t``."""
    ap = t.ap
    ch = ap.channel

    # 1. Key material already present — nothing active left to do.
    if t.handshake_captured or t.pmkid_captured:
        return ActiveRecommendation(
            ACTION_NONE,
            "none",
            ch,
            "Key material for this BSSID is already present in the capture.",
            "Assess PSK strength offline from the captured handshake/PMKID; "
            "no further active step is needed.",
            "",
        )

    # 2. Open — no key to recover.
    if ap.encryption == Encryption.OPEN:
        return ActiveRecommendation(
            ACTION_NONE,
            "none",
            ch,
            "Open network — there is no key to recover.",
            "Traffic is already exposed; capture client traffic passively rather than acting.",
            "",
        )

    # 3. WEP — broken offline from passive frames; remediation, not capture.
    if ap.encryption == Encryption.WEP:
        return ActiveRecommendation(
            ACTION_CONFIG,
            "low",
            ch,
            "WEP is broken offline from passively collected frames.",
            "No gated action is needed to prove the weakness; prioritise migration to WPA2/3.",
            "",
        )

    # 4a. WPA3/WPA2 transition mode — a WPA2-capable client can be downgraded.
    if ap.encryption == Encryption.WPA3 and _has_finding(t, "WPA3_DOWNGRADE_POSSIBLE"):
        return ActiveRecommendation(
            ACTION_DEAUTH,
            "high",
            ch,
            f"WPA3/WPA2 transition mode on channel {ch} (SAE + PSK advertised).",
            "A single-client targeted deauth can push a WPA2-capable client to reassociate over "
            "WPA2, exposing a crackable 4-way handshake (downgrade). WPA3-only closes this.",
            _auth_note(ACTION_DEAUTH),
        )

    # 4. WPA3/SAE or Enterprise — no offline-crackable PSK.
    if ap.encryption in (Encryption.WPA3, Encryption.ENTERPRISE):
        rationale = (
            "WPA3/SAE is not exposed to offline PSK cracking."
            if ap.encryption == Encryption.WPA3
            else "802.1X/Enterprise has no pre-shared key to recover."
        )
        return ActiveRecommendation(
            ACTION_CONFIG,
            "none",
            ch,
            rationale,
            "A handshake or PMKID capture would not yield crackable material; "
            "review PMF/RADIUS/EAP configuration instead.",
            "",
        )

    # 5. WPA / WPA2 personal with no key material captured yet.
    if ap.encryption in _PERSONAL:
        enc = ap.encryption.value.upper()
        if ap.pmf_enabled:
            return ActiveRecommendation(
                ACTION_PMKID,
                "medium",
                ch,
                f"{enc} personal on channel {ch}, PMF enabled, no key material captured yet; "
                "forged deauth is rejected while PMF is on.",
                "A clientless PMKID request (wifi.assoc) may return an RSN PMKID to test PSK "
                "strength offline, without disrupting any client. Deauth is not useful here.",
                _auth_note(ACTION_PMKID),
            )
        return ActiveRecommendation(
            ACTION_PMKID,
            "high",
            ch,
            f"{enc} personal on channel {ch}, PMF off, no handshake or PMKID captured yet.",
            f"Tune to channel {ch} and try a clientless PMKID request first (least disruptive). "
            "If it returns nothing and an associated client is present, a single-client targeted "
            "deauth on this BSSID forces one re-association so the 4-way handshake can be "
            "captured — then test PSK strength offline.",
            _auth_note(ACTION_PMKID),
        )

    # 6. Encryption unknown.
    return ActiveRecommendation(
        ACTION_NONE,
        "none",
        ch,
        "Encryption could not be determined from the capture.",
        "Collect more beacons/probe responses on this channel before deciding on any action.",
        "",
    )


def has_active_suggestion(rec: ActiveRecommendation) -> bool:
    """True when ``rec`` names a gated active primitive (not config/none)."""
    return rec.action in (ACTION_PMKID, ACTION_DEAUTH)
