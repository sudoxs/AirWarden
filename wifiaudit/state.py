"""Label each finding as a CONFIRMED weakness or a POTENTIAL (conditional) one.

- CONFIRMED: the condition is present in the capture, so the network is
  vulnerable now (open network, WEP in use, a captured handshake, a leaked
  credential, ...).
- POTENTIAL: the precondition exists but exploitation needs an event or an
  attack first; ``condition`` says what would have to happen.

This is a pure mapping over finding codes, so it works identically on the file
and live paths.
"""

from __future__ import annotations

from wifiaudit.models import Finding

CONFIRMED = "confirmed"
POTENTIAL = "potential"

# code -> (state, condition). condition is empty for CONFIRMED findings.
_STATE_MAP: dict[str, tuple[str, str]] = {
    # --- CONFIRMED: the weakness / leak is present right now ---
    "OPEN_NETWORK": (CONFIRMED, ""),
    "WEAK_CRYPTO": (CONFIRMED, ""),
    "HANDSHAKE_CAPTURED": (CONFIRMED, ""),
    "PMKID_CAPTURED": (CONFIRMED, ""),
    "DISCONNECT_FLOOD": (CONFIRMED, ""),
    "ENTERPRISE_EAP": (CONFIRMED, ""),
    "WEAK_EAP": (CONFIRMED, ""),
    "EAP_IDENTITY_LEAK": (CONFIRMED, ""),
    "HTTP_CREDENTIAL": (CONFIRMED, ""),
    "HTTP_COOKIE": (CONFIRMED, ""),
    "HTTP_BASIC_AUTH": (CONFIRMED, ""),
    # --- POTENTIAL: exploitable only if a condition/attack is met ---
    "WPS_ENABLED": (
        POTENTIAL,
        "if WPS is not locked, an online PIN / Pixie-Dust attack recovers the PSK",
    ),
    "NO_PMF": (
        POTENTIAL,
        "if a client is associated, forged deauth/disassoc can disconnect it or force a handshake",
    ),
    "WPA3_DOWNGRADE_POSSIBLE": (
        POTENTIAL,
        "if a WPA2-capable client associates and is deauthed, a WPA2 handshake can be captured "
        "and cracked",
    ),
    "PSK_OFFLINE_IF_CAPTURED": (
        POTENTIAL,
        "if a 4-way handshake or PMKID is captured (a client auth, or a deauth to force one), "
        "the PSK is crackable offline",
    ),
    "SAE_ONLINE_ONLY": (
        POTENTIAL,
        "WPA3-SAE resists offline cracking; only an online guessing attack (e.g. wacker) can try "
        "weak passwords",
    ),
    "OWE_EVIL_TWIN": (
        POTENTIAL,
        "Enhanced Open encrypts but does not authenticate the AP; a rogue/evil-twin AP can MitM "
        "clients",
    ),
    "ENTERPRISE_ROGUE_AP": (
        POTENTIAL,
        "if a client does not validate the RADIUS server certificate, a rogue AP can harvest "
        "MSCHAPv2 / identities",
    ),
}


def finding_state(finding: Finding) -> tuple[str, str]:
    """Return (state, condition) for a finding; unknown codes default to CONFIRMED."""
    return _STATE_MAP.get(finding.code, (CONFIRMED, ""))


def is_potential(finding: Finding) -> bool:
    return finding_state(finding)[0] == POTENTIAL
