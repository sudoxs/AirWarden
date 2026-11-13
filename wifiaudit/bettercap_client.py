"""Gated Bettercap REST client (RESERVED — STUB).

All active actions are routed through an ``AuthorizationGate``. The real
implementation is supplied at integration time.
"""

from __future__ import annotations

from wifiaudit.auth_gate import AuthorizationGate


class BettercapClient:
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        gate: AuthorizationGate,
    ) -> None:
        raise NotImplementedError("replaced at integration time")

    def start_recon(self) -> dict:
        raise NotImplementedError("replaced at integration time")

    def list_aps(self) -> dict:
        raise NotImplementedError("replaced at integration time")

    def capture_pmkid(self, bssid: str) -> dict:
        raise NotImplementedError("replaced at integration time")

    def deauth_targeted(self, bssid: str, client_mac: str, reason: str) -> dict:
        raise NotImplementedError("replaced at integration time")
