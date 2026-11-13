"""Gated HTTP client for bettercap's REST API (single-target actions only)."""

from __future__ import annotations

import time
from typing import Any

import requests

from wifiaudit.auth_gate import AuthorizationGate


class BettercapClient:
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        gate: AuthorizationGate,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.auth = (username, password)
        self.gate = gate

    def _cmd(self, command: str, timeout: float = 30.0) -> dict[str, Any]:
        last_err: Exception | None = None
        for attempt in range(3):
            try:
                r = requests.post(
                    f"{self.base_url}/api/cmd/wifi",
                    json={"cmd": command},
                    auth=self.auth,
                    timeout=timeout,
                )
                if 500 <= r.status_code < 600:
                    raise requests.HTTPError(f"bettercap 5xx: {r.status_code}")
                r.raise_for_status()
                return r.json()
            except (requests.ConnectionError, requests.Timeout, requests.HTTPError) as exc:
                last_err = exc
                if attempt < 2:
                    time.sleep(2**attempt)
                    continue
                raise
        raise RuntimeError(f"bettercap command failed: {last_err}")

    def start_recon(self) -> dict[str, Any]:
        return self._cmd("wifi.recon on")

    def list_aps(self) -> dict[str, Any]:
        r = requests.get(
            f"{self.base_url}/api/session/wifi",
            auth=self.auth,
            timeout=10,
        )
        r.raise_for_status()
        return r.json()

    def capture_pmkid(self, bssid: str) -> dict[str, Any]:
        self.gate.assert_target_allowed(bssid)
        self.gate.confirm_active_action("pmkid_capture", bssid, "operator requested PMKID capture")
        return self._cmd(f"wifi.assoc {bssid}")

    def deauth_targeted(self, bssid: str, client_mac: str, reason: str) -> dict[str, Any]:
        self.gate.assert_target_allowed(bssid)
        self.gate.confirm_active_action("deauth_targeted", f"{bssid}/{client_mac}", reason)
        return self._cmd(f"wifi.deauth {client_mac}")
