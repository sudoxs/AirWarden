"""Authorization gate for gated (active) actions."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class AuthorizationError(RuntimeError):
    """Raised when an action is not authorized by the signed scope."""


class AuthorizationGate:
    ENV_FLAG = "WIFIAUDIT_AUTHORIZED"
    SCOPE_ENV = "WIFIAUDIT_SCOPE_FILE"
    DEFAULT_SCOPE = Path("scope.json")

    def __init__(self, scope_path: str | Path | None = None) -> None:
        if os.environ.get(self.ENV_FLAG) != "1":
            raise AuthorizationError(
                f"Active mode disabled. Set {self.ENV_FLAG}=1 only after a "
                "signed scope file is in place."
            )
        path = Path(scope_path or os.environ.get(self.SCOPE_ENV) or self.DEFAULT_SCOPE)
        self.scope = self._load_and_validate(path)
        self.audit_log: list[dict[str, Any]] = []

    @staticmethod
    def _load_and_validate(path: Path) -> dict[str, Any]:
        if not path.is_file():
            raise AuthorizationError(f"Scope file not found: {path}")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise AuthorizationError(f"Scope file is not valid JSON: {exc}") from exc
        required = {
            "engagement_id",
            "authorized_by",
            "valid_from",
            "valid_until",
            "targets",
            "active_actions",
        }
        missing = required - data.keys()
        if missing:
            raise AuthorizationError(f"Scope file missing keys: {sorted(missing)}")
        now = datetime.now(UTC)
        try:
            valid_from = datetime.fromisoformat(data["valid_from"])
            valid_until = datetime.fromisoformat(data["valid_until"])
        except ValueError as exc:
            raise AuthorizationError(f"Scope file has invalid validity dates: {exc}") from exc
        if not (valid_from <= now <= valid_until):
            raise AuthorizationError(
                f"Scope file is outside its validity window "
                f"({data['valid_from']} .. {data['valid_until']})."
            )
        if not isinstance(data["targets"], list) or not data["targets"]:
            raise AuthorizationError("Scope 'targets' must be a non-empty list.")
        if not isinstance(data["active_actions"], list):
            raise AuthorizationError("Scope 'active_actions' must be a list.")
        return data

    @staticmethod
    def _normalize_bssid(bssid: str) -> str:
        return bssid.strip().lower().replace("-", ":")

    def assert_target_allowed(self, bssid: str) -> None:
        normalized = self._normalize_bssid(bssid)
        allowed = {self._normalize_bssid(t) for t in self.scope["targets"]}
        if normalized not in allowed:
            self._log("scope_check", target=normalized, result="denied")
            raise AuthorizationError(f"BSSID {bssid} is not listed in the signed scope.")
        self._log("scope_check", target=normalized, result="allowed")

    def confirm_active_action(self, action: str, target: str, reason: str) -> None:
        if action not in self.scope.get("active_actions", []):
            self._log("action_denied", action=action, target=target, reason="not in scope")
            raise AuthorizationError(f"Action '{action}' is not permitted by the signed scope.")
        phrase = f"CONFIRM {action.upper()} {target}"
        print(f"\n[ACTIVE ACTION] {action} -> {target}\nReason: {reason}")
        typed = input(f"Type exactly '{phrase}' to proceed: ").strip()
        if typed != phrase:
            self._log(
                "action_denied", action=action, target=target, reason="human confirmation failed"
            )
            raise AuthorizationError("Human confirmation failed; aborted.")
        self._log("active_action", action=action, target=target, reason=reason)

    def _log(self, event: str, **fields: Any) -> None:
        self.audit_log.append({"ts": datetime.now(UTC).isoformat(), "event": event, **fields})
