"""Authorization gate for active actions (RESERVED — STUB).

Every active action must pass through ``AuthorizationGate``. The real
implementation is supplied at integration time.
"""

from __future__ import annotations

from pathlib import Path


class AuthorizationError(RuntimeError): ...


class AuthorizationGate:
    ENV_FLAG: str
    SCOPE_ENV: str
    DEFAULT_SCOPE: Path

    def __init__(self, scope_path: str | Path | None = None) -> None:
        raise NotImplementedError("replaced at integration time")

    def assert_target_allowed(self, bssid: str) -> None:
        raise NotImplementedError("replaced at integration time")

    def confirm_active_action(self, action: str, target: str, reason: str) -> None:
        raise NotImplementedError("replaced at integration time")
