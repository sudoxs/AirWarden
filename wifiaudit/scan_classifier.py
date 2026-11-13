"""Scan-type classification (RESERVED — STUB).

The real implementation is supplied at integration time.
"""

from __future__ import annotations

from wifiaudit.models import ScanType


def classify_scan(frames) -> tuple[ScanType, dict]:
    raise NotImplementedError("replaced at integration time")
