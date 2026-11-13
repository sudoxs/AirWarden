"""Passive pcap analysis (RESERVED — STUB).

The real implementation is supplied at integration time.
"""

from __future__ import annotations

from wifiaudit.models import TargetAssessment


def analyze_pcap(path: str) -> tuple[list[TargetAssessment], dict]:
    raise NotImplementedError("replaced at integration time")
