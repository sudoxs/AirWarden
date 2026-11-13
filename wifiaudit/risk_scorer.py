"""Per-target risk scoring (RESERVED — STUB).

The real implementation is supplied at integration time.
"""

from __future__ import annotations

from wifiaudit.models import TargetAssessment


def score_target(t: TargetAssessment) -> float:
    raise NotImplementedError("replaced at integration time")
