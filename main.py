"""Minimal non-CLI entry point: ``python main.py <capture.pcap>``."""

from __future__ import annotations

import sys

from wifiaudit.pcap_analyzer import analyze_pcap
from wifiaudit.report import to_html, to_json
from wifiaudit.risk_scorer import score_target

EXIT_STUB = 3


def run_audit(pcap_path: str, output_prefix: str = "report", redact_macs: bool = True) -> None:
    """Analyze a capture, score and sort targets, and write JSON + HTML reports."""
    try:
        # TODO(integration): pcap_analyzer is a stub — replaced at integration time.
        assessments, meta = analyze_pcap(pcap_path)
        for t in assessments:
            # TODO(integration): risk_scorer is a stub — replaced at integration time.
            t.risk_score = score_target(t)
    except NotImplementedError:
        sys.stderr.write(
            "wifiaudit: analysis modules are stubs in this build — "
            "they are replaced at integration time. Nothing was analyzed.\n"
        )
        sys.exit(EXIT_STUB)

    assessments.sort(key=lambda t: t.risk_score, reverse=True)
    to_json(assessments, meta, f"{output_prefix}.json", redact_macs=redact_macs)
    to_html(assessments, meta, f"{output_prefix}.html", redact_macs=redact_macs)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("usage: python main.py <capture.pcap>\n")
        sys.exit(2)
    run_audit(sys.argv[1])
