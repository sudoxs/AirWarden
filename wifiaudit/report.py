"""Report writers: JSON, CSV, and a self-contained HTML report (Jinja2)."""

from __future__ import annotations

import csv
import json
from dataclasses import asdict
from enum import Enum
from pathlib import Path
from typing import Any

from jinja2 import Environment, select_autoescape

from wifiaudit.advisor import has_active_suggestion, recommend_active_step
from wifiaudit.config import redact_mac
from wifiaudit.models import Encryption, Finding, TargetAssessment

FOOTER = "Authorized engagement only. Active actions require written authorization."

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

CSV_COLUMNS = (
    "bssid",
    "ssid",
    "channel",
    "encryption",
    "wps_enabled",
    "pmf_enabled",
    "vendor",
    "beacon_count",
    "clients",
    "risk_score",
    "handshake_captured",
    "pmkid_captured",
    "finding_codes",
)

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>wifiaudit report</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a1a; }
  h1, h2 { margin-bottom: .4rem; }
  table { border-collapse: collapse; width: 100%; margin: .5rem 0 1.5rem; font-size: .9rem; }
  th, td { border: 1px solid #ccc; padding: .3rem .5rem; text-align: left; vertical-align: top; }
  th { background: #f0f0f0; }
  td.num { text-align: right; }
  .summary td:first-child { font-weight: 600; width: 14rem; }
  p.caption { font-size: .85rem; color: #555; margin: .2rem 0 .6rem; }
  footer { margin-top: 2rem; font-size: .85rem; color: #555; border-top: 1px solid #ccc;
           padding-top: .5rem; }
</style>
</head>
<body>
<h1>wifiaudit report</h1>

<h2>Executive summary</h2>
<table class="summary">
  <tr><td>Scan type</td><td>{{ scan_type }}</td></tr>
  <tr><td>Total APs</td><td>{{ total }}</td></tr>
  {% for band, count in bands.items() %}
  <tr><td>Risk {{ band }}</td><td>{{ count }}</td></tr>
  {% endfor %}
</table>

<h2>Access points</h2>
<table>
  <thead>
    <tr>
      <th>BSSID</th><th>SSID</th><th>CH</th><th>ENC</th><th>WPS</th><th>PMF</th>
      <th>Risk</th><th>HS</th><th>PMKID</th><th>Findings (codes)</th>
      <th>Recommended next step</th>
    </tr>
  </thead>
  <tbody>
  {% for r in rows %}
    <tr>
      <td>{{ r.bssid }}</td><td>{{ r.ssid }}</td><td class="num">{{ r.channel }}</td>
      <td>{{ r.encryption }}</td><td>{{ r.wps }}</td><td>{{ r.pmf }}</td>
      <td class="num">{{ r.risk }}</td><td>{{ r.hs }}</td><td>{{ r.pmkid }}</td>
      <td>{{ r.codes }}</td><td>{{ r.next_step }}</td>
    </tr>
  {% else %}
    <tr><td colspan="11">No access points found.</td></tr>
  {% endfor %}
  </tbody>
</table>

<h2>Requires targeted follow-up</h2>
{% if follow_up %}
<ul>
  {% for bssid in follow_up %}<li>{{ bssid }}</li>{% endfor %}
</ul>
{% else %}
<p>None.</p>
{% endif %}

<h2>Active follow-up recommendations</h2>
<p class="caption">Authorized engagements only — each item describes a single gated,
single-target action and what it would reveal. Nothing here is performed automatically.</p>
{% if active_rows %}
<table>
  <thead>
    <tr>
      <th>BSSID</th><th>CH</th><th>Suggested action</th><th>Priority</th>
      <th>Why</th><th>What it would reveal</th><th>Authorization</th>
    </tr>
  </thead>
  <tbody>
  {% for a in active_rows %}
    <tr>
      <td>{{ a.bssid }}</td><td class="num">{{ a.channel }}</td><td>{{ a.action }}</td>
      <td>{{ a.priority }}</td><td>{{ a.rationale }}</td><td>{{ a.yields }}</td>
      <td>{{ a.authorization_note }}</td>
    </tr>
  {% endfor %}
  </tbody>
</table>
{% else %}
<p>None.</p>
{% endif %}

<footer>{{ footer }}</footer>
</body>
</html>
"""


def _value(v: Any) -> Any:
    """Return an Enum's value, or ``v`` unchanged."""
    return v.value if isinstance(v, Enum) else v


def _mac(mac: str, redact: bool) -> str:
    return redact_mac(mac) if redact else mac


def _dash(v: Any) -> str:
    return "—" if v is None or v == "" else str(v)


def _yn(flag: bool) -> str:
    return "yes" if flag else "no"


def top_finding(t: TargetAssessment) -> Finding | None:
    """Return the most severe finding (ties broken by confidence), or ``None``."""
    if not t.findings:
        return None
    return max(t.findings, key=lambda f: (_SEVERITY_RANK.get(f.severity.lower(), -1), f.confidence))


def risk_band(score: float) -> str:
    """Map a 0-100 risk score to one of the bands ``0-30``, ``31-60``, ``61-100``."""
    if score <= 30:
        return "0-30"
    if score <= 60:
        return "31-60"
    return "61-100"


def needs_targeted_follow_up(t: TargetAssessment) -> bool:
    """True if a WPA2 AP has no handshake/PMKID, or WPS is on without PMF."""
    no_material_wpa2 = (
        not t.handshake_captured and not t.pmkid_captured and t.ap.encryption == Encryption.WPA2
    )
    wps_without_pmf = not t.ap.pmf_enabled and t.ap.wps_enabled
    return no_material_wpa2 or wps_without_pmf


def _next_step(t: TargetAssessment) -> str:
    top = top_finding(t)
    if top is not None and top.recommendation:
        return top.recommendation
    if needs_targeted_follow_up(t):
        return "Targeted follow-up within authorized scope."
    return "No action required; continue monitoring."


def _serialize(t: TargetAssessment, redact: bool) -> dict[str, Any]:
    data = asdict(t)
    ap = data["ap"]
    ap["bssid"] = _mac(ap["bssid"], redact)
    ap["encryption"] = _value(ap["encryption"])
    ap["clients"] = sorted(_mac(c, redact) for c in ap["clients"])
    data["active_recommendation"] = asdict(recommend_active_step(t))
    return data


def _ensure_parent(path: str) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def to_json(
    assessments: list[TargetAssessment],
    meta: dict,
    path: str,
    *,
    redact_macs: bool = True,
) -> None:
    """Write ``{"meta": ..., "assessments": [...]}`` as pretty-printed JSON."""
    doc = {
        "meta": meta,
        "redacted": redact_macs,
        "assessments": [_serialize(t, redact_macs) for t in assessments],
    }
    p = _ensure_parent(path)
    p.write_text(
        json.dumps(doc, indent=2, default=lambda o: _value(o) if isinstance(o, Enum) else str(o)),
        encoding="utf-8",
    )


def to_csv(
    assessments: list[TargetAssessment],
    path: str,
    *,
    redact_macs: bool = True,
) -> None:
    """Write one CSV row per AP. Clients and finding codes are ``;``-joined."""
    p = _ensure_parent(path)
    with p.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for t in assessments:
            ap = t.ap
            writer.writerow(
                {
                    "bssid": _mac(ap.bssid, redact_macs),
                    "ssid": ap.ssid,
                    "channel": ap.channel,
                    "encryption": _value(ap.encryption),
                    "wps_enabled": ap.wps_enabled,
                    "pmf_enabled": ap.pmf_enabled,
                    "vendor": ap.vendor or "",
                    "beacon_count": ap.beacon_count,
                    "clients": ";".join(sorted(_mac(c, redact_macs) for c in ap.clients)),
                    "risk_score": f"{t.risk_score:.1f}",
                    "handshake_captured": t.handshake_captured,
                    "pmkid_captured": t.pmkid_captured,
                    "finding_codes": ";".join(f.code for f in t.findings),
                }
            )


def to_html(
    assessments: list[TargetAssessment],
    meta: dict,
    path: str,
    *,
    redact_macs: bool = True,
) -> None:
    """Render a standalone HTML report (summary, per-AP table, follow-up list)."""
    bands = {"0-30": 0, "31-60": 0, "61-100": 0}
    rows = []
    follow_up = []
    active_rows = []
    for t in assessments:
        ap = t.ap
        bssid = _mac(ap.bssid, redact_macs)
        bands[risk_band(t.risk_score)] += 1
        if needs_targeted_follow_up(t):
            follow_up.append(bssid)
        rec = recommend_active_step(t)
        if has_active_suggestion(rec):
            active_rows.append(
                {
                    "bssid": bssid,
                    "channel": _dash(ap.channel),
                    "action": rec.action,
                    "priority": rec.priority,
                    "rationale": rec.rationale,
                    "yields": rec.yields,
                    "authorization_note": rec.authorization_note,
                }
            )
        rows.append(
            {
                "bssid": bssid,
                "ssid": _dash(ap.ssid),
                "channel": _dash(ap.channel),
                "encryption": _value(ap.encryption),
                "wps": _yn(ap.wps_enabled),
                "pmf": _yn(ap.pmf_enabled),
                "risk": f"{t.risk_score:.1f}",
                "hs": _yn(t.handshake_captured),
                "pmkid": _yn(t.pmkid_captured),
                "codes": _dash(", ".join(f.code for f in t.findings)),
                "next_step": _next_step(t),
            }
        )

    env = Environment(autoescape=select_autoescape(default=True, default_for_string=True))
    html = env.from_string(_HTML_TEMPLATE).render(
        scan_type=_dash(_value(meta.get("scan_type"))),
        total=len(assessments),
        bands=bands,
        rows=rows,
        follow_up=follow_up,
        active_rows=active_rows,
        footer=FOOTER,
    )
    _ensure_parent(path).write_text(html, encoding="utf-8")
