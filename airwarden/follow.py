"""Live-follow mode for ``airwarden survey``: tail growing inputs, dedup findings.

Passive and advisory only, exactly like the one-shot survey. This watches files
that *other* tools (airodump-ng, a growing pcap) write and reports *new* findings
as they appear. It transmits nothing, runs no attack, and never cracks, deauths,
stands up a rogue AP, relays, or brute-forces WPS.

A *finding* is a user-facing observation derived from the existing passive
pipeline — the scan inventory (:mod:`airwarden.scan_ingestor`), the extracted
artifacts (:mod:`airwarden.pcap_extractor`), and handshake evidence
(:mod:`airwarden.handshake_detector`). Findings are deduplicated by a stable
key::

    (finding_type, bssid, client_mac, evidence_hash)

``evidence_hash`` is a short hash of the normalized evidence payload with the
frame number excluded, so a repeated identical detection collapses onto the
first occurrence while its observation count climbs. Distinct findings that
merely share a type are never collapsed — only a full stable-key match does.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from airwarden.handshake_detector import HandshakeEvidence
from airwarden.pcap_extractor import Artifact
from airwarden.scan_ingestor import ScanAP, ScanClient

# Artifact kinds already covered by the dedicated per-pair handshake findings,
# so we do not also emit a finding per raw EAPOL/PMKID frame.
_HANDSHAKE_KINDS = {"WPA_HANDSHAKE", "PMKID"}
# Extra keys that count occurrences rather than identify a finding; excluded
# from the stable key so a growing count does not spawn a new finding.
_VOLATILE_EXTRA = {"count"}


class FollowError(Exception):
    """A file being followed cannot be read (e.g. permission denied)."""


# ---------------------------------------------------------------------------
# Finding model + stable key
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """One user-facing observation from the passive pipeline."""

    finding_type: str
    label: str
    bssid: str | None = None
    ssid: str | None = None
    client_mac: str | None = None
    frame: int | None = None
    key_payload: dict[str, Any] = field(default_factory=dict)

    def evidence_hash(self) -> str:
        """Short hash of the normalized evidence payload (frame excluded)."""
        blob = json.dumps(self.key_payload, sort_keys=True, default=str)
        digest = hashlib.sha1(blob.encode("utf-8"), usedforsecurity=False)
        return digest.hexdigest()[:12]

    def stable_key(self) -> tuple[str, str | None, str | None, str]:
        return (self.finding_type, self.bssid, self.client_mac, self.evidence_hash())

    def key_str(self) -> str:
        t, b, c, h = self.stable_key()
        return f"{t}|{b or '-'}|{c or '-'}|{h}"


# ---------------------------------------------------------------------------
# Finding producers
# ---------------------------------------------------------------------------


def findings_from_ap(ap: ScanAP) -> list[Finding]:
    """Findings implied by one access point's advertised properties."""
    name = ap.essid or "<hidden>"
    enc = (ap.enc or "?").upper()
    auth = (ap.auth or "?").upper()
    out = [
        Finding(
            "AP",
            f"AP discovered: {name} ({enc}/{auth}) ch {ap.channel or '?'}",
            bssid=ap.bssid,
            ssid=ap.essid,
        )
    ]
    if enc in ("OPN", "OPEN"):
        out.append(
            Finding("OPEN_NETWORK", f"open network {name} — client traffic is unencrypted",
                    bssid=ap.bssid, ssid=ap.essid)
        )
    if enc == "WEP":
        out.append(
            Finding("WEP", f"WEP network {name} — key recoverable offline from IVs",
                    bssid=ap.bssid, ssid=ap.essid)
        )
    if ap.wpa3_transition:
        out.append(
            Finding("WPA3_TRANSITION", f"{name} in WPA3/WPA2 transition — downgrade possible",
                    bssid=ap.bssid, ssid=ap.essid)
        )
    if ap.wps_version:
        out.append(
            Finding("WPS", f"{name} advertises WPS ({ap.wps_version})", bssid=ap.bssid,
                    ssid=ap.essid, key_payload={"version": ap.wps_version})
        )
    if ap.hidden:
        out.append(Finding("HIDDEN_SSID", f"hidden SSID on {ap.bssid}", bssid=ap.bssid))
    return out


def findings_from_client(client: ScanClient) -> list[Finding]:
    """Findings implied by one station: association and the SSIDs it probes for."""
    out: list[Finding] = []
    if client.bssid:
        out.append(
            Finding("CLIENT", f"client {client.station} associated to {client.bssid}",
                    bssid=client.bssid, client_mac=client.station)
        )
    for ssid in client.probes:
        out.append(
            Finding("PROBE", f"client {client.station} probing for {ssid!r}",
                    client_mac=client.station, ssid=ssid, key_payload={"ssid": ssid})
        )
    return out


def findings_from_artifact(a: Artifact) -> Finding | None:
    """Turn one extracted artifact into a finding (handshake kinds handled apart)."""
    if a.kind in _HANDSHAKE_KINDS:
        return None
    payload: dict[str, Any] = {k: v for k, v in a.extra.items() if k not in _VOLATILE_EXTRA}
    payload["src"] = a.src
    payload["dst"] = a.dst
    return Finding(a.kind, a.snippet or a.kind, bssid=a.bssid, client_mac=a.src,
                   frame=a.frame, key_payload=payload)


def findings_from_handshake(h: HandshakeEvidence) -> list[Finding]:
    """Handshake / PMKID findings for one (BSSID, client) pair."""
    out: list[Finding] = []
    frame = h.frames[0] if h.frames else None
    if h.complete_handshake:
        span = ""
        if len(h.frames) == 1:
            span = f" (frame {h.frames[0]})"
        elif h.frames:
            span = f" (frames {h.frames[0]}-{h.frames[-1]})"
        out.append(
            Finding("HANDSHAKE", f"Handshake detected{span}", bssid=h.bssid,
                    client_mac=h.client, frame=frame)
        )
    if h.pmkid:
        out.append(
            Finding("PMKID", "PMKID captured", bssid=h.bssid, client_mac=h.client, frame=frame)
        )
    return out


def findings_from_pcap(
    artifacts: list[Artifact], handshakes: list[HandshakeEvidence]
) -> list[Finding]:
    """All findings from a pcap's extracted artifacts and handshake evidence."""
    out: list[Finding] = []
    for a in artifacts:
        f = findings_from_artifact(a)
        if f is not None:
            out.append(f)
    for h in handshakes:
        out.extend(findings_from_handshake(h))
    return out


def attach_ssids(findings: list[Finding], aps: dict[str, ScanAP]) -> None:
    """Fill a finding's SSID from the scan inventory when only the BSSID is known."""
    for f in findings:
        if f.ssid is None and f.bssid and f.bssid in aps:
            f.ssid = aps[f.bssid].essid


# ---------------------------------------------------------------------------
# Deduplication store
# ---------------------------------------------------------------------------


@dataclass
class FindingRecord:
    """The running tally for one stable key."""

    finding: Finding
    first_seen: float
    last_seen: float
    count: int
    sample_frame: int | None


class DedupStore:
    """Collapse repeated findings by stable key, keeping per-key counts/timestamps."""

    def __init__(
        self, *, clock: Callable[[], float] = time.time, started_at: float | None = None
    ) -> None:
        self._clock = clock
        self.started_at = started_at if started_at is not None else clock()
        self._records: dict[tuple[str, str | None, str | None, str], FindingRecord] = {}

    def now(self) -> float:
        return self._clock()

    def observe(self, finding: Finding) -> tuple[FindingRecord, bool]:
        """Register one observation; return ``(record, is_new)``.

        ``is_new`` is True only the first time a stable key is seen. Repeats
        increment the key's count and refresh ``last_seen``.
        """
        key = finding.stable_key()
        now = self._clock()
        rec = self._records.get(key)
        if rec is None:
            rec = FindingRecord(finding, now, now, 1, finding.frame)
            self._records[key] = rec
            return rec, True
        rec.count += 1
        rec.last_seen = now
        if rec.sample_frame is None and finding.frame is not None:
            rec.sample_frame = finding.frame
        return rec, False

    @property
    def records(self) -> list[FindingRecord]:
        return list(self._records.values())

    @property
    def unique_count(self) -> int:
        return len(self._records)

    @property
    def total_count(self) -> int:
        return sum(r.count for r in self._records.values())

    @property
    def duplicate_count(self) -> int:
        """Observations suppressed as repeats (total minus unique)."""
        return self.total_count - self.unique_count


# ---------------------------------------------------------------------------
# CSV tailer
# ---------------------------------------------------------------------------


class CsvTailer:
    """Read only the newly appended, complete lines of a growing CSV.

    Remembers the last byte offset, keeps a partial trailing line until its
    newline arrives, and detects truncation/rotation (the file shrinking below
    the last offset) by restarting from the top.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._pos = 0
        self._buf = ""

    def poll(self) -> tuple[bool, list[str]]:
        """Return ``(rotated, new_complete_lines)``; a missing file yields ``(False, [])``."""
        try:
            size = self.path.stat().st_size
        except FileNotFoundError:
            return False, []
        except PermissionError as exc:
            raise FollowError(f"cannot read {self.path}: {exc}") from exc

        rotated = False
        if size < self._pos:
            rotated = True
            self._pos = 0
            self._buf = ""

        try:
            with self.path.open("rb") as fh:
                fh.seek(self._pos)
                chunk = fh.read()
                self._pos = fh.tell()
        except FileNotFoundError:
            return rotated, []
        except PermissionError as exc:
            raise FollowError(f"cannot read {self.path}: {exc}") from exc

        data = self._buf + chunk.decode("utf-8", errors="ignore")
        parts = data.split("\n")
        self._buf = parts.pop()  # trailing partial line (or "" if data ended in \n)
        # Tolerate CRLF endings (airodump on some platforms, files copied via Windows).
        return rotated, [p[:-1] if p.endswith("\r") else p for p in parts]


# ---------------------------------------------------------------------------
# Reporting + CLI formatting
# ---------------------------------------------------------------------------


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).isoformat()


def record_to_dict(rec: FindingRecord) -> dict[str, Any]:
    """Serialize one record to the finding JSON schema."""
    f = rec.finding
    return {
        "finding_type": f.finding_type,
        "label": f.label,
        "bssid": f.bssid,
        "ssid": f.ssid,
        "client_mac": f.client_mac,
        "count": rec.count,
        "first_seen": _iso(rec.first_seen),
        "last_seen": _iso(rec.last_seen),
        "duplicate": rec.count > 1,
        "duplicate_of": f.key_str(),
        "sample_frame": rec.sample_frame,
    }


def findings_report(
    store: DedupStore, *, follow_mode: bool, files_followed: list[str]
) -> dict[str, Any]:
    """Build the ``session`` + ``findings`` JSON blocks from a dedup store."""
    recs = store.records
    return {
        "session": {
            "started_at": _iso(store.started_at),
            "last_updated_at": _iso(store.now()),
            "follow_mode": follow_mode,
            "files_followed": files_followed,
            "total_findings": store.total_count,
            "unique_findings": store.unique_count,
            "duplicate_findings": store.duplicate_count,
        },
        "findings": [record_to_dict(r) for r in recs],
    }


def format_cli_line(rec: FindingRecord, *, show_count: bool, ts: float | None = None) -> str:
    """One console line: ``[HH:MM:SS] [×N] [context] label``."""
    f = rec.finding
    parts: list[str] = []
    if ts is not None:
        parts.append(datetime.fromtimestamp(ts).strftime("[%H:%M:%S]"))
    if show_count:
        parts.append(f"[×{rec.count}]")
    context = f.ssid or f.bssid or f.client_mac
    if context:
        parts.append(f"[{context}]")
    parts.append(f.label)
    return " ".join(parts)


def session_summary(store: DedupStore, *, duration: float, json_path: str | None) -> str:
    """The Ctrl-C end-of-session summary block."""
    total_seconds = max(int(duration), 0)
    minutes, seconds = divmod(total_seconds, 60)
    hours, minutes = divmod(minutes, 60)
    lines = [
        "=== Session summary ===",
        f"Unique findings: {store.unique_count}",
        f"Duplicates suppressed: {store.duplicate_count}",
        f"Duration: {hours:02d}:{minutes:02d}:{seconds:02d}",
    ]
    if json_path:
        lines.append(f"JSON report written to: {json_path}")
    return "\n".join(lines)
