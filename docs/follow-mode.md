# Live follow mode

`airwarden survey --follow` keeps the process running and polls its inputs for
new data, emitting findings as they are detected and collapsing repeats. It is a
convenience layer over the one-shot `survey` pipeline and shares its posture:
**passive and advisory only** — it reads files that other tools write and never
performs an active action (no deauth, no rogue AP, no relay, no WPS brute-force,
no cracking, no DoS). `--follow` is opt-in; without it, `survey` behaves exactly
as before.

## Usage

```bash
# Terminal 1 — airodump-ng writes a growing CSV
sudo airodump-ng wlan0mon -w ~/wifi/live --band abg --manufacturer --wps

# Terminal 2 — AirWarden follows that CSV
airwarden survey --csv ~/wifi/live-01.csv --follow

# Show repeats too, each marked [×N]
airwarden survey --csv ~/wifi/live-01.csv --follow --show-duplicates

# Write a JSON report (with per-finding counts + a session block) on exit
airwarden survey --csv ~/wifi/live-01.csv --follow -o report.json
```

`--csv`, `--iw`, and `--pcap` all work in follow mode (any subset). An `iw`
scan is a static snapshot, so it is ingested once at startup; a `--pcap` is
re-read each interval (see *Limitations*).

## Flags

| Flag | Default | Meaning |
| ---- | ------- | ------- |
| `--follow` / `-f` | off | Keep running and poll the inputs for new data. |
| `--interval SECONDS` | `2` | Polling interval for `--follow`. |
| `--show-duplicates` / `--hide-duplicates` | hide | Show every observation with a `[×N]` marker, or print each finding only the first time (default). |
| `--duplicate-threshold N` | `1` | With `--show-duplicates`, only surface a repeat once its count reaches `N`. |

## The dedup key

Every finding has a **stable key**:

```
(finding_type, bssid, client_mac, evidence_hash)
```

`evidence_hash` is a short hash of the finding's normalized evidence payload
with the **frame number excluded**, so the same detection seen again (a rewritten
airodump row, the same handshake across a pcap re-read) collapses onto the first
occurrence while its observation count climbs. Only a full stable-key match
collapses — two findings that merely share a `finding_type` are never merged, and
a change in the evidence payload (e.g. a new WPS version) is a *new* finding.

## The `[×N]` marker

With `--show-duplicates`, each line is prefixed with `[×N]`, where `N` is the
current repetition count **including** the first occurrence — so the first print
shows `[×1]`, the second `[×2]`, and so on:

```
[12:34:56] [×1] [wifi-mobile] Handshake detected (frames 221-224)
[12:35:04] [×2] [wifi-mobile] Handshake detected (frames 221-224)
```

With the default `--hide-duplicates`, a finding prints only the first time (no
marker), and each poll that produced new output ends with a summary line:

```
[i] +3 new findings, 7 duplicates suppressed
```

Even when hidden from the console, every repeat still increments the count in the
JSON report.

## JSON schema

Every finding in the JSON report carries:

| Field | Meaning |
| ----- | ------- |
| `finding_type` | The finding category (e.g. `HANDSHAKE`, `OPEN_NETWORK`, `WPS`). |
| `label` | The human-readable one-liner shown on the console. |
| `bssid` / `ssid` / `client_mac` | Attribution, when known. |
| `count` | Total times the same stable key was observed. |
| `first_seen` / `last_seen` | ISO-8601 (UTC) timestamps of the first and latest observation. |
| `duplicate` | `true` when `count > 1`. |
| `duplicate_of` | The stable key as a string (for debugging). |
| `sample_frame` | The frame number of the first occurrence (pcap findings). |

A top-level `session` block is also written:

```json
{
  "session": {
    "started_at": "2026-11-14T12:30:00+00:00",
    "last_updated_at": "2026-11-14T12:42:34+00:00",
    "follow_mode": true,
    "files_followed": ["~/wifi/live-01.csv"],
    "total_findings": 161,
    "unique_findings": 24,
    "duplicate_findings": 137
  }
}
```

The one-shot `survey` writes the same `findings` + `session` blocks (with
`follow_mode: false` and one observation per finding) alongside the existing
per-AP `aps` / `applicability` report, so tooling sees a consistent schema.

## Session summary

On `Ctrl-C`, follow mode prints a final summary:

```
=== Session summary ===
Unique findings: 24
Duplicates suppressed: 137
Duration: 00:12:34
JSON report written to: report.json
```

## Robustness

- **Growing CSV:** only newly appended, *complete* lines are parsed each poll; a
  partial trailing line is buffered until its newline arrives.
- **Rotation / truncation:** if the file shrinks below the last read offset (a
  rewrite or a new file at the same path), the parse restarts from the top with
  a `[i] CSV rotated/truncated; restarting parse` note. Previously seen APs are
  kept — re-reading is idempotent and emits no new findings.
- **Missing or empty files:** tolerated; follow mode simply waits for data.
- **Permission errors:** reported with a clear message.
- **Malformed CSV rows:** logged-over (skipped) rather than crashing.
- **Partial pcap writes:** tolerated; the pcap is retried on the next poll.

## Limitations

- airodump-ng rewrites its CSV in place rather than strictly appending. The
  rewrite is handled by the truncation-restart path, but if a rewrite keeps the
  file the same size or larger, the tailer reads from the old offset; point
  `--csv` at the current `*-NN.csv` file and let the restart path re-sync.
- `--pcap` in follow mode re-reads the whole capture each interval (the dedup
  store suppresses everything already seen). Incremental pcap tailing is not yet
  implemented, so very large growing captures are better analyzed once they are
  final with plain `survey --pcap`.
