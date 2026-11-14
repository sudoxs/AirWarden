# AirWarden

> Passive-first Wi-Fi vulnerability auditor for **authorized** engagements — it
> reads a pcap (or sniffs live), inventories every access point, and reports what
> is vulnerable now, what could become vulnerable, and what has leaked.

## Overview

AirWarden is a defensive WiFi audit tool for **authorized** penetration-testing
engagements. It:

- parses pcap/pcapng captures (passive, default mode),
- classifies the observed scan type (general / targeted / passive-only / unknown),
- inventories access points (encryption, WPS, PMF, clients),
- detects captured key material (4-way handshakes, PMKIDs) and deauth/disassoc floods,
- flags Enterprise EAP methods and cleartext identity leaks, WPA3/WPA2 transition
  (downgrade) mode, and evil-twin bait (SSIDs clients probe for that no AP beacons),
- on **open** (or decrypted) captures, flags cleartext layer-7 data exposure —
  HTTP credential POSTs, session cookies, and Basic-auth — by host and field name,
  never dumping the secret values,
- classifies every finding as an exposure (what leaked, from where, how abusable),
- labels each finding **confirmed** (vulnerable now) or **potential** (vulnerable only
  if a condition/attack is met) and states that condition — e.g. WPA/WPA2 with no
  captured handshake, WPA3-SAE, OWE, or an Enterprise network reachable via a rogue AP,
- scores per-AP risk and writes JSON, CSV, and HTML reports,
- for each target, **describes** the single authorized follow-up action that would
  reveal the most (clientless PMKID request, or a single-client targeted deauth on
  a named BSSID/channel to capture a handshake) — advice only, nothing is sent,
- can perform a small set of **gated** active actions against in-scope BSSIDs only.

Every active action goes through an `AuthorizationGate` that checks a signed-off
scope file. Default mode is passive/audit.

> **Build status:** the analysis, scoring, classification, advisory, and
> reporting modules are implemented and covered by tests — `analyze` runs a full
> passive audit today. The active path (`auth_gate`, `bettercap_client`) is wired
> but needs a reachable Bettercap instance and a signed scope file at run time.

## Platform support

| Command             | Linux | macOS | Windows | Requirements                                        |
| ------------------- | :---: | :---: | :-----: | --------------------------------------------------- |
| `analyze` (passive) |   ✅   |   ✅   |    ✅    | Python 3.11+ only — reads an existing `.pcap` file  |
| `live` (passive)    |   ✅   |   ⚠️   |    ❌    | Monitor-mode adapter and root — sniffs in real time |
| `active` (gated)    |   ✅   |   ⚠️   |    ❌    | Monitor-mode adapter, root, and a running Bettercap |

`analyze` is fully cross-platform: it only reads a capture you already have, so
you can triage on any machine. `live` and `active` drive a monitor-mode radio and
are intended for Linux; they will not work on stock Windows.

## Threat model & authorization prerequisites

Before any use beyond reading your own captures, you must have:

1. **Written authorization** from the owner of every network in scope, naming
   the engagement, the authorizing person, the time window, the BSSIDs, and the
   active actions permitted.
2. A **scope file** (`scope.json`, never committed) derived from
   [`scope.example.json`](scope.example.json):

   | Key              | Meaning                                                   |
   | ---------------- | --------------------------------------------------------- |
   | `engagement_id`  | Your engagement / ticket reference                        |
   | `authorized_by`  | Who signed the authorization                              |
   | `valid_from`     | ISO-8601 start of the authorized window                   |
   | `valid_until`    | ISO-8601 end of the authorized window                     |
   | `targets`        | Explicit list of in-scope BSSIDs                          |
   | `active_actions` | Permitted actions, e.g. `pmkid_capture`; a single-client `deauth_targeted` only if the authorization letter names it |

3. The environment flag `AIRWARDEN_AUTHORIZED=1` set deliberately for the
   session. Without it, `active` refuses to run (exit code `2`).

Captures and reports contain identifying data. MAC addresses are redacted by
default (first three octets kept, rest zeroed). Store `*.pcap`, `report.*`,
`scope.json`, and `audit.log` according to your engagement's data-handling rules;
they are git-ignored.

## Install

Requires Python 3.11+.

**As a tool (recommended)** — an isolated, global `airwarden` command via
[pipx](https://pipx.pypa.io):

```bash
pipx install .
```

Then run it from anywhere:

```bash
airwarden --version
```

**In a virtual environment** — if you prefer a plain venv:

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
```

```bash
pip install .
```

**For development** — editable install with test and lint tools:

```bash
pip install -e ".[dev]"
```

## Quickstart

No capture handy? Generate a tiny sample and analyze it — works on any OS:

```bash
python make_sample.py
```

```bash
airwarden analyze sample.pcap --output-prefix report
```

Open `report.html` in a browser for the exposure & data-leak summary, the per-AP
table with risk scores, the confirmed vs. potential (conditional) vulnerabilities,
the probe-request / evil-twin opportunities, and the "Active follow-up
recommendations" table. `report.json` holds the same data for tooling. That is the
entire passive workflow — no radio, no root, nothing sent.

## Usage

### `analyze` — passive (default)

```bash
airwarden analyze capture.pcap --output-prefix report
```

Writes `report.json` and `report.html` and prints a table
(`BSSID | SSID | CH | ENC | WPS | PMF | Risk | HS | PMKID | Top finding`),
sorted by risk. Use `--no-redact-macs` only when the engagement permits full MACs
in deliverables.

It then prints an **Active follow-up** section (and an "Active follow-up
recommendations" table in the HTML/JSON): for each target it *describes* the one
gated, single-target action that would reveal the most new information — e.g. a
clientless PMKID request, or a single-client targeted deauth on a named BSSID and
channel to capture a 4-way handshake — plus what that action would yield and the
authorization it requires. This is advice only; the `analyze` command never
transmits anything. Targets whose key material is already captured, open networks,
and WPA3/Enterprise networks are marked as needing no active step.

The console also prints the confirmed-vs-potential issue counts, any evil-twin
bait (SSIDs clients probe for that no AP beacons), and how many exposures were
classified. The HTML report breaks each of these out in full, including an
"Exposure & data-leak summary" and a "Potential (conditional) vulnerabilities"
table that states the condition under which each one becomes exploitable.

Equivalent without installing the script: `python -m airwarden.cli analyze capture.pcap`,
or the minimal wrapper `python main.py capture.pcap`.

### `live` — passive real-time capture (Linux)

Sniff a monitor-mode interface and run the full detection pipeline as frames
arrive, refreshing the table live:

```bash
sudo airwarden live --interface wlan0mon
```

The view shows the scan type, the per-AP table, and the "Active follow-up" table,
all updating in real time. It is **passive** — it only receives frames and never
transmits. Useful options:

- `--channel 6` — lock to one channel (needs Linux + `iw`).
- `--hop` — sweep 2.4 GHz channels 1–13 so one radio can see the whole band.
- `--duration 60` — stop after N seconds (default: run until `Ctrl-C`).
- `--output-prefix report` — write `report.json` / `report.html` on exit.
- `--write-pcap capture.pcap` — also save the captured frames for later `analyze`.

A live session and the pcap it writes produce identical findings — `live` and
`analyze` share one detection engine.

### `active` — gated, authorized engagements only

```bash
AIRWARDEN_AUTHORIZED=1 airwarden active --interface wlan0mon
```

Starts Bettercap recon and lists APs. No active action is taken unless
explicitly requested for a single BSSID:

```bash
AIRWARDEN_AUTHORIZED=1 airwarden active --interface wlan0mon --pmkid 00:11:22:33:44:55
```

The BSSID must be listed in `targets` and the action in `active_actions`.

### `survey` — passive enumeration (scan + pcap)

Ingest an airodump-ng CSV and/or an `iw dev scan` dump, optionally enrich it with
evidence from a pcap, and print an advisory per-AP report:

```bash
airwarden survey --csv scan-01.csv --iw iw-scan.txt --pcap capture.pcap -o survey.json
```

Any subset of `--csv` / `--iw` / `--pcap` works. The report shows, per AP: the
inventory, clients and probes, the extracted artifacts (each with a frame number
and an exact Wireshark display filter), handshake/PMKID presence, and an
**advisory applicability matrix** — which authorized test categories (OPN / WEP /
WPA2-PSK / WPA3-SAE / MGT / OWE / WPS) are relevant, with priority, reason,
preconditions, and the evidence still missing. It is advisory only: it runs no
attack. `--backend` selects the pcap extractor (`auto`, `scapy`, or `tshark`);
tshark adds TLS cert subjects, EAP-MD5, MSCHAPv2/NetNTLMv2 and IMSI extraction.

This pipeline is built from five modules: `scan_ingestor` (airodump/iw parsing),
`pcap_extractor` (evidence + frame numbers + filters), `handshake_detector`
(handshake/PMKID presence, no cracking), `attack_mapper` (the advisory matrix),
and `audit_report` (CLI + JSON). Runnable example inputs and a sample JSON output
are in [`examples/`](examples/).

#### Live follow mode (`survey --follow`)

`--follow` keeps `survey` running and polls its inputs for new data, reporting
findings as they appear and **deduplicating** repeats so the console stays
readable during a long capture:

```bash
# Terminal 1 — airodump writes a growing CSV
sudo airodump-ng wlan0mon -w ~/wifi/live --band abg --manufacturer --wps

# Terminal 2 — AirWarden follows that CSV
airwarden survey --csv ~/wifi/live-01.csv --follow

# Or with repeats visible, marked [×N]
airwarden survey --csv ~/wifi/live-01.csv --follow --show-duplicates
```

Each new finding prints once, prefixed with a timestamp:

```
[12:34:56] [wifi-mobile] open network wifi-mobile — client traffic is unencrypted
[i] +3 new findings, 7 duplicates suppressed
```

Follow mode is still **passive and advisory only** — it reads files other tools
write and never performs an active action. The one-shot behavior is unchanged;
`--follow` is opt-in. See [`docs/follow-mode.md`](docs/follow-mode.md) for the
dedup key, the `[×N]` marker, the flags (`--interval`, `--show-duplicates` /
`--hide-duplicates`, `--duplicate-threshold`), and the JSON schema.

### Configuration

Every setting can be supplied as an environment variable prefixed `AIRWARDEN_`
(CLI options take precedence):

| Variable                   | Default                 |
| -------------------------- | ----------------------- |
| `AIRWARDEN_OUTPUT_PREFIX`  | `report`                |
| `AIRWARDEN_REDACT_MACS`    | `true`                  |
| `AIRWARDEN_BETTERCAP_URL`  | `http://127.0.0.1:8081` |
| `AIRWARDEN_BETTERCAP_USER` | `user`                  |
| `AIRWARDEN_BETTERCAP_PASS` | `pass`                  |
| `AIRWARDEN_INTERFACE`      | `wlan0mon`              |
| `AIRWARDEN_SCOPE_PATH`     | `scope.json`            |

### Exit codes

| Code | Meaning                                           |
| ---- | ------------------------------------------------- |
| 0    | Success                                           |
| 1    | Capture file could not be read                    |
| 2    | Not authorized (flag missing or target off-scope) |
| 3    | A required module is unavailable at run time       |

## What this tool does NOT do

- **No broadcast deauth.** There is no broadcast, "all clients", multi-target,
  or range deauthentication of any kind. The only disruptive primitive is a
  single-BSSID, single-client action that must be in scope and individually
  authorized.
- **No cracking.** It records whether handshake/PMKID material was observed; it
  does not attempt to recover keys.
- **No detection evasion.** No MAC spoofing helpers, no IDS/WIDS evasion, no
  stealth modes.
- **No mass targeting.** Active actions take one explicit, in-scope BSSID at a
  time; there is no "attack everything in range" mode.

## Legal disclaimer

This software is provided for authorized security testing and defensive
auditing only. Intercepting or interfering with wireless networks you do not own
or have explicit written permission to test is illegal in most jurisdictions
(for example under computer-misuse, wiretap, and radio-communications law).
You are solely responsible for obtaining authorization and complying with all
applicable laws and your engagement's rules. The authors accept no liability
for misuse. Authorized engagement only. Active actions require written
authorization.

## License

AirWarden is **proprietary — personal and authorized use only**. It is **not**
open source. You may use it for lawful, authorized security testing and for
private study and research. You may **not** copy, redistribute, modify-and-share,
or use it commercially **without prior written permission** from the copyright
holder. See [LICENSE](LICENSE) for the full terms.

Copyright © 2026 sudoxs. All rights reserved.
