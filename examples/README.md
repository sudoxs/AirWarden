# Examples

Sample inputs and output for the passive enumeration pipeline (`airwarden survey`).

| File | What it is |
| ---- | ---------- |
| [`scan-01.csv`](scan-01.csv) | An airodump-ng CSV: four APs (MGT, WPA2-PSK, open, WEP) and two clients. |
| [`iw-scan.txt`](iw-scan.txt) | An `iw dev wlan0 scan` dump: an OWE AP and a WPA3/WPA2-transition AP with WPS. |
| [`survey-output.json`](survey-output.json) | The combined report produced from the two inputs above. |

Reproduce the output:

```bash
airwarden survey --csv examples/scan-01.csv --iw examples/iw-scan.txt -o examples/survey-output.json
```

Add `--pcap capture.pcap` to enrich the report with extracted artifacts
(HTTP credentials/cookies, EAP identities, handshake/PMKID, …), each carrying a
frame number and an exact Wireshark display filter. Everything here is passive
and advisory — no frames are transmitted and no attack is run.
