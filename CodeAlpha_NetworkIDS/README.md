# CodeAlpha_NetworkIDS

**CodeAlpha Cyber Security Internship — Task 4: Network Intrusion Detection System**

A network-based IDS that watches traffic you are allowed to monitor, matches Snort-style signatures, spots simple behavioural anomalies, writes alerts, and can put noisy source IPs on a local blocklist. An optional dashboard graphs what was detected.

Use this only on networks you own or have permission to monitor.

## What it does

| Internship item | How this project covers it |
| --- | --- |
| Network-based IDS | Python engine (Scapy) with a Snort-like rule file; optional notes for Suricata |
| Rules and alerts | `rules/local.rules` plus behavioural checks (port scan, SYN flood, ping sweep, ARP spoof, …) |
| Continuous monitoring | Live sniff on an interface until you stop it, or replay a pcap |
| Response | JSON/text logs, local blocklist, optional webhook, optional local firewall drop |
| Visualization | Flask dashboard with severity, class, timeline, and recent alerts |

This is a **detector**, not an attack toolkit. Demo mode builds synthetic packets in memory so you can see alerts without sending anything on the wire.

## Setup

```bash
cd CodeAlpha_NetworkIDS
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Live capture needs administrator privileges. Demo mode and pcap replay do not.

## Usage

**First run (no root, no live network):**

```bash
python3 nids.py --demo
```

That inspects crafted lab packets, prints alerts, and writes:

- `logs/alerts.jsonl` — one JSON object per alert
- `logs/alerts.log` — human-readable lines
- `logs/blocklist.txt` — source IPs from high-severity alerts

**Open the dashboard:**

```bash
python3 nids.py --dashboard
```

Then visit [http://127.0.0.1:5050](http://127.0.0.1:5050). Leave it running and re-run `--demo` in another terminal to watch the charts update.

**List interfaces / live monitor (authorized network only):**

```bash
python3 nids.py --list-interfaces
sudo python3 nids.py -i en0
```

**Replay a capture file:**

```bash
python3 nids.py -r capture.pcap
```

### Common flags

| Flag | Meaning |
| --- | --- |
| `-i`, `--iface` | Interface to monitor |
| `-c`, `--count` | Stop after N packets |
| `-f`, `--filter` | BPF filter |
| `-r`, `--read` | Read a `.pcap` |
| `--rules` | Path to `local.rules` |
| `--log-dir` | Where alerts are stored |
| `--no-block` | Log only; skip the blocklist |
| `--apply-firewall` | Opt-in local drop for blocklisted IPs |
| `--webhook` | POST each alert as JSON |
| `--demo` | Synthetic packets, nothing transmitted |
| `--dashboard` | Visualization on port 5050 |

## Rules

Signatures live in `rules/local.rules` using a small Snort subset:

```
alert tcp any any -> any 80 (msg:"HTTP directory traversal"; content:"../"; nocase; classtype:web-attack; priority:1; sid:1000001; rev:1;)
```

Behavioural detections (not payload signatures) include:

- TCP port scan (many destination ports from one source)
- SYN flood toward one host
- ICMP flood / ping sweep
- Repeated SSH SYNs
- Long DNS labels (tunneling heuristic)
- ARP replies that map one IP to more than one MAC
- Land-style packets where source IP equals destination IP

Tune thresholds in `detector.py` (`Thresholds`) if your lab traffic is noisier or quieter.

## Response behaviour

1. Every alert is printed and appended to the log files.
2. High-severity alerts add the source IP to `logs/blocklist.txt`.
3. `--webhook URL` posts the alert JSON to your own listener.
4. `--apply-firewall` is **off by default**. If you turn it on, the IDS tries a local drop (macOS `pfctl` table or Linux `iptables`). Review that list before using it on a real host.

The IDS does not forward or hijack traffic. Blocking is a local response on the machine that runs the sensor.

## Optional: Suricata

If you already run [Suricata](https://suricata.io/), you can point it at the same idea: copy `rules/local.rules` into your Suricata rule path and enable it in `suricata.yaml`. This Python project is the self-contained path that matches the earlier sniffer task and does not require installing Suricata.

## Project layout

```
nids.py              CLI: live monitor, pcap replay, demo, dashboard
detector.py          Signature + anomaly engine
ruleset.py           Snort-style rule parser
responder.py         Logs, blocklist, webhook, optional firewall
dashboard.py         Flask API and charts
rules/local.rules    Local signatures
templates/           Dashboard HTML
static/              Dashboard CSS/JS
```

## Internship notes

- Repository name follows CodeAlpha guidance: `CodeAlpha_NetworkIDS`.
- Libraries: [Scapy](https://scapy.net/) for capture, [Flask](https://flask.palletsprojects.com/) + Chart.js for the dashboard.
- Do not run this against networks or people who have not agreed to be monitored.

## Author

Venkata Naga Sriguna Bhasuru  
CodeAlpha Cyber Security Intern — Sep 10 to Oct 10, 2026  
Student ID: CA/DF1/269988
