# BotGeek — AI Security Orchestration Platform
## Graduation Project — Engineering 2025

---

## Architecture

```
User (Natural Language)
        ↓
CommandInterpreter  (NLP intent + target extraction)
        ↓
BotGeek Orchestrator
        ↓
 ┌──────────────────────────────────────┐
 │          Multi-Agent System          │
 │                                      │
 │  ReconAgent     → whois, dig         │
 │  ScanAgent      → nmap               │
 │  VulnAgent      → searchsploit, NVD  │
 │  WebAgent       → nikto, gobuster    │
 │  WifiAgent      → aircrack suite     │
 │  VulnScorer     → ML model           │
 │  ReportAgent    → HTML + TXT         │
 └──────────────────────────────────────┘
```

---

## Install (Parrot OS)

```bash
# No pip install needed — pure Python 3 stdlib
# Parrot OS already has all tools

git clone https://github.com/you/botgeek
cd botgeek
python3 botgeek.py
```

---

## Usage

```
BotGeek > analyse 192.168.1.10
BotGeek > scan ports on 10.0.0.5
BotGeek > check vulnerabilities on 192.168.1.1
BotGeek > wifi scan on wlan0
BotGeek > web scan http://192.168.1.20
BotGeek > generate report
BotGeek > exit
```

---

## Project Structure

```
botgeek/
├── botgeek.py              ← Main entry point
├── core/
│   ├── executor.py         ← Safe subprocess runner
│   └── interpreter.py      ← NLP command parser
├── agents/
│   ├── recon_agent.py      ← Whois, DNS, theHarvester
│   ├── scan_agent.py       ← Nmap scanning + port parsing
│   ├── vuln_agent.py       ← Searchsploit + NVD API + CVE
│   ├── web_agent.py        ← Nikto + Gobuster
│   ├── wifi_agent.py       ← Aircrack-ng suite
│   └── report_agent.py     ← HTML + TXT report generator
├── models/
│   └── vuln_scorer.py      ← ML exploit probability model
└── static/
    └── dashboard.html      ← Web dashboard UI
```

---

## Key Features

- **Natural Language Interface** — type commands like a human
- **Multi-Agent Architecture** — each security domain is isolated
- **NLP Intent Parser** — regex + weighted scoring, zero dependencies
- **NVD CVE Integration** — live queries to NIST vulnerability database
- **ML Exploit Scoring** — sigmoid-based probability model
- **Professional Reports** — HTML + TXT with CVE, severity, remediation
- **Web Dashboard** — dark cyber UI with real-time terminal

---

## Tools Automated

| Tool         | Purpose                    |
|-------------|----------------------------|
| nmap         | Port & service scanning    |
| whois / dig  | Domain intelligence        |
| searchsploit | Exploit lookup             |
| nikto        | Web vulnerability scan     |
| gobuster     | Directory discovery        |
| airmon-ng    | WiFi monitor mode          |
| airodump-ng  | WiFi AP scanning           |
| theHarvester | Email/subdomain harvest    |

---

## Academic Note

This platform is designed for use in controlled lab environments only.
Always obtain written permission before scanning any system.
