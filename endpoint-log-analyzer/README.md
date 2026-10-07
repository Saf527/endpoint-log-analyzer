# Endpoint Log Analyzer

A lightweight Python security tool for analyzing endpoint authentication and process logs, detecting suspicious patterns, assigning severity levels, and generating actionable security reports.

> **Portfolio project:** This project demonstrates practical skills in log analysis, security detection logic, Python automation, incident triage, and security reporting. It is not intended to replace an enterprise SIEM or EDR platform.

## Features

- Parses CSV and JSON endpoint logs
- Normalizes common security events
- Detects repeated authentication failures / brute-force patterns
- Detects successful logins following repeated failures
- Detects PowerShell and encoded-command activity
- Detects suspicious process execution patterns
- Detects privilege-related events
- Detects known suspicious IP addresses from a configurable list
- Assigns `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` severity
- Produces console summaries
- Generates JSON findings for automation
- Generates a standalone HTML investigation report
- Includes sample endpoint data
- Includes unit tests

## Project Structure

```text
endpoint-log-analyzer/
├── analyzer/
│   ├── __init__.py
│   ├── cli.py
│   ├── parser.py
│   ├── rules.py
│   └── scoring.py
├── config/
│   └── suspicious_ips.txt
├── data/
│   └── sample_endpoint_logs.csv
├── reports/
│   └── .gitkeep
├── tests/
│   ├── test_parser.py
│   └── test_rules.py
├── .gitignore
├── LICENSE
├── requirements.txt
└── README.md
```

## Requirements

- Python 3.10+
- No external packages are required for the core analyzer.

## Run the Analyzer

From the project directory:

```bash
python -m analyzer.cli --input data/sample_endpoint_logs.csv --format csv
```

Generate an HTML report:

```bash
python -m analyzer.cli \
  --input data/sample_endpoint_logs.csv \
  --format csv \
  --html-report reports/security_report.html
```

Generate JSON findings:

```bash
python -m analyzer.cli \
  --input data/sample_endpoint_logs.csv \
  --format csv \
  --json-report reports/findings.json
```

Run all outputs together:

```bash
python -m analyzer.cli \
  --input data/sample_endpoint_logs.csv \
  --format csv \
  --html-report reports/security_report.html \
  --json-report reports/findings.json
```

Then open `reports/security_report.html` in a browser.

## Input Format

CSV input should contain these fields:

```text
timestamp,event_type,username,source_ip,process,command_line,status,message
```

Example:

```csv
timestamp,event_type,username,source_ip,process,command_line,status,message
2026-10-01T09:15:00Z,AUTH_FAILURE,admin,203.0.113.50,,,FAILURE,Invalid password
```

The parser also accepts JSON arrays containing equivalent fields.

## Detection Logic

The current version includes intentionally simple, explainable rules:

| Rule | Trigger | Default Severity |
|---|---|---|
| AUTH-BRUTE-001 | Multiple failed authentications from one source IP | HIGH |
| AUTH-SUCCESS-001 | Successful authentication after repeated failures | HIGH |
| PS-ENC-001 | PowerShell encoded command indicator | HIGH |
| PS-001 | Suspicious PowerShell execution | MEDIUM |
| PROC-001 | Suspicious process / command pattern | HIGH |
| PRIV-001 | Privilege-related event | HIGH |
| IP-001 | Source IP appears in local suspicious-IP list | HIGH |

Detection thresholds and suspicious IPs can be adjusted in `analyzer/rules.py` and `config/suspicious_ips.txt`.

## Severity Model

Findings are scored using rule severity and supporting indicators:

- **CRITICAL** — immediate investigation recommended
- **HIGH** — strong suspicious signal
- **MEDIUM** — potentially suspicious activity requiring review
- **LOW** — informational signal

The tool intentionally favors explainability over complex machine-learning models so that each finding can be traced back to a specific detection rule.

## Example Output

```text
Endpoint Log Analyzer
======================

Events analyzed : 15
Findings         : 5

CRITICAL : 0
HIGH     : 3
MEDIUM   : 2
LOW      : 0

Top findings:
[HIGH] AUTH-BRUTE-001 - Repeated authentication failures
[HIGH] PS-ENC-001 - PowerShell encoded command indicator
[HIGH] PROC-001 - Suspicious process execution
```

## Testing

Run:

```bash
python -m unittest discover -s tests -v
```

## Security & Privacy

The sample data uses documentation-only IP addresses and fictional usernames. Do not commit real customer logs, credentials, tokens, personal information, or confidential company data to this repository.

For real investigations, sanitize or anonymize sensitive data before sharing logs.

## Roadmap

Potential future improvements:

- Windows EVTX ingestion
- Sysmon event support
- Sigma-rule compatibility
- MITRE ATT&CK technique mapping
- Timeline visualization
- IP reputation integrations
- SQLite event storage
- Streamlit dashboard
- Export to CSV/PDF
- Configurable YAML detection rules

## Author

**Safwan Shaikh**

Technical Support Engineer | Endpoint Security | Cybersecurity

Portfolio: https://saf527.github.io

GitHub: https://github.com/Saf527

LinkedIn: https://www.linkedin.com/in/safwanshaikha65100200/
