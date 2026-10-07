"""Command-line interface for Endpoint Log Analyzer."""

import argparse
import html
import json
from collections import Counter
from pathlib import Path

from .parser import load_logs
from .rules import run_detections


def load_watchlist(path):
    file_path = Path(path)
    if not file_path.exists():
        return set()

    return {
        line.strip()
        for line in file_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }


def write_json(findings, path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(findings, indent=2), encoding="utf-8")


def write_html(findings, event_count, path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    severity_counts = Counter(item["severity"] for item in findings)

    rows = []
    for item in sorted(findings, key=lambda x: x["risk_score"], reverse=True):
        rows.append(
            "<tr>"
            f"<td>{html.escape(item['severity'])}</td>"
            f"<td>{item['risk_score']}</td>"
            f"<td>{html.escape(item['rule_id'])}</td>"
            f"<td>{html.escape(item['title'])}</td>"
            f"<td>{html.escape(item['timestamp'])}</td>"
            f"<td>{html.escape(item['username'])}</td>"
            f"<td>{html.escape(item['source_ip'])}</td>"
            f"<td>{html.escape(item['description'])}</td>"
            "</tr>"
        )

    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Endpoint Security Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 40px; color: #17202a; background: #f6f8fa; }}
main {{ max-width: 1400px; margin: auto; }}
.card {{ background: white; border: 1px solid #d9dee3; border-radius: 12px; padding: 20px; margin-bottom: 20px; }}
table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
th, td {{ border-bottom: 1px solid #e5e7eb; padding: 10px; text-align: left; vertical-align: top; }}
th {{ background: #f1f5f9; }}
</style>
</head>
<body>
<main>
<div class="card">
<h1>Endpoint Security Report</h1>
<p><strong>Events analyzed:</strong> {event_count}</p>
<p><strong>Findings:</strong> {len(findings)}</p>
<p>
CRITICAL: {severity_counts.get("CRITICAL", 0)} |
HIGH: {severity_counts.get("HIGH", 0)} |
MEDIUM: {severity_counts.get("MEDIUM", 0)} |
LOW: {severity_counts.get("LOW", 0)}
</p>
</div>
<div class="card">
<h2>Findings</h2>
<table>
<thead><tr><th>Severity</th><th>Risk</th><th>Rule</th><th>Title</th><th>Time</th><th>User</th><th>Source IP</th><th>Description</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan="8">No findings.</td></tr>'}</tbody>
</table>
</div>
</main>
</body>
</html>"""
    Path(path).write_text(page, encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="Analyze endpoint logs for suspicious activity.")
    parser.add_argument("--input", required=True, help="Path to CSV or JSON log file.")
    parser.add_argument("--format", default="auto", choices=["auto", "csv", "json"])
    parser.add_argument("--watchlist", default="config/suspicious_ips.txt")
    parser.add_argument("--html-report")
    parser.add_argument("--json-report")
    args = parser.parse_args()

    events = load_logs(args.input, args.format)
    findings = run_detections(events, load_watchlist(args.watchlist))
    counts = Counter(item["severity"] for item in findings)

    print("\nEndpoint Log Analyzer")
    print("=====================")
    print(f"Events analyzed : {len(events)}")
    print(f"Findings        : {len(findings)}")
    print(f"CRITICAL        : {counts.get('CRITICAL', 0)}")
    print(f"HIGH            : {counts.get('HIGH', 0)}")
    print(f"MEDIUM          : {counts.get('MEDIUM', 0)}")
    print(f"LOW             : {counts.get('LOW', 0)}")

    for item in sorted(findings, key=lambda x: x["risk_score"], reverse=True):
        print(f"[{item['severity']}] {item['rule_id']} - {item['title']} (risk {item['risk_score']})")

    if args.json_report:
        write_json(findings, args.json_report)
        print(f"\nJSON report: {args.json_report}")

    if args.html_report:
        write_html(findings, len(events), args.html_report)
        print(f"HTML report: {args.html_report}")


if __name__ == "__main__":
    main()
