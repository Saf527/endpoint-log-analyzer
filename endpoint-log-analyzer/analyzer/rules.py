"""Explainable endpoint security detection rules."""

from collections import Counter, defaultdict
from .scoring import score_finding


def finding(rule_id, title, severity, description, event, indicators=0):
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "risk_score": score_finding(severity, indicators),
        "timestamp": event.get("timestamp", ""),
        "username": event.get("username", ""),
        "source_ip": event.get("source_ip", ""),
        "process": event.get("process", ""),
        "description": description,
    }


def detect_auth_bruteforce(events, threshold=5):
    failures = Counter(
        e["source_ip"]
        for e in events
        if e["event_type"].upper() == "AUTH_FAILURE" and e["source_ip"]
    )

    results = []
    for event in events:
        ip = event["source_ip"]
        if ip and failures[ip] >= threshold and event["event_type"].upper() == "AUTH_FAILURE":
            results.append(
                finding(
                    "AUTH-BRUTE-001",
                    "Repeated authentication failures",
                    "HIGH",
                    f"{failures[ip]} authentication failures observed from {ip}.",
                    event,
                    1,
                )
            )
            break
    return results


def detect_success_after_failures(events, threshold=3):
    failures_by_user_ip = defaultdict(int)
    results = []

    for event in events:
        key = (event["username"], event["source_ip"])
        event_type = event["event_type"].upper()

        if event_type == "AUTH_FAILURE":
            failures_by_user_ip[key] += 1
        elif event_type == "AUTH_SUCCESS" and failures_by_user_ip[key] >= threshold:
            results.append(
                finding(
                    "AUTH-SUCCESS-001",
                    "Successful login after repeated failures",
                    "HIGH",
                    f"Successful authentication followed {failures_by_user_ip[key]} failures "
                    f"for user {event['username']} from {event['source_ip']}.",
                    event,
                    1,
                )
            )
    return results


def detect_powershell(events):
    results = []
    for event in events:
        process = event["process"].lower()
        command = event["command_line"].lower()
        combined = f"{process} {command}"

        if "powershell" not in combined:
            continue

        if "-enc" in combined or "-encodedcommand" in combined:
            results.append(
                finding(
                    "PS-ENC-001",
                    "PowerShell encoded command indicator",
                    "HIGH",
                    "PowerShell execution contains an encoded-command indicator.",
                    event,
                    2,
                )
            )
        elif any(token in combined for token in ("downloadstring", "invoke-webrequest", "iex ")):
            results.append(
                finding(
                    "PS-001",
                    "Suspicious PowerShell execution",
                    "MEDIUM",
                    "PowerShell command line contains a commonly abused execution or download pattern.",
                    event,
                    1,
                )
            )
    return results


def detect_process_patterns(events):
    suspicious = (
        "mimikatz",
        "procdump",
        "psexec",
        "rundll32",
        "regsvr32",
        "certutil",
    )
    results = []

    for event in events:
        combined = f"{event['process']} {event['command_line']}".lower()
        matches = [item for item in suspicious if item in combined]
        if matches:
            results.append(
                finding(
                    "PROC-001",
                    "Suspicious process execution",
                    "HIGH",
                    f"Matched suspicious process pattern(s): {', '.join(matches)}.",
                    event,
                    len(matches),
                )
            )
    return results


def detect_privilege_events(events):
    results = []
    for event in events:
        if event["event_type"].upper() in {"PRIVILEGE_CHANGE", "ADMIN_GROUP_ADD"}:
            results.append(
                finding(
                    "PRIV-001",
                    "Privilege-related activity",
                    "HIGH",
                    "The event indicates a privilege or administrator-group change.",
                    event,
                    1,
                )
            )
    return results


def detect_suspicious_ips(events, suspicious_ips):
    results = []
    for event in events:
        if event["source_ip"] and event["source_ip"] in suspicious_ips:
            results.append(
                finding(
                    "IP-001",
                    "Source IP matched local watchlist",
                    "HIGH",
                    f"Source IP {event['source_ip']} appears in the configured local watchlist.",
                    event,
                    1,
                )
            )
    return results


def run_detections(events, suspicious_ips=None):
    suspicious_ips = suspicious_ips or set()
    findings = []
    findings.extend(detect_auth_bruteforce(events))
    findings.extend(detect_success_after_failures(events))
    findings.extend(detect_powershell(events))
    findings.extend(detect_process_patterns(events))
    findings.extend(detect_privilege_events(events))
    findings.extend(detect_suspicious_ips(events, suspicious_ips))
    return findings
