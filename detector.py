from datetime import datetime, timedelta
import csv
import json

def load_events(path):
    with open(path) as f:
        return json.load(f)["Records"]

def detect_root_usage(event):
    if event.get("userIdentity", {}).get("type") == "Root":
        return {"severity": "HIGH",
                "rule": "Root account used",
                "mitre": "T1078.004"}
    return None
def detect_failed_login(event):
    if event.get("eventName") == "ConsoleLogin":
        outcome = (event.get("responseElements") or {}).get("ConsoleLogin")
        if outcome == "Failure":
            return {"severity": "MEDIUM",
                    "rule": "Failed console login",
                    "mitre": "T1110"}
    return None
def detect_access_key_created(event):
    if event.get("eventName") == "CreateAccessKey":
        return {"severity": "MEDIUM",
                "rule": "New access key created",
                "mitre": "T1098.001"}
    return None

RULES = [detect_root_usage, detect_failed_login, detect_access_key_created]
def parse_time(t):
    return datetime.strptime(t, "%Y-%m-%dT%H:%M:%SZ")

def detect_failed_login_then_key(events):
    findings = []
    last_failure = {}  # IP address -> time of its latest failed login
    for e in sorted(events, key=lambda e: e["eventTime"]):
        ip = e.get("sourceIPAddress")
        when = parse_time(e["eventTime"])
        outcome = (e.get("responseElements") or {}).get("ConsoleLogin")
        if e.get("eventName") == "ConsoleLogin" and outcome == "Failure":
            last_failure[ip] = when
        elif e.get("eventName") == "CreateAccessKey" and ip in last_failure:
            if when - last_failure[ip] <= timedelta(hours=1):
                findings.append({"severity": "HIGH",
                                 "rule": "Failed login followed by new access key",
                                 "mitre": "T1110 + T1098.001",
                                 "time": e["eventTime"],
                                 "ip": ip,
                                 "event": e["eventName"]})
    return findings

def analyze(events):
    findings = []
    for e in events:
        for rule in RULES:
            result = rule(e)
            if result:
                findings.append({**result,
                    "time": e["eventTime"],
                    "ip": e.get("sourceIPAddress"),
                    "event": e["eventName"]})
        findings += detect_failed_login_then_key(events)
    return findings
def write_report(findings, path="report.csv"):
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings = sorted(findings, key=lambda f: order[f["severity"]])
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["severity", "rule", "mitre", "time", "ip", "event"])
        writer.writeheader()
        writer.writerows(findings)
    return findings
if __name__ == "__main__":
    findings = write_report(analyze(load_events("sample_logs/cloudtrail_sample.json")))
    for f in findings:
        print(f["severity"], "-", f["rule"], "-", f["ip"])
    print(f"{len(findings)} findings written to report.csv")