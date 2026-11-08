# CloudTrail Threat Detector

A Python tool that analyzes AWS CloudTrail logs and flags suspicious activity.
Each finding gets a severity level and is mapped to a MITRE ATT&CK technique.

## What it detects

| Rule | Severity | MITRE ATT&CK |
|---|---|---|
| Root account used | HIGH | T1078.004 |
| Failed console login | MEDIUM | T1110 |
| New access key created | MEDIUM | T1098.001 |
| Failed login followed by new access key (same IP, within 1 hour) | HIGH | T1110 + T1098.001 |

## How it works

- Each detection is a small function that inspects one event and returns a
  finding or `None`. Rules are stored in a list, so adding a new detection
  means writing one function and adding it to the list.
- The correlation rule tracks failed logins by IP address and flags a new
  access key created from the same IP within an hour.
- Findings are sorted by severity and written to `report.csv`.

## Run it

```
python detector.py
```

## Run the tests

```
python -m unittest -v
```

## Example output

```
HIGH - Root account used - 203.0.113.5
HIGH - Failed login followed by new access key - 198.51.100.7
HIGH - Failed login followed by new access key - 198.51.100.7
HIGH - Failed login followed by new access key - 198.51.100.7
MEDIUM - Failed console login - 198.51.100.7
MEDIUM - New access key created - 198.51.100.7
6 findings written to report.csv
```

## Notes

- The included log in `sample_logs/` is synthetic data that follows the
  CloudTrail format. It uses reserved documentation IP addresses.
- Built with the Python standard library only, so there is nothing to install.

## Ideas for extending it

- Detect IAM policy changes and security groups opened to 0.0.0.0/0
- Flag logins from a never-before-seen IP for a user
- Read logs directly from an S3 bucket