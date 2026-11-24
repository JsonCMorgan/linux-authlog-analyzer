"""Detections on parsed auth log lines."""

from __future__ import annotations

from collections import Counter
from typing import Any

_SSH_FAIL_THRESHOLD = 6


def analyze_lines(lines: list[str]) -> dict[str, Any]:
    """Parse and flag SSH brute force, sudo, new users, suspicious cron."""
    from authlog_analyzer.parse import parse_line

    parsed: list[dict[str, Any]] = []
    for line in lines:
        row = parse_line(line)
        if row:
            parsed.append(row)

    findings: list[dict[str, Any]] = []
    fails_by_ip: Counter[str] = Counter()

    for row in parsed:
        kind = row.get("kind")
        if kind == "ssh_failed":
            ip = row.get("source_ip", "?")
            fails_by_ip[ip] += 1
            findings.append(
                {
                    "rule": "ssh_failed",
                    "severity": "medium",
                    "summary": f"SSH failed for {row.get('user')} from {ip}",
                    "when": row.get("timestamp_hint"),
                }
            )
        elif kind == "ssh_accepted":
            findings.append(
                {
                    "rule": "ssh_accepted",
                    "severity": "info",
                    "summary": f"SSH accepted for {row.get('user')} from {row.get('source_ip')}",
                    "when": row.get("timestamp_hint"),
                }
            )
        elif kind == "useradd":
            findings.append(
                {
                    "rule": "new_user",
                    "severity": "high",
                    "summary": f"New user account: {row.get('user')}",
                    "when": row.get("timestamp_hint"),
                }
            )
        elif kind == "sudo":
            act = (row.get("action") or "").lower()
            if "not allowed" in act or "incorrect password" in act:
                findings.append(
                    {
                        "rule": "sudo_abuse",
                        "severity": "medium",
                        "summary": f"Sudo issue for {row.get('user')}: {row.get('action')}",
                        "when": row.get("timestamp_hint"),
                    }
                )
        elif kind == "cron":
            cmd = (row.get("cmd") or "").lower()
            if any(x in cmd for x in ("curl", "wget", "bash -c", "/dev/tcp")):
                findings.append(
                    {
                        "rule": "cron_persistence",
                        "severity": "high",
                        "summary": f"Suspicious cron for {row.get('user')}: {row.get('cmd')}",
                        "when": row.get("timestamp_hint"),
                    }
                )

    for ip, count in fails_by_ip.items():
        if count >= _SSH_FAIL_THRESHOLD:
            findings.append(
                {
                    "rule": "ssh_brute_force",
                    "severity": "high",
                    "summary": f"{count} SSH failures from {ip}",
                    "source_ip": ip,
                }
            )

    worst = max(
        ({"critical": 3, "high": 2, "medium": 1, "info": 0, "low": 0}.get(f.get("severity", "low"), 0)
         for f in findings),
        default=0,
    )
    risk = {3: "critical", 2: "high", 1: "medium", 0: "low"}.get(worst, "low")

    return {
        "ok": True,
        "lines_parsed": len(parsed),
        "findings_count": len(findings),
        "risk_level": risk if findings else "low",
        "findings": findings,
    }