"""Parse common auth.log / secure syslog lines."""

from __future__ import annotations

import re
from typing import Any

_LINE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+"
    r"(?P<host>\S+)\s+(?P<proc>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)

_SSH_FAILED = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
_SSH_ACCEPTED = re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>\S+)")
_SUDO = re.compile(r"sudo:\s+(?P<user>\S+)\s*:\s+(?P<action>.*)$")
_NEW_USER = re.compile(r"new user: name=(?P<user>\S+)")
_CRON = re.compile(r"CRON\[(?P<pid>\d+)\]:\s*\((?P<user>\S+)\)\s+(?P<cmd>.*)$")
_CRON_CMD = re.compile(r"^\((?P<user>\S+)\)\s+CMD\s+(?P<cmd>.*)$")


def parse_line(line: str) -> dict[str, Any] | None:
    """Return structured auth line or None."""
    m = _LINE.match(line.strip())
    if not m:
        return None
    msg = m.group("msg")
    row: dict[str, Any] = {
        "raw": line.strip(),
        "timestamp_hint": f"{m.group('month')} {m.group('day')} {m.group('time')}",
        "host": m.group("host"),
        "process": m.group("proc"),
    }
    if fm := _SSH_FAILED.search(msg):
        row["kind"] = "ssh_failed"
        row["user"] = fm.group("user")
        row["source_ip"] = fm.group("ip")
    elif am := _SSH_ACCEPTED.search(msg):
        row["kind"] = "ssh_accepted"
        row["user"] = am.group("user")
        row["source_ip"] = am.group("ip")
    elif sm := _SUDO.search(msg):
        row["kind"] = "sudo"
        row["user"] = sm.group("user")
        row["action"] = sm.group("action")
    elif um := _NEW_USER.search(msg):
        row["kind"] = "useradd"
        row["user"] = um.group("user")
    elif cm := _CRON.search(msg):
        row["kind"] = "cron"
        row["user"] = cm.group("user")
        row["cmd"] = cm.group("cmd")
    elif cm := _CRON_CMD.search(msg):
        row["kind"] = "cron"
        row["user"] = cm.group("user")
        row["cmd"] = cm.group("cmd")
    else:
        return None
    return row