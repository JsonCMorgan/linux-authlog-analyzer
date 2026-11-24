from pathlib import Path

from authlog_analyzer.analyze import analyze_lines


def test_fixture_auth_log():
    lines = Path("tests/fixtures/auth.log").read_text(encoding="utf-8").splitlines()
    r = analyze_lines(lines)
    rules = {f["rule"] for f in r["findings"]}
    assert "ssh_brute_force" in rules
    assert "new_user" in rules
    assert "cron_persistence" in rules