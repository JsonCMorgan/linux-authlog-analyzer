# Linux auth.log Analyzer

[![CI](https://github.com/JsonCMorgan/linux-authlog-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/JsonCMorgan/linux-authlog-analyzer/actions/workflows/ci.yml)

## For mentors (30 seconds)

**What it is:** Offline parser for classic `auth.log` / `secure` lines: SSH failures and brute-force patterns, new users, sudo issues, suspicious cron commands.

**Why it exists:** Shows Linux logging literacy (G10 on your skills map). No agents, no cloud.

```powershell
pip install -e ".[dev]"
pytest -q
python -m authlog_analyzer tests\fixtures\auth.log
```

## License

MIT