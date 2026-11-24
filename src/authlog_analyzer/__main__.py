"""CLI: python -m authlog_analyzer auth.log"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from authlog_analyzer.analyze import analyze_lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze Linux auth.log offline.")
    parser.add_argument("file", nargs="?", help="auth.log path (default: stdin)")
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args(argv)

    if args.file:
        text = Path(args.file).read_text(encoding="utf-8", errors="replace")
    else:
        text = sys.stdin.read()

    lines = text.splitlines()
    result = analyze_lines(lines)
    print(json.dumps(result, indent=None if args.compact else 2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())