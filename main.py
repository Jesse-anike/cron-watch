from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
SCHEDULE_MACROS = {"@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly"}


HEURISTICS = [
    ("reboot_persistence", re.compile(r"^@reboot\b", re.I), "Scheduled command runs at system reboot; confirm owner and purpose."),
    ("remote_download_to_shell", re.compile(r"\b(curl|wget)\b[^\n|;]*\|\s*(sh|bash|zsh)\b", re.I), "Remote content appears to be piped directly into a shell."),
    ("temporary_directory_execution", re.compile(r"(?:^|\s)(/tmp/|/var/tmp/|/dev/shm/)", re.I), "Command references a temporary or shared-memory path."),
    ("encoded_payload", re.compile(r"\bbase64\s+(?:-d|--decode)\b", re.I), "Command decodes a base64 payload; confirm whether this is expected."),
    ("network_tool_in_job", re.compile(r"\b(nc|netcat|ncat|socat)\b", re.I), "Cron command invokes a network utility; validate its purpose."),
]


def is_environment_line(line: str) -> bool:
    return bool(ENV_ASSIGNMENT.match(line))


def inspect_cron_text(text: str, source: str) -> list[dict]:
    findings = []
    for line_number, raw in enumerate(text.splitlines(), start=1):
        entry = raw.strip()
        if not entry or entry.startswith("#") or is_environment_line(entry):
            continue
        matched = []
        for finding_type, pattern, explanation in HEURISTICS:
            if pattern.search(entry):
                matched.append({"type": finding_type, "detail": explanation})
        if matched:
            findings.append({
                "source": source,
                "line": line_number,
                "entry": entry[:500],
                "indicators": matched,
            })
    return findings


def inspect_path(target: Path) -> dict:
    if not target.exists():
        raise FileNotFoundError(f"Target does not exist: {target}")

    files = []
    if target.is_file():
        files = [target]
    elif target.is_dir():
        files = sorted(p for p in target.rglob("*") if p.is_file() and not p.is_symlink())
    else:
        raise ValueError("Target must be a regular file or directory")

    results = []
    errors = []
    for file_path in files:
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
            results.extend(inspect_cron_text(text, str(file_path)))
        except OSError as exc:
            errors.append({"source": str(file_path), "error": str(exc)})

    indicator_counts: dict[str, int] = {}
    for finding in results:
        for indicator in finding["indicators"]:
            kind = indicator["type"]
            indicator_counts[kind] = indicator_counts.get(kind, 0) + 1

    return {
        "files_reviewed": len(files),
        "review_items": results,
        "review_item_count": len(results),
        "indicator_counts": indicator_counts,
        "inspection_errors": errors,
        "note": "Heuristic triage only. Cron entries may be legitimate; verify every item with the system owner. No files or scheduled tasks are modified.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Review cron files and directories for persistence-related command indicators."
    )
    parser.add_argument("target", type=Path, help="Cron file or directory to inspect, e.g. /etc/cron.d")
    parser.add_argument("--output", help="Optional JSON report output path")
    args = parser.parse_args()

    try:
        report = inspect_path(args.target)
    except (OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, indent=2), file=sys.stderr)
        return 2

    rendered = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
