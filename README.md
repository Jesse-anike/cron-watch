# CRON WATCH — Cron Persistence Auditor

A read-only Python auditor for cron files and directories. It highlights scheduled jobs that deserve persistence investigation, including reboot-triggered jobs, remote content piped to a shell, commands referencing temporary directories, encoded payload decoding, and network utilities.

## What it checks

- `@reboot` scheduled entries.
- `curl` or `wget` output piped into a shell.
- References to `/tmp`, `/var/tmp`, or `/dev/shm`.
- `base64 -d` / `--decode` usage.
- `nc`, `netcat`, `ncat`, and `socat` usage.
- Source file and line number for each review item.

## Requirements

- Python 3.10+
- Python standard library only.

## Run

Inspect a single cron file:

```bash
python main.py /etc/crontab
```

Inspect a directory recursively:

```bash
python main.py /etc/cron.d
```

Save a JSON report:

```bash
python main.py /etc/cron.d --output cron-review.json
```

For a broader host review, an administrator can separately export or inspect approved cron locations such as `/etc/crontab`, `/etc/cron.d`, `/etc/cron.hourly`, `/etc/cron.daily`, `/var/spool/cron`, and `/var/spool/cron/crontabs`, depending on the distribution and access policy.

## Tests

```bash
python -m unittest discover -s tests -v
python main.py --help
```

## Interpretation and safety

These are heuristics, not malware verdicts. Legitimate maintenance and deployment jobs may match one or more indicators. Confirm ownership, script contents, file permissions, package provenance, scheduling context, and change records with the system owner. The tool only reads files; it does not delete, disable, execute, or alter cron jobs.

## Portfolio context

Built for Anike-Moses Melie Jesse's defensive cybersecurity portfolio to demonstrate Linux persistence review, cron syntax awareness, Python filesystem analysis, heuristic triage, and safe reporting.
