# PyShield 1.0

A Python command-line prototype for collecting basic security signals on Windows: suspicious process names, selected local TCP ports, executable file reputation, and recent CVE entries. It exports JSON and text reports with a simple heuristic risk score.

> This is an educational scanner, not antivirus protection or a validated vulnerability assessment. A low score does not establish that a computer is safe. Recent CVEs are informational and are not matched against software installed on your computer.

The repository name is **Pyshield1.0**; the current Python package version is **0.1**.

## Features

| Check | Current behavior |
| --- | --- |
| Processes | Searches process names for `keylogger`, `miner`, or `trojan` using psutil. |
| Ports | Attempts TCP connections to `127.0.0.1` on ports 21, 22, 23, 80, 443, and 3389. |
| Files | Walks `C:\`, hashes lowercase `.exe` files with SHA-256, and queries VirusTotal for existing results. File contents are not uploaded. |
| CVE feed | Requests the latest feed from `https://cve.circl.lu/api/last` and attempts to return its first five entries. |
| Reports | Writes `pyshield_report.json` and `pyshield_report.txt` in the current working directory. Existing reports are overwritten. |

## Installation

Use Windows with Python and pip. The source has been checked using Python 3.12; other versions have not been verified. Internet access is needed for dependency installation and external lookups.

```powershell
git clone https://github.com/prathambhavsar220-ai/Pyshield1.0.git
cd Pyshield1.0
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
```

The package installs `psutil` and `requests` and registers the `pyshield` console command. An editable install allows local source edits to take effect without reinstalling.

## Configure VirusTotal

Set your own VirusTotal API key in the same PowerShell session before starting the scanner:

```powershell
$env:VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
```

The key is read from the environment when the module is imported. No `.env` loader is included. Never commit a real key. If the key is absent, each lookup returns a configuration error without making a VirusTotal request. File hashing and the scan delay still occur.

## Run

```powershell
.\.venv\Scripts\pyshield.exe
```

If your environment is activated, you can run `pyshield` directly. The current CLI has no arguments or help parser; options such as `--help` do not prevent a scan.

The file scanner pauses 15 seconds after each hashed executable. Twenty lookups therefore include roughly five minutes of deliberate waiting, plus traversal and network time. The existing limit is checked after each directory, so a directory with many executable files can cause more than 20 files to be scanned. Press Ctrl+C to interrupt; partial results are not saved.

Only inspect computers you are authorized to assess. Requests send file hashes to VirusTotal. Generated reports can contain local paths, process information, and file hashes; inspect them before sharing.

## Python API

```python
from pyshield import run_full_scan, generate_report, save_report

raw = run_full_scan()
report = generate_report(raw)
save_report(report, "pyshield_report.json")
print(report["summary"])
```

Use a filename ending in `.json`; the text filename is derived by replacing that suffix.

## Understanding the output

The JSON contains `scan_time`, `details`, `summary`, `risk_score`, `severity`, `vulnerabilities_found`, `viruses_found`, and `explanation`. Detailed process, port, file, and CVE results are under `details`. The text report contains a summary.

The score is capped at 100 and adds:

- 5 points per matched process name.
- 3 points per open port from the fixed port list.
- 10 points per VirusTotal malicious engine result.
- 5 points per VirusTotal suspicious engine result.

| Score | Severity |
| --- | --- |
| 0–19 | LOW |
| 20–39 | MEDIUM |
| 40–69 | HIGH |
| 70–100 | CRITICAL |

These weights are unvalidated heuristics. An open port can be legitimate, and multiple engines can flag the same file. `viruses_found` means at least one returned malicious count is positive; it is not independent confirmation of infection. `vulnerabilities_found` only indicates a nonempty CVE feed, not a confirmed local vulnerability. Feed entries do not affect the score. Failed lookups do not increase the score, so the explanation can be misleading when data is unavailable.

## Project structure

```text
pyshield/
    __init__.py   Public API and package version
    cli.py        Console entry point
    scanner.py    Coordinates the four checks
    process.py    Process-name heuristics
    ports.py      Local TCP connection checks
    files.py      Hashing and VirusTotal lookups
    vuln.py       Recent CVE feed retrieval
    report.py     Scoring and JSON/text output
setup.py          Packaging and dependencies
tests/            Offline regression tests
ANALYSIS.md       Code review and remaining improvements
```

Generated reports, the empty `pyshield_json.txt`, build output, bytecode, and egg metadata are excluded from version control. The original machine reports are not sample data.

## Known limitations

- File scanning is hardcoded to `C:\` and lowercase `.exe` names. It is not a portable or comprehensive filesystem scanner.
- The intended file limit can be exceeded. There is no directory selection, progress display, retry/backoff, or configurable quota handling.
- VirusTotal requests have a 30-second timeout. Non-200 responses are currently all labeled “Not found in VirusTotal,” including authentication and rate-limit failures.
- CVE retrieval has no timeout or status validation and assumes a list response. Errors become an empty list, which does not distinguish failure from no results.
- Broad exception handlers can hide permission and network problems. Port sockets are not explicitly closed.
- There is no remediation, quarantine, real-time monitoring, installed-software inventory, or guaranteed malware detection.

See [ANALYSIS.md](ANALYSIS.md) for prioritized follow-up work.

## Development checks

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m compileall -q pyshield setup.py
```

Tests use mocked network calls and synthetic report data. They do not scan the host or verify live service availability.

## License

No license has been selected for this repository. Add an appropriate license before presenting this project as freely reusable open-source software.
