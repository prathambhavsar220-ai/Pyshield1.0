# Source review

Reviewed on 2026-10-29. This review covers the supplied Python source; it is not a penetration test or a claim of malware-detection accuracy.

## Publication changes

- Removed the embedded VirusTotal credential from the publication copy. `VT_API_KEY` is now read from the environment and missing configuration returns an explicit error without sending a request. The original credential should be revoked or rotated.
- Added a 30-second timeout to VirusTotal requests.
- Excluded generated machine reports and build artifacts. The supplied text and JSON reports have different timestamps and should not be treated as one consistent example run.
- Added installation, usage, data-sharing, scoring, and limitation documentation plus offline regression checks.

## Remaining findings

| Priority | Location | Finding and suggested action |
| --- | --- | --- |
| High | `vuln.py`, `report.py` | Latest CVE entries are reported as vulnerabilities without matching installed products or versions. Label these as feed information, or implement inventory and version matching before claiming local findings. |
| High | `report.py` | Failed/unknown checks can produce LOW severity and “System appears safe.” Track scan completeness and unknown states separately from the score. |
| Medium | `files.py` | The 20-file limit is checked outside the inner loop, allowing unbounded work within a directory. Enforce the cap immediately after each result and add configurable paths. |
| Medium | `vuln.py` | HTTP request lacks a timeout, status checking, and response-shape validation. A stalled service can block completion, while exceptions become empty results. |
| Medium | `files.py` | Authentication failures, quota responses, and missing hashes share one error. Distinguish status codes and implement quota-aware backoff. |
| Medium | `process.py`, `ports.py`, `files.py`, `vuln.py` | Bare exception handlers suppress diagnostics and may swallow interruption during individual operations. Catch expected exceptions and retain per-check errors. |
| Low | `ports.py` | Sockets are not explicitly closed. Use a socket context manager. |
| Low | `report.py` | Text filename replacement can collide with the JSON path if no `.json` suffix is provided. Validate suffixes or use `pathlib.Path.with_suffix`. |
| Low | `cli.py`, `setup.py` | No argument parser, declared Python support range, or test automation. Add these after defining supported behavior. |

## Validation scope

Offline tests cover missing-key behavior, VirusTotal success and timeout handling, severity boundaries, score capping, and report serialization. Syntax compilation is also checked. A full disk scan and live API requests are deliberately outside these checks; service availability and real detection quality remain unverified.
