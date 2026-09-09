# Verification

Verified on 9 September 2026 using the runtime UTC clock.

## Result

27 automated tests passed under Python 3.12, with secheaders 0.2.0 and openpyxl 3.1.5 installed in an isolated virtual environment. Tests 01 through 18 map to the supplied acceptance criteria. The remaining nine cover malformed JSON and spawn failures, URL metadata association, all HTTP 400–599 responses, cross-format error-response routing, custom ports, CLI validation, concurrent worker execution, subprocess arguments/deadlines and literal spreadsheet text.

The preceding version’s real unauthenticated smoke test against example.com and github.com returned HTTPS 200 for both hosts, assessed both through the released scanner and wrote all five requested formats. Report contents remain outside the deliverable source package. No client targets were used.

## Corrections

- Invalid scanner JSON structures and subprocess startup errors produce Not assessed records instead of crashing the run.
- Liveness metadata is associated with the submitted future's target, rather than looked up using a scanner-returned hostname. The original input is retained in `_input_target`.
- URL parsing handles paths, query strings and explicit ports, validates input before network work, and closes connections after unsuccessful probes. Malformed HTTP responses are treated as no usable response.
- HTML counts only assessed hosts in its scanned total and exposes scan-error reasons in tooltips. A null upstream header value no longer breaks rendering.
- The missing-openpyxl branch reports a skipped file accurately. Repeated format selections are deduplicated, progress remains on stderr and a single generation timestamp is shared by renderers.
- XLSX error text remains literal even when it begins with an equals sign. Setup uses an isolated environment instead of modifying system Python packages.
- Added the missing MIT licence, optional-dependency notes, operational-data ignore rules and regression tests.

## Deliberate clarifications of the brief

The supplied brief is preserved unchanged. The README explains these deviations:

1. Any HTTP 4xx/5xx response at the liveness gate is always Not assessed, including when the scanner returns parseable headers. Its complete scanner result is retained under `_scanner_output`. This avoids treating an error page as an application assessment.
2. A live non-default HTTPS port is Not assessed without invoking secheaders. Inspection of the installed 0.2.0 package showed that its final header fetch omits the explicit port. The wrapper avoids reporting the wrong service and does not modify upstream code.

## Limits of verification

- DNS failure, refusal, TLS failure, subprocess failures and missing openpyxl are controlled test fixtures. They are not claims about live infrastructure.
- Python 3.8 syntax was checked using the parser compatibility mode; the full suite ran on Python 3.12, not a Python 3.8 interpreter.
- Quiet and normal runs have identical text report bytes at a fixed generation time, and identical XLSX cell values. ZIP container metadata in XLSX may differ between runs.
- HTML structure, embedded assets, counts, escaping and dead-host inclusion were checked in code/tests. The browser security policy blocked opening the local report, so visual layout and actual browser click-to-sort behaviour were not verified.
- No 180-target performance run was performed. Both worker pools were verified to overlap work. Operating-system DNS resolution is not bounded by the socket timeout.
- A gate HEAD response and the scanner's later GET response may differ. A 200 challenge page or a later GET-only challenge cannot be detected reliably through this scanner's JSON contract. Findings remain single-vantage observations.

## Reproduce

From the extracted package directory, with the optional test dependency installed:

```bash
python3 -m unittest discover -s . -v
```

## HTTP 4xx/5xx update

On 9 September 2026, the manual-assessment rule was extended from 403/503 to every gate response from 400 through 599 inclusive. All 200 status values are covered by the regression test, including preservation of the scanner output and original status. A separate all-format test verifies 401, 404 and 502 routing, and confirms that 200, 301 and 399 remain assessed when the scanner succeeds. The full 27-test suite passed after this change. No new external scan was needed for this classification-only update.


## Pre-publication security update

On 9 September 2026, a further security pass added 10 regression tests (37 total). The changes protect CSV cells against formula interpretation, escape unsafe display characters while retaining raw JSON, validate hostname lengths and HTTPS flag types, fail early when the scanner is missing, and write CLI reports atomically with private POSIX permissions. Expected CLI failures now have documented exit codes. The 37-test suite passed under Python 3.12, and a new example.com/github.com live run produced five reports successfully. This supersedes earlier test-count and missing-scanner behaviour notes above.
