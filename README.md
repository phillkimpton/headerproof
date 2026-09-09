# headerproof

HTTPS liveness checks and security-header reporting.

`headerproof` wraps the [secheaders](https://github.com/juerkkil/secheaders) scanner. It takes a list of targets, checks each one is actually live before scanning it, runs the header scan only against the live hosts, and writes the results in txt, csv, html, json or xlsx.

The point of the tool is the liveness gate. On a real estate a target list is full of records that resolve but no longer serve, or do not resolve at all. Scanning those and reporting "all headers missing" inflates the numbers and gives owners an easy reason to dismiss the whole report. `headerproof` separates the three states so each goes to the right place:

- **Live and scanned** goes to application owners as observed header results for review.
- **Live but not assessed** (a host that answered with any HTTP 4xx/5xx status, a non-default HTTPS port, or output the scanner could not parse) is flagged separately, never counted as a finding and never counted as clean.
- **Dead** (no DNS answer, or resolves but does not answer over HTTPS) goes to DNS hygiene, not to header owners.

## Requirements

- Python 3.12 is the tested runtime. Use a currently supported Python release. The code retains Python 3.8-compatible syntax, but this is not a claim of runtime support or security maintenance for Python 3.8/3.9.
- `secheaders`, on PATH or importable. Required.
- `openpyxl`. Optional, only needed for xlsx output.

Everything else uses the Python standard library.

## Setup

From the extracted source directory, install the scanner in an isolated environment:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install secheaders
```

Optional, for XLSX reports:

```bash
.venv/bin/python -m pip install openpyxl
```

Check the command:

```bash
.venv/bin/python headerproof.py --help
```

The commands below assume you remain in the extracted source directory. From elsewhere, use the full path to both `.venv/bin/python` and `headerproof.py`.

An existing `pipx install secheaders` installation is also supported if its console command is on PATH. There is no `pip install .` package or installed `headerproof` command in this release; run the script directly.

`headerproof` finds `secheaders` by preferring the console script on PATH, so a pipx-isolated install works without any extra step. If `secheaders` is not found, it falls back to running the module in the current interpreter.

## Usage

Scan a list and write every format:

```bash
.venv/bin/python headerproof.py -l hosts.txt -o all
```

Two specific formats, into a chosen directory:

```bash
.venv/bin/python headerproof.py -l hosts.txt -o csv -o html --outdir ./run
```

A few hosts straight on the command line:

```bash
.venv/bin/python headerproof.py example.com github.com -o txt
```

The target file is one host per line. Bare hostnames and full URLs both work. Blank lines and lines starting with `#` are ignored. Duplicates are removed by exact input text, preserving first-seen order. Positional targets precede file targets. Credentials in URLs, invalid ports and unsupported schemes are rejected before probing.

## Options

- `hosts` positional targets, or use `-l`.
- `-l, --target-list FILE` file of targets, one per line.
- `-o, --out {txt,csv,html,json,xlsx,all}` output format. Repeatable. `all` writes every format. Default `txt`.
- `--outdir DIR` output directory. Default is the current directory.
- `--name NAME` output basename. Default `headerproof-<UTC>`.
- `--workers N` concurrent workers for both the liveness gate and the scan. Default 8.
- `--timeout N` per-host HTTPS socket timeout in seconds. Default 10. Positive integer. The scanner subprocess limit is this value plus 20 seconds.
- `-q, --quiet` suppresses progress. Diagnostics, including a missing XLSX dependency, still go to stderr.

Output files share one timestamped basename, for example `headerproof-20260909-133554Z.csv`.

## Output formats

All formats cover the six core response headers as a status of `OK`, `WARN` or `MISSING`: Content-Security-Policy, X-Frame-Options (framing), Strict-Transport-Security, X-Content-Type-Options, Referrer-Policy and Permissions-Policy. `OK` means present with no warning from this scanner, `WARN` means present but flagged by secheaders, `MISSING` means not set.

- **txt** human-readable, one block per host, with the observed header values, plus a dead-host list at the end.
- **csv** one row per host: the six header statuses, the HTTPS and certificate result, the observed HTTP code, a scan status, and a problem count. Dead hosts appear as rows with a `DEAD_` scan status, so you can filter them in any spreadsheet. CSV is a single flat table and has no tabs.
- **html** a sortable matrix. Click any column header to sort, hover any cell for the header value or the reason it was flagged. Dead hosts are listed in a second table below.
- **json** the full record per host, including the complete secheaders output for every header it returned, plus the liveness metadata. `_input_target` preserves the original submitted target even when the scanner reports a different target. For HTTP 4xx/5xx gate responses, `_scanner_output` preserves the scanner result for manual review without counting its headers as findings. This is the machine-readable source of truth. The other formats summarise the six core headers; json carries everything.
- **xlsx** a four-sheet workbook (needs openpyxl):
  - **Summary** generated timestamp, the target and live/dead/not-assessed counts, and the missing-header totals across the scanned hosts. The management headline.
  - **Live findings** the colour-coded matrix, one row per scanned host, with a frozen header row and an autofilter.
  - **Not assessed** the live hosts that answered but could not be scanned, with the HTTP code and the reason.
  - **Dead hosts** the DNS-hygiene routing list.

## How liveness is decided

For each target `headerproof` first resolves the hostname. No DNS answer is `dead` (`NODNS`). If it resolves, it opens an HTTPS connection and issues a `HEAD /`. Any HTTP status code counts as `live` (the host answered, and its status is recorded). A connection refusal, a timeout, or a TLS failure with no HTTP response is `dead`. Certificate validity is not part of the liveness decision, it is reported separately by secheaders for the hosts that scan.

## Notes and limitations

- This performs active, unauthenticated HTTP requests from one vantage point. It is non-invasive header inspection, not a penetration test, passive packet capture or proof that an application is secure. Only scan targets you are authorised to assess.
- The header analysis is done by secheaders. `headerproof` adds the liveness gate, the routing split and the reporting. Compatibility was verified with secheaders 0.2.0; recheck scanner compatibility and report output after upgrading it. Nothing here is a fork of the scanner.
- A host behind a challenge page or WAF may return a 403 or 503 from outside and land in Not assessed. A 403 or 503 from outside is neither a pass nor a defect. The wrapper sends all HTTP 400–599 gate responses to Not assessed even when the scanner returns parseable headers. A successful challenge page returning 200 cannot reliably be detected; a 200 response does not prove that the intended application was reached.

## Credit

Built around [secheaders](https://github.com/juerkkil/secheaders) by Juha Erkkilä, which does the header fetching and analysis. `headerproof` only orchestrates and reports.


## Implementation clarifications

Parseable scanner JSON alone does not establish assessment quality. The wrapper applies two additional rules:

- Any HTTP 4xx/5xx gate response always needs manual assessment. The released scanner can return valid header findings for an error response, so JSON parseability alone does not establish assessment quality.
- Non-default HTTPS ports are probed normally, but live targets on those ports are not sent to the scanner. In secheaders 0.2.0, the final header fetch uses `target_url.hostname` without `target_url.port`. Reporting that response could attribute the default service's headers to another port. These targets appear in Not assessed with an explicit reason. Upstream remains unmodified.

A missing scanner installation stops the run before network work with an install hint. If an executable disappears after that check, the affected target becomes a scan error. Malformed JSON structures also become scan errors. Absent upstream header contents may be JSON null; they are preserved in JSON and displayed safely. Missing openpyxl skips only XLSX and does not appear in the written-file tally.

The DNS resolver uses the operating system's `getaddrinfo` behaviour; `--timeout` cannot bound a stalled OS DNS lookup. The HTTPS socket timeout and scanner subprocess deadline are separate limits. No fixed completion time is guaranteed for 180 targets. The gate checks HTTPS `HEAD /`, while the scanner may request a different path, follow redirects and make several requests. A dead classification means unreachable from this vantage at this time, not proof that a DNS record can safely be removed. Invalid certificates can make the scanner fail even though the liveness gate succeeds.

## Verification

Before release, 37 automated checks passed under Python 3.12, followed by live checks against example.com and github.com. The development test files are not included in this repository. See VERIFICATION.md for the recorded results and limitations.

## Operational data and licence

Target lists and generated reports are operational data. Keep them outside the source directory, preferably using `--outdir`. The supplied `.gitignore` permits only the named source and documentation files to be added normally; it cannot protect data pasted into tracked files or files force-added to Git.

MIT licensed. See LICENSE. `requirements.txt` has no mandatory Python dependencies and documents the optional XLSX installation. The separately installed scanner remains required for assessments.


## Output safety and exit codes

CLI reports are written through private temporary files and atomically replace the requested report paths. On POSIX systems, new report files have mode 0600 and newly created output directories have mode 0700. Existing directory permissions are not changed. Choose an output directory you control. A repeated basename replaces the previous reports, so use a new name or directory to retain previous runs. An existing report-file symlink is replaced rather than followed. Atomicity is per file, not across all five formats; a later write failure can leave earlier formats updated. If XLSX is skipped, any older XLSX at that path remains untouched and is not reported as newly written.

CSV text that could be interpreted as a formula is prefixed with an apostrophe. Do not strip that prefix or enable spreadsheet external content for untrusted data. Spreadsheet import behaviour varies, so use JSON for exact machine-readable values. Terminal, TXT, HTML and XLSX display text escapes control characters; JSON preserves the original scanner data. XLSX text is stored as text, not a formula.

Exit status 0 means the requested reports were produced, except an optional XLSX skip. It does not mean all targets were assessed or that there were no header warnings. Invalid CLI input exits 2; missing dependencies or output/operational errors exit 1. Keyboard interruption exits 130 after active worker cleanup; an OS DNS call can delay that cleanup. Progress and diagnostics use stderr only.

Use a trusted PATH and Python environment because the wrapper executes the scanner found there. This CLI is not a safe server-side URL-fetching service: caller-selected targets and scanner redirects can reach internal addresses. It applies no destination allowlist or network isolation.

## Release status

Python 3.8 and 3.9 have reached end of life; see the [official Python version status](https://devguide.python.org/versions/). Packaging and cross-version CI have not yet been added. This README and the verification notes describe the implemented behaviour.
