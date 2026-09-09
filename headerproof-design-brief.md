# Design brief: headerproof

Status: for implementation and verification
Audience: Codex (independent build and audit)
Target language: Python 3.8+
Nature: command-line tool that wraps the `secheaders` scanner

This brief specifies a tool called `headerproof`. Treat every requirement marked MUST as binding and every requirement marked SHOULD as a strong default that needs a stated reason to depart from. A reference implementation already exists; this brief is the authority, and the implementation must be verified against it, not the other way round.

## 1. Problem statement

Scanning security headers across a large external estate produces misleading output because a target list always contains hosts that no longer serve, or no longer resolve. A plain scanner reports "all headers missing" for a dead host, which inflates the finding count and gives asset owners a reason to dismiss the whole report. The tool must separate liveness from header hygiene so that dead infrastructure never contaminates header findings, and so each result reaches the correct owner.

## 2. Goals and non-goals

Goals:
- Gate every target on liveness before scanning it.
- Scan only live hosts, using `secheaders` for the header analysis.
- Classify every target into exactly one of three states and keep them separate in all output.
- Emit results in txt, csv, html, json and xlsx.
- Give live progress feedback during runs that take minutes.

Non-goals:
- Do not reimplement header analysis. `secheaders` does it.
- Do not fork or modify `secheaders`. The tool wraps the released package.
- Not a penetration test. It reports what a host publishes to an unauthenticated request from a single vantage.
- No authentication, no crawling, no payloads, no active exploitation.

## 3. The three states

Every target resolves to exactly one:

1. Live and scanned. Resolves, answered over HTTPS, and `secheaders` returned parseable JSON. Carries header findings. Routes to application owners.
2. Live but not assessed. Resolves and answered (any HTTP status), but `secheaders` returned an error or unparseable output (for example a 403 challenge, a 503, or a WAF interstitial). Never a finding, never clean. Routes to a manual second look.
3. Dead. No DNS answer, or resolves but does not answer over HTTPS. Routes to DNS hygiene, not to header owners.

This tri-state separation is the core value of the tool and MUST be preserved in every output format.

## 4. Architecture

- Single-file Python script, standard library only, with one optional dependency.
- `secheaders` is invoked as a subprocess with `--json`, not imported. Rationale: the tool must work when `secheaders` is installed in an isolated environment such as pipx.
- `secheaders` resolution: MUST prefer the `secheaders` console script found on PATH; MUST fall back to `[sys.executable, "-m", "secheaders"]` when it is not on PATH.
- `openpyxl` is the only non-stdlib dependency, required only for xlsx output, and MUST be imported lazily inside the xlsx renderer so that all other formats work without it. If xlsx is requested and `openpyxl` is absent, the tool MUST print an install hint to stderr and skip xlsx without failing the other formats or the process.

## 5. Dependencies

- Python 3.8 or newer.
- `secheaders`, on PATH or importable. Required.
- `openpyxl`. Optional, xlsx only.

## 6. Input handling

- Targets come from positional arguments, from `-l/--target-list FILE`, or both combined.
- The file is one target per line.
- Bare hostnames and full URLs MUST both be accepted.
- Blank lines and lines beginning with `#` MUST be ignored.
- Duplicates MUST be removed while preserving first-seen order.
- If no targets are supplied by any route, exit non-zero with a usage error.

A helper MUST reduce any target to `host[:port]` for the liveness probe by stripping scheme and path. Default port 443.

## 7. Liveness gate

For each target:
1. Resolve the hostname with `socket.getaddrinfo(hostname, port)`. On `socket.gaierror`, the verdict is `dead` with dns `NODNS` and http code `000`.
2. If it resolves, open an HTTPS connection to `host:port` with a per-host timeout and issue `HEAD /`. Certificate verification MUST be disabled for this probe (liveness only; certificate validity is reported separately by `secheaders`). Any HTTP status returned means verdict `live`, dns `resolves`, http code the integer status.
3. On timeout, connection refusal, other `OSError`, or TLS failure with no HTTP response, verdict is `dead`, dns `resolves`, http code `000`.

The gate MUST run concurrently across a worker pool.

## 8. Scanning

For each live target:
- Invoke `secheaders --json <target>` via the resolution rule in section 4, with a timeout that exceeds the per-host timeout by a margin.
- On non-zero exit or empty stdout, produce `{"target": <target>, "error": <stderr or 'scan failed'>}`.
- On a subprocess timeout, produce `{"target": <target>, "error": "scan timeout"}`.
- On JSON parse failure, produce `{"target": <target>, "error": "unparseable scanner output"}`.
- Otherwise return the parsed object.

Scanning MUST run concurrently across a worker pool. Dead targets MUST NOT be scanned.

## 9. Data contract

### 9.1 secheaders JSON (consumed, do not change)

```
{
  "target": "https://example.com",
  "headers": {
    "<header-name-lowercase>": {"defined": bool, "warn": bool, "contents": str, "notes": [str, ...]},
    ...
  },
  "https": {"supported": bool, "certvalid": bool, "redirect": bool}
}
```

### 9.2 Internal record (produced)

Each live-host record is the secheaders object augmented with:
- `_meta`: `{"dns": str, "http_code": str, "verdict": "live"}`
- `_problems`: integer count of MISSING or WARN across the matrix headers (section 10)
- `_scanerror`: boolean, true when the record has no `headers` key

Dead entries are separate: `{"target": str, "dns": str, "http_code": str}`.

Sorting for output: live records first by scan error last, then by descending `_problems`, then by target. Dead entries sorted by target.

## 10. Matrix headers and status

The txt, csv, html and xlsx formats summarise six core response headers, in this order, with these short labels:

1. content-security-policy (CSP)
2. x-frame-options (Framing)
3. strict-transport-security (HSTS)
4. x-content-type-options (X-CTO)
5. referrer-policy (Referrer)
6. permissions-policy (Perms)

Status per header:
- MISSING when the header is absent or `defined` is false.
- WARN when `defined` is true and `warn` is true.
- OK when `defined` is true and `warn` is false.

The json format is exempt from the six-header summary and MUST carry the full secheaders output for every header returned.

## 11. Output formats

All output files share one timestamped basename, default `headerproof-<UTC>` where UTC is `%Y%m%d-%H%M%SZ`, overridable with `--name`. Files are written to `--outdir`, default the current directory, created if absent.

- txt: human-readable, one block per live host with the six header statuses and observed values, the https line and problem count, then a dead-host list at the end.
- csv: one row per host. Columns: target, the six header statuses, https_supported, cert_valid, http_redirect, http_code, scan_status, problems. Scan-error rows carry `SCAN_ERROR` and `n/a` header cells. Dead rows carry `DEAD_<dns>` and empty header cells. CSV is a single flat table with no tabs; dead hosts are included as rows so they can be filtered downstream.
- html: a sortable matrix, one row per live host, cells colour-coded by status, click-to-sort columns, hover a cell for the header value or the flag reason. A second table below lists dead hosts. A summary line states the counts and per-header missing totals. Self-contained, inline CSS and JS, no external assets.
- json: an object with `generated_utc`, `live_count`, `dead_count`, `live` (the full records), and `dead`. This is the machine-readable source of truth.
- xlsx: a workbook of four sheets (requires openpyxl):
  1. Summary: generated timestamp, method line, target and live/not-assessed/dead counts, and the missing-header totals across scanned hosts.
  2. Live findings: the colour-coded matrix, one row per scanned host, frozen header row, autofilter, problem count.
  3. Not assessed: live hosts that answered but could not be scanned, with http code and reason.
  4. Dead hosts: target, dns, http code.

The Live findings and Not assessed split means scan-error records go to Not assessed, not into the findings matrix.

## 12. Progress and logging

- Progress MUST be written to stderr only, never to stdout, so stdout redirection and the output files are never contaminated.
- Progress is on by default and suppressed by `-q/--quiet`.
- Three phases, labelled `[1/3]` liveness gate, `[2/3]` scanning, `[3/3]` writing.
- During the gate and the scan, emit one line per completed host with a running `[n/total]` counter and the per-host verdict or scan result. Because work is concurrent, lines appear in completion order, not list order; this is expected and need not be corrected.
- Each phase ends with a one-line tally.

## 13. CLI surface

```
headerproof [hosts ...] [-l FILE] [-o FMT ...] [--outdir DIR]
            [--name NAME] [--workers N] [--timeout N] [-q]
```

- `hosts` positional targets.
- `-l, --target-list FILE`.
- `-o, --out {txt,csv,html,json,xlsx,all}` repeatable, `all` expands to every format, default `txt`.
- `--outdir DIR` default current directory.
- `--name NAME` default `headerproof-<UTC>`.
- `--workers N` default 8, applied to both pools.
- `--timeout N` default 10 seconds, per host.
- `-q, --quiet` suppress progress.

## 14. Non-functional requirements

- Standard library only, except `openpyxl` for xlsx, lazily imported.
- A run of roughly 180 targets completes in a few minutes at the default worker count.
- Deterministic output given the same responses, except for concurrency-driven ordering of progress lines and the completion order of equal-ranked rows, which is resolved by the sort in section 9.2.
- No global mutable state beyond what a single `main()` needs.

## 15. Governance and data handling

- The tool MUST NOT contain any client name, hostname, IP, or internal identifier anywhere: not in code, comments, docstrings, examples, tests or fixtures. Use `example.com` and `github.com` only.
- The tool is passive and single-vantage. Documentation MUST state this and MUST state that a 403 or 503 from outside is neither a pass nor a defect.
- Any target list or generated output is operational data and stays out of the repository.

## 16. Repository deliverables

- `headerproof.py` the tool.
- `README.md` covering purpose, the three states, requirements, setup, usage, options, output formats, liveness logic, limitations, and credit to secheaders.
- `LICENSE`. MIT is the clean choice to match the wrapped upstream.
- `requirements.txt` noting `openpyxl` as optional (xlsx only); no required third-party packages.

## 17. Acceptance tests

Each test is a verifiable pass or fail. Codex MUST implement these and confirm all pass.

Input:
1. A file with blank lines, a `#` comment, a duplicate host, one bare hostname and one full URL yields the correct de-duplicated target set in first-seen order.
2. No targets by any route exits non-zero with a usage message.

Liveness:
3. A resolvable, serving host is classified live with its real HTTP status.
4. A syntactically valid but non-resolving host (for example `nonexistent-host-xyz.invalid`) is classified dead with dns `NODNS`.
5. A host that resolves but refuses or times out on 443 is classified dead with dns `resolves`, http `000`.

Scanning:
6. A live host returns a record with a `headers` key and a computed `_problems` count matching the matrix statuses.
7. A live host whose scan errors or returns unparseable output becomes a `_scanerror` record and appears in Not assessed, not in Live findings.
8. Dead hosts are never scanned (no subprocess is spawned for them).

secheaders resolution:
9. With `secheaders` on PATH, the console script is used.
10. With `secheaders` not on PATH but importable, the `-m` fallback is used.

Output:
11. `-o all` writes exactly five files sharing one basename.
12. csv contains live rows, scan-error rows and dead rows, distinguishable by the scan_status column.
13. html is self-contained (opens with no network access) and its dead-host table lists every dead target.
14. json round-trips: `live_count` and `dead_count` match the arrays, and each live record retains the full secheaders header set.
15. xlsx has exactly the four named sheets; Live findings excludes scan-error rows; Not assessed contains them; Dead hosts lists every dead target; Summary counts reconcile with json.
16. Requesting xlsx without `openpyxl` prints an install hint, skips xlsx, and still writes the other requested formats with a zero exit.

Progress:
17. By default, phase markers `[1/3]`, `[2/3]`, `[3/3]` and per-host lines appear on stderr and nothing appears on stdout.
18. `-q` suppresses all progress; output files are identical to a non-quiet run.

## 18. Out of scope for this tool, tracked separately

Two improvements belong in `secheaders` itself, not in this wrapper, and should be raised upstream as separate contributions: a configurable `--timeout` flag (the scanner currently hardcodes a 10 second timeout), and native `--csv` output. Neither is part of this tool. They are noted here only so the boundary is explicit: `headerproof` adds the liveness gate, the tri-state routing and the reporting layer; the scanner stays upstream and unmodified.
