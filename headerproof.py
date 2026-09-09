#!/usr/bin/env python3
"""
headerproof.py - liveness-gated security-header reporting around secheaders.

Wraps the `secheaders` scanner (https://github.com/juerkkil/secheaders):
  1. reads a target list,
  2. gates each host on liveness (resolves AND answers over HTTPS),
  3. scans only the live hosts via `secheaders --json`,
  4. renders txt / csv / html / json / xlsx (or all).

Dead hosts are reported separately, never counted as findings and never
counted as clean. Depends only on the Python standard library plus the
`secheaders` command on PATH or module in the current interpreter.
XLSX alone requires the optional openpyxl package.

Usage:
  headerproof.py -l hosts.txt -o all
  headerproof.py -l hosts.txt -o csv -o html --outdir ./run
  headerproof.py example.com github.com -o txt
"""
import argparse
import concurrent.futures as cf
import csv
import datetime
import html as htmllib
import http.client
import importlib.util
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import unicodedata
from urllib.parse import urlsplit

DEFAULT_TIMEOUT = 10
# Columns rendered in the csv/html matrix, in report order. (lowercase header name, short label)
MATRIX = (
    ("content-security-policy", "CSP"),
    ("x-frame-options", "Framing"),
    ("strict-transport-security", "HSTS"),
    ("x-content-type-options", "X-CTO"),
    ("referrer-policy", "Referrer"),
    ("permissions-policy", "Perms"),
)


def read_targets(path):
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            h = line.strip()
            if not h or h.startswith("#"):
                continue
            out.append(h)
    # de-dupe, preserve order
    seen = set()
    uniq = []
    for h in out:
        if h not in seen:
            seen.add(h)
            uniq.append(h)
    return uniq


def target_parts(target):
    """Parse an HTTP(S) target without confusing a bare host:port with a scheme."""
    parsed = urlsplit(target if "://" in target else "https://" + target)
    if (parsed.scheme not in ("http", "https") or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or any(c.isspace() or ord(c) < 32 for c in target)):
        raise ValueError("expected an HTTP(S) URL or hostname, without credentials")
    hostname = parsed.hostname
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        ascii_host = hostname.encode("idna").decode("ascii").rstrip(".")
        labels = ascii_host.split(".")
        if (len(ascii_host) > 253 or any(
                not re.fullmatch(r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?", label)
                for label in labels)):
            raise ValueError("invalid hostname or DNS label length")
    port = parsed.port if parsed.port is not None else 443
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    return parsed.hostname, port


def bare_host(target):
    """Strip scheme, credentials, query and path, leaving host[:port]."""
    hostname, port = target_parts(target)
    if ":" in hostname:
        hostname = "[" + hostname + "]"
    return hostname if port == 443 else "%s:%d" % (hostname, port)


def check_live(target, timeout=DEFAULT_TIMEOUT):
    """Return (verdict, dns, http_code). An HTTP response proves liveness only."""
    hostname, port = target_parts(target)
    try:
        socket.getaddrinfo(hostname, port)
    except socket.gaierror:
        return ("dead", "NODNS", "000")
    conn = None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(hostname, port, timeout=timeout, context=ctx)
        conn.request("HEAD", "/")
        return ("live", "resolves", str(conn.getresponse().status))
    except (OSError, http.client.HTTPException):
        return ("dead", "resolves", "000")
    finally:
        if conn is not None:
            conn.close()


def _secheaders_cmd():
    """Prefer the console script on PATH (works across a pipx-isolated install),
    fall back to running the module in the current interpreter."""
    exe = shutil.which("secheaders")
    return [exe] if exe else [sys.executable, "-m", "secheaders"]


def require_scanner():
    """Fail before network work if neither supported scanner installation exists."""
    if not shutil.which("secheaders") and importlib.util.find_spec("secheaders") is None:
        raise RuntimeError("secheaders is not installed; run: pipx install secheaders")


def display_text(value):
    """Escape terminal/XML control characters; raw evidence remains in JSON."""
    if not isinstance(value, str):
        return value
    return "".join("\\u%04x" % ord(c) if unicodedata.category(c) in ("Cc", "Cf", "Cs")
                   or ord(c) in (0xFFFE, 0xFFFF) else c for c in value)


def csv_value(value):
    """Keep untrusted text from becoming a spreadsheet formula on import."""
    value = display_text(value)
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@", "＝", "＋", "－", "＠")):
        return "'" + value
    return value


def write_report(renderer, records, dead, path, generated):
    """Replace one report atomically using a private file in its output directory."""
    fd, temporary = tempfile.mkstemp(prefix=".headerproof-", dir=os.path.dirname(path) or ".")
    os.close(fd)
    try:
        if renderer(records, dead, temporary, generated) is False:
            return False
        os.replace(temporary, path)
        return True
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def scan_one(target, timeout=DEFAULT_TIMEOUT):
    """secheaders --json for a single live target. Returns the parsed dict."""
    # secheaders 0.2.0 drops explicit ports when fetching the final headers.
    if target_parts(target)[1] != 443:
        return {"target": target, "error": "non-default HTTPS port is not reliably supported by secheaders"}
    try:
        proc = subprocess.run(
            _secheaders_cmd() + ["--json", target],
            capture_output=True, text=True, timeout=timeout + 20, check=False,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return {"target": target, "error": (proc.stderr.strip() or "scan failed")}
        result = json.loads(proc.stdout)
        if not isinstance(result, dict):
            raise ValueError("scanner output must be an object")
        if "headers" in result:
            headers = result["headers"]
            if (not isinstance(headers, dict) or "error" in result
                    or not isinstance(result.get("https", {}), dict)):
                raise ValueError("invalid scanner record")
            for value in headers.values():
                if (not isinstance(value, dict)
                        or not isinstance(value.get("defined"), bool)
                        or not isinstance(value.get("warn"), bool)
                        or not isinstance(value.get("contents"), (str, type(None)))
                        or not isinstance(value.get("notes", []), list)
                        or not all(isinstance(n, str) for n in value.get("notes", []))):
                    raise ValueError("invalid header record")
            if any(not isinstance(v, bool) for v in result.get("https", {}).values()):
                raise ValueError("invalid HTTPS flags")
        else:
            result["error"] = str(result.get("error") or "scanner returned no headers")
        if not isinstance(result.get("target", target), str):
            raise ValueError("invalid target")
        result.setdefault("target", target)
        return result
    except subprocess.TimeoutExpired:
        return {"target": target, "error": "scan timeout"}
    except (ValueError, UnicodeError):
        return {"target": target, "error": "unparseable scanner output"}
    except OSError as exc:
        return {"target": target, "error": "cannot run secheaders: %s" % exc}


def status_of(rec, hdr):
    h = rec.get("headers", {}).get(hdr)
    if not h or not h.get("defined"):
        return "MISSING"
    return "WARN" if h.get("warn") else "OK"


def problem_count(rec):
    if "headers" not in rec:
        return 0
    return sum(1 for hdr, _ in MATRIX if status_of(rec, hdr) in ("MISSING", "WARN"))


def build(records):
    """Count header problems and sort assessed records worst-first."""
    for r in records:
        r["_problems"] = problem_count(r)
        r["_scanerror"] = "headers" not in r
    records.sort(key=lambda r: (1 if r["_scanerror"] else 0, -r["_problems"], r.get("target", ""), r.get("_input_target", "")))
    return records


# ---------- renderers ----------
def render_json(records, dead, path, generated=None):
    payload = {
        "generated_utc": (generated or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "live_count": len(records),
        "dead_count": len(dead),
        "live": records,
        "dead": dead,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def render_csv(records, dead, path, generated=None):
    cols = ["target"] + [lbl for _, lbl in MATRIX] + [
        "https_supported", "cert_valid", "http_redirect", "http_code", "scan_status", "problems"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)

        def write_row(values):
            w.writerow([csv_value(v) for v in values])

        write_row(cols)
        for r in records:
            if r["_scanerror"]:
                write_row([r.get("target", "")] + ["n/a"] * len(MATRIX)
                           + ["", "", "", r["_meta"].get("http_code", ""), "SCAN_ERROR", ""])
                continue
            hp = r.get("https", {})
            write_row([r.get("target", "")]
                       + [status_of(r, hdr) for hdr, _ in MATRIX]
                       + [hp.get("supported", ""), hp.get("certvalid", ""), hp.get("redirect", ""),
                          r["_meta"].get("http_code", ""), "scanned", r["_problems"]])
        for d in dead:
            write_row([d["target"]] + [""] * len(MATRIX)
                       + ["", "", "", d.get("http_code", ""), "DEAD_" + d.get("dns", ""), ""])


def render_txt(records, dead, path, generated=None):
    lines = []
    lines.append("Security header report  (live hosts only; dead listed at end)")
    lines.append("generated %s UTC" % (generated or datetime.datetime.now(datetime.timezone.utc)).strftime("%d %b %Y %H:%M"))
    lines.append("=" * 64)
    for r in records:
        lines.append(r.get("target", ""))
        if r["_scanerror"]:
            lines.append("  SCAN ERROR: %s" % r.get("error", ""))
            lines.append("")
            continue
        for hdr, lbl in MATRIX:
            st = status_of(r, hdr)
            c = r.get("headers", {}).get(hdr, {}).get("contents", "") if st != "MISSING" else ""
            lines.append("  [%-7s] %-26s %s" % (st, hdr, ("= " + c) if c else ""))
        hp = r.get("https", {})
        lines.append("  https supported=%s certvalid=%s redirect=%s http=%s problems=%d"
                     % (hp.get("supported"), hp.get("certvalid"), hp.get("redirect"),
                        r["_meta"].get("http_code", "?"), r["_problems"]))
        lines.append("")
    if dead:
        lines.append("-" * 64)
        lines.append("DEAD / NOT SERVING (%d) - route to DNS hygiene, not header owners:" % len(dead))
        for d in dead:
            lines.append("  %-45s %s %s" % (d["target"], d.get("dns", ""), d.get("http_code", "")))
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(display_text(line) for line in lines) + "\n")


def render_html(records, dead, path, generated=None):
    def escape(value):
        return htmllib.escape(display_text(value))

    COL = {"MISSING": "#cf222e", "WARN": "#9a6700", "OK": "#1a7f37"}
    BG = {"MISSING": "#ffebe9", "WARN": "#fff8c5", "OK": "#dafbe1"}

    def cell(r, hdr):
        if r["_scanerror"]:
            return '<td style="color:#8250df;background:#faf0ff" title="%s">n/a</td>' % escape(r.get("error", "scan error"))
        st = status_of(r, hdr)
        detail = (r.get("headers", {}).get(hdr, {}).get("contents") or "") if st != "MISSING" else "not set"
        notes = "; ".join(r.get("headers", {}).get(hdr, {}).get("notes", []))
        tip = escape((notes + " | " + detail) if notes else detail)
        return '<td style="color:%s;background:%s" title="%s">%s</td>' % (COL[st], BG[st], tip, st)

    trows = []
    for r in records:
        tds = ['<td class=t>%s</td>' % escape(r.get("target", ""))]
        for hdr, _ in MATRIX:
            tds.append(cell(r, hdr))
        code = escape(str(r["_meta"].get("http_code", "")))
        stat = "SCAN ERROR" if r["_scanerror"] else "scanned"
        stcell = ('<td style="color:#8250df;background:#faf0ff">%s</td>' % stat
                  if r["_scanerror"] else '<td>%s</td>' % stat)
        pc = "" if r["_scanerror"] else str(r["_problems"])
        trows.append("<tr>%s<td>%s</td>%s<td>%s</td></tr>" % ("".join(tds), code, stcell, pc))

    drows = "".join(
        "<tr><td class=t>%s</td><td>%s</td><td>%s</td></tr>"
        % (escape(d["target"]), escape(d.get("dns", "")), escape(d.get("http_code", "")))
        for d in dead)

    assessed = [r for r in records if not r["_scanerror"]]

    def miss(hdr):
        return sum(1 for r in assessed if status_of(r, hdr) == "MISSING")

    summ = ("%d live hosts scanned, %d scan errors, %d dead. Among scanned: "
            "CSP missing %d, HSTS missing %d, X-CTO missing %d, Perms missing %d, "
            "Referrer missing %d, Framing missing %d." % (
                len(assessed), len(records) - len(assessed), len(dead),
                miss("content-security-policy"), miss("strict-transport-security"),
                miss("x-content-type-options"), miss("permissions-policy"),
                miss("referrer-policy"), miss("x-frame-options")))
    hdr_cells = "".join("<th>%s</th>" % escape(lbl) for _, lbl in MATRIX)
    ts = (generated or datetime.datetime.now(datetime.timezone.utc)).strftime("%d %b %Y %H:%MZ")
    doc = """<!doctype html><meta charset=utf-8><title>security header report</title>
<style>body{font:13px/1.45 system-ui,Segoe UI,Arial;margin:22px;color:#1f2328}
h1{font-size:17px;margin:0 0 2px}.meta{color:#57606a;margin:0 0 8px}
.s{background:#f6f8fa;border:1px solid #d0d7de;border-radius:6px;padding:10px 12px;margin:8px 0 16px}
table{border-collapse:collapse;width:100%%;font-size:12.5px;margin-bottom:22px}
th,td{border:1px solid #d0d7de;padding:4px 7px;text-align:center;white-space:nowrap}
td.t{text-align:left;font-family:ui-monospace,Menlo,monospace;max-width:360px;overflow:hidden;text-overflow:ellipsis}
th{background:#f6f8fa;position:sticky;top:0;cursor:pointer;user-select:none}
.sw{display:inline-block;width:11px;height:11px;border-radius:2px;vertical-align:-1px;margin-right:4px}
.legend span{margin-right:12px}</style>
<h1>Security header report</h1>
<p class=meta>Generated %s. Unauthenticated HTTP checks via secheaders, liveness-gated. Reported evidence, one vantage, not a penetration test.</p>
<div class=s>%s</div>
<div class="legend s" style="background:#fff">
<span><span class=sw style="background:#ffebe9;border:1px solid #cf222e"></span>MISSING</span>
<span><span class=sw style="background:#fff8c5;border:1px solid #9a6700"></span>WARN</span>
<span><span class=sw style="background:#dafbe1;border:1px solid #1a7f37"></span>OK</span>
<span><span class=sw style="background:#faf0ff;border:1px solid #8250df"></span>scan error</span>
&nbsp; Click a header to sort. Hover a cell for detail.</div>
<table id=live><thead><tr><th>host</th>%s<th>http</th><th>scan</th><th>problems</th></tr></thead>
<tbody>%s</tbody></table>
%s
<script>document.querySelectorAll('table th').forEach((th,i)=>th.onclick=()=>{
 const tb=th.closest('table').querySelector('tbody'),rs=[...tb.rows];
 const num=rs.every(r=>{const t=r.cells[i].textContent.trim();return t===''||!isNaN(Number(t))});
 rs.sort((a,b)=>{const x=a.cells[i].textContent.trim(),y=b.cells[i].textContent.trim();
   return num?(Number(x||0)-Number(y||0)):x.localeCompare(y)});
 if(th.dataset.d=='1'){rs.reverse();th.dataset.d='0'}else th.dataset.d='1';
 rs.forEach(r=>tb.appendChild(r))});</script>""" % (
        ts, escape(summ), hdr_cells, "".join(trows),
        ("<h1>Dead / not serving (%d)</h1><table><thead><tr><th>host</th><th>dns</th><th>http</th></tr>"
         "</thead><tbody>%s</tbody></table>" % (len(dead), drows)) if dead else "")
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)


def render_xlsx(records, dead, path, generated=None):
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill, Alignment
        from openpyxl.utils import get_column_letter
    except ImportError:
        print("  xlsx skipped: openpyxl not installed. Run: python3 -m pip install openpyxl", file=sys.stderr)
        return False

    FILL = {"MISSING": PatternFill("solid", fgColor="FFEBE9"),
            "WARN": PatternFill("solid", fgColor="FFF8C5"),
            "OK": PatternFill("solid", fgColor="DAFBE1"),
            "n/a": PatternFill("solid", fgColor="FAF0FF")}
    FCOL = {"MISSING": "CF222E", "WARN": "9A6700", "OK": "1A7F37", "n/a": "8250DF"}
    hdrfont = Font(bold=True)
    scanned = [r for r in records if not r["_scanerror"]]
    errored = [r for r in records if r["_scanerror"]]

    wb = Workbook()

    def append_row(sheet, values):
        sheet.append([display_text(v) for v in values])

    # --- Summary ---
    ws = wb.active
    ws.title = "Summary"

    def miss(hdr):
        return sum(1 for r in scanned if status_of(r, hdr) == "MISSING")
    ts = (generated or datetime.datetime.now(datetime.timezone.utc)).strftime("%d %b %Y %H:%M")
    rows = [
        ("Security header report", ""),
        ("Generated (UTC)", ts),
        ("Method", "Unauthenticated HTTP checks via secheaders, liveness-gated. One vantage."),
        ("", ""),
        ("Targets", len(records) + len(dead)),
        ("Live scanned", len(scanned)),
        ("Live but not assessed (challenge/error)", len(errored)),
        ("Dead / not serving", len(dead)),
        ("", ""),
        ("Missing headers among scanned", ""),
    ]
    for hdr, lbl in MATRIX:
        rows.append(("  " + lbl + " missing", miss(hdr)))
    for i, (k, v) in enumerate(rows, 1):
        ws.cell(i, 1, k)
        ws.cell(i, 2, v)
    ws["A1"].font = Font(bold=True, size=14)
    for i in (5, 6, 7, 8, 10):
        ws.cell(i, 1).font = hdrfont
    ws.column_dimensions["A"].width = 42
    ws.column_dimensions["B"].width = 60

    # --- Live findings ---
    ws = wb.create_sheet("Live findings")
    cols = ["host"] + [lbl for _, lbl in MATRIX] + [
        "https", "cert", "redirect", "http", "problems"]
    append_row(ws, cols)
    for c in range(1, len(cols) + 1):
        ws.cell(1, c).font = hdrfont
    for r in scanned:
        hp = r.get("https", {})
        row = [r.get("target", "")] + [status_of(r, hdr) for hdr, _ in MATRIX] + [
            hp.get("supported", ""), hp.get("certvalid", ""), hp.get("redirect", ""),
            r["_meta"].get("http_code", ""), r["_problems"]]
        append_row(ws, row)
        rn = ws.max_row
        for ci, (hdr, _) in enumerate(MATRIX, start=2):
            st = status_of(r, hdr)
            cell = ws.cell(rn, ci)
            cell.fill = FILL.get(st, FILL["OK"])
            cell.font = Font(color=FCOL.get(st, "000000"))
            cell.alignment = Alignment(horizontal="center")
    ws.freeze_panes = "B2"
    ws.auto_filter.ref = "A1:%s%d" % (get_column_letter(len(cols)), ws.max_row)
    ws.column_dimensions["A"].width = 44
    for ci in range(2, len(cols) + 1):
        ws.column_dimensions[get_column_letter(ci)].width = 11

    # --- Not assessed ---
    ws = wb.create_sheet("Not assessed")
    append_row(ws, ["host", "http", "reason"])
    for c in range(1, 4):
        ws.cell(1, c).font = hdrfont
    for r in errored:
        append_row(ws, [r.get("target", ""), r["_meta"].get("http_code", ""), r.get("error", "")])
    ws.freeze_panes = "A2"
    ws.column_dimensions["A"].width = 44
    ws.column_dimensions["B"].width = 8
    ws.column_dimensions["C"].width = 80

    # --- Dead hosts ---
    ws = wb.create_sheet("Dead hosts")
    append_row(ws, ["host", "dns", "http"])
    for c in range(1, 4):
        ws.cell(1, c).font = hdrfont
    for d in dead:
        append_row(ws, [d["target"], d.get("dns", ""), d.get("http_code", "")])
    ws.freeze_panes = "A2"
    ws.column_dimensions["A"].width = 44
    ws.column_dimensions["B"].width = 12
    ws.column_dimensions["C"].width = 8

    # Scanner and target text must remain literal, never spreadsheet formulas.
    for sheet in wb:
        for row in sheet:
            for cell in row:
                if cell.data_type == "f":
                    cell.data_type = "s"
    wb.save(path)
    return True


RENDERERS = {"txt": render_txt, "csv": render_csv, "html": render_html,
             "json": render_json, "xlsx": render_xlsx}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="headerproof", description="Liveness-gated security-header reporting around secheaders")
    ap.add_argument("hosts", nargs="*", help="target hosts (or use -l)")
    ap.add_argument("-l", "--target-list", metavar="FILE", help="file of targets, one per line")
    ap.add_argument("-o", "--out", action="append", choices=list(RENDERERS) + ["all"],
                    help="output format; repeatable; 'all' for every format (default txt)")
    ap.add_argument("--outdir", default=".", help="output directory (default: cwd)")
    ap.add_argument("--name", default=None, help="output basename (default: headerproof-<UTC>)")
    ap.add_argument("--workers", type=int, default=8, help="concurrent workers (default 8)")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="per-host timeout seconds (default 10)")
    ap.add_argument("-q", "--quiet", action="store_true", help="suppress progress output")
    args = ap.parse_args(argv)
    if args.workers < 1 or args.timeout < 1:
        ap.error("--workers and --timeout must be positive integers")
    if args.name and (args.name in (".", "..") or any(c in args.name for c in "/\\")
                      or any(unicodedata.category(c).startswith("C") for c in args.name)):
        ap.error("--name must be a basename, not a path")

    targets = list(args.hosts)
    if args.target_list:
        try:
            targets += read_targets(args.target_list)
        except (OSError, UnicodeError) as exc:
            ap.error("cannot read target list: %s" % exc)
    if not targets:
        ap.error("no targets: pass hosts or -l FILE")
    # de-dupe overall
    seen = set()
    targets = [t for t in targets if not (t in seen or seen.add(t))]

    for target in targets:
        try:
            target_parts(target)
        except ValueError as exc:
            ap.error("invalid target %r: %s" % (target, exc))

    formats = list(dict.fromkeys(args.out or ["txt"]))
    if "all" in formats:
        formats = list(RENDERERS)

    require_scanner()
    os.makedirs(args.outdir, mode=0o700, exist_ok=True)
    generated = datetime.datetime.now(datetime.timezone.utc)
    base = args.name or ("headerproof-" + generated.strftime("%Y%m%d-%H%M%SZ"))

    def log(msg):
        if not args.quiet:
            print(display_text(msg), file=sys.stderr, flush=True)

    total = len(targets)

    # 1. liveness gate (threaded)
    log("[1/3] liveness gate: %d targets, %d workers, %ds timeout" % (total, args.workers, args.timeout))
    live_meta = {}
    live_targets = []
    dead = []
    done = 0
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        fut = {ex.submit(check_live, t, args.timeout): t for t in targets}
        for f in cf.as_completed(fut):
            t = fut[f]
            verdict, dns, code = f.result()
            live_meta[t] = {"dns": dns, "http_code": code, "verdict": verdict}
            if verdict == "live":
                live_targets.append(t)
            else:
                dead.append({"target": t, "dns": dns, "http_code": code})
            done += 1
            tag = ("LIVE %s" % code) if verdict == "live" else ("dead %s" % dns)
            log("  [%3d/%d] %-9s %s" % (done, total, tag, t))
    log("  gate done: live=%d dead=%d" % (len(live_targets), len(dead)))

    # 2. scan live hosts (threaded)
    nlive = len(live_targets)
    log("[2/3] scanning %d live hosts via secheaders" % nlive)
    records = []
    done = 0
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        fut = {ex.submit(scan_one, t, args.timeout): t for t in live_targets}
        for f in cf.as_completed(fut):
            r = f.result()
            t = fut[f]
            if 400 <= int(live_meta[t]["http_code"]) < 600:
                r = {"target": t, "error": "HTTP %s at liveness gate; manual assessment required" % live_meta[t]["http_code"],
                     "_scanner_output": r}
            r["_input_target"] = t
            r["_meta"] = live_meta[t]
            records.append(r)
            done += 1
            if "headers" in r:
                p = problem_count(r)
                log("  [%3d/%d] scanned  problems=%d  %s" % (done, nlive, p, r.get("target", "")))
            else:
                log("  [%3d/%d] SCANERR  %s  %s" % (done, nlive, r.get("error", "")[:40], r.get("target", "")))
    log("  scan done: %d scanned, %d scan-errors" % (
        sum(1 for r in records if "headers" in r), sum(1 for r in records if "headers" not in r)))

    records = build(records)
    dead.sort(key=lambda d: d["target"])

    # 3. render
    log("[3/3] writing %s" % ", ".join(formats))
    written = []
    for fmt in formats:
        path = os.path.join(args.outdir, "%s.%s" % (base, fmt))
        if write_report(RENDERERS[fmt], records, dead, path, generated):
            written.append(path)
    log("  writing done: %d written, %d skipped" % (len(written), len(formats) - len(written)))
    for p in written:
        log("  " + p)


def cli():
    """Keep expected operational failures concise and give shells useful exit codes."""
    try:
        main()
    except (OSError, RuntimeError, ValueError) as exc:
        print("headerproof: " + display_text(str(exc)), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("headerproof: interrupted", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(cli())
