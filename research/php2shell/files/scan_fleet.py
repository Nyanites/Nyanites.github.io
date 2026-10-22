#!/usr/bin/env python3
"""
scan_fleet.py — remote exposure scanner for CVE-2026-109619 / CVE-2026-109618.

Defensive tool. It does NOT exploit anything: it fingerprints the PHP version
exposed by each host (X-Powered-By header, then a light HTML fallback) and
compares it against the fixed builds. This is the single most reliable signal
for fleet-wide exposure.

Usage:
    python3 scan_fleet.py http://127.0.0.1:8080 http://127.0.0.1:8085
    python3 scan_fleet.py -f hosts.txt --json out.json
    python3 scan_fleet.py -f hosts.txt --csv out.csv

Exit codes:  0 = none affected   1 = at least one affected   2 = errors only
"""
from __future__ import annotations
import argparse, csv, json, re, sys, urllib.request, urllib.error, ssl
from concurrent.futures import ThreadPoolExecutor

# Fixed build per release branch (php-src advisory GHSA-6wmf-4rv5-p3rp).
FIXED = {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"}

VER_RE = re.compile(r"PHP/?\s*(\d+\.\d+\.\d+)")


def _vtuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def classify(version: str | None) -> tuple[str, str]:
    """Return (verdict, note). Verdicts: AFFECTED | PATCHED | EOL | UNKNOWN."""
    if not version:
        return "UNKNOWN", "no version disclosed"
    branch = ".".join(version.split(".")[:2])
    if branch not in FIXED:
        # 8.0/8.1/7.x/5.x — advisory indicates no or only partial fixes.
        return "EOL", f"{branch} has no/limited fix — treat as exposed, plan upgrade"
    fixed = FIXED[branch]
    if _vtuple(version) < _vtuple(fixed):
        return "AFFECTED", f"fixed in {fixed}"
    return "PATCHED", f"fixed in {fixed}"


def fingerprint(url: str, timeout: float) -> dict:
    """Fetch a host and extract the PHP version without exploiting it."""
    if "://" not in url:
        url = "http://" + url
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # lab/self-signed tolerance
    req = urllib.request.Request(url, headers={"User-Agent": "php2shell-fleet-scan/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            powered = r.headers.get("X-Powered-By", "")
            server = r.headers.get("Server", "")
            body = r.read(65536).decode("utf-8", "replace")
    except urllib.error.URLError as e:
        return {"url": url, "error": str(getattr(e, "reason", e))}
    except Exception as e:  # noqa: BLE001
        return {"url": url, "error": str(e)}

    version = None
    for src in (powered, server, body):
        m = VER_RE.search(src or "")
        if m:
            version = m.group(1)
            break
    verdict, note = classify(version)
    return {"url": url, "server": server, "powered_by": powered,
            "version": version, "verdict": verdict, "note": note}


def main() -> int:
    ap = argparse.ArgumentParser(description="CVE-2026-109619 fleet exposure scanner")
    ap.add_argument("hosts", nargs="*", help="target URLs/host:port")
    ap.add_argument("-f", "--file", help="file with one target per line")
    ap.add_argument("-t", "--timeout", type=float, default=5.0)
    ap.add_argument("-w", "--workers", type=int, default=16)
    ap.add_argument("--json", help="write full results to JSON file")
    ap.add_argument("--csv", help="write results to CSV file")
    args = ap.parse_args()

    targets = list(args.hosts)
    if args.file:
        with open(args.file) as fh:
            targets += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    if not targets:
        ap.error("no targets given (positional args or -f FILE)")

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        results = list(ex.map(lambda u: fingerprint(u, args.timeout), targets))

    width = max(len(r["url"]) for r in results)
    icons = {"AFFECTED": "❌", "EOL": "❌", "PATCHED": "✅", "UNKNOWN": "⚠️ "}
    print(f"{'TARGET':<{width}}  {'PHP':<8}  VERDICT")
    print("-" * (width + 24))
    affected = errors = 0
    for r in sorted(results, key=lambda x: x["url"]):
        if "error" in r:
            errors += 1
            print(f"{r['url']:<{width}}  {'-':<8}  ⚠️  ERROR ({r['error']})")
            continue
        v = r["verdict"]
        if v in ("AFFECTED", "EOL"):
            affected += 1
        print(f"{r['url']:<{width}}  {r['version'] or '?':<8}  "
              f"{icons.get(v,'')} {v}  ({r['note']})")

    if args.json:
        with open(args.json, "w") as fh:
            json.dump(results, fh, indent=2)
        print(f"\n[+] JSON written to {args.json}")
    if args.csv:
        cols = ["url", "version", "verdict", "note", "powered_by", "server", "error"]
        with open(args.csv, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=cols)
            w.writeheader()
            for r in results:
                w.writerow({k: r.get(k, "") for k in cols})
        print(f"[+] CSV written to {args.csv}")

    print(f"\nSummary: {affected} affected/EOL, {errors} errors, "
          f"{len(results) - affected - errors} patched.")
    if affected:
        return 1
    return 2 if errors and affected == 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
