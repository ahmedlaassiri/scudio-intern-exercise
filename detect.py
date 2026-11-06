#!/usr/bin/env python3
"""
detect.py - scan Application Insights `traces` CSV exports and report, per device,
the known problem signatures found in them.

Usage:
    python3 detect.py [LOG_DIR] [--json]

LOG_DIR defaults to ./logs. Every *.csv in it is read; devices are taken from the
cloud_RoleInstance column, so the script works on exports from any device.
Nothing is keyed on device IDs, timestamps or URLs - only on message patterns.

Detectors
    LICENSE-CACHE-STALE   connections blocked with reason=license_inactive AFTER the
                          service already learnt the licence is Active (policy fetch /
                          license.db update) within the same service session.
    CLASSIFIER-CRASH      service exit 0xC0000409 (fail-fast) with the preceding
                          "Classify start" / "truncating to N bytes" lines, plus the
                          fail-open connection count reported by the driver.
    POLICY-RELOAD-LOOP    PolicyWatcher reload -> PolicyStore write -> reload storm:
                          sustained reload rate far above anything a real policy
                          change could produce.
    OTHER-ABNORMAL-EXIT   any service start whose previous exit code is not 0x0 and is
                          not already covered by CLASSIFIER-CRASH.
Known, ignored noise (reported in the summary so it is visible that it was checked):
    "DNS lookup slow"      -> SCU-106 (Won't fix)
    "SSL bypass applied"   -> expected behaviour for pinned certificates
"""
import csv
import glob
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone

# ---------------------------------------------------------------- patterns
RE_SERVICE_START = re.compile(r"^Service starting \(previous exit code (0x[0-9A-Fa-f]+)\)")
RE_LICENSE_BLOCK = re.compile(r"^Connection blocked host=(\S+) reason=license_inactive")
RE_BLOCK_PAGE_LIC = re.compile(r"^Block page served host=(\S+) page=subscription_inactive")
RE_LICENSE_PROOF = re.compile(r"(^Policy fetch OK .*orgLicense=Active)|(^Storage: license\.db updated status=Active)")
RE_LICENSE_CACHE = re.compile(r"^LicenseCache: loaded status=(\w+) from storage, effective=(\w+)")
RE_CLASSIFY_START = re.compile(r"^Classify start url=(\S+) charset=(\S+) bytes=(\d+)")
RE_TRUNCATE = re.compile(r"^Text preprocess: converted to UTF-8, truncating to (\d+) bytes")
RE_CRASH_DUMP = re.compile(r"^Crash dump written (\S+)")
RE_WATCHDOG = re.compile(r"^Watchdog: service process exited unexpectedly, restart #(\d+) at (\S+)")
RE_FAIL_OPEN = re.compile(r"^Driver reports (\d+) connections passed unfiltered while service was down")
RE_WATCH_RELOAD = re.compile(r"^PolicyWatcher: policy\.json changed, reloading")
RE_RELOAD_UNCHANGED = re.compile(r"^Policy reload: version=(\d+) unchanged")
RE_STORE_WRITE = re.compile(r"^PolicyStore: wrote policy\.json")
RE_DNS_SLOW = re.compile(r"^DNS lookup slow")
RE_SSL_BYPASS = re.compile(r"^SSL bypass applied")

CRASH_FAILFAST = "0xC0000409"
# A real policy change happens a few times a day at most. Anything above this
# sustained rate (reloads per minute) is a feedback loop.
RELOAD_LOOP_THRESHOLD_PER_MIN = 10


def parse_ts(s):
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s).astimezone(timezone.utc)


def fmt(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def load_rows(log_dir):
    """Return {device: [row, ...]} sorted by timestamp. Row = dict with parsed fields."""
    devices = defaultdict(list)
    files = sorted(glob.glob(os.path.join(log_dir, "*.csv")))
    if not files:
        sys.exit(f"no CSV files found in {log_dir}")
    for path in files:
        with open(path, newline="", encoding="utf-8-sig") as f:
            for r in csv.DictReader(f):
                try:
                    dims = json.loads(r.get("customDimensions") or "{}")
                except json.JSONDecodeError:
                    dims = {}
                dev = r.get("cloud_RoleInstance") or dims.get("DeviceId") or os.path.basename(path)
                try:
                    sev = int(r.get("severityLevel") or 0)
                except ValueError:
                    sev = 0
                devices[dev].append({
                    "ts": parse_ts(r["timestamp"]),
                    "ver": r.get("appVersion") or r.get("application_Version") or "?",
                    "sev": sev,
                    "msg": r.get("message") or "",
                    "os": dims.get("OS", "?"),
                    "component": dims.get("Component", "?"),
                    "file": os.path.basename(path),
                })
    for rows in devices.values():
        rows.sort(key=lambda x: x["ts"])
    return devices


# ---------------------------------------------------------------- detectors
def detect_license_cache_stale(rows):
    """Blocks for license_inactive after the service already knows the licence is Active,
    within one service session (session = from one 'Service starting' to the next)."""
    findings = []
    session = None

    def close(s):
        if s and s["proof_ts"] and s["blocks_after_proof"]:
            findings.append(s)

    for r in rows:
        m = RE_SERVICE_START.match(r["msg"])
        if m:
            close(session)
            session = {"start": r["ts"], "ver": r["ver"], "os": r["os"], "cache_line": None,
                       "proof_ts": None, "proof_msg": None, "blocks_after_proof": 0,
                       "pages_after_proof": 0, "first_block": None, "last_block": None,
                       "hosts": set()}
            continue
        if session is None:
            continue
        m = RE_LICENSE_CACHE.match(r["msg"])
        if m:
            session["cache_line"] = (r["ts"], r["msg"])
        if RE_LICENSE_PROOF.match(r["msg"]) and session["proof_ts"] is None:
            session["proof_ts"], session["proof_msg"] = r["ts"], r["msg"]
        m = RE_LICENSE_BLOCK.match(r["msg"])
        if m and session["proof_ts"] and r["ts"] > session["proof_ts"]:
            session["blocks_after_proof"] += 1
            session["hosts"].add(m.group(1))
            session["first_block"] = session["first_block"] or r["ts"]
            session["last_block"] = r["ts"]
        if RE_BLOCK_PAGE_LIC.match(r["msg"]) and session["proof_ts"] and r["ts"] > session["proof_ts"]:
            session["pages_after_proof"] += 1
    close(session)
    return findings


def detect_classifier_crash(rows):
    """Fail-fast exits (0xC0000409). For each, attach the last Classify start / truncation
    line before the exit and the fail-open count reported after restart."""
    crashes = []
    last_classify, last_trunc, last_normal = None, None, None
    pending = None
    for r in rows:
        msg = r["msg"]
        m = RE_CLASSIFY_START.match(msg)
        if m:
            last_classify = (r["ts"], m.group(1), m.group(2), int(m.group(3)))
            last_trunc = None
            continue
        m = RE_TRUNCATE.match(msg)
        if m:
            last_trunc = (r["ts"], int(m.group(1)))
            continue
        m = RE_SERVICE_START.match(msg)
        if m:
            code = m.group(1).upper()
            if code == CRASH_FAILFAST.upper():
                pending = {"restart_ts": r["ts"], "ver": r["ver"], "os": r["os"], "exit_code": m.group(1),
                           "last_log_before": last_normal, "classify": last_classify,
                           "truncate": last_trunc, "dump": None, "watchdog": None, "fail_open": None,
                           "down_until": None}
                crashes.append(pending)
            else:
                pending = None
            last_classify = last_trunc = None
            continue
        if pending is not None:
            m = RE_CRASH_DUMP.match(msg)
            if m:
                pending["dump"] = m.group(1)
            m = RE_WATCHDOG.match(msg)
            if m:
                pending["watchdog"] = (int(m.group(1)), m.group(2))
            m = RE_FAIL_OPEN.match(msg)
            if m:
                pending["fail_open"] = int(m.group(1))
            if msg.startswith("HttpFilter started"):
                pending["down_until"] = r["ts"]
            if pending["fail_open"] is not None and pending["down_until"] is not None:
                pending = None
        last_normal = (r["ts"], msg)
    return crashes


def detect_policy_reload_loop(rows):
    per_min = defaultdict(int)
    reloads = unchanged = writes = 0
    first = last = None
    versions = set()
    for r in rows:
        if RE_WATCH_RELOAD.match(r["msg"]):
            reloads += 1
            per_min[r["ts"].replace(second=0, microsecond=0)] += 1
            first = first or r["ts"]
            last = r["ts"]
            versions.add(r["ver"])
        elif RE_RELOAD_UNCHANGED.match(r["msg"]):
            unchanged += 1
        elif RE_STORE_WRITE.match(r["msg"]):
            writes += 1
    if not per_min:
        return None
    peak = max(per_min.values())
    hot_minutes = sum(1 for v in per_min.values() if v >= RELOAD_LOOP_THRESHOLD_PER_MIN)
    if hot_minutes == 0:
        return None
    span_s = max((last - first).total_seconds(), 1)
    return {"reloads": reloads, "unchanged": unchanged, "writes": writes, "first": first, "last": last,
            "peak_per_min": peak, "avg_per_s": reloads / span_s, "hot_minutes": hot_minutes,
            "versions": sorted(versions), "log_rows": reloads + unchanged + writes}


def detect_other_abnormal_exits(rows):
    out = []
    for r in rows:
        m = RE_SERVICE_START.match(r["msg"])
        if m and int(m.group(1), 16) != 0 and m.group(1).upper() != CRASH_FAILFAST.upper():
            out.append((r["ts"], m.group(1)))
    return out


def noise_summary(rows):
    dns = sum(1 for r in rows if RE_DNS_SLOW.match(r["msg"]))
    ssl = sum(1 for r in rows if RE_SSL_BYPASS.match(r["msg"]))
    high = [(r["ts"], r["sev"], r["msg"]) for r in rows if r["sev"] >= 3]
    return dns, ssl, high


# ---------------------------------------------------------------- reporting
def _down_seconds(c):
    """Seconds between the process exit (time reported by the watchdog) and HttpFilter
    coming back. The watchdog only logs HH:MM:SSZ, so the date is taken from the restart."""
    if not (c["watchdog"] and c["down_until"]):
        return None
    try:
        hh, mm, ss = c["watchdog"][1].rstrip("Z").split(":")
        exit_ts = c["restart_ts"].replace(hour=int(hh), minute=int(mm), second=int(float(ss)), microsecond=0)
    except ValueError:
        return None
    return round((c["down_until"] - exit_ts).total_seconds(), 1)


def analyse_device(dev, rows):
    versions = sorted({r["ver"] for r in rows})
    oses = sorted({r["os"] for r in rows})
    report = {"device": dev, "rows": len(rows), "versions": versions, "os": oses,
              "from": fmt(rows[0]["ts"]), "to": fmt(rows[-1]["ts"]), "problems": [], "checked": {}}

    for s in detect_license_cache_stale(rows):
        dur = (s["last_block"] - s["proof_ts"]).total_seconds()
        report["problems"].append({
            "id": "LICENSE-CACHE-STALE",
            "severity": "HIGH",
            "version": s["ver"], "os": s["os"],
            "session_start": fmt(s["start"]),
            "license_cache_at_start": s["cache_line"][1] if s["cache_line"] else None,
            "license_known_active_at": fmt(s["proof_ts"]),
            "proof_line": s["proof_msg"],
            "blocks_after_active": s["blocks_after_proof"],
            "block_pages_after_active": s["pages_after_proof"],
            "distinct_hosts_blocked": len(s["hosts"]),
            "first_block": fmt(s["first_block"]), "last_block": fmt(s["last_block"]),
            "duration_hours": round(dur / 3600, 2),
        })

    crashes = detect_classifier_crash(rows)
    if crashes:
        total_fail_open = sum(c["fail_open"] or 0 for c in crashes)
        report["problems"].append({
            "id": "CLASSIFIER-CRASH",
            "severity": "HIGHEST",
            "count": len(crashes),
            "fail_open_connections_total": total_fail_open,
            "crashes": [{
                "exit_code": c["exit_code"],
                "process_exited_at": c["watchdog"][1] if c["watchdog"] else None,
                "restart_number": c["watchdog"][0] if c["watchdog"] else None,
                "restarted_at": fmt(c["restart_ts"]),
                "filter_back_at": fmt(c["down_until"]) if c["down_until"] else None,
                "down_seconds": _down_seconds(c),
                "fail_open_connections": c["fail_open"],
                "dump": c["dump"],
                "last_classify_before_crash": None if not c["classify"] else {
                    "at": fmt(c["classify"][0]), "url": c["classify"][1],
                    "charset": c["classify"][2], "bytes": c["classify"][3]},
                "truncated_to_bytes": c["truncate"][1] if c["truncate"] else None,
                "version": c["ver"], "os": c["os"],
            } for c in crashes],
        })

    loop = detect_policy_reload_loop(rows)
    if loop:
        report["problems"].append({
            "id": "POLICY-RELOAD-LOOP",
            "severity": "HIGH",
            "versions": loop["versions"],
            "reloads": loop["reloads"], "reloads_unchanged": loop["unchanged"], "policy_writes": loop["writes"],
            "first": fmt(loop["first"]), "last": fmt(loop["last"]),
            "peak_per_minute": loop["peak_per_min"], "avg_per_second": round(loop["avg_per_s"], 2),
            "minutes_over_threshold": loop["hot_minutes"], "telemetry_rows_generated": loop["log_rows"],
            "still_looping_at_end_of_log": (rows[-1]["ts"] - loop["last"]).total_seconds() < 5,
        })

    other = detect_other_abnormal_exits(rows)
    if other:
        report["problems"].append({"id": "OTHER-ABNORMAL-EXIT", "severity": "MEDIUM",
                                   "exits": [{"at": fmt(t), "exit_code": c} for t, c in other]})

    # Expose exposure signals even when no crash followed (useful fleet-wide)
    truncations = [r for r in rows if RE_TRUNCATE.match(r["msg"])]
    dns, ssl, high = noise_summary(rows)
    report["checked"] = {
        "dns_lookup_slow_warnings": {"count": dns, "verdict": "ignored - SCU-106 (Won't fix), cosmetic"},
        "ssl_bypass_pinned_certificate_warnings": {"count": ssl, "verdict": "ignored - expected behaviour for pinned certs"},
        "severity>=3_lines": len(high),
        "text_truncation_events": len(truncations),
    }
    return report


def print_human(rep):
    print("=" * 78)
    print(f"{rep['device']}  rows={rep['rows']}  versions={','.join(rep['versions'])}  OS={'; '.join(rep['os'])}")
    print(f"  log window {rep['from']} -> {rep['to']}")
    if not rep["problems"]:
        print("  no known problem signature detected")
    for p in rep["problems"]:
        print(f"  [{p['severity']}] {p['id']}")
        if p["id"] == "LICENSE-CACHE-STALE":
            print(f"      session started {p['session_start']} (v{p['version']}, {p['os']})")
            print(f"      cache at start : {p['license_cache_at_start']}")
            print(f"      licence Active : {p['license_known_active_at']}  <- '{p['proof_line']}'")
            print(f"      still blocked  : {p['blocks_after_active']} connections / {p['block_pages_after_active']} block pages "
                  f"on {p['distinct_hosts_blocked']} hosts, {p['first_block']} -> {p['last_block']} ({p['duration_hours']} h)")
        elif p["id"] == "CLASSIFIER-CRASH":
            print(f"      {p['count']} fail-fast crash(es), {p['fail_open_connections_total']} connections passed unfiltered in total")
            for c in p["crashes"]:
                lc = c["last_classify_before_crash"]
                print(f"      - exit {c['exit_code']} at {c['process_exited_at']}  restart #{c['restart_number']} {c['restarted_at']}  "
                      f"filter back {c['filter_back_at']} (down ~{c['down_seconds']} s)  fail-open={c['fail_open_connections']} connections")
                if lc:
                    print(f"          last classify : {lc['at']} {lc['url']} charset={lc['charset']} bytes={lc['bytes']}"
                          + (f" -> truncated to {c['truncated_to_bytes']} bytes" if c["truncated_to_bytes"] else ""))
                if c["dump"]:
                    print(f"          dump          : {c['dump']}")
        elif p["id"] == "POLICY-RELOAD-LOOP":
            print(f"      versions={','.join(p['versions'])}  {p['reloads']} reloads ({p['reloads_unchanged']} 'unchanged'), "
                  f"{p['policy_writes']} policy.json writes")
            print(f"      {p['first']} -> {p['last']}  peak {p['peak_per_minute']}/min, avg {p['avg_per_second']}/s, "
                  f"{p['minutes_over_threshold']} min over threshold, {p['telemetry_rows_generated']} telemetry rows, "
                  f"still looping at end of log: {p['still_looping_at_end_of_log']}")
        elif p["id"] == "OTHER-ABNORMAL-EXIT":
            for e in p["exits"]:
                print(f"      - {e['at']} previous exit code {e['exit_code']}")
    c = rep["checked"]
    print("  checked and ruled out:")
    print(f"      DNS lookup slow x{c['dns_lookup_slow_warnings']['count']} ({c['dns_lookup_slow_warnings']['verdict']})")
    print(f"      SSL bypass pinned cert x{c['ssl_bypass_pinned_certificate_warnings']['count']} "
          f"({c['ssl_bypass_pinned_certificate_warnings']['verdict']})")
    print(f"      severity>=3 lines: {c['severity>=3_lines']}   text truncation events: {c['text_truncation_events']}")


def main(argv):
    as_json = "--json" in argv
    args = [a for a in argv if not a.startswith("--")]
    log_dir = args[0] if args else os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    devices = load_rows(log_dir)
    reports = [analyse_device(d, rows) for d, rows in sorted(devices.items())]
    if as_json:
        print(json.dumps(reports, indent=2, default=str))
        return
    for rep in reports:
        print_human(rep)
    print("=" * 78)
    summary = defaultdict(list)
    for rep in reports:
        for p in rep["problems"]:
            summary[p["id"]].append(rep["device"])
    print("SUMMARY")
    if not summary:
        print("  nothing detected")
    for pid, devs in summary.items():
        print(f"  {pid:<22} {len(devs)} device(s): {', '.join(devs)}")


if __name__ == "__main__":
    main(sys.argv[1:])
