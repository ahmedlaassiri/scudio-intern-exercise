# NOTES

## Deliverables

| File | Content |
| --- | --- |
| `tickets.md` | 4 tickets (3 defects + 1 hardening), report → ticket mapping, what was checked and ruled out |
| `kql.md` | Fleet-wide queries per problem (count, first/last seen, version, OS) plus a general abnormal-exit query |
| `detect.py` | Detection script, Python 3 standard library only |
| `detection_output.txt` | Its output on the four provided logs (also reproduced below) |

Run the script with `python3 detect.py [logs_dir] [--json]`. It groups rows by `cloud_RoleInstance`
(falls back to `DeviceId` in `customDimensions`), so any number of devices per file or files per
device works. Nothing is keyed on device IDs, URLs or dates; only on message patterns, exit codes
and rates. `--json` emits the same findings as machine-readable JSON for piping into a ticketing
hook.

### Output on the provided logs

```
==============================================================================
DEV-2208  rows=6749  versions=3.4.2  OS=Windows 10 22H2
  log window 2026-10-14T07:30:00.000Z -> 2026-10-14T14:59:55.345Z
  [HIGHEST] CLASSIFIER-CRASH
      3 fail-fast crash(es), 122 connections passed unfiltered in total
      - exit 0xC0000409 at 08:12:50Z  restart #1 2026-10-14T08:13:10.000Z  filter back 2026-10-14T08:13:11.000Z (down ~21.0 s)  fail-open=36 connections
          last classify : 2026-10-14T08:12:41.000Z https://www3.nhk.example.jp/news/html/20261014/k1001.html charset=utf-8 bytes=18233 -> truncated to 4096 bytes
          dump          : C:\ProgramData\Scudio\dumps\ScudioFilter_20261014_081310.dmp
      - exit 0xC0000409 at 10:28:04Z  restart #2 2026-10-14T10:28:20.000Z  filter back 2026-10-14T10:28:21.000Z (down ~17.0 s)  fail-open=38 connections
          last classify : 2026-10-14T10:27:55.000Z https://news.yahoo.example.jp/articles/8f2c1a charset=shift_jis bytes=31877 -> truncated to 4096 bytes
          dump          : C:\ProgramData\Scudio\dumps\ScudioFilter_20261014_102820.dmp
      - exit 0xC0000409 at 13:02:39Z  restart #3 2026-10-14T13:02:55.000Z  filter back 2026-10-14T13:02:56.000Z (down ~17.0 s)  fail-open=48 connections
          last classify : 2026-10-14T13:02:30.000Z https://www.asahi.example.jp/articles/ASR9 charset=euc-jp bytes=27402 -> truncated to 4096 bytes
          dump          : C:\ProgramData\Scudio\dumps\ScudioFilter_20261014_130255.dmp
  checked and ruled out:
      DNS lookup slow x270 (ignored - SCU-106 (Won't fix), cosmetic)
      SSL bypass pinned cert x212 (ignored - expected behaviour for pinned certs)
      severity>=3 lines: 0   text truncation events: 6
==============================================================================
DEV-3390  rows=29297  versions=3.4.1,3.4.2  OS=Windows 11 23H2
  log window 2026-10-15T06:50:00.000Z -> 2026-10-15T08:39:59.972Z
  [HIGH] POLICY-RELOAD-LOOP
      versions=3.4.2  9419 reloads (9419 'unchanged'), 9419 policy.json writes
      2026-10-15T08:00:00.000Z -> 2026-10-15T08:39:59.939Z  peak 236/min, avg 3.92/s, 40 min over threshold, 28257 telemetry rows, still looping at end of log: True
  checked and ruled out:
      DNS lookup slow x49 (ignored - SCU-106 (Won't fix), cosmetic)
      SSL bypass pinned cert x30 (ignored - expected behaviour for pinned certs)
      severity>=3 lines: 0   text truncation events: 0
==============================================================================
DEV-3391  rows=22359  versions=3.4.1,3.4.2  OS=Windows 10 22H2
  log window 2026-10-16T12:10:00.000Z -> 2026-10-16T13:59:59.948Z
  [HIGH] POLICY-RELOAD-LOOP
      versions=3.4.2  7055 reloads (7055 'unchanged'), 7055 policy.json writes
      2026-10-16T13:30:00.000Z -> 2026-10-16T13:59:59.915Z  peak 237/min, avg 3.92/s, 30 min over threshold, 21165 telemetry rows, still looping at end of log: True
  checked and ruled out:
      DNS lookup slow x53 (ignored - SCU-106 (Won't fix), cosmetic)
      SSL bypass pinned cert x37 (ignored - expected behaviour for pinned certs)
      severity>=3 lines: 0   text truncation events: 0
==============================================================================
DEV-4471  rows=7045  versions=3.4.2  OS=Windows 11 23H2
  log window 2026-10-12T18:02:11.000Z -> 2026-10-13T11:59:59.758Z
  [HIGH] LICENSE-CACHE-STALE
      session started 2026-10-12T18:02:15.000Z (v3.4.2, Windows 11 23H2)
      cache at start : LicenseCache: loaded status=Unknown from storage, effective=Inactive
      licence Active : 2026-10-12T18:02:17.640Z  <- 'Policy fetch OK version=1 rules=38 orgLicense=Active'
      still blocked  : 4625 connections / 230 block pages on 17 hosts, 2026-10-12T18:02:20.347Z -> 2026-10-13T09:41:05.121Z (15.65 h)
  checked and ruled out:
      DNS lookup slow x126 (ignored - SCU-106 (Won't fix), cosmetic)
      SSL bypass pinned cert x64 (ignored - expected behaviour for pinned certs)
      severity>=3 lines: 0   text truncation events: 0
==============================================================================
SUMMARY
  CLASSIFIER-CRASH       1 device(s): DEV-2208
  POLICY-RELOAD-LOOP     2 device(s): DEV-3390, DEV-3391
  LICENSE-CACHE-STALE    1 device(s): DEV-4471
```

Limits of the script, stated honestly: the LICENSE-CACHE-STALE detector keys on the exact
`orgLicense=Active` / `license_inactive` wording; the loop detector uses a fixed threshold of
10 reloads/min (a real policy push produces 1); the crash detector attributes a crash to the last
`Classify start` only if nothing else was logged in between, which is true here but may not be in
a busier log where several workers interleave.

## Running the detection continuously on Azure

The three signatures are cheap KQL, so the first step costs almost nothing:

1. **Log Alert rules (scheduled queries) on the Application Insights workspace**, one per query
   in `kql.md`, evaluated every 5–15 minutes over the last hour. Suggested thresholds: Q4 (any
   abnormal exit code) → fire on ≥ 1 device, severity 1 for exit `0xC0000409`; Q3 (reload loop) →
   fire when any device exceeds 10 reloads/min for 5 consecutive minutes; Q1 (licence blocked after
   Active) → fire on ≥ 1 device with > 10 blocks. Route through an Action Group to the on-call
   channel (Teams) and a Logic App / Azure Function that opens or updates the Jira ticket and
   attaches the affected-device list, so a report from support lands on an existing ticket.
2. **Release-gated canary view**: a Workbook that splits every metric by `application_Version`
   and shows crash rate, reloads/min, telemetry rows/hour and `license_inactive` blocks per device
   for the newest version vs the previous one. SCU-NEW-3 would have been visible in the first
   hundred devices updated: rows/hour per device jumped ~50×. Staged rollouts should pause
   automatically when the canary cohort's rate is X× the baseline.
3. **Crash dump pipeline**: devices already upload dumps; a timer-triggered Function can run
   `!analyze -v` (cdb) on new dumps, bucket them by `FAILURE_BUCKET_ID`, and open one ticket per
   bucket with the count, so the second DEV-2208 crash would already have had a ticket.
4. **Fix the signal at the source** (ticket notes): the three defects are all logged at severity
   0–2. Emit a Warning when effective licence ≠ server licence, when reloads exceed a rate, and an
   Error with URL before a classification aborts; then alerts can be on `severityLevel >= 2` and the
   Verbose lines can stay unshipped (sampled), which also fixes the ingestion-cost side of SCU-NEW-3.
5. **The script itself** can run as a Function on a schedule against an export (or be rewritten as
   the same KQL) when a signature is too stateful for one query, e.g. correlating "last Classify
   start before the crash" across rows.

## Where an LLM could help, and what could go wrong

Useful places:
- **Grouping incoming reports.** SUP-1196 and SUP-1201 are the same bug described as "fan" and
  "battery"; a model clustering reports by symptom, version and time of update would merge them
  before a human reads them, and would propose "matches SCU-103?" for a human to confirm.
- **Summarising a log window.** "Explain what happened on this device between 08:12 and 08:14"
  with the rows as context gives a readable narrative for the ticket and for the support reply to
  the customer.
- **Drafting the ticket** from the template once the detector has produced the evidence block,
  and drafting the customer-facing answer ("yes, it will happen again until 3.4.3; a restart clears
  it") in the customer's language, which also touches SCU-102's problem space.
- **Crash dump triage**: turning a `!analyze -v` output into "Rust panic from invalid UTF-8 slice;
  0xC0000409 is fail-fast, not a buffer overrun" is exactly the explanation a non-Rust developer
  needs, and models are good at it.

What could go wrong:
- **Invented evidence.** A model will happily produce a plausible timestamp or log line that is
  not in the data. Rule: every line quoted in a ticket must come from a query result, not from the
  model's text; the model drafts around evidence it is given, it never produces evidence.
- **Confident wrong root cause.** The DEV-2208 report looks like "Japanese charsets"; a model
  anchoring on the customer's words would blame shift_jis/euc-jp handling, missing that the utf-8
  NHK page crashed too and that two Latin pages were truncated without crashing. Root-cause text
  must stay labelled as a hypothesis with a confidence, and the developer makes the call.
- **Merging things that are not the same.** Clustering by symptom can also fold a new bug into
  an old ticket (SCU-103 "memory" vs the CPU loop). Merges should be suggestions a human accepts.
- **Data handling.** Logs contain URLs, device IDs and sometimes personal data; sending them to a
  hosted model needs the same controls as any other processor (contract, region, retention), or an
  on-prem model.
- **Drift and cost.** Prompts that worked on last month's log format silently degrade when a
  message wording changes; keep the deterministic detectors (regex/KQL) as the source of truth and
  use the model only for text, so a model outage or regression never hides an incident.

## Use of AI

An AI assistant (Claude, via Claude Code, running in this folder) was used heavily, for most of
the work in this submission. Being specific:

What it was used for:
- Reading the four CSV exports and the crash dump, summarising the distinct message patterns per
  device, and pulling the exact lines around each incident (service starts, crashes, policy
  fetches, the first and last `license_inactive` block, the reload-loop start).
- Proposing the three root causes and the report → ticket mapping, including the decision that
  SUP-1196 and SUP-1201 are one bug and that the DEV-2208 crash is byte-offset truncation rather
  than a charset problem.
- Drafting `tickets.md`, `kql.md` and this `NOTES.md`, and writing `detect.py` in full.
- Decoding the tail bytes in the dump (`e3 81 ae … e6` → `の話題、最` + lone lead byte) and
  explaining why 0xC0000409 is a Rust fail-fast rather than a real stack overrun.

What I did myself: set the task, read the exercise and every generated file, pushed back on or
accepted each conclusion, ran the script, filled in this section, and I am the one who will defend
each ticket on the call.

How the answers were checked:
- Every count and timestamp quoted in `tickets.md` comes from a `grep`/`awk`/Python pass over the
  raw CSV rows, run in the session, not from the assistant's prose. One miscount (7 vs 6 later
  policy fetches on DEV-4471) was caught this way and corrected.
- `detection_output.txt` is the real output of `detect.py` on `logs/`. The script was also run on
  a small synthetic log with no known signature to confirm it does not invent findings; it reported
  only a generic abnormal exit code there. A fail-open attribution bug found on the first run was
  fixed before the output was recorded.
- The dump reading was checked against itself: `maxBytes=0x1000`, `truncated` = 4096 bytes, the
  `db` dump at offset 0xff0 and the `r12/r13 = 0xffe` registers all agree with a cut inside a
  3-byte character. The log pattern (utf-8/shift_jis/euc-jp Japanese pages crash, Latin pages
  truncated the same way do not, one Japanese page survives) matches that mechanism.
- The KQL was written against the column mapping given in `EXERCISE.md` (`application_Version`,
  dynamic `customDimensions`) but could not be executed here: there is no workspace in the
  exercise, so syntax should be treated as unverified until run in Application Insights.
- Root-cause text is labelled with a confidence level in each ticket because the code was not
  available; only the dump stack and the log sequences are facts, the code paths are hypotheses.
