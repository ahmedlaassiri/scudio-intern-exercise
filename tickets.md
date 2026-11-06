# Tickets

Four support reports, three distinct defects. SUP-1196 and SUP-1201 are the same bug on two
devices. One hardening ticket (SCU-NEW-4) is split out of the crash because it has a different
fix and owner.

| Report | Device | What actually happened | Ticket |
| --- | --- | --- | --- |
| SUP-1182 | DEV-4471 | Fresh install: in-memory licence state stayed `Inactive` for 15.6 h although the server said `Active` 2 s after start | **SCU-NEW-1** |
| SUP-1190 | DEV-2208 | Service crashed 3 times (fail-fast in the Rust tokenizer) on Japanese pages; driver passed traffic unfiltered for ~20 s each time | **SCU-NEW-2** (+ SCU-NEW-4) |
| SUP-1196 | DEV-3390 | After the 3.4.1 → 3.4.2 update the policy watcher reloads and rewrites `policy.json` ~4×/s forever | **SCU-NEW-3** |
| SUP-1201 | DEV-3391 | Same as SUP-1196 (Windows 10 instead of 11) | **SCU-NEW-3** (duplicate report) |

Log timestamps are UTC, as exported. `sev` = `severityLevel`.

---

## SCU-NEW-1 — LicenseCache is never refreshed in memory after the first policy fetch reports `orgLicense=Active` (fresh install blocks all traffic until restart)

**Title:** LicenseCache keeps `effective=Inactive` after `Policy fetch OK … orgLicense=Active` on a fresh install; every connection is blocked with `license_inactive` until the service restarts

**Type / Priority:** Bug / **High** — on a new install the product blocks 100 % of traffic (including Microsoft login, Teams, Google) for as long as the laptop stays on; it hits every fresh 3.4.2 install, not just this customer. Not Highest because it fails closed (no safety exposure) and a reboot clears it.

**Affected:**
- Version 3.4.2 (only version in the log; fresh install, no earlier version on the device).
- Windows 11 23H2. Very likely any OS: the defect is in the licence cache, not in OS code.
- Devices: DEV-4471. Fleet: every device whose `license.db` is missing or empty at service start (first install, reinstall, profile reset) — see `kql.md` Q1/Q1b.
- Reports: SUP-1182.

**Summary:** On first start there is no `license.db`, so the cache loads `status=Unknown` and treats it as `effective=Inactive`. Two seconds later the policy fetch succeeds with `orgLicense=Active` and `license.db` is updated to `Active` on disk, but the in-memory effective state is never updated. The filter kept blocking every connection with `reason=license_inactive` and serving the *subscription inactive* page for 15 h 39 min, through 6 further successful policy fetches, until the user rebooted. After the reboot the cache loaded `Active` from disk and everything worked.

**Steps to reproduce / conditions:**
1. Install 3.4.2 on a device with no previous Scudio data (no `C:\ProgramData\Scudio\license.db`), with an active subscription.
2. Let the service start and complete its first policy fetch (`orgLicense=Active`).
3. Browse to any site.
4. Do **not** restart the service.

**Expected behaviour:** Once the backend reports `orgLicense=Active` (or at the latest once `license.db` is updated to `Active`), the effective licence state becomes `Active` and normal policy filtering applies, without a restart.

**Actual behaviour:** Effective state stays `Inactive`. Every connection is blocked with `reason=license_inactive`; the *subscription_inactive* block page is served for page loads. The state only becomes `Active` after a service restart, because the cache is re-read from disk at start-up.

**Evidence** (`logs/DEV-4471.csv`):
```
2026-10-12T18:02:11.000Z  sev1  Installer: install completed version=3.4.2
2026-10-12T18:02:15.000Z  sev1  Service starting (previous exit code 0x0)
2026-10-12T18:02:15.120Z  sev1  Storage: license.db not found, creating empty store
2026-10-12T18:02:15.140Z  sev1  LicenseCache: loaded status=Unknown from storage, effective=Inactive
2026-10-12T18:02:17.640Z  sev1  Policy fetch OK version=1 rules=38 orgLicense=Active
2026-10-12T18:02:17.700Z  sev1  Storage: license.db updated status=Active
2026-10-12T18:02:20.347Z  sev1  Connection blocked host=www.bbc.com reason=license_inactive        <- first block, 2.6 s AFTER Active was known
2026-10-12T18:02:48.103Z  sev1  Block page served host=www.nytimes.com page=subscription_inactive
...  6 more "Policy fetch OK version=1 rules=38 orgLicense=Active" at 18:11:49, 19:06:33, 21:03:35, 23:00:02, 07:24:31, 08:10:34, each followed by
     sev0  "Policy unchanged, skipping apply"  — the licence state is still not applied
2026-10-13T09:41:05.121Z  sev1  Connection blocked host=github.com reason=license_inactive        <- last block
2026-10-13T09:41:30.000Z  sev1  Service stopping (system shutdown)
2026-10-13T09:43:02.140Z  sev1  LicenseCache: loaded status=Active from storage, effective=Active  <- fixed by the reboot
2026-10-13T09:43:17.909Z  sev1  Connection blocked host=... reason=category rule=R..               <- normal filtering from here on
```
- Between 18:02:20 and 09:41:05: **4 625** `Connection blocked … reason=license_inactive`, **230** `Block page served … page=subscription_inactive`, on 17 distinct hosts, and **zero** `Connection allowed` lines. After 09:43:02: zero `license_inactive` blocks, 1 190 `Connection allowed`.
- Nothing in that window is logged above severity 1. A device that silently blocks everything for 15 h with the server saying `Active` should at least raise a Warning (see note below).

**Probable cause:** The in-memory `LicenseCache` is populated only at start-up (from `license.db`). The policy-fetch path writes the new licence status to storage but does not notify/invalidate the cache, and the later fetches short-circuit on "policy unchanged" before any licence handling runs. On upgrades `license.db` already contains `Active`, which is why this only shows on fresh installs. Confidence: **high** on "cache not refreshed until restart" (the log proves it), **medium** on the exact code path. Secondary design question for the devs: should `status=Unknown` (no data yet) really map to `effective=Inactive` (fail closed) before the first fetch has had a chance to answer, or should it wait for the first fetch result / use a short grace period?

**Suggested additional change:** log a `Warning` when `effective` licence state ≠ server-reported `orgLicense` for more than one fetch cycle, so this is alertable fleet-wide (today the only signal is an Information-level count).

**Links:** SUP-1182. Not a duplicate of SCU-105 (Android banner not shown on expiry: different platform, opposite symptom). SCU-104 (installer hang) ruled out: install completed in the log.

---

## SCU-NEW-2 — Text truncation at a fixed 4096-byte offset splits a UTF-8 multi-byte character; the Rust tokenizer panics and the whole service fail-fasts (0xC0000409), leaving traffic unfiltered

**Title:** `TextClassifier::Tokenize` truncates UTF-8 input at `maxBytes=4096` without respecting character boundaries → `tokenizers` panics (`slice_error_fail`) → ScudioFilter.exe fail-fast crash → filter fail-open ~20 s per crash

**Type / Priority:** Bug / **Highest** — it is a crash of the filter service, repeatable by simply reading a long Japanese (or any CJK / multi-byte) page, and each crash lets traffic through unfiltered (122 connections in one school day on one device). This is the product failing at its core promise, in a school.

**Affected:**
- Version 3.4.2 (`textclassifier.dll` symbols from `C:\symbols\scudio\3.4.2`). Older versions unknown: check whether the 4096-byte truncation exists in 3.4.1 (`kql.md` Q2b by `application_Version`).
- Windows 10 22H2 (DEV-2208). OS-independent: pure string handling.
- Devices: DEV-2208. Fleet: any device that classifies pages whose text is > 4 096 bytes of UTF-8 and contains multi-byte characters (Japanese, Chinese, Korean, Arabic, Cyrillic, emoji…). `kql.md` Q2.
- Reports: SUP-1190.

**Summary:** Before tokenisation the page text is converted to UTF-8 and cut to 4 096 bytes by byte count. If byte 4 096 falls inside a multi-byte character the buffer ends with a partial sequence. The Rust `tokenizers` normaliser slices the string at that offset, which is not a char boundary, panics, and because the DLL is built with `panic=abort` the panic turns into `__fastfail` → `0xC0000409` → the whole `ScudioFilter.exe` dies. The watchdog restarts it 15–20 s later; meanwhile the driver passes connections unfiltered (fail-open). On DEV-2208 this happened 3 times in 5 hours, each time right after classifying a Japanese news article; the English and French pages that were also truncated did not crash (ASCII never straddles the cut). One Japanese page (mainichi, 14:15) also survived, consistent with a ~1-in-3 chance that the cut lands on a boundary for 3-byte characters.

**Steps to reproduce / conditions:**
1. 3.4.2 with text classification enabled.
2. Load an HTML page whose extracted text is > 4 096 bytes of UTF-8 and consists mostly of 3-byte characters (any NHK/Asahi/Yahoo Japan article; any charset — utf-8, shift_jis and euc-jp all crashed because the cut happens *after* conversion to UTF-8).
3. Repeat with a few different articles; roughly two out of three will crash the service.
4. Deterministic unit repro: call `TextClassifier::Classify` with a string of 1 366 × `あ` (= 4 098 bytes). Byte 4 096 is the first byte of the 1 366th character.

**Expected behaviour:** Truncation must cut on a character boundary (or operate on code points / tokens, not bytes). A malformed string must never take down the service; at worst the single page falls back to the configured failure policy.

**Actual behaviour:** The service process aborts; the browser gets the page (the response was already being processed) and every connection for the next ~20 s is passed unfiltered by the driver; blocked categories load normally until the restart finishes.

**Evidence:**

Log (`logs/DEV-2208.csv`), the same sequence three times:
```
2026-10-14T08:12:41.000Z  sev0  Classify start url=https://www3.nhk.example.jp/news/html/20261014/k1001.html charset=utf-8 bytes=18233
2026-10-14T08:12:41.003Z  sev0  Text preprocess: converted to UTF-8, truncating to 4096 bytes
                                 (no further log line from the process; dump "Debug session time" = 08:12:50.412)
2026-10-14T08:13:10.000Z  sev2  Service starting (previous exit code 0xC0000409)
2026-10-14T08:13:10.005Z  sev1  Watchdog: service process exited unexpectedly, restart #1 at 08:12:50Z
2026-10-14T08:13:10.008Z  sev2  Crash dump written C:\ProgramData\Scudio\dumps\ScudioFilter_20261014_081310.dmp
2026-10-14T08:13:11.000Z  sev1  HttpFilter started
2026-10-14T08:13:11.010Z  sev2  Driver reports 36 connections passed unfiltered while service was down (fail-open)

2026-10-14T10:27:55.000Z  sev0  Classify start url=https://news.yahoo.example.jp/articles/8f2c1a charset=shift_jis bytes=31877
2026-10-14T10:27:55.003Z  sev0  Text preprocess: converted to UTF-8, truncating to 4096 bytes
2026-10-14T10:28:20.000Z  sev2  Service starting (previous exit code 0xC0000409)
2026-10-14T10:28:20.005Z  sev1  Watchdog: service process exited unexpectedly, restart #2 at 10:28:04Z
2026-10-14T10:28:21.010Z  sev2  Driver reports 38 connections passed unfiltered while service was down (fail-open)

2026-10-14T13:02:30.000Z  sev0  Classify start url=https://www.asahi.example.jp/articles/ASR9 charset=euc-jp bytes=27402
2026-10-14T13:02:30.003Z  sev0  Text preprocess: converted to UTF-8, truncating to 4096 bytes
2026-10-14T13:02:55.000Z  sev2  Service starting (previous exit code 0xC0000409)
2026-10-14T13:02:55.005Z  sev1  Watchdog: service process exited unexpectedly, restart #3 at 13:02:39Z
2026-10-14T13:02:56.010Z  sev2  Driver reports 48 connections passed unfiltered while service was down (fail-open)
```
Truncated pages that did **not** crash (same day, same device): bbc.com 09:05:03 (utf-8, 22 410 B), lemonde.fr 11:40:12 (utf-8, 15 020 B), mainichi.example.jp 14:15:09 (utf-8, 12 750 B). So: it is not "Japanese charsets", it is multi-byte text + byte-offset truncation, and it is probabilistic.

Crash dump (`crash_dumps/DEV-2208_ScudioFilter_20261014_081310_analyze.txt`):
- `Failure.Bucket: FAIL_FAST_FATAL_APP_EXIT_c0000409_textclassifier.dll!panic_abort::__rust_start_panic::abort`, `Subcode: 0x7 FAST_FAIL_FATAL_APP_EXIT`. **Note for devs:** 0xC0000409 here is *not* a real stack-buffer overrun; it is the generic status Rust's `panic=abort` produces via `__fastfail`.
- Process uptime 0:42:50 at 08:12:50 → started 07:30:00, matching the log.
- Stack, bottom-up: `WorkerPool::WorkerLoop` → `HtmlPipeline::ProcessResponse` (HtmlPipeline.cpp:311) → `TextPipeline::Run` (TextPipeline.cpp:97) → `TextClassifier::Classify` (TextClassifier.cpp:148) → **`TextClassifier::Tokenize` (TextClassifier.cpp:212)** → `tokenizers_encode` → `Tokenizer::encode_single_sequence` → `NormalizedString::transform_range` → **`core::str::slice_error_fail`** → `panic_fmt` → `rust_panic` → `abort` → `int 29h`.
- `.frame 0c` locals: `ctx = {url="https://www3.nhk.example.jp/news/html/20261014/k1001.html" charset="utf-8"}`, `utf8 = <18233 bytes>`, **`truncated = <4096 bytes>`, `maxBytes = 0x1000`**, `result.categories.size = 0`.
- `db 000001f2b7c40ff0 L10` (last 16 bytes of the truncated buffer): `e3 81 ae | e8 a9 b1 | e9 a1 8c | e3 80 81 | e6 9c 80 | e6` = `の 話 題 、 最` followed by a **lone lead byte `0xE6`** at offset 0xFFF: the 3-byte character that starts there was cut by the 4 096 limit. Registers `r12 = 0xffe`, `r13 = buffer+0xffe` are the slice index the normaliser was working on, right at the broken tail.

**Probable cause:** `TextClassifier::Tokenize` (TextClassifier.cpp ≈ 212) does `truncated = utf8.substr(0, maxBytes)` (or equivalent) with `maxBytes = 4096` on the raw UTF-8 bytes, then hands the string across FFI to the Rust tokenizer, whose `&str` slicing requires valid UTF-8 at the cut point and panics otherwise. Confidence: **high** — dump locals, stack and tail bytes all agree, and the log pattern (Japanese crashes, Latin doesn't) matches.

**Fix suggestions:** back off to the previous UTF-8 lead byte before cutting (or truncate by code points / by tokens after encoding); validate UTF-8 before calling into the tokenizer; add a unit test with CJK text of length 4 095/4 096/4 097/4 098 bytes. See SCU-NEW-4 for making the FFI boundary panic-safe so no future bug in `textclassifier.dll` can kill the service.

**Links:** SUP-1190. Related, not duplicate: SCU-101 (pages with `<meta http-equiv>` charset only are not classified — same charset/text-pipeline area, but here the charset *was* detected and the failure is a crash, not a silent pass-through). SCU-NEW-4 (hardening).

---

## SCU-NEW-3 — 3.4.2 PolicyWatcher ↔ PolicyStore feedback loop: every reload rewrites `policy.json`, which re-triggers the watcher (~4 reloads/s, permanent CPU use, ~700 telemetry rows/min)

**Title:** `PolicyStore` writes `lastChecked` into the watched `policy.json` on every reload, so `PolicyWatcher` re-fires immediately → endless reload loop at ~4 Hz after the 3.4.2 update

**Type / Priority:** Bug / **High** — it affects every device updated to 3.4.2 (both reporters are on different OS/orgs and show the identical pattern), it never stops, it drains laptop batteries, and it floods Application Insights with ~28 k verbose rows per device per 40 minutes (ingestion cost + it will bury real signals). Not Highest because filtering keeps working.

**Affected:**
- Version **3.4.2 only**: both devices ran 3.4.1 for 1–1.3 h in the same logs with zero `PolicyWatcher`/`PolicyStore` lines; the component appears for the first time right after the update (`PolicyWatcher: watching …`).
- Windows 11 23H2 (DEV-3390) and Windows 10 22H2 (DEV-3391).
- Devices: DEV-3390, DEV-3391. Fleet: expect every 3.4.2 device — `kql.md` Q3.
- Reports: SUP-1196, SUP-1201 (same bug; SUP-1201 is a duplicate report, not a second ticket).

**Summary:** 3.4.2 introduced a file watcher on `C:\ProgramData\Scudio\policy.json`. On every change it reloads the policy, finds it unchanged, and then `PolicyStore` writes `policy.json` back with a new `lastChecked` timestamp. That write is itself a change, so the watcher fires again ~220 ms later. Result: 235–237 reloads per minute (3.9/s), each with three verbose log lines, from 30 s after the post-update start until the end of both logs, with no sign of stopping. That is the "3–5 % CPU with no browser open" and the battery drain.

**Steps to reproduce / conditions:**
1. Update any device from 3.4.1 to 3.4.2 (or install 3.4.2 and let the first policy fetch complete).
2. Wait for `PolicyWatcher: watching C:\ProgramData\Scudio\policy.json`.
3. Watch the log / Task Manager: ~4 reload cycles per second, constant CPU, no user activity needed.

**Expected behaviour:** The policy is reloaded only when its content changes (a new version/sha from the server or an admin edit). Writing bookkeeping metadata must not retrigger the watcher, and an unchanged policy should cause no write at all. CPU at idle ≈ 0 %, as in 3.4.1.

**Actual behaviour:** Reload → "unchanged" → write → change event → reload … forever. ScudioFilter.exe sits at 3–5 % CPU; the fan runs; battery drains; telemetry volume for the device multiplies ~50×.

**Evidence** (`logs/DEV-3390.csv`, identical shape in `logs/DEV-3391.csv` one day later):
```
2026-10-15T07:58:00.000Z  3.4.1  sev1  Updater: installing version=3.4.2
2026-10-15T07:58:20.000Z  3.4.1  sev1  Service stopping (update)
2026-10-15T07:59:30.000Z  3.4.2  sev1  Service starting (previous exit code 0x0)
2026-10-15T07:59:32.640Z  3.4.2  sev1  Policy fetch OK version=17 rules=38 orgLicense=Active
2026-10-15T07:59:33.000Z  3.4.2  sev1  PolicyWatcher: watching C:\ProgramData\Scudio\policy.json     <- new in 3.4.2
2026-10-15T08:00:00.000Z  3.4.2  sev0  PolicyWatcher: policy.json changed, reloading
2026-10-15T08:00:00.031Z  3.4.2  sev0  Policy reload: version=17 unchanged (sha=9f3a61c2)
2026-10-15T08:00:00.033Z  3.4.2  sev0  PolicyStore: wrote policy.json lastChecked=08:00:00.033         <- the write that triggers the next event
2026-10-15T08:00:00.253Z  3.4.2  sev0  PolicyWatcher: policy.json changed, reloading                   <- 220 ms later
2026-10-15T08:00:00.284Z  3.4.2  sev0  Policy reload: version=17 unchanged (sha=9f3a61c2)
2026-10-15T08:00:00.286Z  3.4.2  sev0  PolicyStore: wrote policy.json lastChecked=08:00:00.286
... (repeats)
2026-10-15T08:39:59.939Z  3.4.2  sev0  PolicyWatcher: policy.json changed, reloading                   <- still going at end of export
2026-10-15T08:39:59.972Z  3.4.2  sev0  PolicyStore: wrote policy.json lastChecked=08:39:59.972
```
- DEV-3390: **9 419** reload cycles in 40 min (235–236 per minute in every single minute), 9 419 × "unchanged", 9 419 writes, 28 257 verbose rows → 96 % of the whole export.
- DEV-3391: **7 055** cycles in 30 min (234–237/min), starting 13:30:00, 30 s after `PolicyWatcher: watching …` at 13:29:33; still running at 13:59:59.
- Before the update (3.4.1, same devices, 1 h+): 0 `PolicyWatcher`/`PolicyStore`/`Policy reload` lines, 54 and 89 Policy-component lines in total.
- Memory is not mentioned as growing in either report and uptime is < 1 day, so this is not SCU-103.

**Probable cause:** New 3.4.2 `PolicyWatcher` (ReadDirectoryChangesW / FileSystemWatcher on `policy.json`) + `PolicyStore` persisting `lastChecked` into the same file after every reload, with no suppression of self-generated writes and no content-hash short-circuit before writing. Confidence: **high** (the log shows the cycle explicitly, with the write 2 ms before each new change event).

**Fix suggestions:** do not write when the policy is unchanged; keep `lastChecked` out of the watched file (separate state file or registry); ignore change events caused by the process's own writes (compare hash / mtime, or pause the watcher around writes); add a debounce and a rate guard with a Warning if reloads exceed N/min. Also drop these three lines to Verbose-not-shipped or sample them, so a future loop cannot flood AI.

**Links:** SUP-1196, SUP-1201. Ruled out: SCU-103 (memory growth after 3 days; here CPU, < 1 h uptime, memory normal).

---

## SCU-NEW-4 — Hardening: a Rust panic inside `textclassifier.dll` aborts the whole service and leaves the filter fail-open

**Title:** No panic boundary at the `tokenizers_encode` FFI: any panic in `textclassifier.dll` becomes a fail-fast of ScudioFilter.exe and ~20 s of unfiltered traffic

**Type / Priority:** Bug / **Medium** — not customer-visible once SCU-NEW-2 is fixed, but it is the reason a single bad string became a safety incident; the next tokenizer or model bug will do the same.

**Affected:** 3.4.2 (and any version shipping the Rust `textclassifier.dll` with `panic=abort`), all OS, all devices. Reports: SUP-1190 (indirectly).

**Summary:** The crash stack in the DEV-2208 dump shows `tokenizers_encode` → … → `panic_fmt` → `__rust_start_panic::abort` → `int 29h`. The DLL is built with `panic = "abort"`, and the C ABI entry point does not catch panics, so a recoverable per-page error terminates a process that is supposed to be a security control. The watchdog then needs 15–21 s to bring the filter back, and the driver fails open in the meantime (36/38/48 connections per event).

**Steps to reproduce:** any input that panics the tokenizer (SCU-NEW-2 gives one); observe the whole service exit rather than a classification error.

**Expected behaviour:** Panics are caught at the FFI boundary (`std::panic::catch_unwind` with `panic = "unwind"`, or an explicit `Result` return), logged as an Error with the URL, and the pipeline applies the configured failure policy for that one page. Separately, the product should decide explicitly whether the driver should fail open or fail closed while the service is restarting, and that decision should be a policy setting visible to the customer (a school will want fail-closed).

**Actual behaviour:** Whole-process abort; fail-open window; crash dump; no Error-level log line before death.

**Evidence:** `crash_dumps/DEV-2208_ScudioFilter_20261014_081310_analyze.txt` STACK_TEXT frames 0–9; `logs/DEV-2208.csv` lines `Watchdog: … restart #N at …` vs `HttpFilter started` (17–21 s later) and `Driver reports N connections passed unfiltered while service was down (fail-open)`.

**Probable cause:** Build profile `panic = "abort"` plus an `extern "C"` wrapper without `catch_unwind`. Confidence: high for the mechanism (visible in the stack), medium for the build flag specifics.

**Links:** SCU-NEW-2 (trigger), SUP-1190.

---

## Checked and ruled out

| Observation | Where | Verdict |
| --- | --- | --- |
| `DNS lookup slow host=… ms=…` (sev 2) | all four devices, 49–270 lines each, evenly spread over the day, every popular host | SCU-106 "Won't fix", cosmetic. Not correlated with any report time window. |
| `SSL bypass applied host=online.bank.example reason=pinned_certificate` (sev 2) | all four devices (343 lines total), single host | Expected behaviour for certificate pinning; present before and after every incident; unrelated. Worth lowering to Information to reduce noise. |
| SCU-101 (meta-charset pages pass through) | DEV-2208 | Not what happened: charset was known for every `Classify start` and the failure is a crash, not a silent pass-through. Linked as related area. |
| SCU-103 (memory +200 MB after 3 days) | DEV-3390/3391 | Reports say memory normal; uptime < 1 day; symptom is CPU. Not a match. |
| SCU-104 (installer hangs at 90 %) | DEV-4471 | `Installer: install completed version=3.4.2` logged normally. |
| SCU-105 (Android banner) | SUP-1182 | Different platform and opposite symptom. |
| Severity ≥ 3 lines | all devices | None at all. All three defects, including a 15 h total block and a crash, live at severity 0–2: this is an observability gap in itself (see suggestions in SCU-NEW-1 and SCU-NEW-3). |
| Image classifier | all devices | Only the two "Image model loaded" lines per start; nothing abnormal. |
