# KQL — find every affected device

All queries run against the Application Insights `traces` table. Column mapping from the CSV
export: `appVersion` → `application_Version`, `customDimensions` is dynamic (`customDimensions.OS`,
`customDimensions.Component`), device = `cloud_RoleInstance`. Severity: 0 Verbose … 4 Critical.

**Caveat:** several of the signatures below are Verbose (severity 0) lines. If the SDK samples or
filters Verbose in production, Q2b/Q2c/Q3 under-count; Q1, Q2, Q3b and Q4 rely on
Information/Warning lines only and are the ones to alert on.

---

## Q1 — SCU-NEW-1: devices blocking with `license_inactive` *after* the server said `orgLicense=Active`

```kusto
let lookback = 30d;
// first moment each device learnt the licence is Active
let knownActive = traces
| where timestamp > ago(lookback)
| where message startswith "Policy fetch OK" and message has "orgLicense=Active"
| summarize firstActive = min(timestamp) by cloud_RoleInstance;
traces
| where timestamp > ago(lookback)
| where message startswith "Connection blocked" and message has "reason=license_inactive"
| join kind=inner knownActive on cloud_RoleInstance
| where timestamp > firstActive
| summarize blocked = count(),
            firstSeen = min(timestamp),
            lastSeen  = max(timestamp),
            hoursBlocked = round(datetime_diff('minute', max(timestamp), min(timestamp)) / 60.0, 2),
            versions = make_set(application_Version),
            os = any(tostring(customDimensions.OS))
    by cloud_RoleInstance
| order by hoursBlocked desc
```

### Q1b — at-risk signature (fresh installs that started with no licence data), with whether they self-healed

```kusto
let lookback = 30d;
traces
| where timestamp > ago(lookback)
| where message startswith "LicenseCache: loaded status=Unknown"
| summarize unknownStarts = count(), firstSeen = min(timestamp), lastSeen = max(timestamp),
            versions = make_set(application_Version), os = any(tostring(customDimensions.OS))
    by cloud_RoleInstance
| join kind=leftouter (
    traces
    | where timestamp > ago(lookback)
    | where message startswith "Block page served" and message has "page=subscription_inactive"
    | summarize blockPages = count(), lastBlockPage = max(timestamp) by cloud_RoleInstance
  ) on cloud_RoleInstance
| project-away cloud_RoleInstance1
| order by blockPages desc
```

---

## Q2 — SCU-NEW-2: devices with the fail-fast crash (0xC0000409), with fail-open exposure

```kusto
let lookback = 30d;
traces
| where timestamp > ago(lookback)
| where message startswith "Service starting (previous exit code 0xC0000409)"
     or message startswith "Crash dump written"
| summarize crashes = countif(message startswith "Service starting"),
            dumps   = countif(message startswith "Crash dump written"),
            firstSeen = min(timestamp), lastSeen = max(timestamp),
            versions = make_set(application_Version), os = any(tostring(customDimensions.OS))
    by cloud_RoleInstance
| join kind=leftouter (
    traces
    | where timestamp > ago(lookback)
    | where message startswith "Driver reports" and message has "passed unfiltered"
    | parse message with "Driver reports " unfiltered:long " connections passed unfiltered" *
    | summarize unfilteredConnections = sum(unfiltered) by cloud_RoleInstance
  ) on cloud_RoleInstance
| project-away cloud_RoleInstance1
| order by crashes desc
```

### Q2b — what was being classified right before each crash (confirms the trigger fleet-wide)

```kusto
let lookback = 30d;
traces
| where timestamp > ago(lookback)
| where message startswith "Classify start"
     or message startswith "Service starting (previous exit code 0xC0000409)"
| order by cloud_RoleInstance asc, timestamp asc
| extend prevMsg = prev(message), prevTs = prev(timestamp), prevDev = prev(cloud_RoleInstance)
| where message startswith "Service starting" and prevDev == cloud_RoleInstance
      and datetime_diff('second', timestamp, prevTs) < 120
| parse prevMsg with "Classify start url=" url " charset=" charset " bytes=" bytes:long
| extend host = tostring(parse_url(url).Host)
| summarize crashes = count(), firstSeen = min(timestamp), lastSeen = max(timestamp),
            charsets = make_set(charset), hosts = make_set(host), minBytes = min(bytes)
    by cloud_RoleInstance, application_Version
| order by crashes desc
```

### Q2c — exposure: devices that truncate text at all (candidates for the next crash)

```kusto
let lookback = 30d;
traces
| where timestamp > ago(lookback)
| where message startswith "Text preprocess: converted to UTF-8, truncating"
| summarize truncations = count(), firstSeen = min(timestamp), lastSeen = max(timestamp)
    by cloud_RoleInstance, application_Version
| order by truncations desc
```

---

## Q3 — SCU-NEW-3: devices in the policy reload loop

A legitimate policy change happens a handful of times per day. Anything above ~10 reloads in a
minute, sustained, is the loop. The query also reports how long it has been going on and whether
it is still active.

```kusto
let lookback = 30d;
let threshold = 10;           // reloads per minute
traces
| where timestamp > ago(lookback)
| where message == "PolicyWatcher: policy.json changed, reloading"
| summarize reloads = count() by cloud_RoleInstance, application_Version, minute = bin(timestamp, 1m)
| where reloads >= threshold
| summarize loopMinutes = count(),
            reloadsInLoop = sum(reloads),
            peakPerMinute = max(reloads),
            firstSeen = min(minute),
            lastSeen = max(minute) + 1m,
            stillActive = max(minute) > ago(10m)
    by cloud_RoleInstance, application_Version
| order by reloadsInLoop desc
```

### Q3b — same thing without relying on Verbose rows: telemetry volume per device and version

```kusto
let lookback = 30d;
traces
| where timestamp > ago(lookback)
| where message startswith "Telemetry batch sent"
| parse message with "Telemetry batch sent rows=" rows:long
| summarize rowsPerHour = sum(rows) / max_of(1.0, datetime_diff('minute', max(timestamp), min(timestamp)) / 60.0),
            firstSeen = min(timestamp), lastSeen = max(timestamp)
    by cloud_RoleInstance, application_Version
| order by cloud_RoleInstance asc, application_Version asc
// compare 3.4.1 vs 3.4.2 rows/hour per device; a 10x+ jump on 3.4.2 flags the loop
```

### Q3c — rollout view: share of 3.4.2 devices that are looping

```kusto
let lookback = 7d;
let devices342 = traces
| where timestamp > ago(lookback) and application_Version == "3.4.2"
| summarize by cloud_RoleInstance;
let looping = traces
| where timestamp > ago(lookback)
| where message == "PolicyWatcher: policy.json changed, reloading"
| summarize reloads = count() by cloud_RoleInstance, bin(timestamp, 1m)
| where reloads >= 10
| summarize by cloud_RoleInstance;
devices342
| join kind=leftouter (looping | extend isLooping = true) on cloud_RoleInstance
| summarize total342 = count(), looping = countif(isLooping == true)
| extend pct = round(100.0 * looping / total342, 1)
```

---

## Q4 — general health: every abnormal service exit, by exit code and version

Useful as a standing alert; would have caught SCU-NEW-2 on day one.

```kusto
let lookback = 30d;
traces
| where timestamp > ago(lookback)
| where message startswith "Service starting (previous exit code"
| parse message with "Service starting (previous exit code " exitCode ")"
| where exitCode != "0x0"
| summarize restarts = count(), firstSeen = min(timestamp), lastSeen = max(timestamp),
            devices = dcount(cloud_RoleInstance), sampleDevices = make_set(cloud_RoleInstance, 10)
    by exitCode, application_Version, os = tostring(customDimensions.OS)
| order by restarts desc
```
