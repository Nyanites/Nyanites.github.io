# Log-based detection — CVE-2026-109618 / 109619

The network rules flag *attempts*; logs flag the *consequences*. Because the
exploit is a memory-corruption race, the loudest, highest-fidelity signal is
**PHP workers crashing**. These queries are vendor-neutral patterns — adapt
field names to your SIEM.

## 1. Worker segfaults (highest fidelity)

A clean server almost never segfaults PHP workers. A spike is a strong
exploitation indicator.

**mod_php (Apache error_log):**
```
grep -E "child pid [0-9]+ exit signal Segmentation fault \(11\)" /var/log/apache2/error.log
```

**PHP-FPM (fpm error log):**
```
grep -E "child [0-9]+ (exited on signal 11|SIGSEGV)" /var/log/php*-fpm.log
```

**Splunk / SIEM pattern:**
```
index=web ("exit signal Segmentation fault" OR "exited on signal 11")
| bin _time span=1m | stats count by host, _time
| where count > 3
```
Alert threshold: tune to your baseline (most hosts baseline at 0).

## 2. session.upload_progress abuse (109619 trigger path)

Correlate access logs for bursts of multipart POSTs to endpoints that accept
uploads, especially many short/aborted ones from one source (grooming pattern):
```
index=web method=POST uri_path=*upload* status=200
| stats count, dc(cs_bytes) as body_sizes by src_ip
| where count > 50
```
If your app does not legitimately use upload-progress, **any** traffic carrying
`PHP_SESSION_UPLOAD_PROGRESS` is worth surfacing.

## 3. Out-of-memory fatals (109618 trigger path)

109618 is reached by forcing an out-of-memory condition while PHP decodes the
request (malformed/undeclared multipart length, header floods, empty file
controls, deeply nested field names). A burst of memory-exhaustion fatals is
the log-side symptom of that grooming:
```
grep -E "Allowed memory size of [0-9]+ bytes exhausted" /var/log/php_errors.log \
  | awk '{print $1, $2}' | uniq -c | sort -rn
```
```
index=web "Allowed memory size of" "bytes exhausted"
| timechart span=1m count | where count > 10
```
Pair this with the network rules for the same source (SIDs 1026002,
1026004-1026008) to separate an attack from an app that is merely busy. Note
that `memory_limit=-1` (an advisory mitigation) suppresses these fatals, so on
mitigated hosts lean on the segfault signal in section 1 instead.

## 4. Fatal-error backtrace storm (PHP 8.5 path)

On 8.5 the `fatal_error_backtraces` path is the one with confirmed RCE.
Deliberately inducing fatals to reach it shows up as a spike in E_ERROR /
fatal backtrace lines:
```
index=web ("PHP Fatal error" OR "Stack trace:") sourcetype=php_error
| timechart span=1m count | where count > 20
```

## 5. Correlation rule (ties it together)

The strongest alert combines an *attempt* signal with a *crash* signal from the
same host within a short window:
```
(upload_progress_burst OR oom_fatal_burst)  AND  worker_segfault
  by host  within 5m
```
That pairing is very unlikely to be benign and is your page-worthy alert.

## Mitigation-verification signals

After applying mitigations, confirm they took effect in the logs/config:
- `php -i | grep -E "session.upload_progress.enabled|fatal_error_backtraces"`
- Segfault count returns to baseline (0) after patch + worker restart.
- `php -v` reports a fixed build (see `scan_fleet.py`).
