# Validation record

This file records executed checks rather than treating configured CI as a
successful run. Fixture tests do not validate a real mail server.

## Current MVP verification — 4.1.1, 2026-11-04

Baseline: merged PR #9, `7970f0910c89c30d01b43cca32f779b33cc37166`.
The current audit and acceptance boundary are in [mvp.ru.md](mvp.ru.md).
The sections below this one retain the historical verification record.

| Environment | Final full suite | Result |
|---|---|---|
| Ubuntu 22.04, stock Python **3.10.12**, dnsutils | `python3 -m unittest discover -s tests` | **281 tests passed**, no skips; **23.030 s** |
| Python **3.9.25**, dnsutils | `python -m unittest discover -s tests` | **281 tests passed**, no skips; **61.989 s** |

Both disposable Docker containers ran under WSL Ubuntu with `--network none`,
`--read-only`, a read-only checkout and a private executable `/tmp` tmpfs.
Host commands were replaced by fake executables/runners. Real `dig` used only
the ephemeral loopback DNS fixture. No public resolver, DNSBL or live mail
service was contacted.

Additional completed checks:

* Ruff 0.14.10: `ruff check --no-cache mailradar tests` passed.
* ShellCheck 0.8.0: all three Bash entrypoints passed. Each also passed its own
  `bash -n`: `mail-radar`, `miab-radar`, `install.sh`.
* The full suite includes **28 actual CLI executions** of the **14 menu
  workflows**, once through the source launcher and once through a staged
  installed launcher, from an unrelated working directory. Current queue
  records, mailbox UID/folder, JSON/NDJSON termination, log scope and metadata
  field restrictions are asserted. This is a fake-host acceptance test.
* **13 installer tests** cover upgrades, bytecode collisions, unrelated cwd,
  spaces, source preflight, startup isolation, symlinks and failed-install
  preservation. Existing PTY session and signal/rotation tests remain enabled.
* All three new redaction acceptance cases failed against the unmodified model
  before the fix and passed after it. New contract tests cover preflight-before-
  Runner/stdin, invalid offsets/extreme dates, expired-only sender evidence,
  bounded suffix allocation, invalid command JSON/metadata, sensitive map paths,
  retained mailbox conclusions and oversized watch termination.
* `python3 tests/render_task_examples.py` regenerated the anonymized task
  previews with fake host commands and loopback DNS, networking disabled.
* Final `git diff --check` passed.

Live MIAB validation, real service metadata formats from the owner's host,
public DNSBL reachability, external INBOX/restore and production deployment were
not performed. GitHub CI execution is recorded separately after completion;
the workflow definition alone is not a passing-run claim.

## Historical verification — initial 4.0.0

The initial 4.0.0 checked implementation is
`d3775f7cf3acb85779d2d04b6463a8ec8bb197e0` (code, tests, installer and CI;
current history after the owner-author attribution correction).
The subsequent documentation commit does not change those tested files.

## Executed in the development environment

* Static review of baseline `d1add36326b537bc414859e681e3128fb643b515`
  before executing any legacy diagnostic code. The old script was not run.
  The original repository contained no tests or CI, so there is no baseline
  passing-suite claim.
* WSL Ubuntu, Python 3.14: `bash -n install.sh` passed after normalizing its
  line endings to LF. Git Bash was not used as the Linux validation substitute.
* WSL Ubuntu, Python 3.14:
  `python3 -m unittest discover -s tests -p test_install.py -v` passed **7 tests**.
  The tests staged installation under temporary directories; they verified
  source discovery from a different cwd, spaces in paths, installed package
  loading, both launcher contracts, executable modes, refusal of symlink
  destinations, invalid prefix, missing source and refusal to import a malicious
  package from cwd/PYTHONPATH (marker stayed absent). No mail service or network
  was called.
* WSL Ubuntu, Python 3.14:
  `python3 -m unittest discover -s tests -p test_core.py -v` passed **14 tests**
  independently after the review fixes. They cover denied modifying actions,
  fake PATH overrides/MIAB-wrapper marker, descendant cleanup, output caps,
  C1 sanitization, the report-size fallback, private reports, redaction map keys,
  targeted Dovecot metadata and CLI/offline/time boundaries.
* WSL Ubuntu: the documented offline example was executed against the synthetic
  `examples/mail.log`; `examples/output.txt` contains its actual output. Exit 1
  is expected because six fixture lines do not establish full hourly coverage.

## Independent final-review probes

Two synthetic in-memory probes initially reproduced a best-effort 8 MiB report
limit leaving a 12,012,414-byte nested-details
report and retention of U+009B C1 CSI by terminal sanitization. Review also found
wildcard Dovecot user scope and identity-bearing statistic-map keys omitted from
redaction. Five core/launcher and three host findings were corrected in the
working diff with regression tests; see the second-pass audit table. These
probes are not live-host tests.

## Linux compatibility checks actually run

The final complete suite passed **119 tests** in each isolated container:

| Image | Runtime | Result |
|---|---|---|
| `python:3.9-slim-bookworm` | Python **3.9.25** | 119 passed; 12.200 s |
| Local `mail-radar-test:ubuntu22.04` | Ubuntu 22.04 stock Python **3.10.12** | 119 passed; 7.446 s |

The checkout was mounted read-only, networking was disabled and temporary
storage was private to each disposable container. An initial attempt used a
noexec `/tmp` and four fake-executable tests could not run; it was an environment
configuration error. Rerunning with an executable temporary filesystem passed.
Earlier runs passed 94 cases before additional review regressions were added;
the table above records the final executed suite rather than an inferred count.

An additional minimal Ubuntu 22.04 `--doctor --json` smoke run, without mail
utilities/services and with networking disabled, produced a valid partial
report with exit 1, `active_probes=[]` and no traceback. It establishes graceful
degradation in that environment, not live-server diagnostic accuracy.

Reproducible equivalent commands from the checkout root on Linux:

```bash
# Optional developer-only image build; this preparation downloads OS packages.
docker build -t mail-radar-test:ubuntu22.04 -f tests/Dockerfile.ubuntu22 .

docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,exec,nosuid,size=256m \
  --mount "type=bind,source=$PWD,target=/workspace,readonly" \
  --workdir /workspace -e PYTHONDONTWRITEBYTECODE=1 \
  python:3.9-slim-bookworm python -m unittest discover -s tests -v

docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,exec,nosuid,size=256m \
  --mount "type=bind,source=$PWD,target=/workspace,readonly" \
  --workdir /workspace -e PYTHONDONTWRITEBYTECODE=1 \
  mail-radar-test:ubuntu22.04 python3 -m unittest discover -s tests -v
```

The local Ubuntu image contains stock Python 3.10 and ShellCheck, prepared for
testing rather than installed on a production server. In that image, with no
network and a read-only checkout, **ShellCheck 0.8.0 passed** for `mail-radar`,
`miab-radar`, `install.sh`; individual `bash -n` checks also passed. Equivalent
commands inside that image are:

```bash
for script in mail-radar miab-radar install.sh; do bash -n "$script" || exit; done
shellcheck mail-radar miab-radar install.sh
```

On Windows the above Docker commands were invoked via WSL Ubuntu as root to
access its local Docker daemon. Earlier focused WSL runs used Python 3.14;
they supplement the actual Python 3.9/Ubuntu 22.04 compatibility runs.

## GitHub Actions actually verified

On 2026-11-03, the completed [Linux validation run 41473540443](https://github.com/Anton-Babaskin/mail-radar/actions/runs/41473540443)
was checked for PR #2 at head
`8261697bb762d573b6ff12ef30d7a7b75528668b`. Both Ubuntu 22.04 matrix jobs
completed successfully, including Bash syntax, ShellCheck and the full suite:

| Job | Logged result |
|---|---|
| [Python 3.9](https://github.com/Anton-Babaskin/mail-radar/actions/runs/41473540443/job/125373045075) | 119 tests passed; 6.716 s |
| [Python 3.10](https://github.com/Anton-Babaskin/mail-radar/actions/runs/41473540443/job/125373045464) | 119 tests passed; 7.931 s |

The run itself completed on 2026-11-02; the date above records when its
conclusions and test-count logs were verified. The subsequent validation-record
update changes documentation only. These CI jobs use fixtures and fake commands;
they do not establish live mail-server correctness.

That is the historical head recorded by Actions, not a current-history SHA.
The attribution-only rewrite replaced it with
`ef63c49f7ad6e254f7ca3eeebc0d3b94b64c1fcd`; its Git tree is identical.
The tested code commit formerly named `07d4d88` is now `d3775f7` (also the same
tree). Historical Actions metadata is preserved here rather than relabeled as
a run against a different SHA.

## Deliberately not claimed

No test here establishes delivery to an external INBOX, validates production
service configuration, completes a backup/restore, reboots a route, exercises
public DNSBLs/banks, sends mail or tests a real open relay. Real-world deployment
and mail-stack-specific integration validation remain administrator work after
review. No release or deployment is part of this change.

## 4.0.1 MIAB re-audit (2026-11-03)

Base: `4aae39fbdb3e7e2101ef4fd183e2273014e4b084`.
Checked implementation: `7847c0cf518e196670a944a310dd5bd4d6903678`.
The old 119-case baseline passed before repairs; the production-shaped cases
below were missing from that suite. The supplied server transcript was read,
not committed or replayed against real external systems.

| Executed environment | Complete suite result |
|---|---|
| Linux container, Python 3.9.25 | **158 passed**, 12.775 s |
| Ubuntu 22.04 container, stock Python 3.10.12 | **158 passed**, 8.287 s |

Both containers used the same read-only checkout, `--network none`, an
executable private tmpfs, and `PYTHONDONTWRITEBYTECODE=1`, as in the reproducible
commands above. ShellCheck 0.8.0 and individual Bash syntax checks passed again
for the installer and both launchers. No mail daemon or public DNSBL was run.

The suite now includes `tests/test_miab_audit.py` (24 cases): actual Bash launcher
through a real PTY, two successive interactive runs, bad input and Ctrl+C,
trace/header/network menu choices, a linked whole-MIAB fake-command profile,
actual submission/LMTP/Sieve shapes, recent-tail truncation provenance,
server-local/epoch Dovecot scope, null/multiple headers, exact Message-ID,
50-record boundary, independent failed-service behavior, default/runtime
Postgrey configuration reads, unique mounts, XZ/LZMA memory bounds, strict
numeric fields, operator-error privacy, journal templates/context, compact
terminal output, and report-output failure ordering.

`examples/output.txt` and `examples/miab-output.txt` were regenerated by running
the documented offline fixtures. Both return 0 in the observed complete-source
scope. The earlier 4.0.0 exit 1 caused solely by generic LOG-COVERAGE no longer
applies: this evidence boundary is N/A, while real missing/truncated inputs
remain UNKNOWN. External delivery and historical completeness are not inferred.

See `docs/miab-audit-2026-11-03.ru.md` for the source-confirmed findings, corrected
semantics and residual limits. Direct execution of 4.0.1 on the owner's live
MIAB is still not claimed by these isolated checks.

GitHub Actions was also verified for PR #7 at
`59fff645d288af124161710ead9dbc99d38ed806`:
[run41626003559](https://github.com/Anton-Babaskin/mail-radar/actions/runs/41626003559)
completed successfully on both Python3.9 and3.10, with **158 tests per job**,
Bash syntax and ShellCheck. A subsequent cleanup only removes a trailing blank
line and records this result; no diagnostic behavior changes.

## Remaining-review follow-up (2026-11-03)

The expanded suite executed **169 tests without skips** on Ubuntu 22.04 /
Python 3.10.12 (9.822 s) and on Python 3.9.25 (15.698 s). Both containers used
`--network none`, a read-only checkout and private executable `/tmp` tmpfs.
The Ubuntu development Dockerfile now installs dnsutils and Ruff 0.14.10;
the Python 3.9 image was built from `python:3.9-slim-bookworm` with dnsutils.
Final local checks after the bounded-static-rule refinement also passed:
169 tests on Python 3.10 (9.223 s), 169 on Python 3.9 (13.572 s), Ruff, ShellCheck
and Bash syntax for all three scripts. A subsequent review also ensures
master.cf restriction-class declarations are reported as indirect coverage;
final-head CI results are recorded separately below.

Two cases run real `dig`, actual Runner subprocess handling and parse_dns
against a stdlib UDP DNS fixture bound only to 127.0.0.1 at an ephemeral port.
This includes the complete doctor/network analysis path and JSON CLI output,
both DNSBL operational-control pairs, multiple A replies, NXDOMAIN, NODATA
and SERVFAIL. All other host commands are stubbed. No public DNSBL/DQS query,
real TLS service, mail daemon or remote resolver is involved. The Runner port
option remains numeric (1..65535), read-only and subject to --network.
CI explicitly installs dnsutils and executes `dig -v`, so these integration
cases cannot silently disappear for lack of that binary in the configured jobs.

Ruff 0.14.10 `check --no-cache mailradar tests` passed with E9/F selected for
Python 3.9. Six unused imports were removed. Reproduce the Ubuntu checks with
the Docker build/run commands above, using `ruff check --no-cache` in the
read-only mount. The only pip requirement is development tooling.

The additional `test_review_followup.py` cases cover domain/IP typing, DQS
return-code semantics/privacy, malformed/oversized reply filters, HELO/DATA
and master overrides, postscreen weights/threshold/action/allowlisting,
indirect-coverage uncertainty, and the extra policy/header/remote-reply
grammars without invented deliveries. Live MIAB validation remains unclaimed.

GitHub Actions [run 41629045110](https://github.com/Anton-Babaskin/mail-radar/actions/runs/41629045110)
completed successfully for code head `93d69f440f6458c206b2496d42c4893939d2533e`:

| Ubuntu 22.04 job | Observed result |
|---|---|
| [Python 3.9](https://github.com/Anton-Babaskin/mail-radar/actions/runs/41629045110/job/125893613667) | 169 tests passed, 10.105 s; Ruff, ShellCheck and Bash syntax passed |
| [Python 3.10](https://github.com/Anton-Babaskin/mail-radar/actions/runs/41629045110/job/125893613388) | 169 tests passed, 9.325 s; Ruff, ShellCheck and Bash syntax passed |

Both logs report dnsutils `DiG 9.18.39-0ubuntu0.22.04.7-Ubuntu`; neither test
suite skipped the real-dig integration cases. This subsequent documentation
commit only records that completed run and does not change the tested code.

## 4.0.2 runtime follow-up (2026-11-03)

Base: `99c7663c25d64560f3a3da65ad42866e3a70ebea` (merged PR #7, version 4.0.1).
Both runs in the newly supplied private transcript show version 4.0.0. The
follow-up does not treat that older output as execution of the current base.
The base's 169 tests also passed locally before the new repairs (Ubuntu 22.04,
Python 3.10.12, 8.409 s).

| Final local environment | Observed complete-suite result |
|---|---|
| Ubuntu 22.04 container, Python 3.10.12 | **220 passed**, 10.138 s; no skips |
| Python 3.9.25 container with dnsutils | **220 passed**, 16.763 s; no skips |

Both executions used the read-only checkout, `--network none`, a private
executable tmpfs and `PYTHONDONTWRITEBYTECODE=1`. The actual Bash launchers and
staged installed commands execute with their isolated `-I` bootstrap.
Ruff 0.14.10, ShellCheck 0.8.0 and Bash syntax for both launchers and installer
passed. Both anonymized examples were regenerated by the actual offline CLI.

The additional regressions cover delivery/summary severity including a failure
after twenty traces, standalone Dovecot Saved without invented Queue ID,
stdin/journal/watch collection flags, real PTY Ctrl+C after watch, expiry tails
and case-sensitive identifiers, policy address/family/UNIX sockets, real Jammy
unit shapes and SysV startup metadata, same-size/same-timestamp bytecode upgrade,
incremental deep scan including symlink replacement/cycles, and POSIX pipe
deadline/output bounds. The two existing real-dig cases still use loopback DNS;
no public resolver, real mail service or production installation was exercised.

See [runtime audit](runtime-audit-2026-11-03.ru.md) for MR-U001–013, primary sources
and remaining boundaries. The deliberately detached fake process is cleaned by
its test: process-group termination is not a cgroup/security sandbox. A deep
scan's deadline is checked between filesystem operations and cannot interrupt
an individual blocked kernel syscall. Live MIAB verification remains unclaimed.

## 4.1.0 task-focused reports (2026-11-04)

Base: `179dc2b4e8d6aef92de4af0e2dc629ea598c980f` (merged PR #8, version 4.0.2).
The reported menu 6/9 behavior was confirmed in that base: both routed to
doctor; a historical Queue ID count appeared alongside the current snapshot,
and unrelated security/backup findings displaced the selected task's facts.

| Final local environment | Observed result |
|---|---|
| Ubuntu 22.04, stock Python 3.10.12 | **265 tests passed**, 15.480 s, no skips |
| Python 3.9.25 with dnsutils | **265 tests passed**, 29.421 s, no skips |

Ruff 0.14.10 and ShellCheck 0.8.0 passed. Containers used `--network none`,
a read-only checkout and private executable tmpfs. The additional live-dig case
uses the existing ephemeral loopback DNS fixture with all other host commands
stubbed; it performs the actual --dns collector path without public queries.

New regression groups: all fourteen menu choices and direct CLI/menu parity,
selected collector dispatch/absence of unrelated commands, current queue total
versus history and filtered matching, queue priority before retention, text
fallback reasons, structured quota/account no-fetch behavior, successful DNS/TLS
facts and mailbox fields in default display, inline-value safety/omission labels,
and contextual parsing without losing pre-window correlation. Existing log,
read-only, signal, process, installer, report and scope regressions still pass.
Changed older display assertions now check concrete IDs/addresses/stage/delay
and readable sections instead of the superseded short generic summary.

The generator `python3 tests/render_task_examples.py` executed successfully.
It writes anonymized previews in examples/, with fake host/Dovecot commands and
loopback-only DNS. The example with an empty current snapshot and sixteen
historical lifecycles is computed through the real analysis/renderer pipeline.
Only the examples directory was writable in that generator's container.

See [task report contract](task-reports.ru.md). Raw-read limits and unknown
timestamps still imply missing evidence; skipped old grammar is explicitly
counted as unparsed_context. There was no production MIAB execution, package
deployment, service/configuration/queue change or public DNSBL query.
