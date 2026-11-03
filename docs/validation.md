# Validation record

This file records executed checks rather than treating configured CI as a
successful run. Fixture tests do not validate a real mail server.
The final checked implementation is
`07d4d88578cc8c515a65efa91502615b6a762466` (code, tests, installer and CI).
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

## DNSBL return codes (2026-11-03)

Executed in WSL Ubuntu on the `fix/dnsbl-return-codes` branch:

* `python -m unittest discover -s tests` passed **126 tests** with Python 3.9.24,
  3.10.19 and 3.14.4 (119 before, 7 added). `bash -n` and ShellCheck 0.8.0 and
  0.11.0 passed for `mail-radar`, `miab-radar`, `install.sh`.
* A stdlib script sent raw UDP DNS queries for the documented Spamhaus test
  names only (`2.0.0.127.zen`, `1.0.0.127.zen`, `test.dbl`, `dbltest.com.dbl`,
  `example.com.dbl`) and classified the real answers with `dnsbl_state`:

  | Resolver | ZEN controls | DBL positive / negative |
  |---|---|---|
  | WSL system resolver (Windows/ISP path) | `127.255.255.254` on both → `public_resolver_blocked` | `127.0.1.2` / NXDOMAIN → listed / not_listed |
  | 8.8.8.8 | NXDOMAIN on both → positive control fails | NXDOMAIN on both → positive control fails |
  | 1.1.1.1 | `127.255.255.254` on both | `127.255.255.254` on all three |
  | 9.9.9.9 | `127.255.255.254` on both | `test.dbl` `.254`, `dbltest.com` `127.0.1.2`, negative NXDOMAIN |

  Answers depend on the resolver, the zone and the moment; they are not
  reproducible test data. `dig` was not installed and Docker was not available
  to this user, so the real `dig`/Runner path was not exercised in this run;
  it is unchanged and covered by the fake-runner suite.

## Structured log parsing (2026-11-03)

Executed in WSL Ubuntu on the `fix/structured-log-parsing` branch:

* Before the change, a probe fed one line per case to `analyze_logs` on `main`
  with Python 3.9.24, 3.10.19 and 3.14.4. These lines were lost or marked the
  source incomplete on every version: warning/fatal lines (taken as Queue IDs),
  RBL reject with `;` in the reason, quoted local parts with `>` in `to=`,
  `orig_to=` and `from=`, `client=…:port`, `sasl_sender=`, pickup, bounce
  notification, `lost connection`, `reject_warning`. MIAB
  `postfix/submission/smtpd` lines were dropped silently with `complete=True`.
  journald `+0300` and nanosecond timestamps failed on 3.9 and 3.10 only.
  After the change every case parses on all three versions; the injected
  `nrcpt=9` inside a quoted sender does not replace the real `nrcpt=1`.
* `python -m unittest discover -s tests` passed **134 tests** on each of the
  three versions (8 added). The 15 tests added in both stages fail when run
  against the `main` code. ShellCheck 0.8.0/0.11.0 and `bash -n` passed.
* The documented offline example gives exit 1 on `main` and on the branch;
  `examples/output.txt` differs only by the new `reject_warnings` and
  `daemon_warnings` statistics, which were regenerated.

No real mail.log from a production server was available; the line shapes come
from Postfix sources, MIAB's `setup/mail-postfix.sh` and synthetic fixtures.

## Deliberately not claimed

No test here establishes delivery to an external INBOX, validates production
service configuration, completes a backup/restore, reboots a route, exercises
public DNSBLs/banks, sends mail or tests a real open relay. The one-off DNS probe
above queried only Spamhaus' documented test names, outside the test suite, and
does not show how a production host's resolver is treated. Real-world deployment
and mail-stack-specific integration validation remain administrator work after
review. No release or deployment is part of this change.
