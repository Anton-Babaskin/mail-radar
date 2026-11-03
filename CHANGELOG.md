# Changelog

## 4.0.1 — unreleased

* Fix production MIAB submission, Dovecot LMTP session/Sieve formats and
  older-Python journal/CLI timestamps; preserve quoted-field trust boundaries.
* Add compact terminal presentation, --details, --menu, repeatable interactive
  sessions, trace/header choices, input recovery and clean cancellation.
* Prioritize recent default log input under bounds and explain precise source
  failures; preserve explicit-log analysis and acknowledge missing context.
* Avoid false daemon/ban/relay-denial alarms, deduplicate filesystems, resolve
  Postgrey defaults from the installed script/runtime argv without executing it.
* Fix Dovecot exact Message-ID/time filtering and null/multiple headers; prevent
  false 50-record truncation, success-before-report-error, non-finite values,
  oversized log integers and unbounded LZMA dictionaries.
* Consolidate reviewed parser and DNSBL changes from PRs #5/#6, including named
  operator failures and static Postfix reply-filter inspection.
* Add production-shaped synthetic fixtures and real-PTY session regressions.
* Inspect Spamhaus DQS error filters, HELO/DATA restriction chains, postscreen
  weights/threshold/action/allowlist and master overrides; mark indirect access
  map/class coverage unknown. Reject IP literals passed as --domain.
* Recognize prequeue FILTER/HOLD/DISCARD requests, cleanup header warnings and
  standalone SMTP replies without inventing delivery or exposing header text.
* Add pinned Ruff checks and actual dnsutils loopback integration to CI; repair
  audit commit references after the attribution-only history rewrite.

## 4.0.0 — unreleased

* Continue miab-radar as MailRadar in the same project, with `mail-radar` and a
  compatible `miab-radar` launcher and numeric-hours syntax.
* Introduce a shared Python-standard-library workflow for menu/CLI, bounded
  log ingestion, timestamp handling, event correlation, evidence and JSON.
* Add targeted delivery, trace, greylist/whitelist, watch, mailbox metadata and
  post-update modes. Explicit network probes remain separate from local checks.
* Separate UNKNOWN and N/A from verified results; expose source completeness,
  command errors and limits. Distinguish internal hops, next-hop acceptance and
  stored-message evidence.
* Correct missing installer source paths, awk-dependent timestamps, mixed log
  periods, failed-command-as-empty interpretations and recipient-only relay
  checks. Remove credential-file reads and generated Python source from network
  data; replace unconditional deep mailbox scans with targeted opt-in inspection.
* Add staged installation, private create-once reports, redaction with stated
  limits, fake-runner/fixture regression tests and Ubuntu 22.04 CI for Python
  3.9/3.10.
* Record initial source findings, behavior preservation, architecture, sibling
  project boundaries and anonymized incident context under `docs/`.

This entry describes the working change. It is not a release or deployment
announcement. Consult `docs/validation.md` for actually executed checks and
`docs/code-audit.ru.md` for remaining findings and evidence limits.
