# Changelog

## 4.1.2 — unreleased

* Add grouped interactive menus, colored status badges, section/field highlights
  and readable live-watch progress, preserving numeric choices and text labels.
* Enable the fixed ANSI palette only for terminal human output. Respect
  --no-color, nonempty NO_COLOR and TERM=dumb; keep pipes/files/JSON/NDJSON plain.
* Apply trusted styles after sanitization and line wrapping; keep the report
  schema and diagnostic commands unchanged. No runtime dependency was added.

## 4.1.1 — unreleased

* Use one workflow catalogue for CLI/menu/source requirements; require a local
  user for mailbox/account/header tasks and reject empty selectors or ignored
  filters before reading sources or invoking commands.
* Preserve trace links, conclusion references, metadata schema keys and quoted
  addresses consistently through redaction.
* Validate a declared runtime and internal imports before installation; isolate
  Python preflight from caller startup code and explain incomplete installations.
* Bound recent-line allocation, retain expired-only envelope senders, reject
  invalid UTC offsets, and turn malformed/deep command JSON into UNKNOWN.
* Exclude sensitive resolved whitelist indexes and handle symlink cycles; retain
  watch stream metadata when the report hits its size limit.
* Add executable acceptance of all 14 workflows through source and staged
  launchers, regression probes, and a current MVP audit with explicit limits.

## 4.1.0 — unreleased

* Give queue, DNS, account, incoming, outgoing and delay tasks their own CLI/menu
  workflows and relevant collectors; retain the full doctor/post-update audit.
* Replace the generic terminal dump with task sections: current queue entries
  and per-recipient causes, separate history/address/domain groups, message paths,
  visible DNS/TLS results and targets, structured quota and mailbox metadata.
* Apply queue filters/priority before retention, preserve text-fallback sender,
  recipients and reasons, and avoid treating normal active volume as failure.
* Separate known out-of-window parse failures from selected-window coverage;
  preserve pre-window evidence and explicit read/time/access limitations.
* Add menu-to-collector integration, renderer and scope regressions plus generated
  anonymized previews. Output and collection limits are shown separately.

## 4.0.2 — unreleased

* Explain how to update an existing checkout, preserve local changes and
  reinstall the separate global command. Include the running version in help.
* Remove bytecode only for installed module names after updates and reject
  symlinked cache paths, so equal-size source changes with colliding timestamps
  cannot silently load the previous compiled version.
* Aggregate delivery conclusions into summary severity and exit status, retain
  all conclusions in JSON and prioritize later failures in compact output.
  Display standalone Dovecot Saved without a fictitious queue or delivery attempt.
* Preserve source/check incompleteness for bounded stdin, journal and watch;
  restore the caller's signal handlers after watch/session operations.
* Keep expiry/notification/removal in the same queue lifecycle; preserve exact
  Queue ID and Message-ID case while retaining domain-filter semantics.
* Refine local policy-listener address-family matching, actual Postfix service
  instance state and literal Postgrey discovery from SysV startup scripts.
* Bound deep-scan directory enumeration incrementally; use nonblocking POSIX
  subprocess pipes so a held pipe does not leave reader threads past timeout.
* Add synthetic runtime and staged-upgrade regressions and an anonymized audit
  separating the supplied 4.0.0 transcript from findings on the newer baseline.

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
`docs/mvp.ru.md` for the current audit, acceptance scope and evidence limits.
