# Changelog

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
* Name Spamhaus error replies (`127.255.255.252/254/255`, DBL `127.0.1.255`)
  instead of a generic service response, run the operational controls for them
  and report a refused query path as `DNSBL.CONTROL.*` WARN with the fix.
* Add `DNSBL.POSTFIX_FILTER`: Postfix RBL restrictions for public Spamhaus
  zones without a reply filter, or with one that admits error codes, would turn
  those replies into rejections.

This entry describes the working change. It is not a release or deployment
announcement. Consult `docs/validation.md` for actually executed checks and
`docs/code-audit.ru.md` for remaining findings and evidence limits.
