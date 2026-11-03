# Related projects and contract boundaries

Reviewed on 2026-11-02. The canonical [project map](https://github.com/Anton-Babaskin/Anton-Babaskin/blob/main/PROJECTS.md)
still uses historical `miab-radar` and `miab-whitelists` links. The actual
whitelist source for this work is `postfix-postgrey-whitelist`, not
`miab-whitelists-old`. Documentation claims are not a read-only audit.

| Project and reviewed material | Owner responsibility | MailRadar boundary / reuse |
|---|---|---|
| [mail_analyzer.sh](https://github.com/Anton-Babaskin/mail_analyzer.sh/blob/main/readme.md) | Postfix statistics, archived logs, export | Preserve top senders/recipients and failure statistics in the shared event model; do not bundle the entire analyzer. |
| [mailtop](https://github.com/Anton-Babaskin/mailtop/blob/main/mailtop.sh) v2.0.0 | Physical storage and account reconciliation | Reuse the distinction between allocated storage, account state and IMAP quota; broad inventory remains mailtop's job. |
| [MailHunt](https://github.com/Anton-Babaskin/MailHunt/blob/main/mailhunt.sh) v1.2.0 | Dovecot metadata search | Reuse bounded `doveadm fetch` and selected fields; no bodies or attachments, no full script dependency. |
| [postfix-postgrey-whitelist](https://github.com/Anton-Babaskin/postfix-postgrey-whitelist/blob/main/add_whitelists.sh) v2.5 | Change and synchronize allowlists | Diagnose actual hash/CIDR/Postgrey matches and wiring. Suggested repair is an administrator decision; no automatic setup/add/sync. |
| [mail-sec-audit](https://github.com/Anton-Babaskin/mail-sec-audit/blob/main/README.md) | Broad mail-server security posture | Keep Radar's useful focused security signals. Do not execute the audit as a dependency; see the separately confirmed wrapper finding. |
| [smtp-egress-audit](https://github.com/Anton-Babaskin/smtp-egress-audit/blob/main/README.md) | Process attribution of outbound SMTP | Link next investigation there when appropriate; Radar does not create a packet-capture/process monitor. |
| [postfix-relay-rescue](https://github.com/Anton-Babaskin/postfix-relay-rescue/blob/main/README.md) | Relay changes, DBL incident runbook and rollback | Inspect selected transport/relay facts only; no credentials or configuration changes. |
| [FleetOps](https://github.com/Anton-Babaskin/FleetOps/blob/main/fleetops/domain/models.py) | Fleet orchestration, SSH collection and external contract | Keep a versioned local result suitable for a future adapter; no SSH inventory or runtime dependency. |
| [miab-sentry](https://github.com/Anton-Babaskin/miab-sentry/blob/main/README.md) | MailOps control plane, confirmed actions and audit | No Telegram, maintenance workflow or database in Radar. |
| [Postfix-Telegram-Notifier](https://github.com/Anton-Babaskin/Postfix-Telegram-Notifier/blob/main/README.md), [postgrey-telegram-notify](https://github.com/Anton-Babaskin/postgrey-telegram-notify/blob/main/README.md) | Notifications | No third notifier and no automatic publication of reports. |

## FleetOps is an explicit adapter boundary

The inspected FleetOps tree was `46b2efc10d163b8d82a886dce732295fbd0ef7ae`.
`fleetops/domain/models.py` (blob `bf8b5a0f70691fcc4b87cd1599694446d8adf340`)
defines schema `1.0` with `extra="forbid"`. Its `HealthResult` requires
`host{id,hostname}`, `collected_at`, `duration_ms`, `overall_status`, `checks`.
Its `CheckResult` requires `name`, `status`, `summary`, `duration_ms` and supports
`metrics`, `reason`, `error`, `timed_out`, `raw_ref`. Radar's source/evidence,
incident timeline and completeness objects are not those models.

| Radar status | Future FleetOps status | Required preservation |
|---|---|---|
| OK | `ok` | Summary, metrics and evidence reference |
| WARN | `warning` | Reason and next step |
| FAIL | `critical` | Reason and supporting evidence |
| UNKNOWN | `unknown` | Missing evidence/error/timeout and completeness |
| N/A | `unknown` | Explicit `reason="not_applicable"`; never silently map to healthy |

A future adapter must construct the exact required fields, use stable finding
ID as check name, preserve evidence in metrics or a private artifact referenced
by `raw_ref`, and calculate durations from actual measurements. It must not
invent host identity or durations. Radar's `schema_version` is independent:
equal version strings would not establish compatibility. No FleetOps adapter
or changes to FleetOps are claimed by this PR.

## Source reuse

No complete sibling script or third-party source file is copied into Radar.
The package uses Python's standard library and independently implements the
shared workflow. Existing Radar checks and operational semantics above are
retained or corrected; the behavior table in the audit documents each change.
Future copied code must preserve its license and provenance.
