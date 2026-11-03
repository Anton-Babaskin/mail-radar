# MailRadar

Local, evidence-based delivery diagnostics for Mail-in-a-Box and compatible
Postfix/Dovecot hosts. One command collects the available facts, correlates mail
logs and explains where delivery evidence ends. No cloud account or AI is needed.

MailRadar continues the existing **miab-radar** project. `miab-radar` remains a
compatible command; no second repository or separate Mail Doctor is required.

## Быстрый старт

Целевая среда — MIAB на Ubuntu 22.04; базовая диагностика также рассчитана на
обычные Postfix/Dovecot в Debian/Ubuntu. Нужны Bash и Python **3.9+** без pip.
Mailcow/iRedMail не объявляются полностью поддержанными без отдельных адаптеров.

```bash
git clone https://github.com/Anton-Babaskin/mail-radar.git
cd mail-radar
bash ./mail-radar --help
sudo bash ./mail-radar
```

В интерактивном терминале запуск без аргументов открывает сессию меню: после
отчёта Enter возвращает к выбору, `0` завершает работу. В меню доступны также
поиск по идентификатору и выбранные заголовки. `--menu` включает такую сессию
явно, например вместе с `--log`/`--offline`. В cron/pipe вопросы не задаются. Обычный обзор читает доступные
состояние служб, Postfix, очередь и логи, собирает факты в общем временном окне
и показывает статусы с evidence и следующими действиями. Без root доступна
частичная диагностика; недоступные проверки отмечаются UNKNOWN. Обычный
терминальный отчёт краткий; `--details` раскрывает проверки и строки
доказательств, `--json` сохраняет машинный контракт без меню.

Четыре обычных сценария администратора:

```bash
# Не пришло письмо: Message-ID заранее знать не требуется.
sudo bash ./mail-radar --diagnose --from sender@example.org --to office@example.com --hours 24

# Клиент SMTP попал под greylisting/whitelist после обновления.
sudo bash ./mail-radar --whitelist --client-name mx.partner.example --client-ip 203.0.113.10

# Найти сохранённое письмо и текущую папку, не извлекая тело.
sudo bash ./mail-radar --headers '<message.1@example.org>' --user office@example.com

# Разобрать собранные логи на другом компьютере без системных команд и сети.
bash ./mail-radar --trace sender.example --offline --log ./examples/mail.log --since '2026-11-02T09:00:00Z' --until '2026-11-02T10:00:00Z'
```

Для общего обзора без меню используйте `--doctor`. Старые `miab-radar 48` и
`mail-radar 48` означают обычный обзор последних 48 часов.

## Installation

Review the checkout, then install its own files only:

```bash
sudo bash ./install.sh
mail-radar --help
sudo mail-radar --doctor
```

Default destinations are `/usr/local/bin/mail-radar`,
`/usr/local/bin/miab-radar`, and `/usr/local/lib/mail-radar/mailradar/`.
The installer locates sources relative to itself, independent of the current
working directory. It never installs packages, downloads code or changes services.
Existing regular MailRadar files are updated; symlink destinations are refused.
Use a trusted checkout and installation prefix.

An isolated staged install needs no root:

```bash
DESTDIR="$PWD/stage" PREFIX=/usr/local bash ./install.sh
"$PWD/stage/usr/local/bin/mail-radar" --version
```

`PREFIX` must be absolute; `DESTDIR` must be empty or absolute. Run the installer
again from a reviewed checkout to update the package and both launchers together.
There is no runtime dependency on the Git checkout or on sibling projects.

## Workflows and filters

| Mode | Purpose |
|---|---|
| `--doctor` | Fast state snapshot: services, queue, configuration, disks and log evidence |
| `--diagnose` | Targeted delivery investigation with available host and mailbox facts |
| `--trace VALUE` | Correlated queues/events matching a literal Message-ID, queue ID, address, domain or IP |
| `--flow` | Shared-window message/queue/recipient-event and failure statistics |
| `--greylist` | Postgrey reject/pass/retry evidence and triplet boundaries |
| `--whitelist` | Postfix maps, order/overrides, Postgrey file and client match |
| `--watch` | Bounded observation of new log data; `--json` emits NDJSON |
| `--headers MESSAGE_ID` | Selected Date/Received/Message-ID and Dovecot metadata; requires `--user` |
| `--mailboxes` | Targeted account/quota/metadata for `--user`; `--deep` adds physical inspection |
| `--post-update` | Services, Postfix state, whitelist wiring, resolver and backup-tooling signals |

`--from`, `--to`, `--domain`, `--ip`, `--client-name`, `--client-ip` and `--user`
represent different entities. Client whitelist does not authorize a From address.
`--peer IP` adds runtime OS-route evidence; a route is not proof of persistence.
`--deep` requires a specific user/recipient and does not scan every mailbox.

Use `--hours N` or `--since`/`--until` ISO 8601 timestamps. Offsets and `Z` are
honoured. For historical syslog without a year, pass `--year` and `--timezone`
(an IANA zone such as `Europe/Istanbul` or `UTC`). Ambiguous/skipped wall-clock
times require an explicit offset. The report lists source and parsing limits.

`--log PATH` is repeatable and supports plain files, gzip, bzip2 and xz; `--log -`
reads stdin. Without explicit paths, local `mail.log*`/`maillog*` are discovered. Automatic
plain-file scans retain a bounded recent suffix first, with negative line
numbers counting from EOF. Omitted prefixes are explicitly incomplete context;
this is not proof of a fully covered interval. Explicit `--log` scans retain
the caller's forward-source contract.
`--journal` adds newest-first bounded journal collection (including Debian
`postfix@*.service` instances and 24 hours of pre-window context). `--offline` requires explicit logs
and prohibits journal/network commands. `--max-bytes` and `--max-lines` bound
input; hitting a limit marks results incomplete instead of implying no errors.
Compressed input files are limited to 128 MiB each; LZMA decoder dictionary
memory is limited to 64 MiB. A rejected archive is reported as UNKNOWN.

Common anchored Postfix/Postgrey/Dovecot log formats are recognized; unsupported
delivery grammar marks coverage incomplete. Yearless syslog is interpreted as
the newest calendar occurrence not later than `--until`; multi-year archives
need explicit-year timestamps (`--year` supplies a single year). Reinjection is
linked only by explicit same-host evidence with a unique target within 300
seconds. `observed_messages` counts inferred linked groups and can overcount
when hops are missing.

```bash
sudo mail-radar --watch --from sender@example.org --to office@example.com --seconds 180 --log /var/log/mail.log --json
sudo mail-radar --post-update --json
sudo mail-radar --diagnose --to office@example.com --hours 24 --json --report /root/incident-new.json
```

Watch starts at the current end of plain log files and handles observed rotation
and truncation. Rotation races can lose events; gaps are reported and a final
trace over retained logs is recommended. It is not a lossless log collector.

## Active network probes

Local analysis is the default. Explicit `--network` permits bounded DNS, TLS and
local management-endpoint probes, which appear in `active_probes` in the report:

```bash
sudo mail-radar --doctor --network --domain example.com --ip 203.0.113.10 --dkim-selector mail
```

No SMTP AUTH, test message, OTP request or real relay delivery is performed.
A known DKIM selector is used rather than guessing several names and declaring
DKIM absent. Local success does not establish external firewall/provider access.
DNS failures and DNSBL service/error replies remain distinct from a valid clean
or listed result; IP reputation and domain reputation are separate.

## Findings, JSON and exit codes

Human output is Russian, with technical evidence preserved. It is always free
of ANSI controls; `--no-color` is accepted. JSON keys and finding IDs do not
change with human language. `--json` writes one JSON document; watch writes one
valid JSON object per NDJSON line, including start/end/service events.

Reports contain `schema_version`, tool/mode/window/filters, sources,
`completeness`, findings/evidence, statistics/traces and summary. A finding has
an ID, status, title, evidence, next step and details; source/time context is
included where available. Schema version `1.0` is Radar's contract, not automatic
FleetOps compatibility: see [the explicit mapping](docs/integrations.md).

| Status | Meaning |
|---|---|
| OK | Available evidence confirms this individual check |
| WARN | A confirmed condition deserves review |
| FAIL | A confirmed failure requires attention |
| UNKNOWN | Evidence, permissions, tool support or completeness is insufficient |
| N/A | The method does not apply, e.g. CIDR lookup for a domain |

| Exit | Meaning |
|---:|---|
| 0 | No FAIL/WARN/UNKNOWN or incomplete mandatory result in the observed scope |
| 1 | Warning, UNKNOWN or incomplete diagnostics |
| 2 | FAIL findings; also invalid CLI usage (with argument error) |
| 3 | Runtime/output-file error |
| 130 | Interrupted; result is incomplete |

An empty match set does not prove successful delivery. Remote SMTP 250 proves
next-hop acceptance, not the final INBOX. Dovecot Saved proves storage at that
point, not the current folder or the cause of a later move.

## Privacy and read-only boundary

Diagnosis does not change mail configuration, holds, packages, routes, messages,
IMAP flags or queues. No restart/reload, postmap rebuild, postsuper, apt upgrade,
netplan apply or reboot is part of diagnosis. MIAB setup/update wrappers are
never run for version/help detection. `postmap -q` is a read-only lookup.
Dovecot metadata reads may refresh service indexes.

`--report NEW_PATH` creates a private file (0600), refusing existing files and
symlinks. Reports never intentionally include message bodies, attachments or
credential files. They still contain operational identifiers and log evidence.
`--redact` consistently aliases addresses/IPs/domains within one export; review
paths, Queue IDs, Message-IDs and free text before sharing. It is not guaranteed
anonymization. No report is sent to Telegram, email or another service.

Routine blocked relay attempts and successful Fail2Ban bans are observations,
not server-failure findings in a general overview. A matching pre-queue reject
in a targeted investigation remains WARN. The general external-evidence boundary
is N/A; missing or truncated required input still produces UNKNOWN/exit 1.
This changes the previous 4.0.0 behavior where every log report was UNKNOWN.

See [the MIAB production-shape audit](docs/miab-audit-2026-11-03.ru.md) for
regressions discovered after the initial release and the reviewed overlap with
PRs #5/#6.

## Development and evidence

```bash
python3 -m pip install -r requirements-dev.txt
ruff check mailradar tests
python3 -m unittest discover -s tests -v
for script in mail-radar miab-radar install.sh; do bash -n "$script"; done
shellcheck mail-radar miab-radar install.sh
```

Tests use synthetic fixtures and fake host commands. Two integration cases run
the real `dig` against an ephemeral loopback DNS server; install `dnsutils` to
run them locally (CI installs it and checks `dig -v`). No public DNSBL or live
mail server is contacted. Ruff is a development dependency only.
Linux CI covers Python 3.9 and 3.10 on Ubuntu 22.04. A Windows or
Git Bash run alone does not establish Linux support. Actual validation results,
including checks not run, belong in [validation.md](docs/validation.md).

Read [the source audit and preservation table](docs/code-audit.ru.md),
[architecture decision](docs/adr/0001-diagnostics-architecture.md),
[anonymized operational context](docs/engineering-context.ru.md) and
[project boundaries](docs/integrations.md), with
[primary-source semantics](docs/reference-semantics.md). Broader security auditing,
physical-mailbox inventory, relay configuration and fleet orchestration remain
with their existing owner projects. Optional sibling tools are not downloaded
or executed automatically during diagnosis.

## License

MIT — see [LICENSE](LICENSE). Author: Anton Babaskin.
