# Повторный аудит после первого запуска на MIAB

База: `4aae39fbdb3e7e2101ef4fd183e2273014e4b084`, MailRadar 4.0.0.
Проверенная исправленная реализация: `7847c0cf518e196670a944a310dd5bd4d6903678`.
Повод — переданный владельцем вывод запуска на MIAB/Ubuntu 22.04. В этом
отрывке нет Python traceback: меню запускается и заканчивает обзор. Это не
означает, что рабочий сценарий реализован качественно: вывод был перегружен
JSON, общий лимит закончился на 150000 строках, часть штатных наблюдений
получила тревожный статус, реальные варианты почтовых событий терялись.

Исходный присланный вывод содержит эксплуатационные адреса и не добавлен в
репозиторий. `tests/fixtures/logs/miab-production-shapes.log` — синтетическая
фикстура тех же структур, только `.example` и документационные IP. Настоящий
сервер, письма, службы и настройки в процессе разработки не менялись.

## Что проверено

Повторно прочитаны сборщик, runner/allowlist, все грамматики логов, временные
окна/корреляция, CLI/menu/watch, Dovecot adapter, JSON/redaction/report files,
launchers/installer, тесты, README и открытые PR. Исходные 119 Linux-тестов
на базе прошли: они не покрывали ряд нужных production-shaped случаев и
пользовательский путь после первой задачи в настоящем терминале.

P1 — диагностическая корректность, данные или ресурсные границы; P2 —
эксплуатационная пригодность и представление. Это приоритеты исправления,
а не заявление о воспроизведённой эксплуатации уязвимости.

| ID | Приоритет | Место / подтверждение | Исправление и регрессия |
|---|---|---|---|
| MR-M001 | P1 | `logs.PROGRAM/_parse_event`: MIAB `postfix/submission/smtpd`, client port/sasl_sender, NOQUEUE reasons с `;`, quoted local parts, journal offsets на Python 3.9/3.10. По исходнику и synthetic cases; часть уже предложена в PR #6. | Структурные поля, однозначные Queue ID, bounded parsing, timestamp groups; `test_logs` и `test_miab_audit.test_miab_submission_and_actual_lmtp_saved_form_are_recognized`. Неизвестная грамматика остаётся неполной. |
| MR-M002 | P1 | `logs._parse_dovecot/_parse_event`: LMTP `250 2.0.0 <user> SESSION Saved` не совпадал с regex без SESSION; Sieve `stored mail into mailbox` не распознавался. Подтверждено Dovecot 2.3.16 source и fixture. | Отдельно поддержаны session reply и собственная Sieve-строка; произвольное слово Saved в диагностике не доказывает сохранение. `test_miab_audit.test_miab_submission_and_actual_lmtp_saved_form_are_recognized` и старый adversarial Saved test. |
| MR-M003 | P1 | `cli.default_logs/logs.analyze_logs`: numeric rotations сортировались лексикографически; forward cap мог сохранить старый префикс вместо последних событий. В присланном выводе лимит150000 действительно исчерпан, а краткая причина не показана. | Автоматические plain sources читаются bounded suffix first; номера строк с конца отрицательные. Префикс/контекст явно неполон, compressed sources остаются bounded forward. Причина и конкретный источник видны. `test_bounded_automatic_scan_keeps_recent_suffix_and_reports_missing_context`, `test_rotation_priority_does_not_put_date_archives_before_current`. |
| MR-M004 | P2 | `cli.human/menu/main`: raw JSON как человекочитаемый вывод; повторные df mounts; меню завершало процесс после одной задачи, trace/headers были только CLI; ошибки ввода/сигнал не проверялись через PTY. Воспроизведено форматом исходного отчёта и UI-тестами. | `display.py`, --details, --menu, возврат после отчёта, trace/headers/network choices, короткие ошибки и отмена. `InteractiveMenuTests` запускает настоящий Bash launcher через PTY; `test_compact_terminal_output_keeps_json_machine_only`, `test_duplicate_df_mount_is_reported_once`. |
| MR-M005 | P1 | `checks.service_checks/security_checks`, `logs` findings: отдельный inactive spamassassin при active spampd, успешные Fail2Ban bans и background relay denials выглядели как неисправность. Все встречаются в переданном профиле или его семантике. Generic LOG-COVERAGE всегда делал любой отчёт UNKNOWN. | MIAB spampd и disabled optional units отделены от failed/required services; bans и background refusals — наблюдения, targeted refusal остаётся WARN. Внешняя граница — N/A, реальные missing/truncated inputs — UNKNOWN. `test_miab_spampd_does_not_require_spamassassin_daemon`, `test_failed_optional_service_is_not_hidden_as_disabled`, `test_background_relay_rejection_is_not_a_server_failure`, whole-profile test. |
| MR-M006 | P1 | `checks.postgrey_whitelist_checks`: defaults объявлялись неизвестными только из-за отсутствия --whitelist-clients в unit argv. Возможны переменные unit и реальные process options. По исходнику и присланному выводу. | MainPID/cmdline читаются ограниченно; default paths признаются только при подтверждении литералами установленного Perl source. Ничего не source/exec; без подтверждения остаётся UNKNOWN. `test_installed_postgrey_defaults_confirm_real_paths_without_execution`, `test_runtime_postgrey_options_override_unit_placeholders`. |
| MR-M007 | P1 | `mailstore`: date-only query в timezone администратора/UTC вместо сервера, лишний день на midnight, substring HEADER match, ровно50 записей считались усечением, null/multiple headers. Установлено по коду и Dovecot fetch source. | Запрос по server-local dates, точное UTC окно по received epoch, exact Message-ID post-filter, различие50/более50, безопасные null/Received folds. Кандидат без epoch остаётся UNKNOWN. `test_dovecot_exact_message_id_time_scope_and_50_records_are_not_false_truncation`, `test_dovecot_null_headers_and_multiline_received_do_not_crash`, `test_core.StoreTests`. |
| MR-M008 | P1 | DNSBL служебные ответы сводились к generic UNKNOWN без причины и влияния на Postfix. Проверен PR #5 и соответствующие upstream contracts. | Named operator errors, controls и статический анализ reply filters. Описание не обещает отказ всей почте: другие permits/chains могут не довести клиента до RBL. `test_checks` DNSBL error/filter/controls regressions. Ни одного реального запроса DNSBL в тестах. |
| MR-M009 | P1 | Выходной byte cap не ограничивал LZMA dictionary; слишком длинный numeric field мог вызвать int conversion error/Inf; redaction alias numbering имело квадратичную сложность, DQS key в log text проходил общий sanitizer. По исходнику; tiny high-dictionary header и numeric fixture воспроизведены безопасно. | 64MiB decoder memory, 128MiB compressed source input, bounded numeric grammar, finite JSON, O(1) alias counters, общий DQS scrub. `test_lzma_dictionary_memory_is_bounded_and_concatenated_xz_works`, `test_huge_numeric_log_fields_remain_unknown_instead_of_crashing`, `test_finite_json_and_dnsbl_secret_sanitization`, `test_nonfinite_runtime_metadata_is_unknown_not_an_exception`. |
| MR-M010 | P2 | `cli._run_once/write_private`: успех печатался до ошибки записи --report. `--journal` не включал Debian instance unit и под output cap мог сохранить старые данные. По исходнику. | Проверка существующего output до сбора, запись до финального вывода; journal reverse capture, template unit и24h context, затем восстановление source order. `test_existing_report_fails_before_claiming_success`, `test_journal_uses_instance_units_newest_first_and_pre_window_context`, прежние watch NDJSON/signal tests. |

## Проверенные внешние изменения

В единую ветку перенесены и повторно проверены исходники/регрессии из:

* PR #5, head `ca119a4b2790fc6e4b36eed74ca425980d50dfbe`: DNSBL errors/filters.
* PR #6, head `7cf8aa6de98e1e007bcab470efe0e356bdfdf401`: structured log fields.

Это не автоматический merge соседних веток. Документация/статусы и новые
исправления согласованы с общим workflow; новая ветка имеет base main и не
требует цепочки этих двух PR. Их ветки/обсуждения не удалялись.

## Сохранение поведения и изменение статусов

Сохраняются все CLI modes, typed literal filters, numeric hours, оба launcher,
JSON schema1.0, NDJSON watch, report permissions, read-only allowlist и явный
--network. Добавлены поля completeness.log_sources_complete/checks_complete,
--details/--menu и component display/timeutil; runtime dependencies не добавлены.

Целенаправленные изменения: generic external-boundary finding LOG-COVERAGE
теперь N/A вместо безусловного UNKNOWN. Это не доказательство полного окна:
window_coverage_proven по-прежнему false; missing/unparsed/truncated required
data дают UNKNOWN. Background NOQUEUE и работающие bans не объявляются сбоем;
фильтрованный отказ конкретному отправителю/получателю остаётся WARN. Причины
deferred/hold видны рядом с очередью, а не только внутри JSON details.

## Повторная проверка и оставшиеся границы

Новые tests используют только fake runner и обезличенные сообщения. PTY tests
исполняют настоящий launcher, но включают --offline; ни почтовые службы, ни
реальные DNSBL/банки не запускаются. Результаты полного matrix run записаны
в `docs/validation.md`. Пустой/обрезанный отчёт не выдаётся за успешную доставку.

Полнота утраченных логов, старый context за suffix cap, произвольные vendor
formats, сложные Postgrey regex/restriction classes, полный Sieve/alias/account
workflow, backup success без artifact и route persistence остаются явными
границами. Обновлённый код ещё не проверен прямым запуском на сервере владельца.
Не объявляется, что синтетическая MIAB-фикстура заменяет такую проверку.

## Первичные источники

* [Dovecot2.3.16 LMTP source](https://github.com/dovecot/core/blob/2.3.16/src/lmtp/lmtp-local.c): session_id + Saved.
* [Dovecot2.3.16 fetch source](https://github.com/dovecot/core/blob/2.3.16/src/doveadm/doveadm-mail-fetch.c): selected headers, newline-joined repeated headers, received/saved epochs.
* [Postgrey upstream source](https://github.com/schweikert/postgrey/blob/master/postgrey): defaults and hostname whitelist matching. Runtime path confidence is checked against the installed script, not inferred from this URL alone.
* [Spamhaus DNSBL usage](https://www.spamhaus.org/faqs/dnsbl-usage/) and [Postfix access](https://www.postfix.org/access.5.html): reply/error semantics; previous versioned source references remain in reference-semantics.md.
