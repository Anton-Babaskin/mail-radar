# MVP MailRadar 4.1.1: результат аудита

Проверена база `7970f0910c89c30d01b43cca32f779b33cc37166` после merge #9.
Дата проверки: 2026-11-04. Это аудит исходников, fixtures, реальных launchers и
staged installation в Linux. Доступа к рабочему MIAB владельца не было.
Слияние PR, выпуск релиза и развёртывание сюда не входят.

## Что считается работающим MVP

Один запуск выбранной задачи показывает конкретный объект проверки, доступные
факты, источник и границу вывода. Общий обзор сохраняет все прежние полезные
проверки; целевые задачи показывают относящиеся к ним разделы. CLI и 14 пунктов
меню используют общий каталог сценариев. Подробный контракт и примеры вывода —
в [task-reports.ru.md](task-reports.ru.md).

| Задача | Результат и проверяемая граница |
|---|---|
| Текущая очередь | ID, queue state, возраст, размер, envelope sender, recipients и причина каждого получателя; пустая очередь сейчас отделена от сообщений в истории. |
| Входящее / исходящее / задержка / поиск | Время, instance/lifecycle, Queue ID, Message-ID, адреса, relay, SMTP/DSN, попытки и итог по получателям. SMTP 250 не объявляется внешним INBOX. |
| Greylisting / whitelist | Triplet и повторы; active wiring карт, backend, совпадения и порядок policy services; домен SMTP-клиента отделён от From. |
| DNS / TLS | Явные цели: выбранный DNS-домен и собственный MIAB для resolver/relay/TLS. Активные пробы требуют `--network`; внешний сервер автоматически не сканируется. |
| Аккаунт / папки / заголовки | Обязательный один `--user`; quota roots/resources/used/limit/percent; папка, UID, Message-ID, received/saved и flags. Тело/Subject не запрашиваются. Кандидаты без точного Message-ID не выдаются за найденное нужное письмо. |
| Watch | Ограниченные regular-file источники, NDJSON progress/report/finished, явные пробелы при ротации, усечении, лимитах и сигналах. |
| JSON / приватный экспорт | Стабильные finding ID и schema 1.0, согласованные ссылки после redaction, 0600/create-once, ограничения объёма и отсутствие управляющих последовательностей. |
| Установка / обновление | Исходный и установленный launchers, независимость от cwd/PYTHONPATH, проверка runtime до замены файлов, очистка только собственного bytecode. |

Фильтры относятся к конкретному источнику: `--from/--to/--domain/--ip` фильтруют
историю; домен/IP также служат целями DNS. Для whitelist нужны
`--client-name/--client-ip`; для ящика — `--user`, Message-ID и период.
Неприменимый фильтр отклоняется до запуска диагностики. Если к mailbox/account
явно добавлен `--log`, envelope-фильтры относятся только к этому логу, а не к
заголовку From в хранилище. `--to` и обязательный `--user` должны совпадать.

## Подтверждённые дефекты и исправления

Приоритеты: P1 — достоверность/приватность/установка, P2 — отдельные сценарии и
отказоустойчивость. Ни один пункт ниже не основан только на старом выводе 4.0.2.

| ID | Дефект на проверяемой базе | Исправление и регрессия |
|---|---|---|
| MVP-01 / P1 | Redaction оставляла исходный trace.id, но заменяла домен в link.target/conclusion.trace_id; ссылки переставали разрешаться. Также менялись schema keys `date.*.unixtime`. | Общий alias-проход для ссылок, сохранение finding ID и metadata keys; `test_mvp_model.MVPExportTests`. До исправления все три новых export-теста падали. |
| MVP-02 / P1 | Quoted local part с пробелом обезличивался частично. | Адрес целиком заменяется одним alias; динамические ключи статистики согласованы с ним; тот же export-набор. Redaction по-прежнему не гарантирует анонимность. |
| MVP-03 / P1 | `--mailboxes --json` без пользователя мог завершиться OK/N/A, а часть фильтров отображалась, но не применялась к источнику. | Обязательный user scope, явные ошибки несовместимых фильтров, общий каталог CLI/menu/source requirements; `test_mvp_contracts` и 28 запусков `test_mvp_launchers`. |
| MVP-04 / P2 | Пустые `--trace ''` / `--headers ''` выбирали doctor. | Пустой selector — usage error до Runner/stdin; `test_invalid_requests_fail_before_runner_or_stdin_reads`. |
| MVP-05 / P2 | Watch отклонял journal/stdin слишком поздно и не исключал `.lzma`. | Валидация до чтения stdin и запуска journalctl; тот же regression test. |
| MVP-06 / P1 | Неполная копия runtime могла заменить рабочую установку и сломать lazy imports. Произвольные scratch-модули также копировались. | Явный `runtime-files.txt`, проверка синтаксиса/внутренних импортов без выполнения модулей до записи, понятная startup error; два новых staged-install теста. Проверяются missing, syntax и undeclared dependency. |
| MVP-07 / P1 | Python version preflight установщика допускал загрузку пользовательского sitecustomize из PYTHONPATH. | `python3 -I` для обеих Python-проверок; `test_installer_python_ignores_caller_sitecustomize`, marker не создаётся. |
| MVP-08 / P2 | datetime мог нормализовать некорректный UTC offset, незаметно сдвинув окно; выход за календарные границы мог давать traceback. | Компоненты offset проверяются явно, крайние даты дают понятную ошибку; `test_invalid_offsets_do_not_silently_shift_the_requested_window` и preflight regression. |
| MVP-09 / P2 | Строка qmgr expired без предыдущего from-события теряла sender и не находилась через `--from`. | Сохраняется структурный envelope sender; `test_expired_only_log_keeps_sender_for_typed_filter`. |
| MVP-10 / P2 | Recent-log reader сначала разбивал весь byte buffer на строки, даже при `--max-lines 2`. | Обратный поиск LF с выделением только нужного suffix; `test_recent_line_cap_does_not_allocate_all_old_lines` проверяет peak allocation на 250000 строках. |
| MVP-11 / P2 | Глубоко вложенный JSON от postqueue/doveadm вызывал RecursionError; неверные типы metadata могли доходить до renderer. | UNKNOWN вместо traceback, ограниченный контракт типов; `test_recursive_command_json_becomes_unknown_instead_of_traceback` и mailbox regressions. |
| MVP-12 / P1 | Проверка whitelist не исключала credential-like resolved path скомпилированного index; цикл symlink мог оборвать сценарий. | Проверяется и source, и фактический index: `.db` для hash/btree, `.lmdb` и `.cdb`; запрет postmap для такого пути, UNKNOWN для цикла; `test_sensitive_index_and_symlink_cycle_never_trigger_postmap`, восемь backend/cycle cases. На дополнительном проходе LMDB/CDB cases сначала воспроизвели обход, затем прошли после расширения защиты. |
| MVP-13 / P2 | Fallback при отчёте >8 MiB удалял watch metadata; завершение NDJSON затем падало. | Сохраняются небольшие workflow/scope/targets/watch metadata, данные явно помечаются неполными; `test_oversized_watch_finishes_ndjson_with_explicit_incompleteness`. |

## Область просмотра кода

| Файлы | Проверено; решение |
|---|---|
| `mail-radar`, `miab-radar`, `install.sh` | Изоляция Python, version/help, совместимость, cwd, manifest, staged upgrade, symlinks и bytecode. Сохранены Bash launchers, добавлен runtime preflight. |
| `cli.py`, `workflows.py` | Все маршруты меню/CLI, валидация до side effects, выбор источников, сигналы, watch и export. Каталог заменил дублируемые списки сценариев; сборщик/renderer остаются раздельными. |
| `logs.py`, `timeutil.py` | Trust boundaries Postfix/Dovecot, очередь/lifecycle/instance, окна/offsets, архивы/ротация/лимиты, фильтры, статистика. Сохранён структурный parser, исправлены два граничных случая и выделение строк. |
| `checks.py` | Службы, queue JSON/text, whitelist/relay/policy, DNSBL/postscreen, DNS/TLS, disk, SSH, held duplicity/update/backup/route. Сохранены проверки и finding IDs; усилены обработки ошибок и credential exclusions. |
| `mailstore.py` | Один user, точный Message-ID, quota, эпохи/даты, whitelist полей, bounded descriptor-relative deep scan. Metadata reads могут обновлять Dovecot indexes. |
| `model.py`, `runner.py` | JSON contract, ссылки/обезличивание, sanitization, лимиты, приватные файлы; разрешены только диагностические argv, shell=False, timeout/process-group cleanup. Набор metadata fields теперь общий для fetch/allowlist/redaction. |
| `display.py` | Очередь, история, DNS, quota/mailbox, timestamps, пропуски и bounds выводятся по задачам. Сохраняется renderer 4.1.0 с его 12 semantic tests; переписывать его повторно оснований нет. |
| `tests/`, `.github/workflows/`, документация | Полная Linux matrix, настоящие source/staged launchers, PTY, loopback dig, fixtures, примеры и аудит. Runtime по-прежнему stdlib без pip. |

Полная перепись parser/runner ухудшила бы проверяемость без исправления отдельной
подтверждённой причины. Сохранены работающие модули; переписаны контракты
сценариев, redaction и предустановочная проверка. Историческая таблица сохранения
старых проверок — [code-audit.ru.md](code-audit.ru.md); архитектура —
[ADR 0001](adr/0001-diagnostics-architecture.md).

## Оставшиеся ограничения

* Работа новой версии на настоящем MIAB ещё не подтверждена. Нужен обычный
  read-only запуск после обновления checkout/установки и сверка version.
* Текущая очередь неатомарна; просмотр обслуживаемых отдельными Postfix
  instances очередей не заменяется автоматически одним default postqueue.
  Исторические instance/lifecycle разделяются. Внешний INBOX, причина позднего
  перемещения и потерянные архивы без дополнительных данных недоказуемы.
* Индиректные DNSBL в restriction classes/access map actions, выражения Postgrey,
  route persistence и restore backup остаются вне полного автоматического
  доказательства. Неполные данные сохраняют UNKNOWN, а не «исправлено».
* Watch не гарантирует отсутствие потерь при ротации. Metadata/fetch и отчёты
  ограничены; collection/display omissions показаны отдельно. Без Message-ID
  показываются кандидаты, без epoch время остаётся неподтверждённым.
* Manifest preflight предотвращает замену из неполной/синтаксически повреждённой
  копии. Это не rollback при сбое диска, питании или параллельной замене checkout.
  Устанавливать следует из доверенной неизменяемой на время установки копии.
* Redaction не является гарантированной анонимизацией произвольного текста.
  Перед передачей следует проверить пути, Queue ID и Message-ID.

Точные выполненные проверки и CI: [validation.md](validation.md). Старые аудиты
4.0.x остаются журналом исправлений, а не списком открытых багов текущего MVP.
