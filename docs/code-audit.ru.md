# Инженерный аудит MailRadar

Дата первого прохода: 2026-11-02. Проверенная исходная версия:
`d1add36326b537bc414859e681e3128fb643b515` (`main`, miab-radar v3.0).
Итоговая проверенная реализация:
`07d4d88578cc8c515a65efa91502615b6a762466` (MailRadar 4.0.0, код/тесты/установка/CI).
Следующий commit документации не меняет эту проверенную реализацию.
Все старые номера строк ниже относятся именно к этому commit; переименование
launchers не меняет исторические ссылки. Код просмотрен до запуска.
В исходном дереве нет test suite, AGENTS.md или CI. Старый скрипт целиком не
запускался: он автоматически делает внешние сетевые запросы и читает credential
file. Это статический baseline, а не заявление о работе на боевом MIAB.

## Подтверждённые находки первого прохода

P1 означает исправить до новых функций: опасный trust boundary или ложный
диагностический вывод. P2 — исправить до поставки: установка, совместимость,
производительность. Серьёзность и приоритет указаны отдельно. «По исходнику»
не означает воспроизведение на реальном сервере. Эксплуатация уязвимости не
утверждается там, где проверена только небезопасная конструкция.

| ID | Серьёзность / приоритет | Точное место в baseline | Условие и последствие | Подтверждение / требуемая регрессия |
|---|---|---|---|---|
| MR-A001 | Medium / P2 | `install.sh:7`; `README.md:29` | Установка и Quick Run обращаются к отсутствующему `miab-radar.sh`; обычный запуск не устанавливается. Относительный путь зависит от cwd. | По дереву и исходнику. `tests/test_install.py`: установка из другого cwd, реальные файлы, обе команды, PREFIX/DESTDIR, пробелы, отказ symlink. |
| MR-A002 | High / P1 | `miab-radar:70-87`, `:118`, `:537`, `:561` | `gensub` требует gawk; ошибки awk скрыты. Год всегда текущий, offset и ISO не разбираются. Часть разделов читает текущий лог с фильтром, часть фиксированные архивы без фильтра: несопоставимые периоды. | По исходнику. Общий parser и окно; syslog/ISO/offset/Новый год, перемешанные архивы, перекрытие и повторные события. |
| MR-A003 | High / P1 | `miab-radar:60`, `:118`, `:385-388`, `:419-421`, `:578-596`, `:728` | Недоступный лог, ошибка postqueue/grep или пустой результат awk превращаются в нули и зелёные выводы. Полнота не учитывается. | По исходнику. Missing tool/permission/empty/truncated source дают UNKNOWN и ненулевой код неполноты, не «всё работает». |
| MR-A004 | High / P1 | `miab-radar:505-511` | Рассматривается только recipient chain; штатная relay protection в `smtpd_relay_restrictions` получает ложный FAIL. Успешная локальная проверка ошибочно подписана «no open relay». | По исходнику. Relay-only protection, обе цепочки и service overrides; локальная конфигурация не является внешним тестом. |
| MR-A005 | High / P1 | `miab-radar:163-201`, `:209`, `:247-255` | Пустой dig при timeout/SERVFAIL считается clean; любой непустой DNSBL ответ — listing. Четыре угаданных selector без записи считаются отсутствующим DKIM. В список без проверки включена историческая зона SORBS. | По исходнику. Различать DNS response status, служебные DNSBL коды, unknown selector. Внешние сервисы проверять по текущим первичным источникам. |
| MR-A006 | Medium / P1 | `miab-radar:286-341` | После первого полученного сертификата цикл завершается. Остальные порты не проверены; chain/hostname не устанавливаются по expiry/subject. Скрытый stderr затрудняет объяснение ошибки клиента TLS. | По исходнику. Независимые порты, bounded explicit probes, chain/hostname/expiry и причина ошибки; локальное crypto ограничение — UNKNOWN. |
| MR-A007 | High / P1 | `miab-radar:537-564`, `:578-579`, `:622`, `:604`, `:613`, `:636` | Поиск `status=sent/from/message-id` как произвольного текста может принять недоверенное поле за событие. Строки причин печатаются через `echo -e` без очистки terminal control. | По исходнику. Структурный разбор доверенных полей, adversarial HELO/diagnostic fixtures, очистка ANSI/control. |
| MR-A008 | High / P1 | `miab-radar:104`, `:175-185` | Результат внешнего `curl ifconfig.me` вставляется в Python source в одинарных кавычках. Невалидированные кавычки/переводы строк способны изменить программу, а не только адрес. | Небезопасная интерполяция установлена по исходнику; exploit на сети не запускался. Новый runner использует argv, `ipaddress`, без shell/eval/generated source; adversarial аргументы. |
| MR-A009 | Medium / P1 | `miab-radar:526-528` | Для подписи relay читается `/etc/postfix/sasl_passwd`. Пароль явно не печатается, но доступ к полному credential file избыточен и идентификатор пользователя попадает в отчёт. | По исходнику. Новый сборщик не читает credentials; marker/spy fixture для запрещённых чтений и команд. |
| MR-A010 | Medium / P2 | `miab-radar:376`, `:401-404`, `:649-660`, `:685` | Обычный обзор делает глубокие du/find, повторяет сканирование ящиков и не ограничивает время большинства команд. Администратор может ждать полного обхода хранилища. | По исходнику; реальное время на боевом хранилище не измерялось. Быстрый default, targeted/deep opt-in, runner timeout/output caps, cleanup children. |
| MR-A011 | Medium / P1 | `miab-radar:385`, `:401-407` | Подсчёт предполагает hex-first Queue ID; возможны длинные ID с другим алфавитом. mtime queue file не гарантирует время приёма. Совет `postsuper -d ALL deferred` слишком широк для общего отчёта. | По исходнику. JSON queue snapshot, валидированный fallback, queue arrival time, short/long ID, ошибку не считать нулём; destructive совет убран. |
| MR-A012 | Medium / P1 | `miab-radar:475-494` | Чтение только первого совпадения основного sshd_config игнорирует Include/Match/defaults и не доказывает effective SSH posture. | По исходнику. Bounded `sshd -T` либо UNKNOWN с границами; не объявлять custom port защитой. |
| MR-A013 | Medium / P1 | `miab-radar:682-692` | mtime backup directory подписывается «last backup today» без доказательства успешного backup. | По исходнику. Показать подтверждённые metadata отдельно; отсутствие success evidence — UNKNOWN; hold duplicity не менять. |
| MR-A014 | Medium / P2 | `miab-radar:53-57`, `:91`, `:63-67`, `:103-104` | Root обязателен даже для доступных данных, `clear` и ANSI безусловны, сеть запускается без выбора. Это мешает automation/partial analysis и скрывает сетевые действия обычного запуска. | По исходнику. Non-TTY без вопросов/ANSI, no-color, partial access, explicit --network, валидный JSON/NDJSON, legacy numeric CLI. |

## Таблица сохранения полезного поведения

Таблица сверена с модулями `checks`, `logs`, `mailstore`, CLI и regression
fixtures рабочего diff. Перенос старого ложного заключения не считается
сохранением полезной проверки; ограничения ниже перечислены отдельно.

| Исходная проверка | Решение и целевое поведение |
|---|---|
| Host, MIAB version, uptime/load | Сохранены через hostname и bounded /proc metadata; Git metadata вместо запуска MIAB wrappers; недоступное UNKNOWN. |
| Postfix/Dovecot/Nginx/Fail2Ban/NSD/OpenDKIM/Postgrey/SpamPD/PHP-FPM | Сохранены с учётом effective installed stack: optional missing N/A, недоступное UNKNOWN. Добавлены фактический resolver/management и другие найденные фильтры. |
| IPv4/IPv6 DNSBL и domain DBL | Ошибочная boolean-модель заменена явными сетевыми пробами и DNS status. SORBS не переносится как актуальная зона. Реализованный provider-specific контракт — Spamhaus; SpamCop/Barracuda исключены из автоматического набора до отдельной проверки их условий доступа/ответов. Это явное сужение списка провайдеров. |
| PTR, SPF, DKIM, DMARC, MX | Сохранены в контексте конкретного домена; selector задаётся явно, ошибки resolver UNKNOWN. |
| MTA-STS/TLSA | Сохранены как optional presence signal, добавлен TLS-RPT; наличие записи не полная валидация политики/DANE. |
| TLS certificate expiry | Сохранено и расширено; разные порты и протоколы независимы, chain/hostname и ограничения клиента объясняются. |
| Disk percent/inodes | Сохранены быстрые проверки доступных mountpoints. Ошибка чтения не становится OK. |
| Общий размер /home/user-data | Удалён из обычного обзора: глубокий суммарный обход дорог и относится к mailtop. `--deep` измеряет только выбранный ящик; общий total не заявляется сохранённым. Размер файлов не является quota. |
| Queue count/oldest/reasons | Заменены структурным queue snapshot, arrival time и состояниями; небезопасный совет удаления убран. |
| Authentication failures/top source IP | Сохранены в общем окне событий; неполнота и недоверенные поля учитываются. |
| Fail2Ban jails/banned/failed counts | Сохранён bounded read-only status; отсутствие инструмента/jail объясняется отдельно от установленной службы. |
| SSH root/password login/port | Исправлены на effective baseline config или UNKNOWN; ограничения Match-блоков отражены, это не полный security audit. |
| Unattended-upgrades installed | Сохранён package metadata signal без установки/apt update. |
| Relay protection | Исправлена: recipient + relay + overrides, локальная проверка не external open-relay test. |
| Relayhost | Сохранён, credential-file read исключён; transport отделён от OS route. |
| Top authenticated senders | Сохранены в общем периоде; auth identities отдельно от envelope senders. |
| Top recipient domains/status=sent | Сохранены как recipient events с internal/external/local outcomes; каждая строка не считается уникальным письмом. |
| Bounces/deferrals/top reasons | Сохранены структурно, с evidence, recipient scope и единым окном. |
| Rejected incoming/top reasons | Сохранены включая NOQUEUE и policy stages. |
| Mailbox domain/user size/message count/activity | Заменено targeted metadata/IMAP quota и `--deep` одного пользователя; массовый domain/user inventory остаётся mailtop. Physical files включают индексы, не являются message count; размеры файлов не allocated du blocks. Текущие даты Dovecot не подменяются Maildir mtime. |
| Backup directory freshness | Заменена evidence-based границей: directory mtime не success, holds/duplicity отдельно, last success UNKNOWN без доказательства. |
| Recommendations/counts/exit 0/1/2 | Сохранены next steps и exit severity; UNKNOWN/неполнота не дают clean exit. Добавлены schema/evidence/completeness и отдельные CLI/runtime errors. |

## Отдельная находка соседнего проекта

**EXT-A001 — High/P1, вне scope этого PR.** В
`mail-sec-audit.sh:457`, commit
`33f2d519b346eb5a4bd77cfc0b3f203183ac217d`, исходник действительно вызывает
`mailinabox --version`. Установщик MIAB может запускаться через этот wrapper;
аргумент и `head` не делают вызов read-only. Проверено чтением указанной версии,
не запуском. Точный объём исторических изменений неизвестен. Radar не вызывает
соседний скрипт; соседний репозиторий здесь не исправлялся.

## Второй проход и оставшиеся границы

Независимый второй проход проверил `cli.py`, `runner.py`, `model.py`,
`mailstore.py`, `checks.py`, launchers и установку. Рабочая версия ещё не
является релизом; проверенная реализация зафиксирована в
`07d4d88578cc8c515a65efa91502615b6a762466`.

| ID / приоритет | Подтверждение в первоначальном diff | Исправление и регрессия |
|---|---|---|
| MR-R001 / P1 | `model.finish_report`: synthetic nested details оставляли 12,012,414 bytes после заявленного 8 MiB limit; воспроизведено в WSL. | При превышении лимита bounded fallback удаляет nested details/evidence/traces и явно помечает неполноту; `test_core.ReportTests.test_report_size_is_bounded_even_for_nested_details`. |
| MR-R002 / P1 | `model.clean`: `chr(155)+'2J'` сохранял C1 CSI U+009B; воспроизведено в WSL. | Итоговая очистка исключает C1/DEL, ANSI и опасные bidi controls; `test_core.ReportTests.test_unknown_is_not_clean_and_json_has_no_terminal_controls`. |
| MR-R003 / P1 | `runner.valid_user` позволял `*@example.org`/`?@example.org`, которые расширяют Dovecot user scope; установлено по аргументному контракту. | Wildcards отклоняются для локального user scope; `test_core.CLITests.test_unsafe_user_and_mutually_incompatible_flags_are_cli_errors`. |
| MR-R004 / P1 | `model.redact_report` редактировал values, сохраняя идентификаторы в keys статистических словарей; установлено по исходнику. | Редактируются dynamic keys, сохраняются schema keys и finding IDs; `test_core.ReportTests.test_redaction_keeps_ids_and_cross_field_equality`. |
| MR-R005 / P1 | Launcher `python3 -m` ставил cwd раньше PYTHONPATH: локальный пакет мог подменить установленный. | Фиксированный `python3 -I -c` bootstrap загружает trusted module directory без смены cwd; `test_install.StagedInstallTests.test_installed_launcher_ignores_untrusted_cwd_and_pythonpath` (marker остаётся отсутствующим). |
| MR-R006 / P1 | `checks.whitelist_checks` ставил OK карте после первого policy service; порядок был только в details. | WARN для поздней карты и точное описание уже пройденных policy services; `test_checks.ChecksTests.test_map_after_first_policy_warns_without_claiming_earlier_bypass`. |
| MR-R007 / P1 | Inferred default Postgrey files без match могли дать определённый negative result без доказанного active path. | Результат UNKNOWN при неподтверждённых активных файлах; `test_checks.ChecksTests.test_inferred_postgrey_file_without_match_remains_unknown`. |
| MR-R008 / P1 | APT scanner сопоставлял duplicity и held-change error в целом файле, даже из разных транзакций. | Корреляция блока/транзакции, неоднозначное candidate UNKNOWN; `test_checks.ChecksTests.test_apt_different_transactions_do_not_create_false_duplicity_conflict`, `test_apt_adjacent_package_change_block_proves_specific_held_conflict`, `test_apt_ambiguous_error_is_unknown_candidate`. |
| MR-R009 / P2 | `mailstore.physical_usage` проверял time/file budget только внутри per-file loop, оставляя дерево пустых каталогов без этой границы. | Time/directory budget проверяется для каждого каталога, retained errors ограничены; `test_core.StoreTests.test_empty_directory_tree_respects_deep_budget`. |

Регрессии первого прохода распределены так: MR-A001 — `test_install`;
MR-A002/007 — `test_logs` и `test_cli_logs`; MR-A003/004/005/006/011/012/013 —
`test_checks`; MR-A008/009/010/014 — allowlist/timeout/PATH/privacy/CLI tests в
`test_core`, host collector tests и watch tests. Это новые проверки поведения,
не утверждение о воспроизведении полного старого скрипта. Изначальные дефекты
подтверждены указанным статическим baseline; runtime-vulnerability claims не
добавлялись без доказательств.

Список автоматических проверок и результаты конкретного прогона фиксируются
в `docs/validation.md`. Сетевые/боевые проверки не подменяются unit tests.
Отчёт не может подтвердить внешнюю INBOX, полноту потерянных логов, исторический
policy match без данных о конфигурации того времени или persistence маршрута
без доказуемой постоянной конфигурации. Эти границы сохраняются как UNKNOWN.

Оставшиеся проверенные ограничения:

* Последний успешный backup не определяется по directory mtime. Без отдельного
  достоверного completion artifact остаётся UNKNOWN; backup/restore не запускаются.
* Route persistence намеренно UNKNOWN при неподтверждённом backend/config;
  найденные candidate-файлы и runtime route не считаются доказательством reboot.
* `--post-update` читает выбранные Postfix/Dovecot параметры и nginx.conf,
  показывает службы и management availability при `--network`. Полный Nginx
  syntax/include test не запускается (его test mode может открывать log-файлы);
  доступный management endpoint не валидирует admin/status/backup функции.
* Account userdb lookup не доказывает, что authentication включена. Нет полной
  эмуляции aliases/forwarding/Sieve для каждого стека; trace и mailbox metadata
  показывают наблюдаемые события и границы.
* Postgrey Perl regex rules и сложные restriction classes не исполняются и не
  объявляются полностью смоделированными. Старое состояние политики неизвестно
  без исторической конфигурации. DNS-policy presence не полная SPF/DANE validation.
  Неоднозначный двухоктетный Postgrey IPv4 shorthand также UNKNOWN: upstream
  comment и NetAddr constructor argument не совпадают, deployed semantics не
  угадываются. Обычные IP/CIDR и трёхоктетный /24 разбираются отдельно.
* Корреляция reinjection использует явную связь на том же host с единственным
  target в пределах 300 секунд. `observed_messages` — inferred группы таких
  связей, а не гарантированное число уникальных писем; невидимые hops могут
  увеличить счёт. Поддерживаются распространённые anchored log formats;
  неподдержанный delivery grammar помечает источник неполным.
* Для yearless syslog выбирается последнее календарное событие не позже `until`.
  Источник с несколькими годами требует timestamp с явным годом; один `--year`
  задаёт один год и не восстанавливает отсутствующие исторические годы.
* EXT-A001 остаётся внешней находкой; соседний проект в этом PR не исправлялся.

## Третий проход: коды ответа DNSBL (2026-11-03)

Проход выполнен по рекомендации review mail-sec-audit 2026-11 (раздел 8) поверх
`4aae39f` (merge PR #2). Разбор rcode и отказ считать 127.255.255.x listing уже
были в PR #2; ниже то, чего не хватало.

| ID / приоритет | Подтверждение | Исправление и регрессия |
|---|---|---|
| MR-T001 / P1 | `checks.dnsbl_state` сводил 127.255.255.252/254/255 и DBL 127.0.1.255 в `service_or_unrecognized_response`; controls для таких ответов не запускались, причина в отчёте не появлялась. Запуском 2026-11-03: resolver WSL этой машины получает 127.255.255.254 на оба control-имени ZEN, `1.1.1.1` — на все имена ZEN и DBL (сырые DNS-запросы к документированным тестовым именам, `docs/validation.md`). | Коды названы (`zone_name_error`, `public_resolver_blocked`, `query_limit_exceeded`, `ip_query_on_domain_list`, `mixed_error_response`), репутация остаётся UNKNOWN, controls запускаются; код ошибки на control даёт `DNSBL.CONTROL.*` WARN с исправлением. `test_checks`: `test_spamhaus_error_codes_are_named_and_never_listed`, `test_public_resolver_refusal_is_a_confirmed_control_warning`, `test_rate_limited_target_with_passing_controls_stays_unknown`. |
| MR-T002 / P1 | Конфигурация Postfix не проверялась на фильтр кодов ответа. По `proto/postconf.proto` без `=d.d.d.d` отказ выдаётся на любой A-ответ, то есть на коды ошибок Spamhaus; при заблокированном resolver это отказ всей входящей почте. Подтверждено по документации Postfix, на Postfix не воспроизводилось. | `DNSBL.POSTFIX_FILTER` разбирает `reject_rbl_client`/`reject_rhsbl_*` для публичных зон Spamhaus в выбранных restrictions и overrides master.cf, вычисляет фильтр (`n`, `[n;m..k]`) на кодах ошибок. Фильтры MIAB проходят. `test_postfix_reply_filter_syntax`, `test_unfiltered_spamhaus_zone_in_postfix_would_reject_on_error_codes`, `test_miab_reply_filters_pass_and_dqs_zone_is_not_judged`, `test_postfix_filter_without_spamhaus_or_readable_chains`. |

Не моделируются: restriction classes, действия access maps, `smtpd_helo_restrictions`,
`smtpd_data_restrictions` и `postscreen_dnsbl_sites` (у postscreen ещё веса,
threshold и `postscreen_dnsbl_action`). Об этом сообщает finding покрытия.
