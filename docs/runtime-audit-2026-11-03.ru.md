# Runtime-аудит и проверка версии MailRadar

Дата: 2026-11-03. Проверяемая база:
`99c7663c25d64560f3a3da65ad42866e3a70ebea` (`origin/main`, после merge PR #7),
MailRadar 4.0.1. Исправления этого follow-up готовятся как 4.0.2.
Окончательные результаты проверок относятся к фактическому head ветки/PR,
а не к версии из присланного вывода.

## Что следует из присланного вывода

В новом приватном transcript оба запуска подписаны **MailRadar 4.0.0**.
Help не содержит `--menu`/`--details`, а большой отчёт соответствует старому
формату. Это подтверждает запуск старой копии; такой вывод не проверяет
компактное представление и сессию меню из 4.0.1. Причина расхождения — старый
checkout, отдельная установленная копия или другой путь запуска — по одной
версии не устанавливается. Пользовательские изменения не объявляются ошибкой.

Приватный transcript, адреса, домены, IP, пути к письмам и эксплуатационные
идентификаторы не добавлены в репозиторий. Регрессии используют синтетические
строки с `.example` и документационными сетями. Реальные службы, конфигурация,
очередь и письма не менялись.

## Отдельные подтверждённые дефекты новой базы

Старый запуск не доказывает, что новая база свободна от ошибок. Ниже замечания
установлены по исходникам базы и отдельным синтетическим воспроизведениям.
P1 — корректность диагностического вывода/полноты; P2 — эксплуатация и интерфейс.
Приоритет не означает доказанную эксплуатацию уязвимости.

| ID | Приоритет | Условие и проверенное последствие | Исправление в follow-up / регрессия |
|---|---|---|---|
| MR-U001 | P2 | Transcript содержит 4.0.0, а проверяемая main уже 4.0.1. Повторный clone не обновляет имеющуюся копию; Git source и глобальный пакет имеют разные жизненные циклы. | README различает обновление checkout и повторную установку. Help сообщает запущенную версию. `test_runtime_cli.test_help_identifies_running_version_before_any_diagnostics`; `test_install.test_source_update_requires_reinstall_to_upgrade_global_copy`. |
| MR-U002 | P1 | `model.finish_report` учитывал findings, но не delivery conclusions. Поэтому принятая в очередь без известного исхода давала conclusion UNKNOWN при summary OK; expired conclusion FAIL мог не определять FAIL/exit 2. | Общая severity учитывает обе группы, `summary.counts` сохраняет старый findings-only смысл, добавлены `conclusion_counts`. `test_accepted_only_is_unknown_in_summary_and_exit_status`, `test_expiry_is_a_failure_in_json_and_exit_status` в `test_runtime_cli`. |
| MR-U003 | P1 | `cli.conclusions` ограничивал анализ первыми 20 traces, а human — первыми выводами. Поздний failure мог отсутствовать в итоговой группе и коротком ответе. | JSON сохраняет полный набор conclusions; compact display сначала показывает failures и сообщает число скрытых строк. `test_late_failure_is_aggregated_and_visible_in_human_output` ставит отказ после 20 успешных передач. |
| MR-U004 | P1 | Самостоятельная Dovecot Saved-строка не имела Postfix trace и не становилась обычным delivery conclusion. Администратор мог не увидеть подтверждённое сохранение в кратком ответе. | Standalone Saved получает отдельный вывод с evidence; Queue ID и SMTP attempt не выдумываются, транспортные Saved и Dovecot events показаны раздельно. `test_standalone_saved_is_visible_without_inventing_queue_or_double_count`. |
| MR-U005 | P1 | Усечение stdin на границе полной строки, bounded journal и gaps/signal watch могли оставлять source/check completeness согласованной не со всем исходным сбором. Валидность сохранённых строк не восстанавливает отброшенные данные. | Неполный сбор явно отражается в `complete`, `log_sources_complete`, `checks_complete`, truncation и evidence. `test_stdin_cut_at_full_line_marks_source_truncation`, `test_truncated_journal_marks_source_incomplete_even_with_valid_rows`; watch regressions проверяют gaps/signal отдельно. |
| MR-U006 | P2 | Watch/session заменял SIGINT/SIGTERM handlers и мог оставить их вызывающей сессии после возврата. | Предыдущие handlers восстанавливаются в `finally`; реальный PTY-сценарий `test_miab_audit.InteractiveMenuTests.test_ctrl_c_at_menu_after_watch_restores_normal_signal_handling` проверяет Ctrl+C после возврата из watch. Это проверка процесса утилиты, не изменение systemd handlers. |
| MR-U007 | P1 | После terminal expiry служебные notification/removed строки могли создать новый пустой lifecycle. Длинные case-sensitive Queue ID и Message-ID могли объединяться/находиться без учёта регистра. | Expiry-tail остаётся в том же lifecycle; новый ingress/повторное использование ID отделяются. Queue/Message-ID ищутся точно, доменный фильтр сохраняет собственную регистронезависимую семантику. `test_runtime_logs` покрывает expiry→notification→removed, повторный removed, reuse/instance и case-sensitive identifiers. |
| MR-U008 | P1 | `checks.policy_listener_checks`: policy listener оценивался по порту без достаточной проверки локального адреса/семейства. Успех на другом local binding не доказывает доступность настроенного endpoint. | `_listen_socket_rows`, `_localhost_files_targets`, `_unix_policy_listener` учитывают local column, адрес, wildcard bind, family и Unix stream path. Неоднозначность остаётся UNKNOWN. `test_runtime_checks.RuntimeChecksTests.test_same_port_on_different_bind_address_is_not_ok`, `test_ipv6_wildcard_cannot_prove_dual_stack_ipv4`, `test_unix_policy_requires_exact_stream_listen_path`. |
| MR-U009 | P1 | `checks.service_checks`: Debian/MIAB `postfix.service` может быть oneshot umbrella. Его active/exited не доказывает работу экземпляра, а сравнение с одним daemon-шаблоном даёт неверную оценку фактического Postfix instance. | `_postfix_runtime_instances` и `_unit_has_substate` отделяют umbrella от найденных instance units. Недоступный inventory, missing/default failure и превышенный лимит не дают подтверждённый OK. `test_postfix_umbrella_active_exited_does_not_hide_failed_default`, `test_postfix_missing_or_incomplete_actual_unit_is_unknown`, `test_postfix_failed_secondary_instance_is_not_hidden` в `test_runtime_checks`. |
| MR-U010 | P2 | `checks.postgrey_whitelist_checks`: Postgrey может запускаться через SysV wrapper. Проверка только unit executable/runtime argv не устанавливает путь Perl-программы и её literal defaults. | `_postgrey_program_path` без выполнения wrapper читает ограниченные literal startup facts и подтверждает signature установленного Perl source; неизвестный shell syntax не исполняется. `test_postgrey_jammy_sysv_literal_daemon_confirms_installed_defaults`, `test_postgrey_dynamic_daemon_or_missing_signature_stays_unknown`. |
| MR-U011 | P1 | `install.sh`: Python timestamp-based bytecode может пережить обновление исходника той же длины при совпавшем mtime second. Deterministic staged test после установки 0.0.2 и восстановления старого mtime воспроизвёл global version 0.0.1; это симуляция коллизии metadata, не запуск на боевом сервере. | Проверка cache paths и удаление после копирования только `.pyc` устанавливаемых module names. Без recursive delete и перехода по symlink; unrelated cache остаётся. `test_install.StagedInstallTests.test_same_size_same_timestamp_upgrade_cannot_load_old_bytecode`, `test_installer_refuses_symlinked_bytecode_cache_directory` сначала упали на старом installer, после fix прошли. |

## Обновление и проверка запущенной копии

В существующем checkout, после сохранения локальных правок:

```bash
git switch main
git pull --ff-only origin main
bash ./mail-radar --version
sudo bash ./mail-radar --menu
```

При отказе fast-forward или конфликте необходимо сохранить пользовательские
изменения и разобрать расхождение. Данный workflow не стирает рабочую копию.
Для отдельно установленной команды после обновления исходников:

```bash
sudo bash ./install.sh
mail-radar --version
sudo mail-radar --menu
```

Первый вариант запускает source checkout. Второй использует установленный
launcher/package и требует повторной установки; обновление Git само по себе
не заменяет `/usr/local/lib/mail-radar/mailradar`.

## Состояние связанных PR

Изменения PR #6 ранее вошли в ветку PR #5; проверенный общий результат затем
попал в main через PR #7. Устаревший открытый PR #5 закрыт как дублирующий,
его ветка не удалялась. Это приведение состояния репозитория в порядок,
а не дополнительное слияние старой реализации поверх main.

## Проверки и границы

В новом наборе проверяются CLI/JSON severity, краткий human output, source
completeness, signals, queue lifecycle, literal identifiers и host facts.
Сценарий upgrade использует временный staging prefix, не `/usr/local`.
Количество пройденных тестов и статус CI должны подтверждаться фактическим
прогоном этого follow-up; результаты прежней версии не переносятся на него.

При финальном review отдельно проверены intentionally inactive secondary
Postfix units: без подтверждённого требования запуска они дают UNKNOWN,
а не ложный FAIL всей почте. Default inactive daemon и failed actual unit
по-прежнему требуют внимания. Регрессия:
`test_runtime_checks.test_inactive_secondary_unit_is_not_assumed_to_be_a_required_failure`.

Новый код не объявляется проверенным прямым повторным запуском на сервере
владельца. Он по-прежнему не доказывает внешний INBOX, полноту утраченных логов,
историческую конфигурацию, backup success без artifact или persistence маршрута.
Синтетическая форма события и статический service binding не заменяют проверку
всего production workflow. Неподтверждённое остаётся UNKNOWN/N/A по применимости.

Уточнённые host-границы: неизвестное имя/dynamic NSS и неподтверждённый
IPv6 dual-stack не считаются доказательством IPv4 listener. Unix socket в
host namespace не доказывает доступ из chroot, права и корректный policy response.
Текущие Postgrey metadata не устанавливают исторически загруженные правила.

## Дополнительная проверка ресурсных границ

**MR-U012, P2 — инкрементальный deep scan.** `mailstore.physical_usage`
проверял budget между шагами `os.walk`, но перечисление одного большого
каталога могло заранее собрать полный список entries. Исправление использует
инкрементальный `os.scandir(fd)` и DFS: учитываются все встреченные entries,
включая каталоги и пропущенные symlinks; сохраняются отдельный directory budget,
предел глубины 128 и проверка deadline между entry reads. `evidence.files`
считает только обычные файлы. Directory-relative descriptors с `O_NOFOLLOW`
не проходят по подменённому symlink; без безопасного fd API результат UNKNOWN.

`test_runtime_mailstore` проверяет остановку широкого каталога до полного
перечисления (`test_large_single_directory_stops_before_enumerating_all_entries`),
deadline между reads, empty-tree budgets, выбранного пользователя без обхода
соседей, замену каталога symlink и закрытие iterators/descriptors при прерывании.
Это metadata-only обход, без чтения тел или изменения quota.

**MR-U013, P2 — POSIX pipe deadline.** `runner._execute` использовал blocking
reader threads. Если отделённый потомок удерживал pipe открытым, ожидание
reader joins могло добавить по две секунды на поток после command timeout.
Исправление использует selectors/nonblocking I/O и единый deadline для команды
и её stdout/stderr; лимиты обоих потоков остаются отдельными.
`test_runtime_runner.RuntimeRunnerTests.test_detached_pipe_holder_does_not_leak_reader_threads_or_delay_return`
и `test_stdout_and_stderr_are_bounded_independently` используют fake processes.
Detached fixture сама убирает созданного потомка: тест не заявляет, что
process-group SIGKILL нашёл процесс после его собственного `setsid`.

Остаточная граница: `runner.stop` завершает исходную POSIX process group.
Самостоятельно отделившийся через `setsid` потомок не имеет гарантии завершения
этим механизмом. Cgroup/supervisor isolation и security sandbox для произвольных
демонизирующих команд не заявляются. Это граница механизма, а не доказанная
проблема почтового сервера владельца.

Deadline deep scan также проверяется между операциями: он не прерывает уже
заблокировавшийся kernel filesystem syscall внутри одного read/stat/open.

## Первичные источники host-проверок

* Ubuntu Jammy Postfix **3.6.4-1ubuntu1.4**:
  [официальный Debian patch archive](https://archive.ubuntu.com/ubuntu/pool/main/p/postfix/postfix_3.6.4-1ubuntu1.4.debian.tar.xz),
  `debian/postfix.service`, `debian/postfix@.service`, `debian/postfix-instance-generator`.
  Эти файлы проверены для формы umbrella/instance; версия пакета конкретного
  сервера не выводится из наличия ссылки.
* Ubuntu Jammy Postgrey **1.36-5.2**:
  [официальный Debian patch archive](https://archive.ubuntu.com/ubuntu/pool/universe/p/postgrey/postgrey_1.36-5.2.debian.tar.xz),
  `debian/postgrey.init`, и [пакет all.deb](https://archive.ubuntu.com/ubuntu/pool/universe/p/postgrey/postgrey_1.36-5.2_all.deb).
  В этом пакете есть init script с literal `DAEMON`, отдельного native unit нет.
  Проверка читает реально установленный script; archive не исполнялся.
* [systemd v249 SysV generator](https://github.com/systemd/systemd/blob/v249/src/sysv-generator/sysv-generator.c):
  источник для формы unit, генерируемой из init script. Это не повод считать
  любой active/exited unit работающим почтовым daemon без остальных фактов.
