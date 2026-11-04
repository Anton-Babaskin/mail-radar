"""One workflow catalogue for CLI flags, menu routes and collection requirements."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Workflow:
    key: str
    title: str
    help: str
    logs: bool = False
    host: bool = False
    store: str = ""
    conclusions: bool = False
    requires_user: bool = False
    envelope_prompt: bool = False
    period_prompt: bool = False
    menu_label: str = ""
    value_name: str = ""


CATALOGUE = (
    Workflow("doctor", "Общий обзор", "общий обзор", logs=True, host=True),
    Workflow("incoming", "Входящее письмо", "расследовать входящее письмо", logs=True, host=True, store="recipient", conclusions=True, envelope_prompt=True, period_prompt=True, menu_label="Входящее письмо не пришло"),
    Workflow("outgoing", "Исходящее письмо", "расследовать исходящее письмо", logs=True, host=True, conclusions=True, envelope_prompt=True, period_prompt=True, menu_label="Исходящее не дошло"),
    Workflow("delay", "Задержка доставки", "задержки и причины доставки", logs=True, host=True, store="recipient", conclusions=True, envelope_prompt=True, period_prompt=True, menu_label="Задержка письма"),
    Workflow("mailboxes", "Письма и папки ящика", "письма одного локального ящика; нужен --user", host=True, store="user", conclusions=True, requires_user=True, period_prompt=True, menu_label="Письмо в Spam/Trash/другой папке"),
    Workflow("queue", "Текущая очередь и SMTP-отказы", "текущая очередь, адреса, причины и история отказов", logs=True, host=True, menu_label="Очередь сейчас и SMTP-отказы за период"),
    Workflow("greylist", "Greylisting и повторы", "greylisting и повторы", logs=True, conclusions=True, envelope_prompt=True, period_prompt=True),
    Workflow("whitelist", "Whitelist SMTP-клиента", "карты Postfix и whitelist Postgrey", host=True),
    Workflow("dns", "DNS / TLS / resolver / relay", "DNS выбранного домена, TLS и resolver своего MIAB", host=True, menu_label="DNS домена / TLS и resolver своего MIAB"),
    Workflow("account", "Аккаунт, квота и место", "аккаунт, квота и место; нужен --user", host=True, store="user", requires_user=True, menu_label="Место/квота/аккаунт"),
    Workflow("post-update", "После обновления MIAB", "состояние после обновления", logs=True, host=True),
    Workflow("watch", "Наблюдение за доставкой", "наблюдение за новыми событиями", logs=True, conclusions=True, envelope_prompt=True, period_prompt=True, menu_label="Наблюдать за доставкой"),
    Workflow("trace", "Поиск и путь письма", "Message-ID, Queue ID, адрес, домен или IP", logs=True, conclusions=True, period_prompt=True, menu_label="Поиск по Message-ID / Queue ID / домену", value_name="VALUE"),
    Workflow("headers", "Выбранное письмо и заголовки", "выбранный Message-ID; нужен --user", host=True, store="user", conclusions=True, requires_user=True, period_prompt=True, menu_label="Заголовки и текущая папка письма", value_name="MESSAGE_ID"),
    Workflow("diagnose", "Расследование доставки", "разобрать доставку", logs=True, host=True, store="recipient", conclusions=True, envelope_prompt=True, period_prompt=True),
    Workflow("flow", "История доставки", "статистика потока", logs=True),
)
BY_MODE = {workflow.key: workflow for workflow in CATALOGUE}
MENU = CATALOGUE[:14]
LOG_MODES = frozenset(item.key for item in CATALOGUE if item.logs)
HOST_MODES = frozenset(item.key for item in CATALOGUE if item.host)
TITLES = {item.key: item.title for item in CATALOGUE}
