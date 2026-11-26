"""English is the main language; Russian is optional (file `ui-language` in the data directory)."""
from pathlib import Path

LANGUAGES = ('en', 'ru')
FORCED = None  # tests pin a language regardless of the saved choice
_saved = 'en'


def load(root):
    global _saved
    try:
        code = (Path(root) / 'ui-language').read_text(encoding='ascii').strip()
    except (OSError, UnicodeError):
        code = 'en'
    _saved = code if code in LANGUAGES else 'en'


def save(root, code):
    if code not in LANGUAGES:
        raise ValueError('unknown language')
    (Path(root) / 'ui-language').write_text(code + '\n', encoding='ascii')
    load(root)


def language():
    return FORCED or _saved


def tr(en, ru):
    return ru if language() == 'ru' else en


# Texts kept in module-level constants (embedded scripts, provider list); longest first.
FRAGMENTS = {
    'Диагностика: fw-sentinel-monitor не активен. Проверьте systemctl и journalctl.': 'Diagnostics: fw-sentinel-monitor is inactive. Check systemctl and journalctl.',
    'Монитор активен, таблица загружена; зарегистрированных событий пока нет.': 'Monitor active, table loaded; no events logged yet.',
    'Всего зарегистрировано DROP-событий по адресу, активному за 24 часа': 'Total logged DROP events for an address active in the past 24 hours',
    'Диагностика: таблица Sentinel отсутствует. Запустите наблюдение.': 'Diagnostics: Sentinel table is missing. Start observe mode.',
    'Монитор активен · таблица загружена · последнее событие (UTC):': 'Monitor active · table loaded · last event (UTC):',
    'В выбранной категории пока нет зарегистрированных событий.': 'No events have been logged in this category yet.',
    'За последние 24 часа зарегистрированных DROP-событий нет.': 'No DROP events logged in the past 24 hours.',
    'Не удалось получить диагностику мониторинга (': 'Could not retrieve monitoring diagnostics (',
    'Ожидаем реальные события из журнала ядра…': 'Waiting for live events from the kernel log…',
    '0 сек — срок истёк, обновите страницу': '0 s — time expired, refresh the page',
    'Вкладка скрыта · опрос приостановлен': 'Tab hidden · polling paused',
    'ASN · страна · AbuseIPDB: загрузка…': 'ASN · country · AbuseIPDB: loading…',
    'C2-индикаторы (не входящий IP DROP)': 'C2 indicators (not inbound IP DROP)',
    'Сессия истекла: обновите страницу': 'Session expired: refresh the page',
    ' мс · ожидаем события…': ' ms · waiting for events…',
    'Не удалось получить сведения:': 'Could not retrieve information:',
    'Нажмите «Обновить сведения»': 'Click Refresh information',
    'Последнее обращение (UTC):': 'Last seen (UTC):',
    'Доступ к community IP-базе': 'Access to community IP database',
    'Определяем сеть и регион…': 'Looking up network and region…',
    'URL и домены (не IP DROP)': 'URLs and domains (not IP DROP)',
    'Нет связи · повтор через': 'Connection lost · retry in',
    'Репутационный DNS-сервис': 'DNS reputation service',
    'Локальные базы ASN/GeoIP': 'Local ASN/GeoIP databases',
    'Поиск открытых сервисов': 'Search for exposed services',
    'Ожидаем ответ сервера…': 'Waiting for server response…',
    'Репутация отдельных IP': 'Individual IP reputation',
    'Индикаторы и репутация': 'Indicators and reputation',
    'событий в этой сессии': 'events in this session',
    'Проверка выполняется…': 'Check in progress…',
    'Сведения отсутствуют': 'No information available',
    'Проверка индикаторов': 'Indicator lookup',
    'Загрузка данных IP…': 'Loading IP data…',
    'Проверка IP вручную': 'Manual IP lookup',
    'Исследование хостов': 'Host research',
    'Из локального кэша': 'From local cache',
    'Проверка не прошла': 'Check failed',
    'Возобновить ленту': 'Resume feed',
    'Пауза отображения': 'Display paused',
    'IP-база + рейтинг': 'IP database + reputation score',
    'Проверка сканеров': 'Scanner lookup',
    'Фишинговые URL': 'Phishing URLs',
    ' мс · ': ' ms · ',
    'Подключаемся…': 'Connecting…',
    'Пауза ленты': 'Pause feed',
    'НАБЛЮДЕНИЕ': 'OBSERVE',
    'Провайдер:': 'Provider:',
    '% · прошло': '% · elapsed',
    'ASN/страна': 'ASN/country',
    'ПРОПУЩЕН': 'PASSED',
    'страна —': 'country —',
    'БЛОК': 'BLOCKED',
    'сек': 's',
    'мин': 'min',
    'с': 's',
}


def localize(text):
    if language() != 'ru':
        for ru, en in FRAGMENTS.items():
            text = text.replace(ru, en)
    return text
