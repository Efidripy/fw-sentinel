"""Full-screen live events and policy settings."""
import datetime
import locale
import os
import sqlite3
import subprocess
import textwrap
import time
import unicodedata

import i18n

tr = i18n.tr


def clean(value):
    return ''.join(ch for ch in str(value or '') if not unicodedata.category(ch).startswith('C'))


def filter_events(rows, selected):
    return [row for row in rows if selected == 'all' or row[6] == selected]


def format_event(row):
    _, stamp, ip, port, proto, reason, verdict, hits = row
    try:
        stamp = datetime.datetime.fromisoformat(str(stamp).replace('Z', '+00:00')).astimezone().strftime('%H:%M:%S')
    except (ValueError, TypeError, OverflowError):
        stamp = clean(stamp)
    suffix = ' x'+str(hits) if hits and hits > 1 else ''
    return '{} {:7} {} {}/{} {}{}'.format(stamp, clean(verdict).upper(), clean(ip), clean(port), clean(proto), clean(reason), suffix)


def selections(fw, cfg):
    result = {key: bool(cfg.get(key, False)) for key in fw.WEB_BOOL_FIELDS}
    result['geo_choice'] = cfg.get('geo_mode', 'ru_only') if cfg.get('geo_enabled', False) else 'off'
    return result


def toggle(values, key):
    if key in ('off', 'ru_only', 'non_ru_only'):
        values['geo_choice'] = key
    else:
        values[key] = not values[key]


def apply(fw, values, answer):
    if answer.lower() != 'y':return None
    connection = os.environ.get('SSH_CONNECTION', '').split()
    return fw.ui_apply_start({key: bool(values[key]) for key in fw.WEB_BOOL_FIELDS} |
                             {'geo_choice': values['geo_choice']}, connection[0] if connection else None)


def change(fw, kind, row, answer):
    if answer.lower() == 'y' and row:
        return fw.change_entry(kind, row[2], True)
    return None


def run(fw):
    try:
        cfg = fw.config()
        if not hasattr(os, 'geteuid') or os.geteuid() != 0:
            print(tr('Run top as root.', 'Запустите top от root.'))
            return
        locale.setlocale(locale.LC_ALL, '')
        import curses
        if hasattr(curses, 'set_escdelay'):curses.set_escdelay(25)
        curses.wrapper(_screen, fw, cfg, curses)
    except KeyboardInterrupt:
        pass
    except (OSError, ValueError, RuntimeError, ImportError) as exc:
        print(tr('Cannot start top:', 'Не удалось запустить top:'), clean(exc))


def _screen(screen, fw, cfg, curses):
    import webui
    screen.timeout(300)
    try:curses.curs_set(0)
    except curses.error:pass
    colors = {}
    try:
        if curses.has_colors():
            curses.start_color()
            try:curses.use_default_colors(); background = -1
            except curses.error:background = curses.COLOR_BLACK
            for number, (name, color) in enumerate((('drop', curses.COLOR_RED), ('observe', curses.COLOR_YELLOW), ('pass', curses.COLOR_GREEN)), 1):
                curses.init_pair(number, color, background)
                colors[name] = curses.color_pair(number)
    except curses.error:colors = {}
    draft = fw.policy_draft()
    saved = selections(fw, draft['candidate'] if draft else cfg)
    values = saved.copy()
    items = [(key, label, desc) for key, label, desc in webui.control_features()]
    items += [(key, label, label) for key, label in webui.control_geo_items()]
    rows = []; cursor = 0; selected = 0; selected_id = None; following = True; tab = 0; mode = 0; paused = False
    filters = ('all', 'observe', 'drop'); last_health = 0; health = {}; count = 0
    job = fw.ui_apply_current(); info = {}; status = ''; pending = None

    def put(y, x, value, attr=0):
        h, w = screen.getmaxyx()
        if y < 0 or y >= h or x < 0 or x >= w-1:return
        try:screen.addnstr(y, x, clean(value), max(0, w-x-1), attr)
        except curses.error:pass

    while True:
        now = time.monotonic()
        try:
            if now-last_health >= 10:
                health = webui.live_health(); count = len(fw.recent_drop_causes(limit=1000, hours=24)); last_health = now
            if not paused:
                incoming = fw.live_events(cursor, 100)
                if incoming:
                    cursor = incoming[-1][0]; rows = (rows+incoming)[-500:]
            if job:
                info = fw.ui_apply_status(job)
                status = '{}% {} {}'.format(info.get('percent', 0), info.get('message', ''), info.get('error') or '')
                if info.get('status') in ('trial', 'finished', 'error') or info.get('error'):
                    job = None
                    if not info.get('error') and info.get('status') != 'error':
                        cfg = fw.config(); draft = fw.policy_draft()
                        saved = selections(fw, draft['candidate'] if draft else cfg)
                        values = saved.copy()
            trial = webui.pending_trial()
        except (OSError, ValueError, RuntimeError, KeyError, fw.sqlite3.Error) as exc:
            status = clean(exc); trial = None
        visible = filter_events(rows, filters[mode])
        if tab == 0:
            if following:selected = max(0, len(visible)-1)
            else:
                selected = next((i for i, row in enumerate(visible) if row[0] == selected_id), 0)
                if visible:selected_id = visible[selected][0]
        else:selected = min(selected, len(items)-1)
        h, w = screen.getmaxyx(); screen.erase()
        put(0, 0, 'FW Sentinel | '+tr('Mode', 'Режим')+': '+str(health.get('mode', '?'))+' | '+tr('Monitor', 'Монитор')+': '+(tr('active','активен') if health.get('monitor_active') else tr('inactive','не активен')))
        put(1, 0, tr('1 Live  |  2 Settings  |  Tab switch  |  Q quit','1 Лента  |  2 Настройки  |  Tab переключить  |  Q выход'))
        if tab == 0:
            height = max(0, h-5); start = max(0, min(selected-height+1, max(0, len(visible)-height)))
            for index, row in enumerate(visible[start:start+height], start):
                put(2+index-start, 0, format_event(row), colors.get(row[6], 0) | (curses.A_REVERSE if index == selected else 0))
            put(h-3, 0, tr('Filter','Фильтр')+': '+(tr('all','все') if mode == 0 else tr('observe','наблюдение') if mode == 1 else tr('blocked','заблокировано'))+(' | '+tr('Paused','Пауза') if paused else '')+' | '+tr('Blocked IPs (24h)','Заблокировано IP (24 ч)')+': '+('1000+' if count >= 1000 else str(count)))
            hint = tr('F filter  Space pause  Up/Down select  A trust  B ban', 'F фильтр  Пробел пауза  Стрелки выбор  A доверие  B бан')
        else:
            # a low window keeps the list and gives up description lines first
            lines = max(0, min(3, h-7)); height = max(0, h-4-lines); start = max(0, min(selected-height+1, max(0, len(items)-height)))
            for index, (key, label, desc) in enumerate(items[start:start+height], start):
                mark = ('(•)' if values['geo_choice'] == key else '( )') if key in fw.WEB_GEO_MODES else ('[x]' if values[key] else '[ ]')
                prefix = tr('Geo: ', 'География: ') if key in fw.WEB_GEO_MODES else ''
                put(2+index-start, 0, prefix+mark+' '+label, curses.A_REVERSE if index == selected else 0)
            description = textwrap.wrap(items[selected][2], max(1, w-1))[:lines]
            for n, line in enumerate(description):put(h-2-lines+n, 0, line)
            hint = tr('Up/Down select  Space toggle  Enter apply  Esc reset', 'Стрелки выбор  Пробел отметить  Enter применить  Esc сброс')
        if trial:
            status = tr('Trial: confirm within 120 seconds: Y confirm / N cancel', 'Пробный режим: подтвердите за 120 секунд: Y подтвердить / N отменить')
        put(h-2, 0, pending[0] if pending else status); put(h-1, 0, hint); screen.refresh()
        key = screen.getch()
        try:
            if pending:
                if key in (ord('y'), ord('Y')):
                    action, value = pending[1], pending[2]
                    if action == 'apply':job = apply(fw, values, 'y'); info = {}; status = ''
                    else:
                        try:
                            changed = change(fw, action, value, 'y')
                            status = tr('Done', 'Готово') if changed else tr('No changes', 'Без изменений')
                        finally:screen.clear()
                elif key not in (ord('n'), ord('N'), 27, -1):continue
                if key != -1:pending = None
            elif trial and key in (ord('y'), ord('Y'), ord('n'), ord('N')):
                try:(fw.web_confirm if key in (ord('y'), ord('Y')) else fw.web_abort)(trial[0]); job = None; info = {}; status = tr('Done', 'Готово')
                finally:screen.clear()
            elif key in (ord('q'), ord('Q')):break
            elif key in (ord('1'), ord('2'), 9):tab = (1-tab if key == 9 else key-ord('1')); selected = 0; following = True; selected_id = None
            elif key == curses.KEY_UP:
                selected = max(0, selected-1)
                if tab == 0 and visible:following = False; selected_id = visible[selected][0]
            elif key == curses.KEY_DOWN:
                selected = max(0, min((len(visible)-1 if tab == 0 else len(items)-1), selected+1))
                if tab == 0 and visible:following = selected == len(visible)-1; selected_id = visible[selected][0]
            elif tab == 0 and key == curses.KEY_END:following = True; selected_id = None
            elif tab == 0:
                if key in (ord('f'), ord('F')):mode = (mode+1)%3; selected = 0; following = True; selected_id = None
                elif key == ord(' '):paused = not paused
                elif key in (ord('a'), ord('A'), ord('b'), ord('B')) and visible:
                    kind = 'allow' if key in (ord('a'), ord('A')) else 'ban'
                    question = tr('Trust', 'Доверять') if kind == 'allow' else tr('Ban', 'Забанить')
                    pending = (question+' '+clean(visible[selected][2])+'? y/n', kind, visible[selected])
            else:
                if key == ord(' '):toggle(values, items[selected][0])
                elif key == 27:values = saved.copy()
                elif key in (10, 13, curses.KEY_ENTER) and not job:pending = (tr('Apply settings? y/n', 'Применить настройки? y/n'), 'apply', None)
        except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired, sqlite3.Error) as exc:status = clean(exc); pending = None
