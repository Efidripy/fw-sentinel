import unittest
from unittest.mock import Mock, patch

import sys
import types
import sqlite3
import subprocess

import i18n
import tui

if sys.platform == "win32":
    sys.modules.setdefault("fcntl", types.ModuleType("fcntl"))
import webui


class TuiTests(unittest.TestCase):
    def setUp(self):
        self.fw = Mock()
        self.fw.WEB_BOOL_FIELDS = ('one', 'two')
        self.fw.WEB_GEO_MODES = ('off', 'ru_only', 'non_ru_only')
        self.row = (1, '2026-01-01T12:00:00+00:00', '1.2.3.4\x1b', 443, 'tcp', 'bad\nreason', 'drop', 2)

    def test_filter_and_clean(self):
        self.assertEqual(tui.filter_events([self.row], 'observe'), [])
        self.assertEqual(tui.filter_events([self.row], 'drop'), [self.row])
        line = tui.format_event(self.row)
        self.assertNotIn('\x1b', line)
        self.assertNotIn('\n', line)
        self.assertIn('x2', line)

    def test_toggle_and_apply(self):
        values = tui.selections(self.fw, {'one': True})
        tui.toggle(values, 'two')
        tui.toggle(values, 'ru_only')
        with patch.dict('os.environ', {'SSH_CONNECTION': '192.0.2.1 1 192.0.2.2 22'}):
            tui.apply(self.fw, values, 'n')
            self.fw.ui_apply_start.assert_not_called()
            tui.apply(self.fw, values, 'y')
        self.fw.ui_apply_start.assert_called_once_with({'one': True, 'two': True, 'geo_choice': 'ru_only'}, '192.0.2.1')

    def test_change_confirmation(self):
        for kind in ('ban', 'allow'):
            tui.change(self.fw, kind, self.row, 'n')
            self.fw.change_entry.assert_not_called()
            tui.change(self.fw, kind, self.row, 'y')
            self.fw.change_entry.assert_called_once_with(kind, self.row[2], True)
            self.fw.change_entry.reset_mock()

    def test_english(self):
        with patch.object(i18n, 'FORCED', 'en'):
            labels = [part for item in webui.control_features() for part in item]
            labels += [part for item in webui.control_geo_items() for part in item]
            self.assertNotRegex(' '.join(labels), '[А-Яа-яЁё]')

    def screen_run(self, keys, batches=None, statuses=None, on_key=None):
        screen = Mock()
        screen.getmaxyx.return_value = (24, 80)
        keys = iter(keys)
        def getch():
            key = next(keys)
            if on_key:on_key(key, screen)
            return key
        screen.getch.side_effect = getch
        curses = Mock()
        curses.error = type('CursesError', (Exception,), {})
        curses.has_colors.return_value = False
        curses.A_REVERSE = 256
        curses.KEY_UP, curses.KEY_DOWN, curses.KEY_END, curses.KEY_ENTER = 259, 258, 360, 343
        self.fw.sqlite3 = sqlite3
        self.fw.policy_draft.return_value = None
        self.fw.config.return_value = {'one': False, 'two': False}
        self.fw.ui_apply_current.return_value = None
        self.fw.live_events.side_effect = batches or (lambda *args: [])
        if not isinstance(self.fw.recent_drop_causes.return_value, list):
            self.fw.recent_drop_causes.return_value = []
        if statuses:self.fw.ui_apply_status.side_effect = statuses
        with patch.object(webui, 'control_features', return_value=[('one', 'One', 'Description'), ('two', 'Two', 'Description')]), \
             patch.object(webui, 'control_geo_items', return_value=[('off', 'Off'), ('ru_only', 'RU'), ('non_ru_only', 'Other')]), \
             patch.object(webui, 'live_health', return_value={}), patch.object(webui, 'pending_trial', return_value=None):
            tui._screen(screen, self.fw, self.fw.config(), curses)
        return screen

    def test_screen_follow_and_allow_selected(self):
        row2 = (2, self.row[1], '192.0.2.2', 80, 'tcp', 'reason', 'pass', 1)
        row3 = (3, self.row[1], '192.0.2.3', 80, 'tcp', 'reason', 'drop', 1)
        batches = iter([[self.row, row2], [row3], [], [], [], []])
        screen = self.screen_run([259, -1, ord('a'), ord('y'), ord('q')], lambda *args: next(batches))
        self.fw.change_entry.assert_called_once_with('allow', self.row[2], True)
        screen.clear.assert_called_once()
        rendered = [call.args[2] for call in screen.addnstr.call_args_list if len(call.args) > 4 and call.args[4] & 256]
        self.assertIn('192.0.2.2', rendered[0])
        self.assertTrue(any('1.2.3.4' in line for line in rendered[1:]))

    def test_screen_follow_new_and_apply_cancel(self):
        row2 = (2, self.row[1], '192.0.2.2', 80, 'tcp', 'reason', 'pass', 1)
        batches = iter([[self.row], [row2], [], [], [], []])
        screen = self.screen_run([-1, ord('a'), ord('y'), ord('2'), 10, ord('n'), ord('q')], lambda *args: next(batches, []))
        self.fw.change_entry.assert_called_once_with('allow', row2[2], True)
        self.fw.ui_apply_start.assert_not_called()

    def test_screen_apply_completion_reset_and_no_duplicate(self):
        self.fw.ui_apply_start.return_value = 'job'
        self.fw.config.side_effect = [{'one': False}, {'one': True}]
        statuses = [{'status': 'checking', 'percent': 30}, {'status': 'finished', 'percent': 100, 'message': 'Finished'}]
        screen = self.screen_run([ord('2'), ord(' '), 10, ord('y'), 10, 27, ord('q')], statuses=statuses)
        self.fw.ui_apply_start.assert_called_once_with({'one': True, 'two': False, 'geo_choice': 'off'}, None)
        self.assertEqual(self.fw.ui_apply_status.call_count, 2)
        self.assertTrue(any('[x] One' in c.args[2] for c in screen.addnstr.call_args_list))

    def test_screen_errors_and_count(self):
        self.fw.change_entry.side_effect = sqlite3.OperationalError('database error')
        self.fw.recent_drop_causes.return_value = list(range(1000))
        screen = self.screen_run([ord('b'), ord('y'), ord('q')], lambda *args: [self.row] if args[0] == 0 else [])
        self.fw.recent_drop_causes.assert_called_once_with(limit=1000, hours=24)
        self.assertTrue(any('1000+' in c.args[2] for c in screen.addnstr.call_args_list))
        self.assertTrue(any('database error' in c.args[2] for c in screen.addnstr.call_args_list))
        screen.clear.assert_called_once()

    def test_apply_timeout_is_displayed(self):
        self.fw.ui_apply_start.side_effect = subprocess.TimeoutExpired('apply', 1)
        screen = self.screen_run([ord('2'), 10, ord('y'), ord('q')])
        self.assertTrue(any('timed out' in c.args[2] for c in screen.addnstr.call_args_list))

    def test_no_change_status(self):
        self.fw.change_entry.return_value = False
        screen = self.screen_run([ord('a'), ord('y'), ord('q')], lambda *args: [self.row] if args[0] == 0 else [])
        self.assertTrue(any('No changes' in c.args[2] for c in screen.addnstr.call_args_list))

    def test_selection_survives_trimming(self):
        rows = [(i, self.row[1], '192.0.2.'+str(i), 80, 'tcp', '', 'drop', 1) for i in range(1, 501)]
        new = (501, self.row[1], '192.0.2.501', 80, 'tcp', '', 'drop', 1)
        batches = iter([rows, [new], [], [], []])
        self.screen_run([259, ord('b'), ord('y'), ord('q')], lambda *args: next(batches, []))
        self.fw.change_entry.assert_called_once_with('ban', rows[-2][2], True)


if __name__ == '__main__':
    unittest.main()
