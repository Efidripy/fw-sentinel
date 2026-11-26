"""Apply without the 120 s button only when the admin cannot be locked out."""
import ipaddress
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import fw_sentinel as fw


def nets(*values):
    return [ipaddress.ip_network(v) for v in values]


class ApplyNow(unittest.TestCase):
    CFG = {'autoban_enabled': False, 'geo_enabled': False}

    def reason(self, client, cfg=None, **sets):
        return fw.lockout_reason(client, dict(self.CFG, **(cfg or {})), sets)

    def test_safe_and_unsafe_clients(self):
        self.assertEqual(self.reason('8.8.4.4'), '')
        for bad in (None, '', 'junk', '127.0.0.1', '10.0.0.2'):
            self.assertTrue(self.reason(bad), bad)
        self.assertTrue(self.reason('8.8.4.4', scanners=nets('8.8.4.0/24')))
        self.assertTrue(self.reason('8.8.4.4', scanners_hosts={int(ipaddress.ip_address('8.8.4.4'))}))
        self.assertEqual(self.reason('8.8.4.4', trusted=nets('8.8.4.4/32'), manual=nets('8.8.4.4/32')), '')
        self.assertEqual(self.reason('8.8.4.4', threat_watch=nets('8.8.4.4/32')), '')
        self.assertTrue(self.reason('8.8.4.4', {'threat_watch_enforce': True}, threat_watch=nets('8.8.4.4/32')))

    def test_geofilter(self):
        geo = nets('8.8.4.0/24')
        self.assertEqual(self.reason('8.8.4.4', {'geo_enabled': True}, geo=geo), '')
        self.assertTrue(self.reason('1.1.1.1', {'geo_enabled': True}, geo=geo))
        self.assertTrue(self.reason('8.8.4.4', {'geo_enabled': True, 'geo_mode': 'non_ru_only'}, geo=geo))

    def run_worker(self, lockout):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(fw, 'ROOT', Path(tmp)):
            token = 'a' * 32
            fw._ui_job_save(token, {'status': 'queued', 'base_signature': 'x', 'selections': {}, 'client': '8.8.4.4'})
            trial = {'token': 'b' * 32, 'deadline': 9999999999, 'lockout': lockout}
            with mock.patch.object(fw, 'policy_signature', return_value='x'), mock.patch.object(fw, 'config', return_value={}), \
                 mock.patch.object(fw, 'web_stage'), mock.patch.object(fw, 'web_activate', return_value=trial) as activate, \
                 mock.patch.object(fw, 'web_confirm') as confirm:
                fw.ui_apply_worker(token)
            activate.assert_called_once_with('8.8.4.4')
            return confirm

    def test_panel_hides_buttons_of_a_self_confirming_apply(self):
        import webui
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(fw, 'ROOT', Path(tmp)):
            pending = Path(tmp) / ('.pending-' + 'c' * 32)
            pending.mkdir()
            (pending / 'web.json').write_text('{"deadline": 9999999999, "auto": true}')
            self.assertIsNone(webui.pending_trial())
            (pending / 'web.json').write_text('{"deadline": 9999999999, "auto": false}')
            self.assertEqual(webui.pending_trial(), ('c' * 32, 9999999999))

    def test_apply_job_reports_progress(self):
        import webui
        seen = []
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(fw, 'ROOT', Path(tmp)):
            token = 'd' * 32
            fw._ui_job_save(token, {'status': 'queued', 'created_unix': 1, 'base_signature': 'x', 'selections': {}})

            def stage(_selections):
                fw.apply_step(25, 'собираем')
                seen.append(fw.ui_apply_status(token))

            with mock.patch.object(fw, 'policy_signature', return_value='x'), mock.patch.object(fw, 'config', return_value={}), \
                 mock.patch.object(fw, 'web_stage', side_effect=stage), \
                 mock.patch.object(fw, 'web_activate', side_effect=RuntimeError('boom')):
                with self.assertRaises(RuntimeError):
                    fw.ui_apply_worker(token)
        self.assertEqual((seen[0]['status'], seen[0]['percent'], seen[0]['message']), ('checking', 25, 'собираем'))
        self.assertGreater(seen[0]['elapsed'], 0)
        self.assertIsNone(fw.PROGRESS)
        self.assertIn('data.percent', webui.UI_APPLY_PROGRESS_SCRIPT)

    def test_worker_confirms_only_when_safe(self):
        self.run_worker('').assert_called_once_with('b' * 32)
        self.run_worker('ваш IP есть в списках').assert_not_called()


if __name__ == '__main__':
    unittest.main()
