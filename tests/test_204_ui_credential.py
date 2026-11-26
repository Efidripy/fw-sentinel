"""2.0.4: 250ms live polling without duplicate requests; safe UI password lifecycle."""
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import credentials
import webui

import i18n  # noqa: E402

def setUpModule():  # these checks read the Russian texts
    i18n.FORCED = 'ru'


def tearDownModule():
    i18n.FORCED = None


class PasswordTests(unittest.TestCase):
    def test_new_password_is_12_random_alphanumerics(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td)
            a, action = credentials.ensure_credentials(path)
            self.assertEqual(action, 'created')
            self.assertEqual(len(a), 12)
            self.assertTrue(a.isalnum())
            self.assertEqual((path/'ui-token').read_text().strip(), a)
            self.assertEqual(stat.S_IMODE((path/'ui-token').stat().st_mode), 0o600)
            b, action = credentials.ensure_credentials(path)
            self.assertEqual((b,action),(a,'preserved'))
            self.assertNotEqual(a, credentials.new_password())

    def test_rotates_legacy_token_exactly_once(self):
        with tempfile.TemporaryDirectory() as td:
            token = Path(td)/'ui-token'
            token.write_text('a'*43+'\n')
            new, action = credentials.ensure_credentials(Path(td))
            self.assertEqual(action,'rotated-legacy')
            self.assertEqual(len(new),12)
            self.assertNotEqual(new,'a'*43)
            same, action = credentials.ensure_credentials(Path(td))
            self.assertEqual((same,action),(new,'preserved'))

    def test_preserves_custom_secret_and_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);token=root/'ui-token'
            token.write_text('custom-user-passphrase\n')
            value,action=credentials.ensure_credentials(root)
            self.assertEqual((value,action),('custom-user-passphrase','preserved'))
            token.unlink(); token.symlink_to(root/'outside')
            with self.assertRaisesRegex(ValueError,'symlink'):
                credentials.ensure_credentials(root)

    def test_rejects_empty_token(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/'ui-token').write_text('')
            with self.assertRaisesRegex(ValueError,'empty'):
                credentials.ensure_credentials(root)


class PollingTests(unittest.TestCase):
    def test_active_250ms_only_backoff_and_sequential(self):
        script = webui.LIVE_SCRIPT
        self.assertIn('const pollMs=()=>Number(rate.value)*1000',script)
        self.assertNotIn('setInterval(',script)
        self.assertIn('if(!active()||pending)return',script)
        self.assertIn('schedule(next)',script)
        self.assertIn("document.addEventListener('visibilitychange'",script)
        self.assertIn('AbortController()',script)
        self.assertIn('RETRY_MS*2**(failures-1)',script)
        self.assertIn("status===401",script)
        self.assertNotIn('1500',script)
        self.assertIn('<option value="0.25">Обновление 0,25 сек</option>',webui.live_rate_options())
        self.assertEqual(webui.live_rate_options().count('<option'),9)

if __name__ == '__main__':
    unittest.main()
