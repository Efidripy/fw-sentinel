"""English by default, Russian only when chosen."""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import fw_sentinel as fw
import i18n
import webui


class Language(unittest.TestCase):
    def test_default_choice_and_garbage(self):
        forced, i18n.FORCED = i18n.FORCED, None
        try:
            with tempfile.TemporaryDirectory() as tmp:
                i18n.load(tmp)
                self.assertEqual(i18n.tr('yes', 'да'), 'yes')
                i18n.save(tmp, 'ru')
                self.assertEqual(i18n.tr('yes', 'да'), 'да')
                with self.assertRaises(ValueError):
                    i18n.save(tmp, 'xx')
                (Path(tmp) / 'ui-language').write_text('zz')
                i18n.load(tmp)
                self.assertEqual(i18n.language(), 'en')
        finally:
            i18n.FORCED = forced

    def test_english_pages_have_no_cyrillic(self):
        repo = Path(fw.__file__).parent
        no_nft = lambda *a, **k: subprocess.CompletedProcess(a, 1, '', '')
        with tempfile.TemporaryDirectory() as tmp:
            for name in ('config.json', 'sources.json', 'asn.txt', 'allow.txt', 'manual-bans.txt', 'vpn-clients.txt'):
                shutil.copy(repo / name, Path(tmp) / name)
            (Path(tmp) / 'ui-token').write_text('strong12letters')
            with mock.patch.object(fw, 'ROOT', Path(tmp)), mock.patch.object(fw, 'run', no_nft),                  mock.patch.object(webui, 'TOKEN_FILE', Path(tmp) / 'ui-token'), mock.patch.object(i18n, 'FORCED', 'en'):
                pages = (webui.overview(), webui.events_page({}), webui.access_page(), webui.sources_page(),
                         webui.control_page(), webui.recovery_page())
        for page in pages:
            # the button that switches to Russian is named in Russian on purpose
            self.assertEqual(re.findall('[Ѐ-ӿ]+', page.replace('Русский', '')), [])


if __name__ == '__main__':
    unittest.main()
