"""Routine feed clean-up is not a warning; real failures still are."""
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import fw_sentinel as fw


class QuietNotes(unittest.TestCase):
    def test_routine_notes_disappear(self):
        for text in ('advanced_blocklist_all: broad subnets omitted: 2',
                     'advanced_firehol_1: broad/non-public subnets omitted: 12',
                     'cidr_x: private/reserved networks omitted: 8',
                     "advanced_threatview_high: broad/non-public subnets omitted: 6; advanced_threatview_high: "
                     "malformed IP/CIDR rows skipped: 2 (examples 1800: '120.229.26.013'; 13231: '81.183.41.001')",
                     "advanced_threatview_high: malformed IP/CIDR rows skipped: 2 (examples 1800: '120.229"):
            self.assertEqual(fw.notable(text), '', text)

    def test_real_problems_stay(self):
        problem = 'advanced_nerd_scan: suspicious feed coverage change 10->1 (cached set preserved)'
        self.assertEqual(fw.notable('advanced_nerd_scan: broad/non-public subnets omitted: 1; ' + problem), problem)
        self.assertEqual(fw.notable('x: All source mirrors failed (NO CACHE)'), 'x: All source mirrors failed (NO CACHE)')

    def test_source_rows_use_the_same_filter(self):
        import webui
        row = {'name': 'x', 'group': 'THREAT', 'count': 1, 'enabled': True, 'updated': '',
               'error': 'x: broad subnets omitted: 2', 'warning': ''}
        repo = Path(fw.__file__).parent
        with tempfile.TemporaryDirectory() as tmp:
            for name in ('config.json', 'sources.json', 'asn.txt', 'allow.txt', 'manual-bans.txt', 'vpn-clients.txt'):
                shutil.copy(repo / name, Path(tmp) / name)
            (Path(tmp) / 'ui-token').write_text('strong12letters')
            with mock.patch.object(fw, 'ROOT', Path(tmp)),                  mock.patch.object(webui, 'TOKEN_FILE', Path(tmp) / 'ui-token'),                  mock.patch.object(fw, 'feed_refresh_catalog', return_value={'x': row}),                  mock.patch.object(fw, 'feed_refresh_status', return_value={}):
                self.assertNotIn('omitted', webui.sources_page())


if __name__ == '__main__':
    unittest.main()
