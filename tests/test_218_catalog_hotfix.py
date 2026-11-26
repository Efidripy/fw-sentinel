"""Regression for 2.0.17 sync hang and partial-sync diagnostics."""
import contextlib
import datetime as dt
import io
import ipaddress
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock
from types import SimpleNamespace
import fw_sentinel as fw

import i18n  # noqa: E402

def setUpModule():  # these checks read the Russian texts
    i18n.FORCED = 'ru'


def tearDownModule():
    i18n.FORCED = None


class CatalogHotfix218(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        prev=fw.ROOT;fw.ROOT=self.root;self.addCleanup(setattr,fw,'ROOT',prev)
        repo=Path(__file__).resolve().parents[1]
        (self.root/'config.json').write_text((repo/'config.json').read_text())
        (self.root/'sources.json').write_text((repo/'sources.json').read_text())

    def test_single_pass_without_any_quadratic_equality(self):
        class NoCompare:
            network_address=SimpleNamespace(is_global=True)
            is_multicast=False
            def __eq__(self,other):raise AssertionError('Never compare networks to the entire public list')
        nets=[NoCompare() for _ in range(500)]
        with mock.patch.object(fw,'parse_cidr',return_value=(nets,[])):
            public,ignored=fw.parse_advanced_source(b'',{'format':'cidr'},fw.config())
        self.assertEqual(len(public),500)
        self.assertEqual(ignored,[])

    def test_large_feed_linear_time(self):
        # 25k globally routable IPs. The original O(n^2) version can hang.
        data='\n'.join(f'50.{i//65536}.{(i//256)%256}.{i%256}' for i in range(25000)).encode()
        start=time.monotonic()
        result,ignored=fw.parse_advanced_source(data,{'format':'cidr'},fw.config())
        elapsed=time.monotonic()-start
        self.assertEqual(len(result),25000)
        self.assertEqual(ignored,[])
        self.assertLess(elapsed,8.0,'CIDR parser is unexpectedly slow')

    def test_private_ips_filtered_without_list_membership(self):
        data=b'8.8.8.8\n10.10.10.10\n127.0.0.1\n1.1.1.1\n'
        public,ignored=fw.parse_advanced_source(data,{'format':'cidr'},fw.config())
        self.assertEqual([str(x) for x in public],['8.8.8.8/32','1.1.1.1/32'])
        self.assertEqual(set(ignored),{'10.10.10.10/32','127.0.0.1/32'})

    def test_selected_source_progress_and_persistent_diagnostics(self):
        output=io.StringIO()
        with mock.patch.object(fw,'acquire_source',return_value=([ipaddress.ip_network('8.8.8.8')],'fresh',[])) as download:
            with contextlib.redirect_stderr(output):
                result=fw.prepare_advanced_feeds('firehol_1')
        self.assertEqual(list(result),['firehol_1'])
        self.assertIn('[1/1] firehol_1: загрузка/проверка...',output.getvalue())
        download.assert_called_once()
        state=fw._read_advanced_sync_status()
        self.assertEqual(state['firehol_1']['status'],'fresh')
        meta=fw.advanced_source_status()['firehol_1']
        self.assertEqual(meta['last_status'],'fresh')
        self.assertEqual(meta['count'],0)  # Not actually downloaded by mocked source.

    def test_partial_error_does_not_prevent_next_source(self):
        with mock.patch.object(fw,'acquire_source',side_effect=[ValueError('HTTP 404'),([ipaddress.ip_network('8.8.8.8')],'fresh',[])]) as source:
            with contextlib.redirect_stderr(io.StringIO()):
                values=fw.prepare_advanced_feeds('misp_skipa')
            self.assertEqual(values['misp_skipa']['status'],'failed')
            self.assertIn('HTTP 404',fw.advanced_source_status()['misp_skipa']['last_error'])
        # isolated next call does not depend on previous failure
        with mock.patch.object(fw,'acquire_source',return_value=([ipaddress.ip_network('8.8.8.8')],'fresh',[])):
            with contextlib.redirect_stderr(io.StringIO()):
                values=fw.prepare_advanced_feeds('misp_groupib')
            self.assertEqual(values['misp_groupib']['status'],'fresh')
        self.assertEqual(fw.advanced_source_status()['misp_skipa']['last_status'],'failed')

    def test_keyboard_interrupt_preserves_cache_and_records_progress(self):
        p=self.root/'cache'/'sources'/'advanced_firehol_1.txt'
        p.parent.mkdir(parents=True);p.write_text('1.1.1.1/32\n')
        with mock.patch.object(fw,'acquire_source',side_effect=KeyboardInterrupt()), \
             mock.patch.object(fw,'nft',side_effect=AssertionError('No firewall modification')):
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(KeyboardInterrupt):fw.prepare_advanced_feeds('firehol_1')
        self.assertEqual(p.read_text(),'1.1.1.1/32\n')
        self.assertEqual(fw._read_advanced_sync_status()['firehol_1']['status'],'interrupted')

    def test_status_uses_metadata_not_bulk_parse_and_expires(self):
        cache=self.root/'cache'/'sources'/'advanced_firehol_1.txt'
        cache.parent.mkdir(parents=True,exist_ok=True);cache.write_text('8.8.8.8/32\n')
        meta=cache.with_suffix('.meta.json')
        meta.write_text(json.dumps({'updated':fw.now(),'count':1,'sha256':'test'}))
        with mock.patch.object(fw,'line_networks',side_effect=AssertionError('No bulk parsing in UI')):
            self.assertEqual(fw.advanced_source_status()['firehol_1']['count'],1)
        stale=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=8)).isoformat()
        meta.write_text(json.dumps({'updated':stale,'count':1}))
        self.assertEqual(fw.advanced_source_status()['firehol_1']['count'],0)

    def test_bad_source_name(self):
        with self.assertRaisesRegex(ValueError,'Неизвестная база'):
            fw.prepare_advanced_feeds('does-not-exist')

if __name__=='__main__':unittest.main()
