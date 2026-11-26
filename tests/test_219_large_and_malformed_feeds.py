"""2.0.19: large NERD Scan lists and isolated invalid ThreatView rows."""
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
import fw_sentinel as fw


class LargeFeedFix219(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        old=fw.ROOT;fw.ROOT=self.root;self.addCleanup(setattr,fw,'ROOT',old)
        repo=Path(__file__).resolve().parents[1]
        (self.root/'config.json').write_text((repo/'config.json').read_text())
        (self.root/'sources.json').write_text((repo/'sources.json').read_text())
        self.cfg=fw.config()
        self.nerd=fw.sources()['advanced_feeds']['nerd_scan']
        self.threatview=fw.sources()['advanced_feeds']['threatview_high']

    def test_nerd_scan_can_parse_over_300k_lines(self):
        count=320001
        # /32s in 52.0.0.0/8; enough unique IPs to exceed old row limit.
        data='\n'.join(f'52.{i>>16}.{(i>>8)&255}.{i&255}' for i in range(count)).encode()
        start=time.monotonic()
        nets,ignored=fw.parse_advanced_source(data,self.nerd,self.cfg)
        self.assertEqual(len(nets),count)
        self.assertEqual(ignored,[])
        self.assertLess(time.monotonic()-start,18,'large feed parser unusually slow')
        self.assertEqual(str(nets[-1]),'52.4.226.0/32')

    def test_nerd_scan_has_source_specific_limit_and_other_feeds_stay_strict(self):
        data=b'8.8.8.8\n'*(fw.MAX_ADVANCED_LINES+1)
        with self.assertRaisesRegex(ValueError,'too many CIDR entries'):
            fw.parse_advanced_source(data,self.nerd,self.cfg)
        with self.assertRaisesRegex(ValueError,'too many CIDR entries'):
            fw.parse_advanced_source(b'8.8.8.8\n'*(fw.MAX_LINES+1),{'format':'cidr'},self.cfg)

    def test_threatview_invalid_row_skipped_not_parsed_as_wrong_ip(self):
        lines=b'8.8.8.8\n120.229.26.013\n1.1.1.1\n2001:4860:4860::8888\n'
        nets,ignored=fw.parse_advanced_source(lines,self.threatview,self.cfg)
        self.assertEqual([str(x) for x in nets],['8.8.8.8/32','1.1.1.1/32','2001:4860:4860::8888/128'])
        self.assertEqual(ignored.invalid_count,1)
        self.assertIn('120.229.26.013',ignored.invalid_samples[0])
        self.assertNotIn('120.229.26.13/32',[str(x) for x in nets], 'do not guess intended host')

    def test_download_succeeds_with_one_bad_and_records_warning(self):
        data=b'8.8.8.8\n120.229.26.013\n1.1.1.1\n'
        with mock.patch.object(fw,'urls_download',return_value=data):
            networks,origin,issues=fw.acquire_source('advanced_threatview_high',
                [self.threatview['url']],lambda body:fw.parse_advanced_source(body,self.threatview,self.cfg),self.cfg)
        self.assertEqual(origin,'fresh')
        self.assertIn('malformed IP/CIDR rows skipped: 1',' '.join(issues))
        self.assertEqual(len(networks),2)
        path=self.root/'cache/sources/advanced_threatview_high.txt'
        self.assertIn('8.8.8.8/32',path.read_text())
        self.assertNotIn('120.229.26.013',path.read_text())
        self.assertEqual(json.loads(path.with_suffix('.meta.json').read_text())['count'],2)

    def test_mostly_broken_threatview_refused_existing_cache_kept(self):
        cache=self.root/'cache/sources/advanced_threatview_high.txt'
        cache.parent.mkdir(parents=True,exist_ok=True)
        cache.write_text('8.8.8.8/32\n')
        cache.with_suffix('.meta.json').write_text(json.dumps({'count':1,'updated':fw.now()}))
        bad=b'10.10.10.010\n'*40+b'1.1.1.1\n'
        with mock.patch.object(fw,'urls_download',return_value=bad):
            nets,origin,issues=fw.acquire_source('advanced_threatview_high',
                [self.threatview['url']],lambda body:fw.parse_advanced_source(body,self.threatview,self.cfg),self.cfg)
        self.assertEqual(origin,'cache')
        self.assertEqual([str(n) for n in nets],['8.8.8.8/32'])
        self.assertIn('too many invalid CIDR rows',' '.join(issues))
        self.assertEqual(cache.read_text(),'8.8.8.8/32\n')

    def test_unrelated_sources_still_reject_malformed_ip(self):
        with self.assertRaises(ValueError):
            fw.parse_advanced_source(b'8.8.8.8\n120.229.26.013\n',{'format':'cidr'},self.cfg)

    def test_large_cache_meta_is_visible_without_reading_bulk_networks(self):
        path=self.root/'cache/sources/advanced_nerd_scan.txt'
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text('8.8.8.8/32\n')
        path.with_suffix('.meta.json').write_text(json.dumps({'count':380000,'updated':fw.now()}))
        with mock.patch.object(fw,'line_networks',side_effect=AssertionError('Do not parse 380k IPs for status')):
            status=fw.advanced_source_status()
        self.assertEqual(status['nerd_scan']['count'],380000)

    def test_selected_sync_preserves_firewall_and_existing_policy(self):
        data=b'8.8.8.8\n120.229.26.013\n1.1.1.1\n'
        with mock.patch.object(fw,'urls_download',return_value=data),\
             mock.patch.object(fw,'nft',side_effect=AssertionError('feed sync may not mutate nft')):
            with contextlib.redirect_stderr(io.StringIO()):
                result=fw.prepare_advanced_feeds('threatview_high')
        self.assertEqual(result['threatview_high']['status'],'fresh')
        self.assertIn('malformed IP/CIDR rows skipped: 1',result['threatview_high']['issues'][0])
        st=fw.advanced_source_status()['threatview_high']
        self.assertEqual(st['count'],2)
        self.assertIn('malformed IP/CIDR rows skipped: 1',st['last_warning'])
        self.assertEqual(st['last_error'],'')

if __name__=='__main__':unittest.main()
