"""Compact advanced feeds and bounded nft host batches."""
import contextlib
import io
import ipaddress
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import fw_sentinel as fw


class Bulk223(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.old=fw.ROOT;fw.ROOT=self.root;self.addCleanup(setattr,fw,'ROOT',self.old)
        repo=Path(__file__).resolve().parents[1]
        self.cfg=json.loads((repo/'config.json').read_text())
        self.cfg.update(geo_enabled=False,asn_enabled=False,advanced_feed_pack_enabled=True)
        self.spec={'url':fw.NERD_SCAN_URL,'format':'cidr','enabled':True,'confidence':'scanner'}
        for name in ('manual-bans.txt','allow.txt','vpn-clients.txt','asn.txt'):
            (self.root/name).write_text('')
        (self.root/'sources.json').write_text(json.dumps({'cidr':{},'advanced_feeds':{'bulk':self.spec}}))

    def test_large_parse_cache_and_coverage(self):
        count=50001
        data=('\n'.join(f'52.{i>>16}.{(i>>8)&255}.{i&255}' for i in range(count))+'\n').encode()
        spec=self.spec
        parse=lambda b:fw.parse_advanced_source(b,spec,self.cfg,compact=True)
        with mock.patch.object(fw,'urls_download',return_value=data):
            result,used,issues=fw.acquire_source('advanced_bulk',[spec['url']],parse,self.cfg,compact=True)
        self.assertEqual(used,'fresh');self.assertFalse(issues)
        self.assertEqual(len(result.hosts),count);self.assertFalse(result.nets)
        path=self.root/'cache/sources/advanced_bulk.txt'
        self.assertEqual(len(fw.line_networks(path)),count)
        with mock.patch.object(fw,'line_networks',side_effect=AssertionError('bulk cache must stream')):
            cached=fw.source_cache_if_fresh('advanced_bulk',168,compact=True)
        self.assertEqual(cached.hosts,result.hosts)
        with mock.patch.object(fw,'urls_download',return_value=b'52.0.0.1\n'):
            retained,used,issues=fw.acquire_source('advanced_bulk',[spec['url']],parse,self.cfg,compact=True)
        self.assertEqual(used,'cache');self.assertEqual(len(retained.hosts),count)
        self.assertIn('suspicious feed coverage',str(issues))

    def test_render_batches_and_policy(self):
        hosts=set(range(int(ipaddress.IPv4Address('52.0.0.0')),int(ipaddress.IPv4Address('52.0.0.0'))+40001))
        sets={k:[] for k in ('geo','scanners','asn','manual','trusted','vpn_clients','threat_ssh','threat_watch')}
        sets.update(scanners_hosts=hosts,threat_watch_hosts={int(ipaddress.IPv4Address('8.8.8.8'))})
        self.cfg.update(wan_interfaces=['eth0'],threat_watch_enforce=True)
        rules=fw.render_rules(self.cfg,sets,True)
        self.assertIn('set scanhost4 { type ipv4_addr; }',rules)
        self.assertIn('ip saddr @scanhost4 counter drop',rules)
        self.assertIn('ip saddr @watchhost4 counter drop',rules)
        self.assertIn('ip saddr != @scanhost4',rules)
        self.assertIn('ip saddr != @watchhost4',rules)
        chunks=[x for x in rules.splitlines() if x.startswith('add element inet fw_sentinel scanhost4')]
        self.assertEqual([x.count(',')+1 for x in chunks],[20000,20000,1])
        self.assertLess(rules.index('@allow4 accept'),rules.index('@scanhost4 counter'))

    def test_nft_load_and_memory_gate(self):
        batch=('add table inet fw_sentinel\n'
               'add element inet fw_sentinel scanhost4 { 8.8.8.8, 1.1.1.1 }\n'
               'add element inet fw_sentinel watchhost4 { 9.9.9.9 }\n')
        result=mock.Mock(returncode=0,stderr='',stdout='')
        with mock.patch.object(fw,'run',return_value=result) as run, \
             mock.patch('builtins.open',mock.mock_open(read_data='MemAvailable: 1000000 kB\n')):
            fw.nft(batch);self.assertEqual(run.call_count,3)
            self.assertNotIn('add element',run.call_args_list[0].kwargs['input'])
            run.reset_mock();fw.nft(batch,check_only=True)
            self.assertEqual(run.call_count,1);self.assertIn('-c',run.call_args.args)
        with mock.patch.object(fw,'run',return_value=result) as run, \
             mock.patch('builtins.open',mock.mock_open(read_data='MemAvailable: 1 kB\n')), \
             contextlib.redirect_stderr(io.StringIO()) as err:
            fw.nft(batch);self.assertEqual(run.call_count,1)
            self.assertIn('insufficient',err.getvalue())
            self.assertIn('(3 ',fw.bulk_warning())
            # Other batches (service ports, rearmed bans) stay atomic and are never skipped.
            run.reset_mock()
            other='flush set inet fw_sentinel autosafetcp\nadd element inet fw_sentinel autosafetcp { 22 }\n'
            fw.nft(other);self.assertEqual(run.call_count,1)
            self.assertEqual(run.call_args.kwargs['input'],other)
            self.assertIn('(3 ',fw.bulk_warning())
            fw.nft('add table inet fw_sentinel\n');self.assertEqual(fw.bulk_warning(),'')
        with mock.patch.object(fw,'run',side_effect=[result,mock.Mock(returncode=1,stderr='failed',stdout='')]), \
             mock.patch('builtins.open',side_effect=OSError):
            with self.assertRaisesRegex(RuntimeError,'failed'):fw.nft(batch)

    def test_check_and_audit_find_cached_host(self):
        cache=self.root/'cache/sources/advanced_bulk.txt';cache.parent.mkdir(parents=True)
        cache.write_text('52.1.2.3/32\n')
        cache.with_suffix('.meta.json').write_text(json.dumps({'updated':fw.now(),'count':1}))
        (self.root/'vpn-clients.txt').write_text('52.1.2.3\n')
        sets,_,_=fw.build_sets_from_sources(self.cfg,False)
        self.assertEqual(fw.audit_vpn(self.cfg,sets),[('52.1.2.3',['scanners'])])
        with mock.patch.object(fw,'config',return_value=self.cfg), \
             mock.patch('sys.argv',['fw-sentinel','check','52.1.2.3']), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            fw.main()
        self.assertIn('scanners match',out.getvalue())
