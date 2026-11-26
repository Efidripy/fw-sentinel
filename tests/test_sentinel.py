import contextlib
from io import StringIO
import ipaddress
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import fw_sentinel as fw
import webui

class SentinelTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)
        self.oldroot=fw.ROOT;fw.ROOT=self.path;self.addCleanup(setattr,fw,'ROOT',self.oldroot)
        self.cfg={
          'wan_interfaces':['enp3s0'], 'ssh_ports':[22,2202], 'geo_enabled':True,
          'geo_ports':[443,8443], 'scanner_enabled':True, 'asn_enabled':True,
          'logging_enabled':True,'log_rate_per_sec':3,
          'ssh_rate_enabled':True,'ssh_rate_per_minute':10,'ssh_rate_burst':10,
          'min_scanner_prefix_v4':8,'min_scanner_prefix_v6':16,
          'min_ru_ipv4':1,'min_ru_ipv6':1,'max_feed_bytes':30000,'max_growth_factor':3,'min_keep_fraction':.2,
          'ui_port':1488, 'geo_tag':'ru'
        }
        (self.path/'config.json').write_text(json.dumps(self.cfg))
        (self.path/'sources.json').write_text(json.dumps({'geoip':[],'cidr':{}}))
        (self.path/'asn.txt').write_text('')
        (self.path/'allow.txt').write_text('203.0.113.1\n')
        (self.path/'manual-bans.txt').write_text('192.0.2.44\n')
        (self.path/'ui-token').write_text('abc123')
        self.sets={
          'geo':[ipaddress.ip_network('5.0.0.0/8'),ipaddress.ip_network('2001:db8::/32')],
          'scanners':[ipaddress.ip_network('198.51.100.0/24'),ipaddress.ip_network('2001:db8:abcd::/48')],
          'manual':[ipaddress.ip_network('192.0.2.44')],
          'trusted':[ipaddress.ip_network('203.0.113.1')]
        }

    def test_observe_never_drops(self):
        text=fw.render_rules(self.cfg,self.sets,enforce=False)
        self.assertNotIn(' drop',text)
        self.assertIn('FWS O_SCAN4:',text)
        self.assertIn('counter return',text)

    def test_enforce_drops_banned_geo_and_rate(self):
        text=fw.render_rules(self.cfg,self.sets,enforce=True)
        self.assertIn('counter drop',text)
        self.assertIn('th dport { 443, 8443 } ip saddr != @ru4',text)
        self.assertIn('iifname != { "enp3s0" } accept',text)
        self.assertIn('fib daddr type != local accept',text)
        self.assertIn('ct state established,related accept',text)
        self.assertIn('hook prerouting priority -150',text)
        self.assertEqual(text.count('meter fws_ssh4'),1)
        self.assertEqual(text.count('meter fws_ssh6'),1)
        self.assertIn('limit rate over 10/minute burst 10 packets',text)
        self.assertIn('jump ssh_excess',text)
        self.assertIn('log prefix "FWS D_SSH: "',text)
        self.assertLess(text.index('ip saddr @allow4 accept'),text.index('ip saddr @ban4 counter drop'))

    def test_no_global_whitelist_or_ban(self):
        (self.path/'allow.txt').write_text('0.0.0.0/0\n')
        with self.assertRaises(ValueError):fw.line_networks(self.path/'allow.txt')

    def test_overlap_no_removal_from_feed(self):
        sets={**self.sets,'trusted':[ipaddress.ip_network('198.51.100.17')]}
        text=fw.render_rules(self.cfg,sets,True)
        self.assertIn('198.51.100.0/24',text)
        self.assertIn('198.51.100.17',text)

    def test_failing_nft_change_not_persisted(self):
        old=(self.path/'manual-bans.txt').read_text()
        fw.set_state('enforce')
        with mock.patch.object(fw,'nft',side_effect=RuntimeError('simulated nft failure')):
            with self.assertRaises(RuntimeError):fw.change_entry('ban','8.8.8.8',True)
        self.assertEqual((self.path/'manual-bans.txt').read_text(),old)

    def test_change_ban_while_observe_off(self):
        fw.set_state('off')
        self.assertTrue(fw.change_entry('ban','8.8.8.8',True))
        self.assertFalse(fw.change_entry('ban','8.8.8.8',True))
        self.assertTrue(fw.change_entry('ban','8.8.8.8',False))

    def test_block_admin_rejected(self):
        (self.path/'allow.txt').write_text('8.8.8.8\n')
        with self.assertRaises(ValueError):fw.change_entry('ban','8.8.8.8')

    def test_source_growth_is_rejected_and_cache_retained(self):
        cfg=self.cfg.copy()
        f=self.path/'cache'/'sources'/'cidr_test.txt'
        f.parent.mkdir(parents=True)
        f.write_text('8.8.8.0/24\n')
        with mock.patch.object(fw,'urls_download',return_value=b'8.0.0.0/8\n'):
            nets,where,issues=fw.acquire_source('cidr_test',['https://example.com'],lambda b:fw.parse_cidr(b,8,16),cfg)
        self.assertEqual(where,'cache')
        self.assertEqual(str(nets[0]),'8.8.8.0/24')
        self.assertTrue(issues)

    def test_geoip_parser(self):
        def varint(x):
            out=[]
            while x>127:out.append((x&127)|128);x>>=7
            return bytes(out+[x])
        def f(n,b):return bytes([(n<<3)|2])+varint(len(b))+b
        cidr=f(1,bytes([8,8,8,0]))+bytes([16])+varint(24)
        entry=f(1,b'ru')+f(2,cidr)
        got=fw.parse_geoip(f(1,entry))
        self.assertEqual([str(x) for x in got],['8.8.8.0/24'])
        with self.assertRaises(ValueError):fw.parse_geoip(f(1,entry[:-3]))

    def test_kernel_log(self):
        line='Nov 25 IN=enp3s0 OUT= MAC=aa FWS D_SCAN4: IN=enp3s0 SRC=8.8.8.8 DST=1.1.1.1 PROTO=TCP SPT=23456 DPT=443'
        got=fw.parse_kernel(line)
        self.assertEqual(got[1:],('8.8.8.8',443,'TCP','SCAN4','drop'))
        self.assertIsNone(fw.parse_kernel('normal traffic SRC=8.8.8.8'))

    def test_render_does_not_flush_other_firewalls(self):
        output=fw.render_rules(self.cfg,self.sets,True)
        self.assertNotIn('flush ruleset',output)
        self.assertNotIn('delete table inet fw\n',output)

    def test_missing_watchdog_refuses_firewall_enable(self):
        fw.set_state('observe')
        fw.atomic_write(self.path/'active.nft','ORIGINAL')
        result=mock.Mock(returncode=1,stderr='systemd unavailable')
        with mock.patch.object(fw,'build_sets_from_sources',return_value=(self.sets,[],{})), \
             mock.patch.object(fw,'nft') as apply, \
             mock.patch.object(fw,'run',return_value=result):
            with self.assertRaises(RuntimeError):fw.enforce()
        # A check-only parse is allowed, but no apply should occur.
        self.assertEqual(apply.call_count,1)
        self.assertTrue(apply.call_args_list[0].kwargs.get('check_only'))
        self.assertFalse(list(self.path.glob('.pending-*')))
        self.assertEqual((self.path/'active.nft').read_text(),'ORIGINAL')
        self.assertEqual(fw.state()['mode'],'observe')

    def test_no_confirmation_restores_previous_rules(self):
        fw.set_state('observe')
        fw.atomic_write(self.path/'active.nft','ORIGINAL')
        result=mock.Mock(returncode=0,stderr='')
        with mock.patch.object(fw,'build_sets_from_sources',return_value=(self.sets,[],{})), \
             mock.patch.object(fw,'nft') as apply, \
             mock.patch.object(fw,'run',return_value=result), \
             mock.patch('select.select',return_value=([],[],[])):
            fw.enforce()
        self.assertEqual((self.path/'active.nft').read_text(),'ORIGINAL')
        self.assertEqual(fw.state()['mode'],'observe')
        self.assertGreaterEqual(apply.call_count,3)
        self.assertFalse(list(self.path.glob('.pending-*')))

    def test_policy_change_is_not_silently_applied_by_timer(self):
        fw.set_state('enforce')
        self.cfg['geo_enabled']=False
        (self.path/'config.json').write_text(json.dumps(self.cfg))
        with mock.patch.object(fw,'build_sets_from_sources',return_value=(self.sets,[],{})), \
             mock.patch.object(fw,'nft') as apply:
            with self.assertRaisesRegex(RuntimeError,'Policy settings changed'):
                fw.refresh()
        apply.assert_not_called()
        self.assertEqual(fw.state()['mode'],'enforce')

    def test_guard_does_nothing_if_off(self):
        fw.set_state('off')
        with mock.patch.object(fw,'nft') as apply:
            fw.guard()
        apply.assert_not_called()

    def test_guard_recovers_missing_table(self):
        fw.set_state('enforce')
        fw.atomic_write(self.path/'active.nft','STORED-SNAPSHOT')
        with mock.patch.object(fw,'run',return_value=mock.Mock(returncode=1)), \
             mock.patch.object(fw,'nft') as apply:
            fw.guard()
        self.assertEqual(apply.call_count,2)
        self.assertEqual(apply.call_args_list[0].args[0],'STORED-SNAPSHOT')
        self.assertTrue(apply.call_args_list[0].kwargs.get('check_only'))

    def test_web_basic_auth(self):
        old=webui.TOKEN_FILE;webui.TOKEN_FILE=self.path/'ui-token';self.addCleanup(setattr,webui,'TOKEN_FILE',old)
        self.assertEqual(len(webui.csrf()),64)
        body=webui.doc('<h2>OK</h2>')
        self.assertIn('FW SENTINEL',body)
        self.assertIn('127.0.0.1',body)
        self.assertIn('1488',body)
        self.assertNotIn('abc123',body)

if __name__=='__main__':unittest.main()
