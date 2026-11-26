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

import i18n  # noqa: E402

def setUpModule():  # these checks read the Russian texts
    i18n.FORCED = 'ru'


def tearDownModule():
    i18n.FORCED = None


class Features202(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        old=fw.ROOT;fw.ROOT=self.root;self.addCleanup(setattr,fw,'ROOT',old)
        cfg=json.loads((Path(__file__).resolve().parents[1]/'config.json').read_text())
        cfg['wan_interfaces']=['enp3s0'];self.cfg=cfg
        (self.root/'config.json').write_text(json.dumps(cfg))
        src=json.loads((Path(__file__).resolve().parents[1]/'sources.json').read_text())
        (self.root/'sources.json').write_text(json.dumps(src))
        for file in ('manual-bans.txt','allow.txt','vpn-clients.txt','asn.txt'):
            (self.root/file).write_text('')
        (self.root/'ui-token').write_text('test-secret')
        previous_token=webui.TOKEN_FILE;webui.TOKEN_FILE=self.root/'ui-token'
        self.addCleanup(setattr,webui,'TOKEN_FILE',previous_token)
        self.sets={x:[] for x in ('geo','scanners','manual','trusted','vpn_clients','threat_ssh','threat_watch')}
        self.sets['trusted']=[ipaddress.ip_network('8.8.8.8')]
        self.sets['vpn_clients']=[ipaddress.ip_network('9.9.9.9')]
        self.sets['scanners']=[ipaddress.ip_network('9.9.9.0/24')]
        self.sets['threat_ssh']=[ipaddress.ip_network('9.9.9.9'),ipaddress.ip_network('1.1.1.1')]
        self.sets['threat_watch']=[ipaddress.ip_network('9.9.9.9'),ipaddress.ip_network('2.2.2.0/24')]
        self.sets['manual']=[ipaddress.ip_network('6.6.6.6')]
        self.sets['geo']=[ipaddress.ip_network('5.0.0.0/8')]

    def test_spamhaus_jsonl_uses_metadata(self):
        sample=b'{"cidr":"5.6.7.0/24","sblid":"SBL1"}\n{"type":"metadata","timestamp":42,"copyright":"(c) Spamhaus"}\n'
        nets, ignored=fw.parse_spamhaus_drop(sample)
        self.assertEqual(str(nets[0]),'5.6.7.0/24')
        self.assertEqual(ignored,[])
        with self.assertRaisesRegex(ValueError,'metadata'):
            fw.parse_spamhaus_drop(b'{"cidr":"5.6.7.0/24"}\n')

    def test_dshield_tsv_parsing_not_a_plain_list(self):
        txt=b'# source\n198.51.100.0\t198.51.100.255\t24\t999\tExample\n'
        ns,_=fw.parse_dshield(txt)
        self.assertEqual([str(n) for n in ns],['198.51.100.0/24'])
        with self.assertRaisesRegex(ValueError,'range mismatch'):
            fw.parse_dshield(b'198.51.100.0\t198.51.101.255\t24\n')

    def test_spamhaus_original_is_saved_with_attribution(self):
        txt=b'{"cidr":"5.6.7.0/24"}\n{"timestamp":1,"copyright":"Spamhaus Project"}\n'
        with mock.patch.object(fw,'urls_download',return_value=txt):
            n,where,issues=fw.acquire_source('threat_watch_test',['https://test'],fw.parse_spamhaus_drop,self.cfg,preserve_original=True)
        self.assertEqual(where,'fresh');self.assertEqual(issues,[])
        self.assertEqual((self.root/'cache/sources/threat_watch_test.original.jsonl').read_bytes(),txt)

    def test_spamhaus_respects_daily_fetch_interval(self):
        filename=self.root/'cache/sources/threat_watch_spamhaus_v4.txt'
        filename.parent.mkdir(parents=True)
        filename.write_text('5.6.7.0/24\n')
        (filename.parent/'threat_watch_spamhaus_v4.meta.json').write_text(
            json.dumps({'updated':fw.now(),'count':1}))
        with mock.patch.object(fw,'urls_download',side_effect=AssertionError('should not refetch')):
            n,where,issues=fw.acquire_source('threat_watch_spamhaus_v4',
                ['https://test'],fw.parse_spamhaus_drop,self.cfg,min_refresh_seconds=86400)
        self.assertEqual(where,'cache-fresh')

    def test_stale_ssh_feed_fails_open_for_user_safety(self):
        filename=self.root/'cache/sources/threat_ssh_blocklist_ssh.txt'
        filename.parent.mkdir(parents=True)
        filename.write_text('9.9.9.9\n')
        (filename.parent/'threat_ssh_blocklist_ssh.meta.json').write_text(
            json.dumps({'updated':'2020-01-01T00:00:00+00:00','count':1}))
        with mock.patch.object(fw,'urls_download',side_effect=RuntimeError('offline')):
            n,where,issues=fw.acquire_source('threat_ssh_blocklist_ssh',
                ['https://test'],lambda b:fw.parse_cidr(b),self.cfg,max_stale_hours=72)
        self.assertEqual(n,[])
        self.assertTrue(any('expired' in issue for issue in issues))
        self.assertEqual(filename.read_text(),'9.9.9.9\n')

    def test_live_list_edits_refuse_unconfirmed_policy(self):
        fw.set_state('enforce')
        source=json.loads((self.root/'sources.json').read_text())
        source['threat_watch']['added']={'url':'https://example.com','format':'cidr'}
        (self.root/'sources.json').write_text(json.dumps(source))
        with mock.patch.object(fw,'nft') as nft:
            with self.assertRaisesRegex(RuntimeError,'Policy settings changed'):
                fw.change_entry('vpn','9.9.9.9',True)
            nft.assert_not_called()
        self.assertEqual((self.root/'vpn-clients.txt').read_text(),'')

    def test_vpn_client_exempt_only_on_vpn_ports(self):
        cfg={**self.cfg,'geo_enabled':True,'threat_ssh_enforce':True}
        t=fw.render_rules(cfg,self.sets,enforce=True)
        self.assertIn('th dport { 443, 8443 } ip saddr @vpn4 accept',t)
        self.assertLess(t.index('ip saddr @ban4 counter drop'),t.index('ip saddr @vpn4 accept'))
        self.assertLess(t.index('ip saddr @scan4 counter drop'),t.index('ip saddr @vpn4 accept'))
        self.assertIn('tcp dport { 22 } ct state new ip saddr @sshbad4 counter drop',t)
        self.assertNotIn('tcp dport { 443, 8443 } ct state new ip saddr @sshbad4',t)
        self.assertIn('ip saddr @watch4 counter',t)
        self.assertNotIn('ip saddr @watch4 counter drop',t)

    def test_if_ssh_on_443_no_rate_or_ssh_reputation_for_vpn(self):
        cfg={**self.cfg,'ssh_ports':[22,443,8443],'geo_ports':[443,8443],'vpn_ports':[443,8443],'threat_ssh_enforce':True}
        t=fw.render_rules(cfg,self.sets,True)
        self.assertIn('tcp dport { 22 } ct state new',t)
        self.assertNotIn('tcp dport { 22, 443',t)
        self.assertNotIn('tcp dport { 443',t.split('  chain ssh_guard {',1)[1])
        cfg['ssh_ports']=[443]
        t=fw.render_rules(cfg,self.sets,True)
        self.assertNotIn('meter fws_ssh',t)
        self.assertNotIn('saddr @sshbad4 counter drop',t)

    def test_vpn_client_ip_cannot_be_manually_banned(self):
        (self.root/'vpn-clients.txt').write_text('9.9.9.9\n')
        with self.assertRaisesRegex(ValueError,'protected VPN'):
            fw.change_entry('ban','9.9.9.9',True)
        self.assertTrue(fw.change_entry('vpn','9.9.9.9',False))
        self.assertTrue(fw.change_entry('ban','9.9.9.9',True))

    def test_global_threat_never_drops_even_with_enforce(self):
        t=fw.render_rules({**self.cfg,'threat_ssh_enforce':True},self.sets,True)
        self.assertIn('log prefix "FWS O_WATCH4: "',t)
        self.assertNotIn('FWS D_WATCH',t)

    def test_catalog_change_requires_reconfirm_before_nightly_sync(self):
        fw.set_state('enforce')
        src=json.loads((self.root/'sources.json').read_text())
        src['threat_watch']['new_feed']={'url':'https://example.com/block.txt','format':'cidr'}
        (self.root/'sources.json').write_text(json.dumps(src))
        with mock.patch.object(fw,'build_sets_from_sources',return_value=(self.sets,[],{})),mock.patch.object(fw,'nft') as nft:
            with self.assertRaisesRegex(RuntimeError,'Policy settings changed'):fw.refresh()
            nft.assert_not_called()

    def test_vpn_audit_marks_false_positive(self):
        results=fw.audit_vpn({**self.cfg,'geo_enabled':True},self.sets)
        self.assertIn('9.9.9.9',dict(results))
        self.assertIn('scanners',dict(results)['9.9.9.9'])
        self.assertIn('outside RU geofilter',dict(results)['9.9.9.9'])

    def test_log_parser_reputation(self):
        got=fw.parse_kernel('FWS O_WATCH4: SRC=9.9.9.9 PROTO=TCP DPT=443')
        self.assertEqual(got[-2:],('WATCH4','observe'))
        got=fw.parse_kernel('FWS D_SSHREP4: SRC=9.9.9.9 PROTO=TCP DPT=22')
        self.assertEqual(got[-2:],('SSHREP4','drop'))

    def test_webui_has_vpn_client_management(self):
        (self.root/'vpn-clients.txt').write_text('9.9.9.9\n')
        html=webui.access_page()
        self.assertIn('Исключения для клиентов VPN',html)
        self.assertIn('/vpn-add',html)
        self.assertIn('/vpn-remove',html)

if __name__=='__main__':unittest.main()
