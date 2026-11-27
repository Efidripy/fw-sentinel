import ipaddress
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest import mock

import autoban
import fw_sentinel as fw


class SSHParsingTests(unittest.TestCase):
    def test_success_methods_and_global_addresses(self):
        for method in ('publickey', 'password', 'keyboard-interactive/pam'):
            line=f'Accepted {method} for root from 8.8.8.8 port 123 ssh2'
            self.assertEqual(autoban.parse_ssh(line), ('accepted', '8.8.8.8', method))
        self.assertIsNone(autoban.parse_ssh('Accepted password for root from 127.0.0.1 port 3 ssh2'))
        self.assertIsNone(autoban.parse_ssh('prefix Accepted password for root from 8.8.8.8 port 3 ssh2'))

    def test_attacker_controlled_username_uses_last_address(self):
        for prefix in ('Failed password for invalid user ', 'Invalid user '):
            suffix=' ssh2' if prefix.startswith('Failed') else ''
            line=prefix+'evil from 6.6.6.6 port 1 ssh2 from 8.8.8.8 port 22'+suffix
            self.assertEqual(autoban.parse_ssh(line), ('failed', '8.8.8.8', None))
        self.assertIsNone(autoban.parse_ssh('Invalid user x from 8.8.8.8 port 1 extra'))
        self.assertIsNone(autoban.parse_ssh('Failed password for root from 10.0.0.1 port 3 ssh2'))

    def test_validation(self):
        with self.assertRaises(ValueError):autoban.validate({'ssh_watch_enabled':True})
        with self.assertRaises(ValueError):autoban.validate({'ssh_watch_enabled':'true'})

    def test_rule_sets_without_traps(self):
        cfg={'wan_interfaces':['eth0'],'autoban_enabled':True,'ssh_watch_enabled':True}
        with mock.patch.object(autoban,'protected_ports',return_value=(set(),set())):
            rules=fw.render_rules(cfg,{k:[] for k in ('trusted','manual','scanners','geo')},True)
        for value in ('set trap4', 'set trap6', 'set sshtrust4', 'set sshtrust6', 'saddr @trap4', 'saddr @sshtrust4'):
            self.assertIn(value,rules)

    def test_trust_table_initialization(self):
        con=sqlite3.connect(':memory:')
        try:
            autoban.init_db(con)
            con.execute('INSERT INTO ssh_trust VALUES(?,?,?)',('8.8.8.8','publickey',123))
            self.assertEqual(con.execute('SELECT method FROM ssh_trust').fetchone()[0],'publickey')
        finally:con.close()


class SSHBehaviourTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        original=fw.ROOT;fw.ROOT=self.root;self.addCleanup(setattr,fw,'ROOT',original)
        cfg=json.loads((Path(__file__).resolve().parents[1]/'config.json').read_text(encoding='utf-8'))
        cfg.update(wan_interfaces=['ens3'],autoban_enabled=True,ssh_watch_enabled=True,geo_enabled=False)
        (self.root/'config.json').write_text(json.dumps(cfg))
        (self.root/'sources.json').write_text(json.dumps({'cidr':{},'threat_ssh':{},'threat_watch':{}}))
        for name,value in (('allow.txt','1.1.1.1\n'),('vpn-clients.txt',''),('manual-bans.txt','9.9.9.9\n'),('asn.txt','')):
            (self.root/name).write_text(value)
        fw.set_state('enforce')
        self.con=fw.db();self.addCleanup(self.con.close)
        for target,name,value in ((autoban,'discover_services',(set(),set())),(fw,'nft',None),
                                  (fw,'run',mock.Mock(returncode=0,stderr=''))):
            patch=mock.patch.object(target,name,return_value=value);patch.start();self.addCleanup(patch.stop)
        self.clock=100.
        self.detector=autoban.Detector(fw,self.con,clock=lambda:self.clock)

    def fail(self,ip='8.8.4.4'):return self.detector.handle(ip,0,ssh=True)

    def test_sixth_failure_bans_all_ports_for_an_hour(self):
        for _ in range(5):self.assertFalse(self.fail())
        self.assertTrue(self.fail())
        self.assertIn('trap4',str(fw.nft.call_args_list));self.assertIn('3600s',str(fw.nft.call_args_list))
        self.assertFalse(self.detector.probes)

    def test_old_failures_and_allowlisted_address_do_not_ban(self):
        for _ in range(5):self.assertFalse(self.fail())
        self.clock+=601
        self.assertFalse(self.fail())
        for _ in range(8):self.assertFalse(self.fail('1.1.1.1'))

    def test_slow_guesser_is_banned_on_the_tenth_failure_of_a_day(self):
        for _ in range(9):
            self.assertFalse(self.fail());self.clock+=1700
        self.assertTrue(self.fail())
        for _ in range(30):  # nine a day never reaches the daily limit
            self.assertFalse(self.fail('8.8.8.8'));self.clock+=10000

    def test_scan_ban_is_upgraded_by_brute_force(self):
        for port in range(20000,20006):self.detector.handle('8.8.4.4',port,'TCP')
        self.assertEqual(self.con.execute('SELECT count(*) FROM auto_ban_traps').fetchone()[0],0)
        for _ in range(5):self.fail()
        self.assertTrue(self.fail())
        self.assertEqual(self.con.execute('SELECT count(*) FROM auto_ban_traps').fetchone()[0],1)

    def test_trust_lasts_by_method_never_shrinks_and_blocks_bans(self):
        self.assertTrue(autoban.trust_ssh(fw,self.con,'8.8.4.4','publickey'))
        long_expiry=self.con.execute('SELECT expires_at FROM ssh_trust').fetchone()[0]
        self.assertTrue(autoban.trust_ssh(fw,self.con,'8.8.4.4','password'))
        self.assertEqual(self.con.execute('SELECT method,expires_at FROM ssh_trust').fetchone(),('publickey',long_expiry))
        self.assertGreater(long_expiry,time.time()+29*86400)
        for _ in range(10):self.assertFalse(self.fail())
        self.assertFalse(autoban.trust_ssh(fw,self.con,'9.9.9.9','publickey'))
        self.assertTrue(autoban.revoke_ssh_trust(fw,'8.8.4.4'))
        self.assertEqual(autoban.list_ssh_trust(self.root),[])

    def test_panel_offers_the_switch_and_plain_text(self):
        import webui
        (self.root/'ui-token').write_text('strong12letters')
        patch=mock.patch.object(webui,'TOKEN_FILE',self.root/'ui-token');patch.start();self.addCleanup(patch.stop)
        self.assertIn('name="ssh_watch_enabled"',webui.control_page())
        self.assertNotIn('???',webui.access_page())


if __name__=='__main__':unittest.main()
