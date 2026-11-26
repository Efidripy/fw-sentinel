"""FW Sentinel 2.0.3: color meaning, safe logging, live read-only auth, IP handling."""
import base64
import json
from http.server import ThreadingHTTPServer
import ipaddress
from pathlib import Path
import re
import sys
import tempfile
import threading
import unittest
from unittest import mock
from urllib.error import HTTPError
from urllib.request import Request, urlopen

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import fw_sentinel as fw
import webui


class RadarTests(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root=Path(self.folder.name)
        self.origroot=fw.ROOT
        self.origtoken=webui.TOKEN_FILE
        fw.ROOT=self.root
        webui.TOKEN_FILE=self.root/'ui-token'
        self.addCleanup(setattr,fw,'ROOT',self.origroot)
        self.addCleanup(setattr,webui,'TOKEN_FILE',self.origtoken)
        self.cfg=json.loads((Path(__file__).resolve().parents[1]/'config.json').read_text())
        self.cfg['wan_interfaces']=['ens3']
        (self.root/'config.json').write_text(json.dumps(self.cfg))
        (self.root/'sources.json').write_text('{"cidr":{}}')
        for name in ('allow.txt','manual-bans.txt','vpn-clients.txt','asn.txt'):
            (self.root/name).write_text('')
        webui.TOKEN_FILE.write_text('test-token')
        self.sets={k:[] for k in ('geo','scanners','manual','trusted','vpn_clients','threat_ssh','threat_watch')}
        self.sets['manual']=[ipaddress.ip_network('8.8.8.8')]
        self.sets['trusted']=[ipaddress.ip_network('1.1.1.1')]
        self.sets['vpn_clients']=[ipaddress.ip_network('9.9.9.9')]
        self.sets['scanners']=[ipaddress.ip_network('8.8.8.0/24')]

    def test_new_parsed_verdicts(self):
        line='SRC=1.1.1.1 DST=2.2.2.2 PROTO=TCP SPT=52346 DPT=443'
        for kind,expected in [('P_PASS',('PASS','pass')),('P_TRUSTED',('TRUSTED','pass')),('P_VPN',('VPN','pass')),('D_SCAN4',('SCAN4','drop')),('O_WATCH4',('WATCH4','observe'))]:
            out=fw.parse_kernel('FWS '+kind+': '+line)
            self.assertEqual(out[-2:],expected)
        self.assertIsNone(fw.parse_kernel('FWS P_PASS: SRC=not-an-ip DPT=443'))

    def test_sampling_is_passive_and_443_unlimited(self):
        output=fw.render_rules(self.cfg,self.sets,True)
        self.assertIn('tcp dport { 443, 8443 }',output)
        self.assertIn('log prefix "FWS P_PASS: "',output)
        self.assertIn('log prefix "FWS P_VPN: "',output)
        self.assertIn('log prefix "FWS P_TRUSTED: "',output)
        self.assertTrue(all('drop' not in row and 'reject' not in row for row in output.splitlines() if 'FWS P_' in row))
        self.assertNotIn('tcp dport { 443, 8443 } ct state new tcp flags syn meter',output)
        self.assertIn('tcp dport { 22 } ct state new tcp flags syn meter',output)

    def test_green_happens_after_blacklist_scan_geo_except_allow(self):
        output=fw.render_rules({**self.cfg,'geo_enabled':True},self.sets,True)
        trusted=output.index('FWS P_TRUSTED: ')
        self.assertLess(trusted,output.index('ip saddr @allow4 accept'))
        self.assertLess(output.index('ip saddr @ban4 counter drop'), output.index('FWS P_VPN: '))
        self.assertLess(output.index('FWS P_VPN: '),output.index('ip saddr @vpn4 accept'))
        self.assertLess(output.index('ip saddr @scan4 counter drop'),output.index('FWS P_PASS: '))
        self.assertLess(output.index('FWS D_GEO4'),output.index('FWS P_PASS: '))
        self.assertIn('ip saddr @ru4 limit rate 2/second',output)

    def test_looks_like_green_but_only_after_filter(self):
        output=fw.render_rules(self.cfg,self.sets,False)
        self.assertIn('ip saddr != @ban4 ip saddr != @scan4 ip saddr != @scanhost4 ip saddr != @asn4 ip saddr != @watch4 ip saddr != @watchhost4',output)
        # Existing blacklist matches can only be yellow (observe) in observer mode.
        self.assertNotIn('FWS D_SCAN4',output)

    def test_optional_and_bounded(self):
        output=fw.render_rules({**self.cfg,'live_pass_logging_enabled':False},self.sets,True)
        self.assertNotIn('FWS P_',output)
        for x in (0,11,'12',False):
            with self.assertRaisesRegex(ValueError,'live_pass_log_rate'):
                fw.render_rules({**self.cfg,'live_pass_log_rate_per_sec':x},self.sets,True)

    def test_cannot_silently_change_sampling_policy(self):
        fw.set_state('enforce')
        self.cfg['live_pass_log_rate_per_sec']=3
        self.assertNotEqual(fw.state()['policy_signature'],fw.policy_signature(self.cfg))

    def test_live_cursor_and_recent_tail(self):
        with fw.db() as con:
            for i in range(85):
                con.execute('INSERT INTO events(timestamp,ip,port,proto,reason,verdict) VALUES (?,?,?,?,?,?)',(f'2026-11-25T20:{i%60:02d}:00+00:00','1.1.1.1',443,'TCP','PASS','pass'))
        records=fw.live_events(0,60)
        self.assertEqual(len(records),60)
        self.assertEqual(records[0][0],26)
        self.assertEqual(records[-1][0],85)
        self.assertEqual([r[0] for r in fw.live_events(81,10)],[82,83,84,85])
        with self.assertRaises(ValueError):fw.live_events(-1)
        with self.assertRaises(ValueError):fw.live_events(0,10000)

    def test_live_http_auth_csp_json_and_no_changes(self):
        with fw.db() as con:
            con.execute('INSERT INTO events(timestamp,ip,port,proto,reason,verdict) VALUES (?,?,?,?,?,?)',('2026-11-25T12:00:00+00:00','4.4.4.4',443,'TCP','PASS','pass'))
        with mock.patch.object(fw,'run',return_value=mock.Mock(returncode=1)):
            server=ThreadingHTTPServer(('127.0.0.1',0),webui.Handler)
            th=threading.Thread(target=server.serve_forever,daemon=True);th.start()
            base=f'http://127.0.0.1:{server.server_port}'
            auth={'Authorization':'Basic '+base64.b64encode(b'admin:test-token').decode()}
            try:
                with self.assertRaises(HTTPError) as bad:urlopen(base+'/api/live',timeout=2)
                self.assertEqual(bad.exception.code,401)
                resp=urlopen(Request(base+'/',headers=auth),timeout=3)
                home=resp.read().decode()
                csp=resp.headers.get('Content-Security-Policy','')
                token=re.search(r'<script nonce="([A-Za-z0-9_-]+)">',home)
                self.assertTrue(token)
                self.assertIn("script-src 'nonce-"+token.group(1)+"'",csp)
                self.assertIn('LIVE TRAFFIC',home)
                self.assertIn('/api/live',home)
                api=urlopen(Request(base+'/api/live?since=0',headers=auth),timeout=3)
                self.assertEqual(api.headers.get_content_type(),'application/json')
                records=json.load(api)['events']
                self.assertEqual(len(records),1)
                self.assertEqual(records[0]['verdict'],'pass')
                self.assertEqual(records[0]['ip'],'4.4.4.4')
                with self.assertRaises(HTTPError) as err:urlopen(Request(base+'/api/live?since=-1',headers=auth),timeout=3)
                self.assertEqual(err.exception.code,400)
                self.assertFalse((self.root/'active.nft').exists())
            finally:
                server.shutdown();server.server_close();th.join(timeout=3)


if __name__=='__main__':unittest.main()
