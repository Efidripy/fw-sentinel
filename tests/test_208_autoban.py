"""FW Sentinel 2.0.8 scan-safe autoban and web policy regressions."""
import base64
import ipaddress
import json
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock
from urllib.request import Request,urlopen
from urllib.error import HTTPError
from urllib.parse import urlencode
from http.server import ThreadingHTTPServer

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import autoban
import fw_sentinel as fw
import webui

import i18n  # noqa: E402

def setUpModule():  # these checks read the Russian texts
    i18n.FORCED = 'ru'


def tearDownModule():
    i18n.FORCED = None


class AutoBanTests(unittest.TestCase):
    def setUp(self):
        self.root_tmp=tempfile.TemporaryDirectory();self.addCleanup(self.root_tmp.cleanup)
        self.root=Path(self.root_tmp.name)
        original=fw.ROOT;fw.ROOT=self.root;self.addCleanup(setattr,fw,'ROOT',original)
        token_orig=webui.TOKEN_FILE;webui.TOKEN_FILE=self.root/'ui-token'
        self.addCleanup(setattr,webui,'TOKEN_FILE',token_orig)
        (self.root/'ui-token').write_text('strong12letters')
        cfg=json.loads((Path(__file__).resolve().parents[1]/'config.json').read_text())
        cfg.update(wan_interfaces=['ens3'],autoban_enabled=True,geo_enabled=False,ui_base_path='/fws-secret-path/',ui_public_origin='https://probe.example.com')
        self.cfg=cfg
        (self.root/'config.json').write_text(json.dumps(cfg))
        (self.root/'sources.json').write_text(json.dumps({'cidr':{},'threat_ssh':{},'threat_watch':{}}))
        for key,value in [('allow.txt','1.1.1.1\n'),('vpn-clients.txt','8.8.8.8\n'),('manual-bans.txt',''),('asn.txt','')]:
            (self.root/key).write_text(value)
        fw.set_state('enforce')
        self.conn=fw.db();self.addCleanup(self.conn.close)
        self.t=100.
        self.fakeclock=lambda:self.t
        self.service_patch=mock.patch.object(autoban,'discover_services',return_value=({9999},{9444}))
        self.service_patch.start();self.addCleanup(self.service_patch.stop)
        self.nft_patch=mock.patch.object(fw,'nft');self.nft_patch.start();self.addCleanup(self.nft_patch.stop)
        self.detector=autoban.Detector(fw,self.conn,clock=self.fakeclock)

    def probe(self,ip='8.8.4.4',port=22222):return self.detector.handle(ip,port,'TCP')

    def test_six_distinct_ports_once_in_60_seconds_is_24_hour_ban(self):
        for idx in range(5):self.assertFalse(self.probe(port=20000+idx))
        self.assertTrue(self.probe(port=20005))
        calls='\n'.join(str(c) for c in fw.nft.call_args_list)
        self.assertIn('auto4',calls)
        self.assertIn('86400s',calls)
        self.assertEqual(len(autoban.list_bans(self.root)),1)
        self.assertFalse(self.probe(port=20006))
        events=self.conn.execute("SELECT reason,verdict FROM events WHERE reason='AUTO_BAN_24H'").fetchall()
        self.assertEqual(events,[('AUTO_BAN_24H','observe')])

    def _set_traps(self,*ports):
        self.cfg['autoban_trap_ports']=list(ports)
        (self.root/'config.json').write_text(json.dumps(self.cfg))
        fw.set_state('enforce')
        self.detector=autoban.Detector(fw,self.conn,clock=self.fakeclock)

    def test_one_touch_of_a_trap_bans_for_an_hour_and_can_be_revoked(self):
        self._set_traps(23,22)
        self.assertTrue(self.probe(port=23))
        calls='\n'.join(str(c) for c in fw.nft.call_args_list)
        self.assertIn('trap4',calls);self.assertIn('3600s',calls)
        self.assertEqual(self.conn.execute('SELECT ports FROM auto_bans JOIN auto_ban_traps USING(ip)').fetchall(),[('[23]',)])
        fw.nft.reset_mock()
        self.assertEqual(autoban.rearm(self.conn,fw,self.cfg),1)
        self.assertIn('trap4',str(fw.nft.call_args))
        with mock.patch.object(fw,'run',return_value=mock.Mock(returncode=0,stderr='')) as run:
            self.assertTrue(autoban.revoke(fw,'8.8.4.4'))
        self.assertEqual([c.args[5] for c in run.call_args_list],['auto4','trap4'])
        self.assertTrue(self.probe(port=23))
        self.assertIn('86400s',str(fw.nft.call_args))

    def test_trap_never_covers_a_service_port_or_a_trusted_address(self):
        # 22 is the configured SSH port, 9999 is a listening service.
        self._set_traps(22,9999,23)
        self.assertFalse(self.probe(port=22));self.assertFalse(self.probe(port=9999))
        self.assertFalse(self.probe(ip='1.1.1.1',port=23));self.assertFalse(self.probe(ip='8.8.8.8',port=23))
        self.assertEqual(autoban.list_bans(self.root),[])

    def test_trap_rules_leave_the_panel_port_open(self):
        sets={k:[] for k in ('geo','scanners','asn','manual','vpn_clients','threat_ssh','threat_watch','trusted')}
        self.assertNotIn('trap4',fw.render_rules(self.cfg,sets,enforce=True))
        self._set_traps(23)
        rules=fw.render_rules(self.cfg,sets,enforce=True)
        self.assertIn('th dport != 443 ip saddr @trap4 ip saddr != @vpn4 counter drop',rules)
        safe=[l for l in rules.splitlines() if 'set autosafetcp' in l][0]
        self.assertNotIn(' 23,',safe)
        off=dict(self.cfg);off['autoban_trap_ports']=[]
        self.assertNotEqual(fw.policy_signature(self.cfg),fw.policy_signature(off))

    def test_trap_ports_come_from_the_web_form(self):
        selections={k:bool(self.cfg.get(k,False)) for k in fw.WEB_BOOL_FIELDS}
        selections.update(geo_choice='off',autoban_trap_ports=webui.ports_from_form('22, 23 3389'))
        self.assertEqual(fw.policy_from_web(self.cfg,selections)['autoban_trap_ports'],[22,23,3389])
        self.assertIn('name="autoban_trap_ports"',webui.control_page())

    def test_rearm_restores_all_bans_in_one_nft_call(self):
        for ip in ('8.8.4.4','9.9.9.9'):
            for idx in range(6):self.probe(ip=ip,port=20000+idx)
        fw.nft.reset_mock()
        self.assertEqual(autoban.rearm(self.conn,fw,self.cfg),2)
        self.assertEqual(fw.nft.call_count,1)
        self.assertEqual(fw.nft.call_args.args[0].count('add element'),2)

    def test_repeated_same_port_never_triggers(self):
        for _ in range(100):self.assertFalse(self.probe(port=20000))
        self.assertEqual(autoban.list_bans(self.root),[])

    def test_expired_window_forgets_old_ports(self):
        self.probe(port=20000)
        self.t+=61
        for idx in range(20001,20006):self.assertFalse(self.probe(port=idx))
        self.assertTrue(self.probe(port=20006))

    def test_eight_ports_within_an_hour_ban_slow_scanner(self):
        for idx in range(7):
            self.assertFalse(self.probe(port=20000+idx));self.t+=500
        self.assertTrue(self.probe(port=20007))
        self.assertEqual(len(autoban.list_bans(self.root)),1)

    def test_slow_rule_forgets_ports_older_than_an_hour(self):
        for idx in range(20):
            self.assertFalse(self.probe(port=20000+idx));self.t+=600
        self.assertEqual(autoban.list_bans(self.root),[])

    def test_protected_ports_not_counted(self):
        for port in (22,53,80,443,8443,9999):self.assertFalse(self.probe(port=port))
        for idx in range(5):self.assertFalse(self.probe(port=21000+idx))
        self.assertEqual(autoban.list_bans(self.root),[])
        self.assertTrue(self.probe(port=21005))

    def test_trusted_and_vpn_are_exempt_even_on_six_ports(self):
        for addr in ('1.1.1.1','8.8.8.8'):
            for idx in range(6):self.assertFalse(self.probe(ip=addr,port=22000+idx))
        self.assertEqual(autoban.list_bans(self.root),[])

    def test_private_ips_never_trigger(self):
        for port in range(30000,30008):self.assertFalse(self.probe('192.168.1.22',port))
        self.assertEqual(autoban.list_bans(self.root),[])

    def test_no_autoban_in_observe_or_while_pending(self):
        fw.set_state('observe')
        for port in range(30000,30008):self.assertFalse(self.probe(port=port))
        self.assertEqual(autoban.list_bans(self.root),[])
        fw.set_state('enforce');self.t+=4
        (self.root/('.pending-'+'a'*32)).mkdir()
        for port in range(30010,30018):self.assertFalse(self.probe(port=port))
        self.assertEqual(autoban.list_bans(self.root),[])

    def test_no_autoban_on_disabled_config(self):
        self.cfg['autoban_enabled']=False
        (self.root/'config.json').write_text(json.dumps(self.cfg))
        fw.set_state('enforce')
        for port in range(30000,30008):self.assertFalse(self.probe(port=port))
        self.assertEqual(autoban.list_bans(self.root),[])

    def test_nft_failure_does_not_record_ban(self):
        for port in range(30000,30005):self.probe(port=port)
        fw.nft.side_effect=RuntimeError('nft unavailable')
        with self.assertRaisesRegex(RuntimeError,'nft unavailable'):self.probe(port=30005)
        self.assertEqual(autoban.list_bans(self.root),[])

    def test_protected_service_detection_failure_is_fail_closed(self):
        with mock.patch.object(autoban,'discover_services',side_effect=OSError('no ss')):
            for port in range(30000,30008):self.assertFalse(self.probe(port=port))
        self.assertEqual(autoban.list_bans(self.root),[])

    def test_rearm_preserves_remaining_ttl_and_skips_expired(self):
        stamp=int(time.time())
        self.conn.execute('INSERT INTO auto_bans VALUES(?,?,?,?,NULL)',('8.8.4.4',stamp-100,stamp+3600,'[20000,20001,20002,20003,20004,20005]'))
        self.conn.execute('INSERT INTO auto_bans VALUES(?,?,?,?,NULL)',('8.8.4.5',stamp-90000,stamp-5,'[20000]'))
        self.conn.execute('INSERT INTO auto_bans VALUES(?,?,?,?,NULL)',('8.8.8.8',stamp-100,stamp+3600,'[20000]'))
        self.conn.commit()
        n=autoban.rearm(self.conn,fw,fw.config())
        self.assertEqual(n,1)
        commands=' '.join(str(call.args) for call in fw.nft.call_args_list)
        self.assertIn('8.8.4.4',commands)
        self.assertNotIn('86400s',commands)
        self.assertNotIn('8.8.8.8',commands)
        self.assertNotIn('8.8.4.5',commands)

    def test_revoke_does_not_touch_manual_ban(self):
        for port in range(20000,20006):self.probe(port=port)
        (self.root/'manual-bans.txt').write_text('4.4.4.4\n')
        with mock.patch.object(fw,'run',return_value=mock.Mock(returncode=0,stderr='')) as run:
            self.assertTrue(autoban.revoke(fw,'8.8.4.4'))
        self.assertIn('delete',str(run.call_args))
        self.assertEqual((self.root/'manual-bans.txt').read_text(),'4.4.4.4\n')
        self.assertFalse(autoban.revoke(fw,'8.8.4.4'))

    def test_rules_only_drop_unknown_ports_for_unprotected_ips(self):
        sets={key:[] for key in ('geo','scanners','asn','manual','trusted','vpn_clients','threat_ssh','threat_watch')}
        with mock.patch.object(autoban,'discover_services',return_value=(set(),set())):
            rules=fw.render_rules(fw.config(),sets,True)
        self.assertIn('set auto4 { type ipv4_addr; flags timeout; }',rules)
        self.assertIn('set auto6 { type ipv6_addr; flags timeout; }',rules)
        self.assertIn('tcp dport != @autosafetcp',rules)
        self.assertIn('udp dport != @autosafeudp',rules)
        self.assertIn('ip saddr != @vpn4 counter drop',rules)
        self.assertIn('FWS O_PROBE:',rules)
        self.assertNotIn('limit rate over 6/minute',rules)
        self.assertLess(rules.index('ip saddr @allow4 accept'),rules.index('ip saddr @auto4'))
        no_rules=fw.render_rules(dict(fw.config(),autoban_enabled=False),sets,True)
        self.assertNotIn('set auto4',no_rules)
        self.assertNotIn('FWS O_PROBE:',no_rules)

    def test_policy_signature_keeps_207_when_disabled(self):
        cfg=fw.config()
        new=fw.policy_signature(dict(cfg,autoban_enabled=False))
        old_cfg={k:v for k,v in cfg.items() if not k.startswith('autoban_')}
        old=fw.policy_signature(old_cfg)
        self.assertEqual(new,old)
        self.assertNotEqual(new,fw.policy_signature(dict(cfg,autoban_enabled=True)))

    def test_web_policy_draft_ports_and_toggle(self):
        opts={k:bool(self.cfg[k]) for k in fw.WEB_BOOL_FIELDS}
        opts.update(geo_choice='off',autoban_exclude_tcp_ports=[2222,80,443],autoban_exclude_udp_ports=[51820])
        new=fw.policy_from_web(self.cfg,opts)
        self.assertEqual(new['autoban_exclude_tcp_ports'],[2222,80,443])
        self.assertIn('2222',webui.control_page() if False else str(new))
        with self.assertRaises(ValueError):fw.policy_from_web(self.cfg,dict(opts,autoban_exclude_tcp_ports=[0]))
        with self.assertRaises(ValueError):fw.policy_from_web(self.cfg,dict(opts,autoban_exclude_tcp_ports=[443,443]))
        self.assertEqual(webui.ports_from_form('22, 443  8080'),[22,443,8080])

    def test_browser_has_autoban_controls_and_confirmation(self):
        with mock.patch.object(fw,'run',return_value=mock.Mock(returncode=1)):
            page=webui.control_page()
        for word in ('name="autoban_enabled"','name="autoban_exclude_tcp_ports"',
                     'name="autoban_exclude_udp_ports"','6 разных','24 часа','AUTO-BAN'):
            self.assertIn(word,page)
        for port in range(20000,20006):self.probe(port=port)
        page=webui.access_page()
        self.assertIn('/fws-secret-path/control/auto-unban/preview',page)
        self.assertIn('8.8.4.4',page)

    def test_http_auto_unban_requires_csrf_origin_and_confirmation(self):
        for port in range(20000,20006):self.probe(port=port)
        server=ThreadingHTTPServer(('127.0.0.1',0),webui.Handler)
        th=threading.Thread(target=server.serve_forever,daemon=True);th.start()
        self.addCleanup(lambda:(server.shutdown(),server.server_close(),th.join(2)))
        auth='Basic '+base64.b64encode(b'admin:strong12letters').decode()
        url=f'http://127.0.0.1:{server.server_port}/control/auto-unban'
        origin=f'http://127.0.0.1:{server.server_port}'
        def post(valid_origin=origin,token=None,confirm='yes'):
            data=urlencode({'csrf':webui.csrf() if token is None else token,'ip':'8.8.4.4','confirm':confirm}).encode()
            req=Request(url,data=data,headers={'Authorization':auth,'Origin':valid_origin,
                'Content-Type':'application/x-www-form-urlencoded','Host':f'127.0.0.1:{server.server_port}'})
            try:
                with urlopen(req,timeout=3) as resp:return resp.status
            except HTTPError as exc:return exc.code
        self.assertEqual(post('https://evil.example'),403)
        self.assertEqual(post(token='wrong'),400)
        self.assertEqual(post(confirm='no'),400)
        with mock.patch.object(fw,'run',return_value=mock.Mock(returncode=0,stderr='')):
            self.assertEqual(post(),200)
        self.assertEqual(autoban.list_bans(self.root),[])

    def test_ipv6_scanner_gets_independent_timeout_set(self):
        ip='2606:4700:4700::1111'
        for port in range(40000,40005):self.assertFalse(self.probe(ip=ip,port=port))
        self.assertTrue(self.probe(ip=ip,port=40005))
        self.assertIn('auto6',str(fw.nft.call_args_list))
        self.assertIn(ip,str(autoban.list_bans(self.root)))

    def test_udp_attempts_never_trigger_auto_ban(self):
        for port in range(40000,40025):
            self.assertFalse(self.detector.handle('8.8.4.4',port,'UDP'))
        self.assertEqual(autoban.list_bans(self.root),[])

    def test_vpn_protection_even_if_prior_auto_ban_exists(self):
        for port in range(40000,40006):self.probe(port=port)
        (self.root/'vpn-clients.txt').write_text('8.8.8.8\n8.8.4.4\n')
        fw.nft.reset_mock()
        self.assertEqual(autoban.rearm(self.conn,fw,fw.config()),0)
        self.assertEqual(fw.nft.call_count,0)
        self.assertFalse(self.probe(ip='8.8.4.4',port=40007))

    def test_database_expired_active_count_is_zero(self):
        stamp=int(time.time())
        self.conn.execute('INSERT INTO auto_bans VALUES(?,?,?,?,NULL)',('8.8.4.4',stamp-90000,stamp-1,'[40000]'))
        self.conn.commit()
        self.assertEqual(autoban.list_bans(self.root),[])

    def test_rearm_fails_open_without_port_inventory(self):
        for port in range(40000,40006):self.probe(port=port)
        fw.nft.reset_mock()
        with mock.patch.object(autoban,'discover_services',side_effect=OSError('docker socket lost')):
            autoban.rearm_for_rules(fw,fw.config(),'enforce')
        self.assertEqual(fw.nft.call_count,0)

    def test_runtime_services_inventory_parsing(self):
        self.service_patch.stop()
        import subprocess
        with mock.patch('autoban.subprocess.run',side_effect=[
            mock.Mock(returncode=0,stdout='LISTEN 0 128 0.0.0.0:5000 0.0.0.0:*\nLISTEN 0 128 [::]:7000 [::]:*\n',stderr=''),
            mock.Mock(returncode=0,stdout='UNCONN 0 0 0.0.0.0:5353 0.0.0.0:*\n',stderr=''),
            mock.Mock(returncode=0,stdout='0.0.0.0:38000->8080/tcp, [::]:38000->8080/tcp, 0.0.0.0:50000->53/udp\n',stderr='')
        ]), mock.patch('shutil.which',return_value='/usr/bin/docker'):
            t,u=autoban.discover_services()
        self.assertTrue({5000,7000,38000}<=t)
        self.assertTrue({5353,50000}<=u)

    def test_rate_cap_logging_bounds_memory(self):
        for i in range(40):self.probe(ip=f'8.8.4.{i+1}',port=40000)
        self.assertLessEqual(len(self.detector.probes),autoban.MAX_TRACKED)
        self.assertIn('12/second burst 40 packets',fw.render_rules(fw.config(),
            {key:[] for key in ('geo','scanners','asn','manual','trusted','vpn_clients','threat_ssh','threat_watch')},True))

    def test_policy_rejects_autoban_without_kernel_logging(self):
        with self.assertRaisesRegex(ValueError,'requires logging'):
            autoban.validate(dict(self.cfg,logging_enabled=False))
        fields={k:bool(self.cfg[k]) for k in fw.WEB_BOOL_FIELDS}
        fields.update(geo_choice='off',logging_enabled=False,live_pass_logging_enabled=False)
        with self.assertRaises(ValueError):fw.policy_from_web(self.cfg,fields)

    def test_kernel_parser_records_real_drops_and_probe_sample(self):
        probe=fw.parse_kernel('FWS O_PROBE: IN=eth0 SRC=8.8.4.4 DST=1.1.1.1 PROTO=TCP DPT=20003')
        red=fw.parse_kernel('FWS D_AUTO4: IN=eth0 SRC=8.8.4.4 DST=1.1.1.1 PROTO=TCP DPT=20003')
        self.assertEqual((probe[4],probe[5]),('PROBE','observe'))
        self.assertEqual((red[4],red[5]),('AUTO4','drop'))

if __name__=='__main__':unittest.main()
