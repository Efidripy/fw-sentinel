"""Regressions from the 2026-11-26 audit: rollback watchdog, lists, feeds, UI auth."""
import base64
import fcntl
import http.client
import ipaddress
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import fw_sentinel as fw
import webui

import i18n  # noqa: E402

def setUpModule():  # these checks read the Russian texts
    i18n.FORCED = 'ru'


def tearDownModule():
    i18n.FORCED = None


class Audit(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        prev=fw.ROOT;fw.ROOT=Path(tmp.name);self.addCleanup(setattr,fw,'ROOT',prev)
        cfg=json.loads((Path(__file__).resolve().parents[1]/'config.json').read_text())
        cfg.update(wan_interfaces=['ens3'])
        for name,data in {'config.json':json.dumps(cfg),
                          'sources.json':'{"cidr":{},"threat_watch":{},"threat_ssh":{}}',
                          'allow.txt':'1.1.1.1\n','manual-bans.txt':'','vpn-clients.txt':'',
                          'asn.txt':'','active.nft':'old snapshot'}.items():
            (fw.ROOT/name).write_text(data)
        fw.set_state('observe')
        self.sets={k:[] for k in ('geo','scanners','asn','manual','vpn_clients','threat_ssh','threat_watch')}
        self.sets['trusted']=[ipaddress.ip_network('1.1.1.1')]
        self.calls=[]

    def _run(self,*args,**kwargs):
        self.calls.append(args)
        return mock.Mock(returncode=0,stdout='',stderr='')

    def _stopped_timer(self):
        return any(a[:2]==('systemctl','stop') for a in self.calls)

    def _enforce(self,nft=None,select=None):
        with mock.patch.object(fw,'build_sets_from_sources',return_value=(self.sets,[],{})), \
             mock.patch.object(fw,'ssh_client',return_value=None), \
             mock.patch.object(fw,'nft',side_effect=nft), \
             mock.patch.object(fw,'run',side_effect=self._run), \
             mock.patch('select.select',side_effect=select):
            fw.enforce()

    def test_ctrl_c_during_confirmation_rolls_back(self):
        with self.assertRaises(KeyboardInterrupt):
            self._enforce(select=KeyboardInterrupt)
        self.assertFalse(list(fw.ROOT.glob('.pending-*')))
        self.assertEqual(fw.state()['mode'],'observe')

    def test_failed_rollback_keeps_watchdog_timer(self):
        def nft(batch,check_only=False):
            if batch=='old snapshot':raise RuntimeError('rollback failed')
        with self.assertRaises(RuntimeError):
            self._enforce(nft=nft,select=RuntimeError('boom'))
        self.assertTrue(list(fw.ROOT.glob('.pending-*')))
        self.assertFalse(self._stopped_timer())

    def test_web_activate_failed_rollback_keeps_watchdog_timer(self):
        def nft(batch,check_only=False):
            if not check_only:raise RuntimeError('nft down')
        draft={'candidate':fw.config(),'vpn_warnings':[]}
        with mock.patch.object(fw,'policy_draft',return_value=draft), \
             mock.patch.object(fw,'build_sets_from_sources',return_value=(self.sets,[],{})), \
             mock.patch.object(fw,'nft',side_effect=nft), \
             mock.patch.object(fw,'run',side_effect=self._run):
            with self.assertRaises(RuntimeError):fw.web_activate()
        self.assertFalse(self._stopped_timer())

    def test_failure_before_apply_never_touches_live_table(self):
        draft={'candidate':fw.config(),'vpn_warnings':[]}
        with mock.patch.object(fw,'policy_draft',return_value=draft), \
             mock.patch.object(fw,'build_sets_from_sources',return_value=(self.sets,[],{})), \
             mock.patch.object(fw,'nft'), \
             mock.patch.object(fw,'run',side_effect=self._run), \
             mock.patch.object(fw,'atomic_write',side_effect=OSError('disk full')):
            with self.assertRaises(OSError):fw.web_activate()
        self.assertFalse(any(a[:2]==('nft','delete') for a in self.calls))
        self.assertTrue((fw.ROOT/'active.nft').exists())
        self.assertFalse(list(fw.ROOT.glob('.pending-*')))

    def test_remove_matches_non_canonical_ipv6_line(self):
        fw.set_state('off')
        (fw.ROOT/'manual-bans.txt').write_text('2606:4700:4700:0:0:0:0:1111  # typed by hand\n')
        self.assertTrue(fw.change_entry('ban','2606:4700:4700::1111',False))
        self.assertEqual(fw.line_networks(fw.ROOT/'manual-bans.txt'),[])

    def test_unban_works_when_ip_is_also_trusted(self):
        fw.set_state('off')
        (fw.ROOT/'manual-bans.txt').write_text('1.1.1.1\n')
        self.assertTrue(fw.change_entry('ban','1.1.1.1',False))

    def test_truncated_download_falls_back_to_next_mirror(self):
        class Response:
            def __init__(self,url):self.url=url
            def __enter__(self):return self
            def __exit__(self,*a):return False
            def geturl(self):return self.url
            def read(self,n):
                if 'bad' in self.url:raise http.client.IncompleteRead(b'')
                return b'ok'
        with mock.patch('urllib.request.urlopen',side_effect=lambda req,timeout:Response(req.full_url)):
            self.assertEqual(fw.urls_download(['https://bad.test/a','https://good.test/a'],10),b'ok')

    def test_ui_auth_rejects_empty_token_and_non_ascii_password(self):
        def authorized(password,token):
            (fw.ROOT/'ui-token').write_text(token)
            header='Basic '+base64.b64encode(f'admin:{password}'.encode()).decode()
            with mock.patch.object(webui,'TOKEN_FILE',fw.ROOT/'ui-token'):
                return webui.Handler.authorized(mock.Mock(headers={'Authorization':header}))
        self.assertFalse(authorized('',''))
        self.assertFalse(authorized('пароль','SecureTestPass12'))
        self.assertTrue(authorized('SecureTestPass12','SecureTestPass12\n'))

    def _feed(self,body,name='cidr_x'):
        return fw.acquire_source(name,[],lambda d:fw.parse_cidr(d),fw.config(),loader=lambda:body)

    def test_block_feed_never_contains_private_or_reserved_ranges(self):
        nets,used,issues=self._feed(b'10.0.0.0/8\n192.0.0.0/8\n127.0.0.1\n100.64.1.0/24\n224.0.0.0/8\n'
                                    b'fe80::/64\nfc00::/16\n::1\n8.8.8.0/24\n2606:4700::/32\n')
        self.assertEqual([str(n) for n in nets],['8.8.8.0/24','2606:4700::/32'])
        self.assertIn('private/reserved networks omitted: 8',' '.join(issues))

    def test_first_download_of_oversized_feed_is_refused(self):
        for body in (b'1.0.0.0/8\n2.0.0.0/8\n3.0.0.0/8\n4.0.0.0/8\n5.0.0.0/8\n',b'2600::/16\n'):
            nets,used,issues=self._feed(body)
            self.assertEqual((nets,used),([],'cache'))
            self.assertIn('too much address space',' '.join(issues))
        self.assertEqual(len(self._feed(b'1.0.0.0/8\n2.0.0.0/8\n')[0]),2)

    def test_geo_allow_list_is_not_capped(self):
        body=b''.join(b'%d.0.0.0/8\n'%i for i in range(1,12))
        self.assertEqual(self._feed(body,'geo_ru')[1],'fresh')

    def _global_lock_free(self):
        fd=os.open(fw.ROOT/'.lock',os.O_CREAT|os.O_RDWR,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            return True
        except BlockingIOError:return False
        finally:os.close(fd)

    def _refresh(self,during_download):
        def build(cfg,refresh=True):
            sets={**self.sets,**fw.local_sets()}
            during_download()
            return sets,[],{}
        with mock.patch.object(fw,'build_sets_from_sources',side_effect=build),              mock.patch.object(fw,'render_rules',return_value='batch') as render,              mock.patch.object(fw,'apply_rules') as apply:
            fw.refresh()
        return render,apply

    def test_sync_downloads_without_global_lock_and_sees_new_bans(self):
        fw.set_state('observe')
        free=[]
        def during():
            free.append(self._global_lock_free())
            (fw.ROOT/'manual-bans.txt').write_text('8.8.8.8\n')
        render,apply=self._refresh(during)
        self.assertEqual(free,[True])
        self.assertEqual([str(n) for n in render.call_args.args[1]['manual']],['8.8.8.8/32'])
        apply.assert_called_once()
        self.assertTrue(self._global_lock_free())

    def test_sync_refuses_to_apply_if_settings_changed_during_download(self):
        for during in (lambda:(fw.ROOT/'asn.txt').write_text('AS1\n'),
                       lambda:(fw.ROOT/'.pending-x').mkdir()):
            with self.assertRaises(RuntimeError):self._refresh(during)
            self.assertTrue(self._global_lock_free())

    def test_extra_feed_download_leaves_global_lock_free(self):
        free=[]
        def acquire(*a,**k):
            free.append(self._global_lock_free())
            return [],'cache',[]
        with mock.patch.object(fw,'acquire_source',side_effect=acquire):
            with self.assertRaises(RuntimeError):fw.prepare_extra_feeds()
        self.assertNotIn(False,free)

    def test_monitor_survives_a_locked_database(self):
        import sqlite3
        con=mock.Mock()
        process=mock.Mock(stdout=['FWS D_SCAN4: SRC=8.8.8.8 DPT=443 PROTO=TCP']*2)
        process.poll.return_value=0
        with mock.patch.object(fw,'db',return_value=con),              mock.patch.object(fw,'compact_events'),              mock.patch.object(fw,'store_event',side_effect=sqlite3.OperationalError('database is locked')),              mock.patch.object(fw.autoban,'Detector'),              mock.patch('subprocess.Popen',return_value=process):
            with self.assertRaisesRegex(RuntimeError,'stream ended'):fw.monitor()
        self.assertEqual(con.rollback.call_count,2)

    def test_pages_before_authentication_reveal_nothing(self):
        for host,code in (('127.0.0.1:1488',401),('evil.example',403)):
            handler=mock.Mock(headers={'Host':host})
            handler.allowed_origins.return_value={'127.0.0.1:1488':''}
            handler.authorized.return_value=False
            self.assertFalse(webui.Handler.gate(handler))
            status,body=handler.respond.call_args.args[:2]
            self.assertEqual(status,code)
            for secret in ('SENTINEL','2.0.21','<nav','href'):self.assertNotIn(secret,body)

    def _event(self,ip,port,verdict='drop',reason='D_SCAN4',stamp=None):
        return (stamp or fw.now(),ip,port,'TCP',reason,verdict)

    def test_blocked_address_keeps_one_row_with_hits_and_ports(self):
        con=fw.db();self.addCleanup(con.close)
        for port in (22,80,22,443):fw.store_event(con,self._event('8.8.8.8',port))
        last=con.execute('SELECT max(id) FROM events').fetchone()[0]
        fw.store_event(con,self._event('8.8.8.8',443));con.commit()
        rows=con.execute('SELECT id,hits,ports FROM events').fetchall()
        self.assertEqual([r[1:] for r in rows],[(5,'80/TCP:1 22/TCP:2 443/TCP:2')])
        self.assertGreater(rows[0][0],last)
        group=fw.event_groups()[0][0]
        self.assertEqual((group['total'],group['drop']),(5,5))
        self.assertEqual({p['port']:p['total'] for p in group['ports']},{22:2,80:1,443:2})
        self.assertEqual((group['lifetime'],fw.drop_total()),(5,(5,1)))
        (fw.ROOT/'ui-token').write_text('SecureTestPass12')
        with mock.patch.object(webui,'TOKEN_FILE',fw.ROOT/'ui-token'):
            self.assertIn('8.8.8.8',webui.events_page({}))
        self.assertEqual(fw.recent_drop_ips()[0][1],5)

    def test_old_duplicates_are_merged_and_auto_ban_markers_survive(self):
        con=fw.db();self.addCleanup(con.close)
        rows=[self._event('8.8.4.4',p,'observe','O_PROBE') for p in (1,2,3)]
        rows.append(self._event('8.8.4.4',3,'observe','AUTO_BAN_24H'))
        con.executemany('INSERT INTO events(timestamp,ip,port,proto,reason,verdict) VALUES (?,?,?,?,?,?)',rows)
        fw.compact_events(con);fw.compact_events(con)
        self.assertEqual(con.execute('SELECT reason,hits,ports FROM events ORDER BY id').fetchall(),
                         [('O_PROBE',3,'1/TCP:1 2/TCP:1 3/TCP:1'),('AUTO_BAN_24H',1,'')])

    def test_allowed_traffic_is_kept_for_one_hour_and_cap_counts_rows(self):
        con=fw.db();self.addCleanup(con.close)
        old=(fw.dt.datetime.now(fw.dt.timezone.utc)-fw.dt.timedelta(minutes=61)).isoformat(timespec='seconds')
        fw.store_event(con,self._event('8.8.8.8',443,'pass','PASS',old))
        fw.store_event(con,self._event('8.8.8.8',443,'pass','PASS'))
        fw.store_event(con,self._event('1.0.0.1',22,'drop',stamp=old))
        fw.prune_events(con,90)
        self.assertEqual(sorted(r[0] for r in con.execute('SELECT verdict FROM events')),['drop','pass'])
        with mock.patch.object(fw,'MAX_EVENT_ROWS',1):fw.prune_events(con,90)
        self.assertEqual(con.execute('SELECT count(*) FROM events').fetchone()[0],1)

    def test_lifetime_counter_survives_pruning_and_legacy_ports_stay_unknown(self):
        con=fw.db();self.addCleanup(con.close)
        old=(fw.dt.datetime.now(fw.dt.timezone.utc)-fw.dt.timedelta(days=100)).isoformat(timespec='seconds')
        fw.store_event(con,self._event('8.8.8.8',22,stamp=old))
        fw.prune_events(con,90);con.commit()
        self.assertEqual(con.execute('SELECT count(*) FROM events').fetchone()[0],0)
        fw.store_event(con,self._event('8.8.8.8',22));con.commit()
        self.assertEqual(fw.drop_total(),(2,1))
        con.execute("UPDATE events SET hits=9,ports='22/TCP 80/TCP'");con.commit()
        fw.store_event(con,self._event('8.8.8.8',80));fw.store_event(con,self._event('8.8.8.8',443));con.commit()
        ports={p['port']:p['total'] for p in fw.event_groups()[0][0]['ports']}
        self.assertEqual(ports,{22:None,80:None,443:1})


    def test_main_page_carries_cached_intel_and_live_events_carry_hits(self):
        con=fw.db();self.addCleanup(con.close)
        for port in (22,80):fw.store_event(con,self._event('8.8.8.8',port))
        con.commit()
        self.assertEqual(fw.live_events(0,1)[0][-1],2)
        self.assertEqual(webui.ipintel.cached_many(['8.8.8.8'],fw.ROOT),{})
        intel=webui.ipintel._db(fw.ROOT)
        intel.execute('INSERT INTO intel(ip,geo_checked,abuse_checked,geo_json,abuse_json) VALUES (?,1,1,?,?)',
                      ('8.8.8.8','{"asn":15169,"isp":"<b>"}','{"score":7}'))
        intel.commit();intel.close()
        with mock.patch.object(webui.ipintel,'_fetch_abuse') as remote:
            known=webui.ipintel.cached_many(['8.8.8.8','1.0.0.1'],fw.ROOT)
            html=webui.dropped_ip_table(fw.recent_drop_ips(24))
        remote.assert_not_called()
        self.assertEqual((list(known),known['8.8.8.8']['score']),(['8.8.8.8'],7))
        self.assertIn('data-intel="{&quot;',html)
        self.assertNotIn('<b>',html)

    def test_ssh_port_follows_socket_then_sshd_and_warns_on_mismatch(self):
        def system(socket,sshd):
            return lambda *args,**kw: mock.Mock(returncode=0,stdout=socket if args[0]=='systemctl' else sshd)
        moved='ActiveState=active\nListen=0.0.0.0:1452 (Stream)\nListen=[::]:1452 (Stream)\n'
        with mock.patch.dict(os.environ,{},clear=True):
            with mock.patch.object(fw,'run',side_effect=system(moved,'port 22\n')):
                self.assertEqual(fw.detect_ssh_ports(),[1452])
                self.assertIn('1452',fw.ssh_port_warning({'ssh_ports':[22]}))
                self.assertEqual(fw.ssh_port_warning({'ssh_ports':[1452]}),'')
                (fw.ROOT/'ui-token').write_text('strong12letters')
                with mock.patch.object(webui,'TOKEN_FILE',fw.ROOT/'ui-token'):
                    self.assertIn('SSH-порт:',webui.overview())
            with mock.patch.object(fw,'run',side_effect=system('ActiveState=inactive\n','port 2200\n')):
                self.assertEqual(fw.detect_ssh_ports(),[2200])
            with mock.patch.object(fw,'run',side_effect=OSError):
                self.assertEqual((fw.detect_ssh_ports(),fw.ssh_port_warning({'ssh_ports':[22]})),([],''))

    def test_countdown_starts_only_after_rules_and_bans_are_loaded(self):
        order=[]
        def run(*args,**kwargs):
            if args[0]=='systemd-run':order.append(next(a for a in args if a.startswith('--on-active')))
            elif args[:2]==('systemctl','stop'):order.append('stop '+args[2][-11:])
            return mock.Mock(returncode=0,stdout='',stderr='')
        def nft(batch,check_only=False):
            if not check_only:order.append('load')
        draft={'candidate':fw.config(),'vpn_warnings':[]}
        with mock.patch.object(fw,'policy_draft',return_value=draft), \
             mock.patch.object(fw,'build_sets_from_sources',return_value=(self.sets,[],{})), \
             mock.patch.object(fw,'render_rules',return_value='rules'), \
             mock.patch.object(fw,'run',side_effect=run), mock.patch.object(fw,'nft',side_effect=nft):
            result=fw.web_activate()
        self.assertEqual(order,['--on-active=900s','load','--on-active=120s','stop -load.timer'])
        meta=json.loads((fw.ROOT/('.pending-'+result['token'])/'web.json').read_text())
        self.assertEqual(meta['deadline'],result['deadline'])


if __name__=='__main__':
    unittest.main()
