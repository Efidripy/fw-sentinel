"""2.0.13: durable escalating bans and compact IP summary / safer controls."""
import ipaddress
import json
import datetime as dt
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import autoban
import fw_sentinel as fw
import webui

import i18n  # noqa: E402

def setUpModule():  # these checks read the Russian texts
    i18n.FORCED = 'ru'


def tearDownModule():
    i18n.FORCED = None


class EscalatingBans(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        original=fw.ROOT;fw.ROOT=self.root;self.addCleanup(setattr,fw,'ROOT',original)
        token=webui.TOKEN_FILE;webui.TOKEN_FILE=self.root/'ui-token'
        self.addCleanup(setattr,webui,'TOKEN_FILE',token)
        (self.root/'ui-token').write_text('someSecurePass12')
        self.cfg=json.loads((Path(__file__).resolve().parents[1]/'config.json').read_text())
        self.cfg.update(wan_interfaces=['ens3'],autoban_enabled=True,geo_enabled=False,
                        asn_enabled=False,threat_watch_enforce=True,threat_ssh_enforce=True,
                        ui_base_path='/secret/',ui_public_origin='https://probe.example.test')
        (self.root/'config.json').write_text(json.dumps(self.cfg))
        (self.root/'sources.json').write_text('{"cidr":{},"threat_ssh":{},"threat_watch":{}}')
        for name,text in [('allow.txt','1.1.1.1\n'),('vpn-clients.txt','8.8.8.8\n'),
                          ('manual-bans.txt',''),('asn.txt','')]:
            (self.root/name).write_text(text)
        fw.set_state('enforce')
        (self.root/'active.nft').write_text('a confirmed snapshot')
        self.con=fw.db();self.addCleanup(self.con.close)
        self.fake_time=100.0
        self.services=mock.patch.object(autoban,'discover_services',return_value=({9999},{9944}))
        self.services.start();self.addCleanup(self.services.stop)
        self.nft_patch=mock.patch.object(fw,'nft');self.nft=self.nft_patch.start();self.addCleanup(self.nft_patch.stop)
        self.detector=autoban.Detector(fw,self.con,clock=lambda:self.fake_time)

    def trigger(self, ip='8.8.4.4', base=20000):
        for port in range(base,base+5):
            self.assertFalse(self.detector.handle(ip,port,'TCP'))
        self.assertTrue(self.detector.handle(ip,base+5,'TCP'))

    def expire(self,ip='8.8.4.4'):
        self.con.execute('UPDATE auto_bans SET expires_at=0 WHERE ip=?',(ip,))
        self.con.commit()
        self.fake_time+=61

    def test_all_five_steps_sixth_and_later_cap_at_year(self):
        durations=[86400,604800,2592000,15552000,31536000,31536000]
        for idx,duration in enumerate(durations,1):
            self.trigger(base=22000+idx*10)
            row=self.con.execute('SELECT created_at,expires_at FROM auto_bans WHERE ip=?',('8.8.4.4',)).fetchone()
            self.assertEqual(row[1]-row[0],duration)
            strikes=self.con.execute('SELECT strikes FROM auto_ban_strikes WHERE ip=?',('8.8.4.4',)).fetchone()[0]
            self.assertEqual(strikes,idx)
            self.assertIn(f'{duration}s',str(self.nft.call_args_list))
            if idx!=len(durations):self.expire()
        self.assertEqual(self.con.execute('SELECT count(*) FROM auto_ban_history').fetchone()[0],6)
        records=self.con.execute('SELECT DISTINCT reason FROM events WHERE reason LIKE "AUTO_BAN_%" ORDER BY id').fetchall()
        self.assertEqual([x[0] for x in records],['AUTO_BAN_24H','AUTO_BAN_7D','AUTO_BAN_30D','AUTO_BAN_180D','AUTO_BAN_365D'])

    def test_repeat_needs_six_fresh_ports_after_expiry(self):
        self.trigger();self.expire()
        self.assertFalse(self.detector.handle('8.8.4.4',39001,'TCP'))
        self.assertEqual(self.con.execute('SELECT strikes FROM auto_ban_strikes').fetchone()[0],1)
        for port in range(39002,39006):self.assertFalse(self.detector.handle('8.8.4.4',port,'TCP'))
        self.assertTrue(self.detector.handle('8.8.4.4',39006,'TCP'))
        self.assertEqual(self.con.execute('SELECT strikes FROM auto_ban_strikes').fetchone()[0],2)

    def test_no_rebanning_during_active_ttl_or_from_stale_probes(self):
        self.trigger()
        self.fake_time+=61
        for port in range(30100,30106):self.assertFalse(self.detector.handle('8.8.4.4',port,'TCP'))
        self.assertEqual(self.con.execute('SELECT strikes FROM auto_ban_strikes').fetchone()[0],1)
        self.expire()
        self.assertFalse(self.detector.handle('8.8.4.4',30107,'TCP'))
        self.assertEqual(self.con.execute('SELECT strikes FROM auto_ban_strikes').fetchone()[0],1)

    def test_ban_revocation_does_not_erase_strike(self):
        self.trigger()
        with mock.patch.object(fw,'run',return_value=mock.Mock(returncode=0,stdout='',stderr='')):
            self.assertTrue(autoban.revoke(fw,'8.8.4.4'))
        self.fake_time+=61
        self.trigger(base=25000)
        self.assertEqual(self.con.execute('SELECT strikes FROM auto_ban_strikes').fetchone()[0],2)

    def test_migration_idempotent_and_preserves_active_existing_ban(self):
        with tempfile.TemporaryDirectory() as tmp:
            file=Path(tmp)/'events.sqlite3'
            con=sqlite3.connect(file)
            con.execute('CREATE TABLE auto_bans (ip TEXT PRIMARY KEY, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, ports TEXT NOT NULL, revoked_at INTEGER)')
            con.execute('INSERT INTO auto_bans VALUES (?,?,?,?,NULL)',('8.8.4.4',111,9999999999,'[10,11,12,13,14,15]'))
            con.commit()
            autoban.init_db(con);autoban.init_db(con);con.commit()
            self.assertEqual(con.execute('SELECT strikes FROM auto_ban_strikes').fetchone()[0],1)
            self.assertEqual(con.execute('SELECT COUNT(*) FROM auto_ban_history').fetchone()[0],1)
            self.assertEqual(len(autoban.active_bans(con)),1)
            con.close()

    def test_nft_failure_does_not_advance_offense_count(self):
        for port in range(20000,20005):self.assertFalse(self.detector.handle('8.8.4.4',port,'TCP'))
        with mock.patch.object(fw,'nft',side_effect=RuntimeError('nft add failed')):
            with self.assertRaisesRegex(RuntimeError,'nft add failed'):
                self.detector.handle('8.8.4.4',20005,'TCP')
        self.assertEqual(self.con.execute('SELECT count(*) FROM auto_ban_history').fetchone()[0],0)
        self.assertEqual(self.con.execute('SELECT count(*) FROM auto_ban_strikes').fetchone()[0],0)

    def test_six_known_vpn_ports_never_trigger_and_protected_admin_safe(self):
        for addr in ('1.1.1.1','8.8.8.8'):
            for p in range(30000,30012):self.assertFalse(self.detector.handle(addr,p,'TCP'))
        for p in (22,53,80,443,8443,9999,8080,9443):
            self.assertFalse(self.detector.handle('8.8.4.4',p,'TCP'))
        self.assertEqual(autoban.list_bans(self.root),[])

    def test_readonly_summary_has_exactly_three_columns_and_real_drop_counts(self):
        base=dt.datetime.now(dt.timezone.utc).replace(microsecond=0).replace(minute=0,second=0)-dt.timedelta(hours=1)
        stamp=lambda mins:(base+dt.timedelta(minutes=mins)).isoformat()
        rows=[(stamp(1),'8.8.4.4',22,'TCP','WATCH4','drop'),
              (stamp(2),'8.8.4.4',22,'TCP','WATCH4','drop'),
              (stamp(3),'1.1.1.1',443,'TCP','PASS','pass'),
              (stamp(4),'9.9.9.9',80,'TCP','SCAN4','drop'),
              (stamp(5),'8.8.4.4',443,'TCP','WATCH4','drop')]
        self.con.executemany('INSERT INTO events(timestamp,ip,port,proto,reason,verdict) VALUES(?,?,?,?,?,?)',rows)
        self.con.commit()
        results=fw.recent_drop_ips(limit=10)
        self.assertEqual(results[0],('8.8.4.4',3,stamp(5)))
        self.assertEqual(results[1][0:2],('9.9.9.9',1))
        self.assertNotIn('1.1.1.1',str(results))
        html=webui.dropped_ip_table(results)
        self.assertIn('class="blocked-ip-grid"',html)
        self.assertEqual(html.count('class="blocked-ip-card"'),len(results) if 'results' in locals() else len(entries))
        self.assertIn('/secret/events?ip=8.8.4.4&amp;verdict=drop',html)
        self.assertIn(stamp(5).replace('T',' ')[:19],html)

    def test_one_main_control_block_and_manual_rollback_kept(self):
        html=webui.control_page()
        self.assertIn('Состояние и управление защитой',html)
        self.assertIn('УСИЛЕННАЯ АВТОЗАЩИТА · ВКЛЮЧЕНА ПОСТОЯННО',html)
        self.assertNotIn('Режим Sentinel:',html)
        self.assertNotIn('Шаг 2 из 3',html)
        self.assertEqual(html.count('class="control-panel protection-status"'),1)
        self.assertIn('Отключить блокировки',html)
        self.assertIn('Автоматические баны — нарастающие сроки',html)
        self.assertIn('365 дней',html)

    def test_overview_shows_new_table_and_not_old_selection(self):
        self.con.execute("INSERT INTO events(timestamp,ip,port,proto,reason,verdict) VALUES(?,?,?,?,?,?)",
                         (dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds'),'8.8.4.4',22,'TCP','WATCH4','drop'))
        self.con.commit()
        with mock.patch.object(fw,'run',return_value=mock.Mock(returncode=0,stdout='',stderr='')):
            html=webui.overview()
        self.assertIn('<h2>Отброшенные пакеты</h2>',html)
        self.assertNotIn('3 колонки IP',html)
        self.assertIn('DROP-событий',html)
        self.assertNotIn('Последние события (выборка)',html)
        self.assertIn('8.8.4.4',html)
        self.assertIn('250',html)


if __name__=='__main__':unittest.main()
