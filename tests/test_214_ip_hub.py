"""2.0.14 IP block hub: no repeat third-party API requests for cached IPs."""
from __future__ import annotations
import base64
import datetime as dt
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock
from urllib.error import HTTPError
from urllib.request import Request,urlopen

import fw_sentinel as fw
import autoban
import ipintel
import webui

import i18n  # noqa: E402

def setUpModule():  # these checks read the Russian texts
    i18n.FORCED = 'ru'


def tearDownModule():
    i18n.FORCED = None


class IPHubTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        self.root=Path(t.name)
        original=fw.ROOT;fw.ROOT=self.root;self.addCleanup(setattr,fw,'ROOT',original)
        tok=webui.TOKEN_FILE;webui.TOKEN_FILE=self.root/'ui-token';self.addCleanup(setattr,webui,'TOKEN_FILE',tok)
        (self.root/'ui-token').write_text('testpassword')
        source=Path(__file__).resolve().parents[1]
        cfg=json.loads((source/'config.json').read_text())
        cfg.update(ui_base_path='/secret/',ui_public_origin='https://probe.example.test')
        (self.root/'config.json').write_text(json.dumps(cfg))
        for name,contents in [('allow.txt',''),('manual-bans.txt','9.9.9.9\n'),('vpn-clients.txt',''),('asn.txt',''),('sources.json','{"cidr":{}}')]:
            (self.root/name).write_text(contents)

    def test_cache_result_once_across_reads_and_no_date_field_needed(self):
        calls=[]
        def geo(addr):
            calls.append('geo')
            return {'asn':15169,'country':'United States','isp':'Google LLC'}
        def abuse(ip,root):
            calls.append('abuse')
            return {'score':87,'reports':100,'checked_at':'2025-01-01T00:00:00Z'}
        with mock.patch.object(ipintel.ipmeta,'_fetch',side_effect=geo), mock.patch.object(ipintel,'_fetch_abuse',side_effect=abuse), mock.patch.object(ipintel,'_LAST_REMOTE',0):
            first=ipintel.lookup('8.8.8.8',self.root)
            second=ipintel.lookup('8.8.8.8',self.root)
            self.assertEqual(first['score'],87)
            self.assertEqual(second['score'],87)
            self.assertEqual(calls,['geo','abuse'])
            self.assertTrue(second['cached'])
        stored=ipintel.cached('8.8.8.8',self.root)
        self.assertEqual(stored['asn'],15169)
        self.assertEqual(stored['score'],87)

    def test_old_cache_remains_valid_indefinitely(self):
        db=ipintel._db(self.root)
        try:
            db.execute("INSERT INTO intel(ip,geo_checked,abuse_checked,geo_json,abuse_json) VALUES (?,?,?,?,?)",
                       ('8.8.8.8',1,1,json.dumps({'asn':15169,'country':'США','isp':'Google'}),json.dumps({'score':12})))
            db.commit()
        finally:db.close()
        with mock.patch.object(ipintel.ipmeta,'_fetch',side_effect=AssertionError('extra geo call')):
            with mock.patch.object(ipintel,'_fetch_abuse',side_effect=AssertionError('extra abuse call')):
                data=ipintel.lookup('8.8.8.8',self.root)
        self.assertEqual(data['score'],12)
        self.assertEqual(data['asn'],15169)

    def test_active_bans_moved_to_access_manual_details_closed(self):
        with mock.patch.object(autoban,'list_bans_detailed',return_value=[('8.8.4.4',0,9999999999,'[20001,20002,20003,20004,20005,20006]',2)]):
            html=webui.access_page()
            self.assertIn('Блокировки IP',html)
            self.assertIn('АВТОБАН №2',html)
            self.assertIn('/secret/control/auto-unban/preview',html)
            self.assertIn('data-intel-on-open="8.8.4.4"',html)
            self.assertNotIn('data-intel-ip="8.8.4.4"',html)
            self.assertIn('<details class="manual-lists"><summary>Ручные списки IP',html)
            self.assertNotIn('<details class="manual-lists" open',html)
            self.assertIn('РУЧНОЙ',html)
        with mock.patch.object(autoban,'list_bans_detailed',return_value=[]):
            with mock.patch.object(fw,'state',return_value={'mode':'observe'}):
                ctrl=webui.autoban_control_panel({})
                self.assertNotIn('control/auto-unban/preview',ctrl)
                self.assertIn('/secret/access',ctrl)

    def test_three_columns_recent_day_sorting_and_ip_embedded_meta(self):
        now=dt.datetime.now(dt.timezone.utc)
        fresh=now.isoformat(timespec='seconds')
        old=(now-dt.timedelta(days=2)).isoformat(timespec='seconds')
        con=fw.db()
        try:
            for ip,ts,num in [('1.1.1.1',fresh,3),('8.8.8.8',fresh,8),('9.9.9.9',old,40)]:
                for _ in range(num):
                    con.execute('INSERT INTO events(timestamp,ip,port,proto,reason,verdict) VALUES (?,?,?,?,?,?)',(ts,ip,22,'TCP','WATCH4','drop'))
            con.commit()
        finally:con.close()
        entries=fw.recent_drop_ips()
        self.assertEqual([ip for ip,_,_ in entries],['8.8.8.8','1.1.1.1'])
        html=webui.dropped_ip_table(entries)
        self.assertIn('class="blocked-ip-grid"',html)
        self.assertEqual(html.count('class="blocked-ip-card"'),len(results) if 'results' in locals() else len(entries))
        self.assertIn('data-intel-ip="8.8.8.8"',html)
        self.assertNotIn('9.9.9.9',html)

    def test_intel_get_requires_auth_custom_header_same_origin(self):
        server=ThreadingHTTPServer(('127.0.0.1',0),webui.Handler)
        worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
        base=f'http://127.0.0.1:{server.server_port}/secret/api/ip-intel?ip=8.8.8.8'
        auth='Basic '+base64.b64encode(b'admin:testpassword').decode()
        try:
            with self.assertRaises(HTTPError) as cm:
                urlopen(Request(base,headers={'Host':'probe.example.test','X-FWS-Intel':'1'}),timeout=4)
            self.assertEqual(cm.exception.code,401)
            with self.assertRaises(HTTPError) as cm:
                urlopen(Request(base,headers={'Host':'probe.example.test','Authorization':auth}),timeout=4)
            self.assertEqual(cm.exception.code,403)
            with self.assertRaises(HTTPError) as cm:
                urlopen(Request(base,headers={'Host':'probe.example.test','Authorization':auth,'X-FWS-Intel':'1','Sec-Fetch-Site':'cross-site'}),timeout=4)
            self.assertEqual(cm.exception.code,403)
            with mock.patch.object(ipintel,'lookup',return_value={'ip':'8.8.8.8','score':87,'asn':15169}) as look:
                response=urlopen(Request(base,headers={'Host':'probe.example.test','Authorization':auth,'X-FWS-Intel':'1','Sec-Fetch-Site':'same-origin'}),timeout=4)
                self.assertEqual(response.status,200)
                self.assertEqual(json.load(response)['score'],87)
                look.assert_called_once_with('8.8.8.8',self.root)
        finally:
            server.shutdown();server.server_close();worker.join(timeout=3)

if __name__=='__main__':unittest.main()

class LegacyCacheReuseTests(unittest.TestCase):
    def test_read_successful_old_ipwho_cache_without_network(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            old=sqlite3.connect(root/'ip-metadata.sqlite3')
            old.execute('CREATE TABLE ip_info(ip TEXT PRIMARY KEY,fetched INTEGER,payload TEXT)')
            old.execute('INSERT INTO ip_info VALUES (?,?,?)',('8.8.8.8',1,json.dumps({'ip':'8.8.8.8','asn':15169,'country':'US','isp':'Google'})))
            old.commit();old.close()
            with mock.patch.object(ipintel.ipmeta,'_fetch',side_effect=AssertionError('old geo must be reused')):
                with mock.patch.object(ipintel,'_fetch_abuse',return_value={'score':50}):
                    with mock.patch.object(ipintel,'_LAST_REMOTE',0):
                        info=ipintel.lookup('8.8.8.8',root)
                        self.assertEqual(info['asn'],15169)
                        self.assertEqual(info['score'],50)
