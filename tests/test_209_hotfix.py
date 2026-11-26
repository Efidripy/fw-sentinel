"""Origin/CSRF security, radar health and monitor lifecycle regression tests."""
import base64
import json
import sqlite3
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import fw_sentinel as fw
import webui

import i18n  # noqa: E402

def setUpModule():  # these checks read the Russian texts
    i18n.FORCED = 'ru'


def tearDownModule():
    i18n.FORCED = None


class OriginAndMonitorTests(unittest.TestCase):
    def test_explicit_origins_strict_with_default_port(self):
        expected='https://probe.example.com'
        self.assertTrue(webui.origin_allowed(expected,expected))
        self.assertTrue(webui.origin_allowed(expected+':443',expected))
        self.assertTrue(webui.origin_allowed('null',expected,'same-origin','navigate'))
        self.assertFalse(webui.origin_allowed('null',expected,'cross-site','navigate'))
        self.assertFalse(webui.origin_allowed('null',expected,'same-origin','cors'))
        self.assertFalse(webui.origin_allowed('null',expected,'','navigate'))
        for origin in ('https://probe.example.com.evil.tld','http://probe.example.com',
                       'https://probe.example.com/','https://probe.example.com:444',
                       'https://user@probe.example.com', 'https://probe.example.com:0'):
            with self.subTest(origin=origin):
                self.assertFalse(webui.origin_allowed(origin,expected,'same-origin','navigate'))

    def test_missing_origin_uses_token_fallback_when_metadata_absent(self):
        expected='https://probe.example.com'
        self.assertTrue(webui.origin_allowed(None,expected,'same-origin','navigate'))
        self.assertTrue(webui.origin_allowed(None,expected,'',''))
        self.assertTrue(webui.origin_allowed(None,expected,'none','navigate'))
        self.assertTrue(webui.origin_allowed(None,expected,'','',expected+'/fws-secret-path/control'))
        self.assertFalse(webui.origin_allowed(None,expected,'','', 'https://evil.invalid/form'))
        for site,mode in [('cross-site','navigate'),('same-site','navigate'),
                          ('same-origin','cors'),('same-origin','cors')]:
            with self.subTest(site=site,mode=mode):
                self.assertFalse(webui.origin_allowed(None,expected,site,mode))

    def test_web_http_form_and_health_in_subdirectory(self):
        with tempfile.TemporaryDirectory() as td:
            old_root,old_token=fw.ROOT,webui.TOKEN_FILE
            fw.ROOT=Path(td);webui.TOKEN_FILE=fw.ROOT/'ui-token'
            for name,contents in {
                 'ui-token':'test-password', 'allow.txt':'','manual-bans.txt':'',
                 'vpn-clients.txt':'','asn.txt':'','sources.json':'{"cidr":{}}',
                 'config.json':json.dumps({'ui_port':1488,'ui_base_path':'/fws-secret-path/',
                    'ui_public_origin':'https://probe.example.com',
                    'wan_interfaces':['eth0'],'ssh_ports':[22], 'vpn_ports':[443],
                    'geo_ports':[443], 'geo_enabled':False,'ssh_rate_per_minute':10})
            }.items(): (fw.ROOT/name).write_text(contents)
            con=fw.db();con.execute("INSERT INTO events(timestamp,ip,port,proto,reason,verdict) VALUES (?,?,?,?,?,?)",('2026-11-25T18:30:00+00:00','8.8.8.8',443,'TCP','WATCH4','observe'));con.commit();con.close()
            server=ThreadingHTTPServer(('127.0.0.1',0),webui.Handler)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            base=f'http://127.0.0.1:{server.server_port}'
            auth='Basic '+base64.b64encode(b'admin:test-password').decode()
            headers={'Host':'probe.example.com','Authorization':auth}
            def post(origin_marker='missing',fetch_site='same-origin',mode='navigate',csrf=True):
                h={**headers,'Content-Type':'application/x-www-form-urlencoded',
                   'Sec-Fetch-Site':fetch_site,'Sec-Fetch-Mode':mode}
                if origin_marker!='missing':h['Origin']=origin_marker
                form=urlencode({'csrf':webui.csrf() if csrf else 'wrong','ip':'9.9.9.9'}).encode()
                return urlopen(Request(base+'/ban',headers=h,data=form),timeout=3)
            try:
                with patch.object(fw,'run',side_effect=lambda *a,**kw:Mock(returncode=0 if a[0]=='systemctl' else 1)):
                    page=urlopen(Request(base+'/',headers=headers),timeout=4).read().decode()
                    self.assertIn('id="radar-health"',page)
                    self.assertIn('fetch("/fws-secret-path/api/health"',page)
                    data=json.load(urlopen(Request(base+'/api/health',headers=headers),timeout=3))
                    self.assertTrue(data['monitor_active']);self.assertFalse(data['table_active'])
                    self.assertEqual(data['last_event_utc'],'2026-11-25T18:30:00+00:00')
                    self.assertIn('Операция выполнена',post().read().decode())
                    self.assertIn('9.9.9.9',(fw.ROOT/'manual-bans.txt').read_text())
                    for origin,site,mode in [('https://evil.invalid','same-origin','navigate'),
                                             ('missing','cross-site','navigate'),
                                             ('null','cross-site','navigate')]:
                        with self.subTest(origin=origin,site=site),self.assertRaises(HTTPError) as raised:
                            post(origin,site,mode)
                        self.assertEqual(raised.exception.code,403)
                        if origin=='https://evil.invalid':
                            body=raised.exception.read().decode()
                            self.assertIn('Origin запрещён',body)
                            self.assertIn('https://evil.invalid',body)
                            self.assertIn('https://probe.example.com',body)
                    self.assertIn('Операция выполнена',post('null','same-origin','navigate').read().decode())
                    with self.assertRaises(HTTPError) as raised:post('null','same-origin','navigate',csrf=False)
                    self.assertEqual(raised.exception.code,400)
                    with self.assertRaises(HTTPError) as raised:post(csrf=False)
                    self.assertEqual(raised.exception.code,400)
                    # API must still be protected by Basic auth.
                    with self.assertRaises(HTTPError) as raised:
                        urlopen(Request(base+'/api/health',headers={'Host':headers['Host']}),timeout=3)
                    self.assertEqual(raised.exception.code,401)
            finally:
                server.shutdown();server.server_close();thread.join(timeout=2)
                fw.ROOT,webui.TOKEN_FILE=old_root,old_token

    def test_monitor_journal_eof_triggers_failure_for_systemd_restart(self):
        with tempfile.TemporaryDirectory() as td:
            old_root=fw.ROOT;fw.ROOT=Path(td)
            (fw.ROOT/'config.json').write_text('{"event_retention_days":90}')
            process=Mock();process.stdout=iter([]);process.poll.return_value=0
            try:
                with patch.object(fw.subprocess,'Popen',return_value=process),self.assertRaisesRegex(RuntimeError,'ended unexpectedly'):
                    fw.monitor()
            finally:fw.ROOT=old_root

if __name__=='__main__': unittest.main()
