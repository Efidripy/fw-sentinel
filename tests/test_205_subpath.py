"""2.0.5 subpath and reverse-proxy tests, including origin and POST safety."""
from http.server import ThreadingHTTPServer
from pathlib import Path
import base64
import json
import re
import sys
import tempfile
import threading
import unittest
from unittest import mock
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import fw_sentinel as fw
import webui

PREFIX='/fws-secret-path/'
DOMAIN='https://probe.example.com'

import i18n  # noqa: E402

def setUpModule():  # these checks read the Russian texts
    i18n.FORCED = 'ru'


def tearDownModule():
    i18n.FORCED = None


class SubpathTests(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory()
        self.oldroot=fw.ROOT
        self.oldtoken=webui.TOKEN_FILE
        fw.ROOT=Path(self.folder.name)
        webui.TOKEN_FILE=fw.ROOT/'ui-token'
        (fw.ROOT/'ui-token').write_text('test-password',encoding='utf-8')
        (fw.ROOT/'allow.txt').write_text('',encoding='utf-8')
        (fw.ROOT/'manual-bans.txt').write_text('',encoding='utf-8')
        (fw.ROOT/'vpn-clients.txt').write_text('',encoding='utf-8')
        (fw.ROOT/'sources.json').write_text('{"cidr":{}}',encoding='utf-8')
        (fw.ROOT/'config.json').write_text(json.dumps(dict(version='2.0.5',ui_port=1488,
             ui_base_path=PREFIX,ui_public_origin=DOMAIN,geo_enabled=False,geo_ports=[443],
             vpn_ports=[443],ssh_ports=[22],wan_interfaces=['eth0'],ssh_rate_per_minute=10)))
        self.patcher=mock.patch.object(fw,'run',return_value=mock.Mock(returncode=1))
        self.patcher.start()
        self.srv=ThreadingHTTPServer(('127.0.0.1',0),webui.Handler)
        self.thread=threading.Thread(target=self.srv.serve_forever,daemon=True)
        self.thread.start()
        self.base=f'http://127.0.0.1:{self.srv.server_port}'
        self.creds='Basic '+base64.b64encode(b'admin:test-password').decode()

    def tearDown(self):
        self.srv.shutdown();self.srv.server_close();self.thread.join(2)
        self.patcher.stop()
        fw.ROOT=self.oldroot
        webui.TOKEN_FILE=self.oldtoken
        self.folder.cleanup()

    def get(self,path,public=True,auth=True):
        headers={'Host':'probe.example.com' if public else f'127.0.0.1:{self.srv.server_port}'}
        if auth:headers['Authorization']=self.creds
        return urlopen(Request(self.base+path,headers=headers),timeout=3)

    def post(self,path,origin=DOMAIN,ip='9.9.9.9',host='probe.example.com'):
        data=urlencode({'csrf':webui.csrf(),'ip':ip}).encode()
        return urlopen(Request(self.base+path,data=data,headers={'Host':host,'Origin':origin,
            'Authorization':self.creds,'Content-Type':'application/x-www-form-urlencoded'}),timeout=3)

    def test_menu_links_search_and_live_radar_have_prefix(self):
        # Nginx with proxy_pass trailing / strips the prefix before forwarding.
        page=self.get('/').read().decode()
        self.assertIn(f'href="{PREFIX}events"',page)
        self.assertIn(f'href="{PREFIX}access"',page)
        self.assertIn(f'href="{PREFIX}sources"',page)
        self.assertIn(f'href="{PREFIX}"',page)
        self.assertIn(f'fetch("{PREFIX}api/live"+',page)
        self.assertNotIn('fetch(\'/api/live',page)
        events=self.get('/events').read().decode()
        self.assertIn(f'action="{PREFIX}events"',events)
        access=self.get('/access').read().decode()
        for action in ('ban','unban','allow','unallow','vpn-add','vpn-remove'):
            if action in ('unban','unallow','vpn-remove'):continue
            self.assertIn(f'action="{PREFIX}{action}"',access)
        self.assertEqual(json.loads(self.get('/api/live?since=0').read())['events'],[])

    def test_intact_prefixed_routes_also_work(self):
        self.assertIn('FW SENTINEL',self.get(PREFIX).read().decode())
        self.assertIn('История по IP',self.get(PREFIX+'events').read().decode())
        self.assertEqual(json.loads(self.get(PREFIX+'api/live?since=0').read())['events'],[])

    def test_https_origin_accepted_for_post_stripped_and_full_path(self):
        html=self.post('/vpn-add',ip='8.8.4.4').read().decode()
        self.assertIn(f'href="{PREFIX}access"',html)
        self.assertIn('8.8.4.4',(fw.ROOT/'vpn-clients.txt').read_text())
        self.post(PREFIX+'ban',ip='9.9.9.9')
        self.assertIn('9.9.9.9',(fw.ROOT/'manual-bans.txt').read_text())

    def test_cross_origin_and_host_rejected(self):
        for origin in ('https://evil.invalid','http://probe.example.com','https://probe.example.com.evil.net'):
            with self.subTest(origin=origin),self.assertRaises(HTTPError) as raised:
                self.post('/ban',origin=origin)
            self.assertEqual(raised.exception.code,403)
        with self.assertRaises(HTTPError) as raised:
            self.get('/',public=True,auth=False)
        self.assertEqual(raised.exception.code,401)

    def test_ssh_tunnel_local_mode_and_origin_still_work(self):
        self.assertIn('FW SENTINEL',self.get('/',public=False).read().decode())
        local=f'http://127.0.0.1:{self.srv.server_port}'
        self.post('/ban',origin=local,host=f'127.0.0.1:{self.srv.server_port}',ip='1.1.1.1')
        self.assertIn('1.1.1.1',(fw.ROOT/'manual-bans.txt').read_text())

    def test_unapproved_hostname_blocked_even_with_valid_basic_auth(self):
        with self.assertRaises(HTTPError) as raised:
            urlopen(Request(self.base+'/',headers={'Host':'attacker.example','Authorization':self.creds}),timeout=3)
        self.assertEqual(raised.exception.code,403)

    def test_bad_prefix_and_origin_are_not_accepted(self):
        for bad in ('/hello','//evil/','/a/../','/a?b/','https://evil/'):
            with self.subTest(value=bad):
                (fw.ROOT/'config.json').write_text(json.dumps({'ui_base_path':bad,'ui_public_origin':DOMAIN}))
                with self.assertRaises(ValueError):webui.base_path()
        for bad in ('http://insecure.example','https://a.example/foo','https://a.example?ok=1','https://user@host.example'):
            with self.subTest(value=bad):
                (fw.ROOT/'config.json').write_text(json.dumps({'ui_base_path':PREFIX,'ui_public_origin':bad}))
                with self.assertRaises(ValueError):webui.public_origin()

if __name__=='__main__':unittest.main()
