"""Shell UI and resilient same-site admin POST, without weakening CSRF."""
import base64
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch, Mock
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import fw_sentinel as fw
import webui

import i18n  # noqa: E402

def setUpModule():  # these checks read the Russian texts
    i18n.FORCED = 'ru'


def tearDownModule():
    i18n.FORCED = None


class ShellWebUITests(unittest.TestCase):
    def test_terminal_chrome_routes_and_labels(self):
        with tempfile.TemporaryDirectory() as d:
            old_root=fw.ROOT
            fw.ROOT=Path(d)
            (fw.ROOT/'config.json').write_text(json.dumps({'ui_base_path':'/fws-secret-path/','ui_public_origin':'https://probe.example.com'}))
            try:
                html=webui.doc('<h2>Проверка</h2>',title='Управление')
                self.assertIn('FW SENTINEL // SECURE TERMINAL',html)
                self.assertIn('/fws-secret-path/control',html)
                self.assertIn('aria-current="page"',html)
                self.assertIn('Настройки защиты',html)
                self.assertIn('font-variant-ligatures:none',html)
                self.assertNotIn('src="https://',html)
            finally:
                fw.ROOT=old_root

    def test_post_origin_fallback_never_replaces_csrf(self):
        with tempfile.TemporaryDirectory() as td:
            old_root,old_token=fw.ROOT,webui.TOKEN_FILE
            fw.ROOT=Path(td);webui.TOKEN_FILE=fw.ROOT/'ui-token'
            config={'ui_base_path':'/fws-secret-path/', 'ui_public_origin':'https://probe.example.com',
                    'wan_interfaces':['eth0'],'geo_enabled':False, 'ssh_ports':[22], 'geo_ports':[443],
                    'vpn_ports':[443], 'ssh_rate_per_minute':10}
            for name,body in {'config.json':json.dumps(config),'ui-token':'secret-browser-pass',
                              'allow.txt':'','vpn-clients.txt':'','manual-bans.txt':'','asn.txt':'',
                              'sources.json':'{"cidr":{}}'}.items():
                (fw.ROOT/name).write_text(body)
            server=ThreadingHTTPServer(('127.0.0.1',0),webui.Handler)
            worker=threading.Thread(target=server.serve_forever,daemon=True)
            worker.start()
            host=f'http://127.0.0.1:{server.server_port}'
            auth='Basic '+base64.b64encode(b'admin:secret-browser-pass').decode()
            def post(path,form,headers=None):
                base={'Authorization':auth,'Host':'probe.example.com','Content-Type':'application/x-www-form-urlencoded'}
                base.update(headers or {})
                req=Request(host+'/'+path,headers=base,data=urlencode(form).encode())
                try:
                    response=urlopen(req,timeout=3)
                    return response.status,response.read().decode()
                except HTTPError as ex:
                    return ex.code,ex.read().decode()
            try:
                with patch.object(fw,'run',return_value=Mock(returncode=1)), patch.object(fw,'web_stage') as stage:
                    form={'csrf':webui.csrf(),'geo_choice':'off',
                          'scanner_enabled':'1','autoban_exclude_tcp_ports':'443,8443',
                          'autoban_exclude_udp_ports':'443'}
                    status,body=post('control/stage',form)
                    self.assertEqual(status,200,body[:500])
                    self.assertIn('Черновик сохранён',body)
                    stage.assert_called_once()
                    self.assertTrue(stage.call_args.args[0]['scanner_enabled'])
                    for headers in ({'Origin':'https://evil.invalid'},
                                    {'Origin':'null','Sec-Fetch-Site':'cross-site'},
                                    {'Sec-Fetch-Site':'cross-site'},
                                    {'Referer':'https://evil.invalid/path'}):
                        code,body=post('control/stage',form,headers)
                        self.assertEqual(code,403,headers)
                    for headers in ({}, {'Sec-Fetch-Site':'same-origin','Sec-Fetch-Mode':'navigate'},
                                    {'Origin':'null','Sec-Fetch-Site':'same-origin','Sec-Fetch-Mode':'navigate'}):
                        code,body=post('control/stage',{**form,'csrf':'not-valid'},headers)
                        self.assertEqual(code,400,headers)
                    self.assertEqual(stage.call_count,1)
            finally:
                server.shutdown();server.server_close();worker.join(timeout=2)
                fw.ROOT,webui.TOKEN_FILE=old_root,old_token

if __name__=='__main__':unittest.main()
