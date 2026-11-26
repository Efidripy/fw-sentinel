"""HTTP tests for subpath bulk lists and the provider key vault."""
import base64
import json
from http.server import ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request,urlopen

import fw_sentinel as fw
import provider_keys
import webui

BASE=Path(__file__).resolve().parents[1]

import i18n  # noqa: E402

def setUpModule():  # these checks read the Russian texts
    i18n.FORCED = 'ru'


def tearDownModule():
    i18n.FORCED = None


class HTTP217(unittest.TestCase):
    def test_subpath_bulk_import_auth_csrf_and_provider_keys(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            old_root,old_token=fw.ROOT,webui.TOKEN_FILE
            fw.ROOT=root;webui.TOKEN_FILE=root/'ui-token'
            try:
                (root/'ui-token').write_text('testpassword')
                cfg=json.loads((BASE/'config.json').read_text())
                cfg.update(ui_base_path='/secret987/',ui_public_origin='https://example.test')
                (root/'config.json').write_text(json.dumps(cfg))
                (root/'sources.json').write_text((BASE/'sources.json').read_text())
                for filename,value in [('allow.txt','8.8.8.8\n'),('manual-bans.txt',''),('vpn-clients.txt',''),('asn.txt','')]:
                    (root/filename).write_text(value)
                with mock.patch.object(fw,'run',return_value=mock.Mock(returncode=1)):
                    server=ThreadingHTTPServer(('127.0.0.1',0),webui.Handler)
                    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
                    try:
                        base='http://127.0.0.1:'+str(server.server_port)
                        auth={'Authorization':'Basic '+base64.b64encode(b'admin:testpassword').decode()}
                        def get(path):return urlopen(Request(base+'/secret987'+path,headers=auth),timeout=3).read().decode()
                        def post(path,values,headers=None):
                            body=urlencode({'csrf':webui.csrf(),**values}).encode('utf-8')
                            h={**auth,'Origin':base,'Content-Type':'application/x-www-form-urlencoded',**(headers or {})}
                            return urlopen(Request(base+'/secret987'+path,data=body,headers=h),timeout=3).read().decode()
                        page=get('/access')
                        self.assertIn('/secret987/bulk/ban',page)
                        self.assertIn('/secret987/bulk/allow',page)
                        self.assertIn('/secret987/provider/set',get('/sources'))
                        result=post('/bulk/ban',{'ips':'9.9.9.9\n9.9.9.9,1.1.1.1\n8.8.8.8\nBAD'})
                        self.assertIn('Добавлено: 2',result)
                        self.assertIn('Дубли: 1',result)
                        self.assertIn('Конфликты: 1',result)
                        self.assertIn('Ошибки: 1',result)
                        again=post('/bulk/ban',{'ips':'9.9.9.9 1.1.1.1'})
                        self.assertIn('Добавлено: 0',again)
                        key='AbCdeFGHIJKLMnop1234'
                        posted=post('/provider/set',{'provider':'crowdsec','key':key})
                        self.assertIn('Ключ сохранён',posted)
                        self.assertNotIn(key,posted)
                        self.assertTrue(provider_keys.enabled(root,'crowdsec'))
                        # Browser omits blank key: this MUST disable the provider.
                        disabled=post('/provider/set',{'provider':'crowdsec','key':''})
                        self.assertIn('источник отключён',disabled)
                        self.assertFalse(provider_keys.enabled(root,'crowdsec'))
                        # CSRF and cross-origin checks stay mandatory.
                        with self.assertRaises(HTTPError) as err:
                            post('/bulk/ban',{'ips':'3.3.3.3'},headers={'Origin':'https://foreign.example'})
                        self.assertEqual(err.exception.code,403)
                        with self.assertRaises(HTTPError) as err:
                            post('/bulk/allow',{'csrf':'wrong','ips':'3.3.3.3'})
                        self.assertEqual(err.exception.code,400)
                    finally:
                        server.shutdown();server.server_close();thread.join(timeout=2)
            finally:
                fw.ROOT,webui.TOKEN_FILE=old_root,old_token

if __name__=='__main__':unittest.main()
