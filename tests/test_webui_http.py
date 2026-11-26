"""Local socket HTTP smoke tests: auth, CSRF, update, cross-site POST refusal."""
import base64
from http.server import ThreadingHTTPServer
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest import mock
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


class WebUIHTTPTest(unittest.TestCase):
    def test_local_http_workflow(self):
        with tempfile.TemporaryDirectory() as folder:
            original_root, original_token = fw.ROOT, webui.TOKEN_FILE
            root=Path(folder);fw.ROOT=root;webui.TOKEN_FILE=root/'ui-token'
            try:
                (root/'ui-token').write_text('testpassword')
                (root/'allow.txt').write_text('8.8.8.8\n')
                (root/'manual-bans.txt').write_text('')
                (root/'vpn-clients.txt').write_text('')
                (root/'config.json').write_text('{"ui_port":1488,"geo_enabled":false,"geo_ports":[443],"ssh_rate_per_minute":10,"ssh_ports":[22],"wan_interfaces":["eth0"]}')
                (root/'sources.json').write_text('{"cidr":{}}')
                (root/'asn.txt').write_text('')
                fake=mock.Mock(returncode=1)
                with mock.patch.object(fw,'run',return_value=fake):
                    server=ThreadingHTTPServer(('127.0.0.1',0),webui.Handler)
                    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
                    base=f'http://127.0.0.1:{server.server_port}'
                    try:
                        with self.assertRaises(HTTPError) as cm:
                            urlopen(base+'/',timeout=3)
                        self.assertEqual(cm.exception.code,401)
                        hdr={'Authorization':'Basic '+base64.b64encode(b'admin:testpassword').decode()}
                        body=urlopen(Request(base+'/',headers=hdr),timeout=3).read().decode()
                        self.assertIn('FW SENTINEL',body)
                        self.assertIn('1488',body)
                        form=urlencode({'csrf':webui.csrf(),'ip':'9.9.9.9'}).encode()
                        write_headers={**hdr,'Origin':base,'Content-Type':'application/x-www-form-urlencoded'}
                        result=urlopen(Request(base+'/ban',data=form,headers=write_headers),timeout=3).read().decode()
                        self.assertIn('Операция выполнена',result)
                        self.assertIn('9.9.9.9',(root/'manual-bans.txt').read_text())
                        vpn_form=urlencode({'csrf':webui.csrf(),'ip':'8.8.4.4'}).encode()
                        vpn_response=urlopen(Request(base+'/vpn-add',data=vpn_form,headers=write_headers),timeout=3).read().decode()
                        self.assertIn('Операция выполнена',vpn_response)
                        self.assertIn('8.8.4.4',(root/'vpn-clients.txt').read_text())
                        self.assertIn('Исключения для клиентов VPN',urlopen(Request(base+'/access',headers=hdr),timeout=3).read().decode())
                        with self.assertRaises(HTTPError) as cm:
                            urlopen(Request(base+'/ban',data=form,headers={**write_headers,'Origin':'http://evil.invalid'}),timeout=3)
                        self.assertEqual(cm.exception.code,403)
                    finally:
                        server.shutdown();server.server_close();thread.join(timeout=2)
            finally:
                fw.ROOT,webui.TOKEN_FILE=original_root,original_token

if __name__=='__main__':unittest.main()
