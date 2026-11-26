"""Regression for Chrome: no-referrer gives Origin:null on HTML form POST."""
import base64
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import fw_sentinel as fw
import webui

class ReferrerPolicyRegressionTests(unittest.TestCase):
    def test_referrer_policy_and_provenance_validation(self):
        with tempfile.TemporaryDirectory() as td:
            old_root,old_token=fw.ROOT,webui.TOKEN_FILE
            fw.ROOT=Path(td);webui.TOKEN_FILE=fw.ROOT/'ui-token'
            for name,data in {
                'ui-token':'test-secret',
                'config.json':json.dumps({'ui_base_path':'/secret/','ui_public_origin':'https://trrr.example.com'}),
                'manual-bans.txt':'', 'vpn-clients.txt':'', 'allow.txt':'',
                'sources.json':'{}', 'asn.txt':'',
            }.items(): (fw.ROOT/name).write_text(data)
            server=ThreadingHTTPServer(('127.0.0.1',0),webui.Handler)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            auth='Basic '+base64.b64encode(b'admin:test-secret').decode()
            host=f'http://127.0.0.1:{server.server_port}'
            headers={'Host':'trrr.example.com','Authorization':auth}
            try:
                with patch.object(fw,'run'):
                    res=urlopen(Request(host+'/',headers=headers),timeout=5)
                    self.assertEqual(res.headers.get('Referrer-Policy'),'same-origin')
                    html=res.read().decode('utf-8')
                    self.assertIn('<meta name="referrer" content="same-origin">',html)
                    self.assertNotIn('<meta name="referrer" content="no-referrer">',html)
                    self.assertEqual(webui.origin_allowed('https://trrr.example.com','https://trrr.example.com','same-origin','navigate'),True)
                    self.assertTrue(webui.origin_allowed('null','https://trrr.example.com','same-origin','navigate'))
                    self.assertFalse(webui.origin_allowed('null','https://trrr.example.com','cross-site','navigate'))
                    # POST with browser's real same-origin Origin and a deliberately wrong token
                    # must reach CSRF validation (400) rather than fail origin precheck (403).
                    form=urlencode({'csrf':'bad-token','geo_choice':'off'}).encode()
                    req=Request(host+'/control/stage', data=form, headers={**headers,
                        'Origin':'https://trrr.example.com','Sec-Fetch-Site':'same-origin',
                        'Sec-Fetch-Mode':'navigate','Content-Type':'application/x-www-form-urlencoded'})
                    with self.assertRaises(HTTPError) as raised:urlopen(req,timeout=5)
                    self.assertEqual(raised.exception.code,400)
            finally:
                server.shutdown();server.server_close();thread.join(timeout=2)
                fw.ROOT,webui.TOKEN_FILE=old_root,old_token

if __name__=='__main__':unittest.main()
