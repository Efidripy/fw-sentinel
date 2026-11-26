"""Unified source list, scoped CSRF-safe refresh jobs, real progress, no nft mutation."""
from __future__ import annotations
import base64
import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.request import Request, urlopen, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError
from urllib.parse import urlencode
from unittest import mock
from http.server import ThreadingHTTPServer
import fw_sentinel as fw
import webui

BASE=Path(__file__).resolve().parents[1]

import i18n  # noqa: E402

def setUpModule():  # these checks read the Russian texts
    i18n.FORCED = 'ru'


def tearDownModule():
    i18n.FORCED = None


class FeedRefresh221(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        orig=fw.ROOT;fw.ROOT=self.root;self.addCleanup(setattr,fw,'ROOT',orig)
        orig_token=webui.TOKEN_FILE;webui.TOKEN_FILE=self.root/'ui-token';self.addCleanup(setattr,webui,'TOKEN_FILE',orig_token)
        (self.root/'ui-token').write_text('test_password')
        cfg=json.loads((BASE/'config.json').read_text())
        cfg.update(ui_base_path='/secret_path/',ui_public_origin='https://example.test')
        (self.root/'config.json').write_text(json.dumps(cfg))
        (self.root/'sources.json').write_text((BASE/'sources.json').read_text())
        for f in ('asn.txt','allow.txt','manual-bans.txt','vpn-clients.txt'):
            (self.root/f).write_text('')

    def test_single_consolidated_table_and_update_per_source(self):
        cached=self.root/'cache/sources';cached.mkdir(parents=True)
        (cached/'advanced_nerd_scan.meta.json').write_text(json.dumps({'count':353080,'updated':fw.now()}))
        (cached/'cidr_old_orphan.meta.json').write_text(json.dumps({'count':18,'updated':fw.now()}))
        page=webui.sources_page()
        self.assertEqual(page.count('<table class="feed-table">'),1)
        self.assertNotIn('Загруженные списки ·',page)
        self.assertIn('353080',page)
        self.assertIn('cidr_old_orphan',page)
        self.assertIn('name="source" value="advanced_nerd_scan"',page)
        self.assertIn('name="source" value="cidr_censys"',page)
        self.assertIn('name="source" value="threat_watch_blocklist_bots"',page)
        self.assertIn('action="/secret_path/sources/refresh"',page)
        self.assertIn('class="feed-progress" hidden',page)
        self.assertIn('api/feed-refresh-status',page)
        self.assertEqual(page.count('data-feed-source="advanced_nerd_scan"'),1)
        self.assertIn('Базы с регистрацией',page)
        self.assertNotIn('source='+str(self.root),page)

    def test_start_worker_is_async_single_and_validates_source(self):
        with mock.patch.object(fw,'run',return_value=mock.Mock(returncode=0,stderr='',stdout='')) as process:
            with mock.patch.object(fw,'nft',side_effect=AssertionError('NEVER nft in enqueuing')):
                token=fw.feed_refresh_start('advanced_nerd_scan')
        self.assertEqual(len(token),32)
        self.assertIn('systemd-run',str(process.call_args_list))
        self.assertIn('feed-refresh-worker',str(process.call_args_list))
        self.assertEqual(fw.feed_refresh_status()['state'],'queued')
        with mock.patch.object(fw,'run',return_value=mock.Mock(returncode=0)):
            with self.assertRaisesRegex(RuntimeError,'Уже обновляется'):
                fw.feed_refresh_start('advanced_misp_cyberok')
        with self.assertRaisesRegex(ValueError,'Неизвестная база'):
            fw.feed_refresh_start('bad;touch /tmp/pwn')
        self.assertFalse(list(self.root.glob('.pending-*')))

    def test_worker_download_parse_cache_real_percent_and_no_firewall(self):
        name='advanced_threatview_high'
        token='e'*32
        fw._feed_job_path().parent.mkdir(parents=True)
        fw.atomic_write(fw._feed_job_path(),json.dumps({'id':token,'source':name,'state':'queued','percent':0,'created':0}))
        data=b'8.8.8.8\n1.1.1.1\n2001:4860:4860::8888\n'
        def fake_download(urls,limit,progress=None):
            if progress:
                progress(0,len(data));progress(len(data)//2,len(data));progress(len(data),len(data))
            return data
        states=[];original=fw.atomic_write
        def capture(path,content,*args,**kwargs):
            if path==fw._feed_job_path():
                values=json.loads(content)
                states.append((values['state'],values['percent'],values['message']))
            return original(path,content,*args,**kwargs)
        with mock.patch.object(fw,'nft',side_effect=AssertionError('NEVER mutate nft')):
            with mock.patch.object(fw,'urls_download',side_effect=fake_download):
                with mock.patch.object(fw,'atomic_write',side_effect=capture):
                    fw.feed_refresh_worker(token)
        result=fw.feed_refresh_status()
        self.assertEqual(result['state'],'done')
        self.assertEqual(result['percent'],100)
        self.assertEqual(fw.feed_refresh_catalog()[name]['count'],3)
        self.assertIn('download',[q[0] for q in states])
        self.assertIn('parse',[q[0] for q in states])
        self.assertIn('validate',[q[0] for q in states])
        self.assertTrue(any(5<percent<65 for st,percent,_ in states if st=='download'))
        self.assertEqual(states[-1][0],'done')
        self.assertFalse(list(self.root.glob('.pending-*')))

    def test_bad_download_preserves_existing_cache_and_error_status(self):
        name='advanced_threatview_high';token='b'*32
        path=self.root/'cache/sources'/f'{name}.txt';path.parent.mkdir(parents=True)
        path.write_text('8.8.8.8/32\n')
        path.with_suffix('.meta.json').write_text(json.dumps({'count':1,'updated':fw.now()}))
        fw.atomic_write(fw._feed_job_path(),json.dumps({'id':token,'source':name,'state':'queued','percent':0}))
        with mock.patch.object(fw,'urls_download',side_effect=RuntimeError('Provider down')):
            fw.feed_refresh_worker(token)
        self.assertEqual(fw.feed_refresh_status()['state'],'error')
        self.assertIn('Provider down',fw.feed_refresh_status()['error'])
        self.assertEqual(path.read_text(),'8.8.8.8/32\n')
        self.assertEqual(fw.feed_refresh_catalog()[name]['count'],1)

    def test_worker_updates_legacy_cidr_feed_without_touching_firewall(self):
        source='cidr_censys';token='f'*32
        fw._feed_job_path().parent.mkdir(parents=True)
        fw.atomic_write(fw._feed_job_path(),json.dumps({'id':token,'source':source,'state':'queued','percent':0}))
        with mock.patch.object(fw,'urls_download',return_value=b'8.8.8.8\n1.1.1.1\n'):
            with mock.patch.object(fw,'nft',side_effect=AssertionError('No active firewall mutation')):
                fw.feed_refresh_worker(token)
        self.assertEqual(fw.feed_refresh_status()['state'],'done')
        self.assertEqual(fw.feed_refresh_catalog()[source]['count'],2)
        self.assertTrue((self.root/'cache/sources/cidr_censys.txt').exists())

    def test_empty_content_length_reports_bytes_not_a_guessed_percentage(self):
        # Bytes are measured, but progress has no invented total if the server
        # didn't supply Content-Length.
        class Response:
            headers={}
            def __init__(self):self.steps=iter((b'8.8.8.8\n',b'1.1.1.1\n',b''))
            def geturl(self):return 'https://example.test/list'
            def read(self,n):return next(self.steps)
            def __enter__(self):return self
            def __exit__(self,*_):pass
        progress=[]
        with mock.patch.object(fw.urllib.request,'urlopen',return_value=Response()):
            data=fw.urls_download(['https://example.test/list'],1024,progress=lambda got,total:progress.append((got,total)))
        self.assertEqual(data,b'8.8.8.8\n1.1.1.1\n')
        self.assertEqual(progress[-1],(len(data),None))

    def test_authenticated_csrf_origin_and_safe_endpoint(self):
        server=ThreadingHTTPServer(('127.0.0.1',0),webui.Handler)
        th=threading.Thread(target=server.serve_forever,daemon=True);th.start()
        root=f'http://127.0.0.1:{server.server_port}'
        auth='Basic '+base64.b64encode(b'admin:test_password').decode()
        common={'Authorization':auth,'Host':'example.test'}
        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self,*a,**kw):return None
        try:
            with self.assertRaises(HTTPError) as err:
                urlopen(Request(root+'/secret_path/api/feed-refresh-status',headers={'Host':'example.test','X-FWS-Feed':'1'}),timeout=3)
            self.assertEqual(err.exception.code,401)
            with self.assertRaises(HTTPError) as err:
                urlopen(Request(root+'/secret_path/api/feed-refresh-status',headers=common),timeout=3)
            self.assertEqual(err.exception.code,403)
            r=urlopen(Request(root+'/secret_path/api/feed-refresh-status',headers={**common,'X-FWS-Feed':'1'}),timeout=3)
            self.assertEqual(json.load(r),{})
            def post(fields,extra=None):
                payload=urlencode(fields).encode()
                return build_opener(NoRedirect()).open(Request(root+'/secret_path/sources/refresh',data=payload,
                    headers={**common,'Origin':'https://example.test','Content-Type':'application/x-www-form-urlencoded',**(extra or {})}),timeout=3)
            with self.assertRaises(HTTPError) as err:post({'csrf':'wrong','source':'advanced_nerd_scan'})
            self.assertEqual(err.exception.code,400)
            with self.assertRaises(HTTPError) as err:post({'csrf':webui.csrf(),'source':'advanced_nerd_scan'},{'Origin':'https://malicious.example'})
            self.assertEqual(err.exception.code,403)
            with self.assertRaises(HTTPError) as err:post({'csrf':webui.csrf(),'source':'bad_source'})
            self.assertEqual(err.exception.code,400)
            with mock.patch.object(fw,'run',return_value=mock.Mock(returncode=0,stderr='',stdout='')):
                with self.assertRaises(HTTPError) as err:post({'csrf':webui.csrf(),'source':'advanced_nerd_scan'})
            self.assertEqual(err.exception.code,303)
            self.assertEqual(err.exception.headers.get('Location'),'/secret_path/sources')
            self.assertEqual(fw.feed_refresh_status()['source'],'advanced_nerd_scan')
        finally:
            server.shutdown();server.server_close();th.join(timeout=3)

if __name__=='__main__':unittest.main()
