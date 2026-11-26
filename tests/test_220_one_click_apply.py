"""2.0.20: single apply button, isolated systemd worker and 120s rollback."""
from __future__ import annotations
import base64
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen
from urllib.parse import urlencode
from urllib.error import HTTPError

import fw_sentinel as fw
import webui

import i18n  # noqa: E402

def setUpModule():  # these checks read the Russian texts
    i18n.FORCED = 'ru'


def tearDownModule():
    i18n.FORCED = None


class SingleApplyTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        original=fw.ROOT;fw.ROOT=self.root;self.addCleanup(setattr,fw,'ROOT',original)
        oldtoken=webui.TOKEN_FILE;webui.TOKEN_FILE=self.root/'ui-token'
        self.addCleanup(setattr,webui,'TOKEN_FILE',oldtoken)
        (self.root/'ui-token').write_text('secret_browser_password')
        conf=json.loads((Path(__file__).resolve().parents[1]/'config.json').read_text())
        conf.update(ui_base_path='/secret/',ui_public_origin='https://probe.example.test')
        (self.root/'config.json').write_text(json.dumps(conf))
        (self.root/'sources.json').write_text(json.dumps({'cidr':{},'threat_watch':{},'threat_ssh':{},'advanced_feeds':{}}))
        for name,text in [('allow.txt','1.1.1.1\n'),('vpn-clients.txt','8.8.8.8\n'),('manual-bans.txt',''),('asn.txt','')]:
            (self.root/name).write_text(text)
        self.options={key:bool(conf.get(key,False)) for key in fw.WEB_BOOL_FIELDS}
        self.options['geo_choice']='off'

    def test_one_click_form_and_no_draft_form(self):
        page=webui.control_page()
        self.assertIn('action="/secret/control/apply-now"',page)
        self.assertIn('ПРИМЕНИТЬ ПРАВИЛА',page)
        self.assertNotIn('action="/secret/control/stage"',page)
        self.assertNotIn('Сохранить черновик и проверить',page)
        self.assertNotIn('Введите ВКЛЮЧИТЬ',page)
        self.assertIn('120 секунд',page)
        self.assertIn('/secret/control/confirm',webui.shield_controls('enforce',{})) if webui.pending_trial() else None

    def test_submit_creates_job_without_touching_running_nft(self):
        with mock.patch.object(fw,'run',return_value=mock.Mock(returncode=0,stderr='',stdout='')) as invoke:
            with mock.patch.object(fw,'nft',side_effect=AssertionError('No nft before worker!')):
                token=fw.ui_apply_start(self.options)
        self.assertEqual(len(token),32)
        rec=fw._ui_job_read(token)
        self.assertEqual(rec['status'],'queued')
        self.assertEqual(rec['selections'],self.options)
        self.assertEqual(fw.ui_apply_status(token)['status'],'queued')
        self.assertIn('systemd-run',str(invoke.call_args_list))
        self.assertIn('ui-apply-worker',str(invoke.call_args_list))
        with mock.patch.object(fw,'run',return_value=mock.Mock(returncode=0)):
            with self.assertRaisesRegex(RuntimeError,'Проверка уже идёт'):
                fw.ui_apply_start(self.options)
        self.assertEqual(len(list(self.root.glob('.ui-apply-*.json'))),1)

    def test_progress_survives_page_reload(self):
        with mock.patch.object(fw,'run',return_value=mock.Mock(returncode=0,stderr='',stdout='')):
            token=fw.ui_apply_start(self.options)
        self.assertEqual(fw.ui_apply_current(),token)
        page=webui.control_page()  # browser returned without ?job=...
        self.assertIn('id="ui-apply-status"',page)
        self.assertIn('api/ui-apply-status',page)
        self.assertIn('ПРИМЕНИТЬ ПРАВИЛА',page)
        self.assertIn('disabled>ПРИМЕНИТЬ ПРАВИЛА',page)

    def test_worker_runs_checks_then_trial_not_confirm(self):
        token='c'*32
        fw._ui_job_save(token,{'status':'queued','created_unix':0,
                               'message':'','base_signature':fw.policy_signature(fw.config()),
                               'selections':self.options})
        with mock.patch.object(fw,'web_stage',return_value={'candidate':{}}) as stage:
            with mock.patch.object(fw,'web_activate',return_value={'token':'d'*32,'deadline':9999999999}) as activate:
                fw.ui_apply_worker(token)
        stage.assert_called_once_with(self.options)
        activate.assert_called_once_with(None)  # no client IP: manual confirmation stays
        rec=fw._ui_job_read(token)
        self.assertEqual(rec['status'],'trial')
        self.assertEqual(rec['deadline'],9999999999)
        self.assertEqual(rec['trial_token'],'d'*32)
        self.assertEqual(fw.ui_apply_status(token)['status'],'finished')  # no pending marker created by mock
        self.assertEqual(fw.config()['advanced_feed_pack_enabled'],False)

    def test_worker_reports_failure_and_no_trial(self):
        token='e'*32
        fw._ui_job_save(token,{'status':'queued','created_unix':0,'message':'',
                               'base_signature':fw.policy_signature(fw.config()),'selections':self.options})
        with mock.patch.object(fw,'web_stage',side_effect=RuntimeError('nft -c refused')):
            with mock.patch.object(fw,'web_activate',side_effect=AssertionError('should not activate')):
                with self.assertRaisesRegex(RuntimeError,'nft -c refused'):
                    fw.ui_apply_worker(token)
        status=fw.ui_apply_status(token)
        self.assertEqual(status['status'],'error')
        self.assertIn('nft -c refused',status['error'])
        page=webui.control_page(job=token)
        self.assertIn('Применение отклонено',page)
        self.assertIn('nft -c refused',page)

    def test_worker_refuses_stale_config_before_any_checks(self):
        token='f'*32
        fw._ui_job_save(token,{'status':'queued','created_unix':0,'message':'',
                               'base_signature':'mismatch','selections':self.options})
        with mock.patch.object(fw,'web_stage',side_effect=AssertionError('No stage')):
            with self.assertRaises(RuntimeError):fw.ui_apply_worker(token)
        self.assertEqual(fw.ui_apply_status(token)['status'],'error')

    def test_http_post_one_click_and_separate_status_endpoint(self):
        server=ThreadingHTTPServer(('127.0.0.1',0),webui.Handler)
        th=threading.Thread(target=server.serve_forever,daemon=True);th.start()
        base=f'http://127.0.0.1:{server.server_port}'
        auth='Basic '+base64.b64encode(b'admin:secret_browser_password').decode()
        headers={'Authorization':auth,'Host':'probe.example.test','Content-Type':'application/x-www-form-urlencoded'}
        fields={'csrf':webui.csrf(),'geo_choice':'off','scanner_enabled':'1',
                'autoban_exclude_tcp_ports':'22,443,8443',
                'autoban_exclude_udp_ports':'53,443',
                'autoban_trap_ports':''}
        from urllib.request import build_opener,HTTPHandler,HTTPRedirectHandler
        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self,*args,**kwargs):return None
        try:
            with mock.patch.object(fw,'ui_apply_start',return_value='a'*32) as submit:
                req=Request(base+'/secret/control/apply-now',data=urlencode(fields).encode(),headers=headers)
                try:
                    build_opener(NoRedirect()).open(req,timeout=5)
                except HTTPError as exc:
                    self.assertEqual(exc.code,303)
                    self.assertEqual(exc.headers['Location'],'/secret/control?job='+'a'*32)
                submit.assert_called_once()
                self.assertTrue(submit.call_args.args[0]['scanner_enabled'])
                self.assertEqual(submit.call_args.args[0]['autoban_trap_ports'],[])  # cleared field removes traps
            with mock.patch.object(fw,'ui_apply_status',return_value={'status':'checking','message':'Проверяем'}) as status:
                req=Request(base+'/secret/api/ui-apply-status?job='+'a'*32,headers={'Authorization':auth,'Host':'probe.example.test'})
                with urlopen(req,timeout=5) as resp:
                    self.assertEqual(resp.status,200)
                    self.assertEqual(json.load(resp)['status'],'checking')
                status.assert_called_once_with('a'*32)
            req=Request(base+'/secret/control/apply-now',data=urlencode({**fields,'csrf':'bad'}).encode(),headers=headers)
            with self.assertRaises(HTTPError) as bad:
                urlopen(req,timeout=5)
            self.assertEqual(bad.exception.code,400)
        finally:
            server.shutdown();server.server_close();th.join(timeout=3)

    def test_broken_pipe_does_not_try_to_send_twice(self):
        handler=object.__new__(webui.Handler)
        with mock.patch.object(handler,'send_safe_headers',side_effect=BrokenPipeError):
            self.assertIsNone(handler.respond(200,'sample'))

if __name__=='__main__':unittest.main()
