"""Read-only previews, explicit activation, automatic rollback, and admin web controls."""
import base64
import ipaddress
import json
from pathlib import Path
import tempfile
import threading
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
import unittest
from unittest import mock
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import fw_sentinel as fw
import webui

import i18n  # noqa: E402

def setUpModule():  # these checks read the Russian texts
    i18n.FORCED = 'ru'


def tearDownModule():
    i18n.FORCED = None


class Controls(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        original=fw.ROOT;fw.ROOT=Path(self.tmp.name);self.addCleanup(setattr,fw,'ROOT',original)
        original_token=webui.TOKEN_FILE;webui.TOKEN_FILE=fw.ROOT/'ui-token';self.addCleanup(setattr,webui,'TOKEN_FILE',original_token)
        (fw.ROOT/'ui-token').write_text('StrongPassword12')
        cfg=json.loads((Path(__file__).resolve().parents[1]/'config.json').read_text())
        cfg.update(wan_interfaces=['ens3'],ui_base_path='/secret/',ui_public_origin='https://panel.example')
        (fw.ROOT/'config.json').write_text(json.dumps(cfg))
        (fw.ROOT/'sources.json').write_text('{"cidr":{},"threat_ssh":{},"threat_watch":{}}')
        for name,contents in [('allow.txt','1.1.1.1\n'),('manual-bans.txt',''),('vpn-clients.txt','8.8.8.8\n'),('asn.txt','')]:
            (fw.ROOT/name).write_text(contents)
        self.sets={'geo':[ipaddress.ip_network('185.0.0.0/8'),ipaddress.ip_network('2001:db8::/32')],
            'scanners':[ipaddress.ip_network('198.51.100.0/24')],
            'asn':[ipaddress.ip_network('203.0.113.0/24')],
            'trusted':[ipaddress.ip_network('1.1.1.1')],
            'manual':[],'vpn_clients':[ipaddress.ip_network('8.8.8.8')],
            'threat_ssh':[],'threat_watch':[]}
        (fw.ROOT/'state.json').write_text(json.dumps({'mode':'observe','updated':'now','issues':[],'policy_signature':fw.policy_signature(cfg)}))
        (fw.ROOT/'active.nft').write_text('old fw rules')
        self.options={k:bool(cfg[k]) for k in fw.WEB_BOOL_FIELDS}
        self.options['geo_choice']='off'

    def test_distinct_geo_policies_and_vpn_no_rate(self):
        c=fw.config()
        normal=fw.render_rules({**c,'geo_enabled':True,'geo_mode':'ru_only'},self.sets,True)
        invert=fw.render_rules({**c,'geo_enabled':True,'geo_mode':'non_ru_only'},self.sets,True)
        self.assertIn('tcp, udp } th dport { 443, 8443 } ip saddr != @ru4 counter drop',normal)
        self.assertIn('tcp, udp } th dport { 443, 8443 } ip saddr @ru4 counter drop',invert)
        self.assertNotIn('tcp dport { 443, 8443 } ct state new tcp flags syn meter',invert)
        self.assertLess(invert.index('ip saddr @vpn4 accept'),invert.index('ip saddr @ru4 counter drop'))

    def test_scanner_asn_are_independent(self):
        c=fw.config()
        scanner_disabled=fw.render_rules({**c,'scanner_enabled':False,'asn_enabled':True},self.sets,True)
        asn_disabled=fw.render_rules({**c,'scanner_enabled':True,'asn_enabled':False},self.sets,True)
        self.assertIn('ip saddr @asn4 counter drop',scanner_disabled)
        self.assertNotIn('ip saddr @scan4 counter drop',scanner_disabled)
        self.assertIn('ip saddr @scan4 counter drop',asn_disabled)
        self.assertNotIn('ip saddr @asn4 counter drop',asn_disabled)

    def test_draft_does_not_modify_active_rules_or_config(self):
        opts=dict(self.options, geo_choice='non_ru_only')
        with mock.patch.object(fw,'build_sets_from_sources',return_value=(self.sets,[],{})), mock.patch.object(fw,'nft') as nft:
            data=fw.web_stage(opts)
        self.assertEqual(data['candidate']['geo_mode'],'non_ru_only')
        self.assertEqual(fw.config()['geo_enabled'],False)
        self.assertEqual((fw.ROOT/'active.nft').read_text(),'old fw rules')
        self.assertEqual(fw.state()['mode'],'observe')
        self.assertEqual(nft.call_count,1)
        self.assertEqual(nft.call_args.kwargs,{'check_only':True})

    def test_web_activate_confirm_commit_and_timer(self):
        self.test_draft_does_not_modify_active_rules_or_config()
        with mock.patch.object(fw,'build_sets_from_sources',return_value=(self.sets,[],{})), mock.patch.object(fw,'nft') as nft, mock.patch.object(fw,'run',return_value=mock.Mock(returncode=0,stderr='')) as run:
            result=fw.web_activate()
            self.assertEqual(fw.config()['geo_enabled'],False)
            self.assertTrue((fw.ROOT/('.pending-'+result['token'])).exists())
            self.assertIn('systemd-run',str(run.call_args_list))
            fw.web_confirm(result['token'])
        self.assertTrue(fw.config()['geo_enabled'])
        self.assertEqual(fw.config()['geo_mode'],'non_ru_only')
        self.assertEqual(fw.state()['mode'],'enforce')
        self.assertNotEqual((fw.ROOT/'active.nft').read_text(),'old fw rules')
        self.assertFalse(list(fw.ROOT.glob('.pending-*')))

    def test_timeout_rollback_restores_config_snapshot_state(self):
        self.test_draft_does_not_modify_active_rules_or_config()
        with mock.patch.object(fw,'build_sets_from_sources',return_value=(self.sets,[],{})), mock.patch.object(fw,'nft'), mock.patch.object(fw,'run',return_value=mock.Mock(returncode=0,stderr='')):
            result=fw.web_activate()
            fw.rollback(result['token'])
        self.assertEqual(fw.config()['geo_enabled'],False)
        self.assertEqual(fw.state()['mode'],'observe')
        self.assertEqual((fw.ROOT/'active.nft').read_text(),'old fw rules')
        self.assertFalse(list(fw.ROOT.glob('.pending-*')))

    def test_guard_refuses_to_replace_unconfirmed_rules(self):
        (fw.ROOT/('.pending-'+'a'*32)).mkdir()
        with mock.patch.object(fw,'nft',side_effect=AssertionError('nft modified')):
            fw.guard()
        with self.assertRaisesRegex(RuntimeError,'неподтверждённые'):
            fw.disable()

    def test_draft_rejects_malformed_options(self):
        with self.assertRaises(ValueError):fw.policy_from_web(fw.config(),dict(self.options,geo_choice='both'))
        with self.assertRaises(ValueError):fw.policy_from_web(fw.config(),{'geo_choice':'off'})
        with self.assertRaises(ValueError):fw.policy_from_web(fw.config(),dict(self.options,threat_ssh_enabled=False,threat_ssh_enforce=True))

    def test_control_page_has_local_subpath_links_and_forms(self):
        with mock.patch.object(fw,'run',return_value=mock.Mock(returncode=1)):
            html=webui.control_page()
        for marker in ('/secret/control/apply-now','/secret/control/stop','/secret/control/apply-now','geo_choice',
                       'value="ru_only"','value="non_ru_only"','name="asn_enabled"','name="scanner_enabled"',
                       'name="ssh_rate_enabled"'):
            self.assertIn(marker,html)
        self.assertIn('/secret/control',webui.overview() if False else webui.doc(''))

    def test_http_post_stage_csrf_and_origin(self):
        server=ThreadingHTTPServer(('127.0.0.1',0),webui.Handler)
        t=threading.Thread(target=server.serve_forever,daemon=True);t.start()
        self.addCleanup(lambda: (server.shutdown(),server.server_close(),t.join(timeout=2)))
        auth='Basic '+base64.b64encode(b'admin:StrongPassword12').decode()
        url=f'http://127.0.0.1:{server.server_port}/control/stage'
        values=dict(csrf=webui.csrf(),geo_choice='off')
        values.update({k:'1' for k,v in self.options.items() if k!='geo_choice' and v})
        def post(origin,csrf_value):
            data=dict(values,csrf=csrf_value)
            req=Request(url,data=urlencode(data).encode('utf-8'),headers={
                'Authorization':auth,'Origin':origin,'Content-Type':'application/x-www-form-urlencoded','Host':f'127.0.0.1:{server.server_port}'})
            try:
                with urlopen(req,timeout=3) as resp:return resp.status
            except HTTPError as err:return err.code
        with mock.patch.object(fw,'nft'), mock.patch.object(fw,'build_sets_from_sources',return_value=(self.sets,[],{})):
            self.assertEqual(post('https://evil.example',webui.csrf()),403)
            self.assertEqual(post(f'http://127.0.0.1:{server.server_port}','wrong'),400)
            self.assertEqual(post(f'http://127.0.0.1:{server.server_port}',webui.csrf()),200)
        self.assertTrue((fw.ROOT/'web-policy-draft.json').exists())

if __name__=='__main__':unittest.main()
