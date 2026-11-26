"""2.0.12 aggressive one-button profile: scanner/WATCH on VPN, with rollback."""
import base64
import ipaddress
import json
from pathlib import Path
import tempfile
import threading
from http.server import ThreadingHTTPServer
from unittest import TestCase, main, mock
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


class QuickShield(TestCase):
    def setUp(self):
        # Previous tests exercise the original 2.0.12 quick-profile logic;
        # the new extra-feeds readiness contract is tested separately.
        self._extra_ready=mock.patch.object(fw,'extras_status',return_value={
            'ready':True,'key_ready':True,
            'sources':{name:42 for name in fw.EXTRA_THREAT_FEEDS}})
        self._extra_ready.start()
        self.addCleanup(self._extra_ready.stop)
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.old_root=fw.ROOT;fw.ROOT=Path(self.tmp.name);self.addCleanup(setattr,fw,'ROOT',self.old_root)
        self.old_token=webui.TOKEN_FILE;webui.TOKEN_FILE=fw.ROOT/'ui-token'
        self.addCleanup(setattr,webui,'TOKEN_FILE',self.old_token)
        self.cfg=json.loads((Path(__file__).resolve().parents[1]/'config.json').read_text())
        self.cfg.update(wan_interfaces=['eth0'],ui_public_origin='https://probe.example.com',
                        ui_base_path='/fws-secret-path/')
        for name,data in {'config.json':json.dumps(self.cfg),'sources.json':'{"cidr":{},"threat_watch":{},"threat_ssh":{}}',
                          'allow.txt':'1.1.1.1\n','manual-bans.txt':'','vpn-clients.txt':'8.8.8.8\n','asn.txt':'',
                          'ui-token':'SecretPassword123'}.items():
            (fw.ROOT/name).write_text(data,encoding='utf8')
        self.sets={k:[] for k in ('geo','scanners','asn','manual','trusted','vpn_clients','threat_ssh','threat_watch')}
        self.sets['trusted']=[ipaddress.ip_network('1.1.1.1')]
        self.sets['vpn_clients']=[ipaddress.ip_network('8.8.8.8')]
        self.sets['scanners']=[ipaddress.ip_network('8.8.8.0/24')]
        self.sets['threat_watch']=[ipaddress.ip_network('9.9.9.0/24')]
        (fw.ROOT/'state.json').write_text(json.dumps({'mode':'observe','policy_signature':fw.policy_signature(self.cfg)}))
        (fw.ROOT/'active.nft').write_text('old policy')

    def render(self,drop_watch=False,enforce=True):
        config={**self.cfg,'threat_watch_enforce':drop_watch,'autoban_enabled':False}
        return fw.render_rules(config,self.sets,enforce)

    def test_watch_only_observes_unless_both_optin_and_enforce(self):
        self.assertIn('FWS O_WATCH4:',self.render(False,True))
        self.assertNotIn('FWS D_WATCH4:',self.render(False,True))
        self.assertIn('FWS O_WATCH4:',self.render(True,False))
        policy=self.render(True,True)
        self.assertIn('FWS D_WATCH4:',policy)
        self.assertIn('ip saddr @watch4 counter drop',policy)
        self.assertNotIn('FWS O_WATCH4:',policy)

    def test_scan_and_watch_drop_before_vpn_whitelist_on_443(self):
        policy=self.render(True,True)
        self.assertLess(policy.index('ip saddr @scan4 counter drop'),policy.index('ip saddr @vpn4 accept'))
        self.assertLess(policy.index('ip saddr @watch4 counter drop'),policy.index('ip saddr @vpn4 accept'))
        self.assertNotIn('dport != { 443, 8443 } ip saddr @scan4',policy)
        self.assertNotIn('dport != { 443, 8443 } ip saddr @watch4',policy)
        self.assertLess(policy.index('ip saddr @allow4 accept'),policy.index('ip saddr @watch4 counter drop'))
        self.assertLess(policy.index('ip saddr @ban4 counter drop'),policy.index('ip saddr @vpn4 accept'))

    def test_autoban_still_excludes_vpn_and_listening_service_ports(self):
        config={**self.cfg,'threat_watch_enforce':True,'autoban_enabled':True}
        with mock.patch.object(fw.autoban,'protected_ports',return_value=({22,443,8443,9000},{443,8443,51820})):
            policy=fw.render_rules(config,self.sets,True)
        self.assertIn('set autosafetcp { type inet_service; elements = { 22, 443, 8443, 9000 }',policy)
        self.assertIn('tcp dport != @autosafetcp ip saddr @auto4',policy)
        self.assertIn('ip saddr @watch4 counter drop',policy)

    def test_quick_shield_requires_static_ssh_allow(self):
        (fw.ROOT/'allow.txt').write_text('')
        with self.assertRaisesRegex(RuntimeError,'SSH-IP'):fw.web_quick_shield()

    def test_quick_shield_provisionally_stages_and_arms_rollback(self):
        with (mock.patch.object(fw,'build_sets_from_sources',return_value=(self.sets,[],{})),
              mock.patch.object(fw.autoban,'protected_ports',return_value=({22,443,8443},{443,8443})),
              mock.patch.object(fw,'nft') as nft,
              mock.patch.object(fw,'run',return_value=mock.Mock(returncode=0,stderr='')) as runner):
            result=fw.web_quick_shield()
            self.assertEqual(fw.config()['autoban_enabled'],False)
            self.assertEqual(fw.state()['mode'],'observe')
            self.assertTrue((fw.ROOT/('.pending-'+result['token'])).exists())
            staged=json.loads((fw.ROOT/('.pending-'+result['token'])/'new.config.json').read_text())
            self.assertTrue(staged['scanner_enabled'])
            self.assertTrue(staged['threat_watch_enforce'])
            self.assertTrue(staged['autoban_enabled'])
            self.assertFalse(staged['geo_enabled'])
            self.assertFalse(staged['asn_enabled'])
            self.assertIn('FWS D_WATCH4:',(fw.ROOT/('.pending-'+result['token'])/'new.nft').read_text())
            self.assertGreaterEqual(sum(1 for c in nft.call_args_list if c.kwargs.get('check_only')),2)
            self.assertTrue(any(c.args[0]=='systemd-run' and '--on-active=120s' in c.args for c in runner.call_args_list))
            with mock.patch.object(fw.autoban,'rearm_for_rules'):
                fw.web_confirm(result['token'])
            self.assertEqual(fw.state()['mode'],'enforce')
            self.assertTrue(fw.config()['autoban_enabled'])
            self.assertTrue(fw.config()['threat_watch_enforce'])
            self.assertFalse(list(fw.ROOT.glob('.pending-*')))

    def test_quick_shield_rolls_back_if_not_confirmed(self):
        with (mock.patch.object(fw,'build_sets_from_sources',return_value=(self.sets,[],{})),
              mock.patch.object(fw.autoban,'protected_ports',return_value=({22,443,8443},{443,8443})),
              mock.patch.object(fw,'nft'),
              mock.patch.object(fw,'run',return_value=mock.Mock(returncode=0,stderr=''))):
            result=fw.web_quick_shield()
            fw.rollback(result['token'])
        self.assertEqual(fw.config()['autoban_enabled'],False)
        self.assertEqual(fw.state()['mode'],'observe')
        self.assertEqual((fw.ROOT/'active.nft').read_text(),'old policy')

    def test_one_click_web_form_and_origin_null_with_valid_csrf(self):
        server=ThreadingHTTPServer(('127.0.0.1',0),webui.Handler)
        t=threading.Thread(target=server.serve_forever,daemon=True);t.start()
        self.addCleanup(lambda:(server.shutdown(),server.server_close(),t.join(timeout=2)))
        base=f'http://127.0.0.1:{server.server_port}'
        auth='Basic '+base64.b64encode(b'admin:SecretPassword123').decode()
        h={'Host':'probe.example.com','Authorization':auth,'Origin':'null',
           'Sec-Fetch-Site':'same-origin','Sec-Fetch-Mode':'navigate','Content-Type':'application/x-www-form-urlencoded'}
        def post(csrf_value,headers=None):
            req=Request(base+'/control/quick-shield',headers=headers or h,
                        data=urlencode({'csrf':csrf_value}).encode())
            try:
                with urlopen(req,timeout=4) as response:return response.status,response.read().decode()
            except HTTPError as e:return e.code,e.read().decode()
        self.assertIn('/fws-secret-path/control/apply-now',webui.control_page())
        self.assertNotIn('/fws-secret-path/control/quick-shield',webui.control_page())
        with mock.patch.object(fw,'run',return_value=mock.Mock(returncode=1)):
            self.assertIn('/fws-secret-path/control/quick-shield',webui.overview())
        with mock.patch.object(fw,'web_quick_shield') as activate:
            self.assertEqual(post('bad')[0],400)
            self.assertEqual(post(webui.csrf(),{**h,'Sec-Fetch-Site':'cross-site'})[0],403)
            self.assertEqual(post(webui.csrf(),{**h,'Origin':'https://evil.example'})[0],403)
            self.assertEqual(post(webui.csrf())[0],200)
            activate.assert_called_once()

if __name__=='__main__':main()
