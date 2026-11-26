"""Permanent confirmation, explicit cancellation and reboot-safe restoration."""
import base64
import ipaddress
import json
from pathlib import Path
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from unittest import mock

import fw_sentinel as fw
import webui

import i18n  # noqa: E402

def setUpModule():  # these checks read the Russian texts
    i18n.FORCED = 'ru'


def tearDownModule():
    i18n.FORCED = None


class PermanentShield(unittest.TestCase):
    def setUp(self):
        # Previous tests exercise the original 2.0.12 quick-profile logic;
        # the new extra-feeds readiness contract is tested separately.
        self._extra_ready=mock.patch.object(fw,'extras_status',return_value={
            'ready':True,'key_ready':True,
            'sources':{name:42 for name in fw.EXTRA_THREAT_FEEDS}})
        self._extra_ready.start()
        self.addCleanup(self._extra_ready.stop)
        # Never query the host's real ss/docker.
        services=mock.patch.object(fw.autoban,'discover_services',return_value=(set(),set()))
        services.start();self.addCleanup(services.stop)
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        prev=fw.ROOT;fw.ROOT=Path(self.tmp.name);self.addCleanup(setattr,fw,'ROOT',prev)
        old=webui.TOKEN_FILE;webui.TOKEN_FILE=fw.ROOT/'ui-token'
        self.addCleanup(setattr,webui,'TOKEN_FILE',old)
        self.cfg=json.loads((Path(__file__).resolve().parents[1]/'config.json').read_text())
        self.cfg.update(wan_interfaces=['ens3'],ui_public_origin='https://probe.example.com',
                        ui_base_path='/secret/')
        for name,data in {'config.json':json.dumps(self.cfg),
                          'sources.json':'{"cidr":{},"threat_watch":{},"threat_ssh":{}}',
                          'allow.txt':'1.1.1.1\n','manual-bans.txt':'','vpn-clients.txt':'',
                          'asn.txt':'','ui-token':'SecureTestPass12','active.nft':'old nft snapshot'}.items():
            (fw.ROOT/name).write_text(data)
        fw.set_state('observe')
        self.sets={k:[] for k in ('geo','scanners','asn','manual','vpn_clients','threat_ssh','threat_watch')}
        self.sets['trusted']=[ipaddress.ip_network('1.1.1.1')]
        self.successful=mock.Mock(returncode=0,stdout='enabled\n',stderr='')

    def _stage(self):
        with (mock.patch.object(fw,'build_sets_from_sources',return_value=(self.sets,[],{})),
              mock.patch.object(fw.autoban,'protected_ports',return_value=({22,443,8443},{443,8443})),
              mock.patch.object(fw,'nft'),
              mock.patch.object(fw,'run',return_value=self.successful)):
            return fw.web_quick_shield()

    def test_page_has_explicit_confirmation_and_cancel(self):
        result=self._stage()
        html=webui.control_page()
        self.assertIn('ОСТАВИТЬ ПРАВИЛА',html)
        self.assertIn('/secret/control/cancel-trial',html)
        self.assertIn('/secret/control/confirm',html)
        self.assertIn('id="shield-countdown"',html)
        self.assertIn(result['token'],html)
        with mock.patch.object(fw,'run',return_value=self.successful):
            self.assertIn('Новые правила включены',webui.overview())
        self.assertIn('120',html)

    def test_cancellation_restores_existing_snapshot_without_new_confirmation(self):
        result=self._stage()
        with (mock.patch.object(fw,'nft'),mock.patch.object(fw,'run',return_value=self.successful)):
            self.assertTrue(fw.web_abort(result['token']))
            with self.assertRaisesRegex(RuntimeError,'подтверждения'):
                fw.web_confirm(result['token'])
        self.assertEqual(fw.state()['mode'],'observe')
        self.assertEqual((fw.ROOT/'active.nft').read_text(),'old nft snapshot')
        self.assertEqual(fw.config()['autoban_enabled'],False)

    def test_reboot_during_trial_discards_trial_and_keeps_old_policy(self):
        result=self._stage()
        with (mock.patch.object(fw,'nft') as calls,
              mock.patch.object(fw,'run',return_value=self.successful),
              mock.patch.object(fw.autoban,'rearm_for_rules')):
            fw.restore()
        self.assertFalse(list(fw.ROOT.glob('.pending-*')))
        self.assertEqual(fw.state()['mode'],'observe')
        self.assertEqual((fw.ROOT/'active.nft').read_text(),'old nft snapshot')
        self.assertEqual(fw.config()['autoban_enabled'],False)
        self.assertIn('old nft snapshot',str(calls.call_args_list))

    def test_after_confirm_boot_restores_permanent_policy_and_records_boot_id(self):
        result=self._stage()
        with (mock.patch.object(fw,'nft'),
              mock.patch.object(fw,'run',return_value=self.successful),
              mock.patch.object(fw.autoban,'rearm_for_rules')):
            fw.web_confirm(result['token'])
            self.assertEqual(fw.state()['mode'],'enforce')
            self.assertTrue(fw.config()['threat_watch_enforce'])
            confirmed=(fw.ROOT/'active.nft').read_text()
            self.assertIn('D_WATCH4',confirmed)
            fw.restore()
            report=fw.persistence_report()
        self.assertTrue(report['ready'],report)
        self.assertTrue(report['restored_this_boot'])
        self.assertTrue((fw.ROOT/'last-restore.json').exists())
        self.assertEqual((fw.ROOT/'active.nft').read_text(),confirmed)
        self.assertIn('ПРИМЕНИТЬ ПРАВИЛА',webui.control_page())
        self.assertNotIn('ВКЛЮЧИТЬ АВТОЗАЩИТУ — 120',webui.control_page())

    def test_verification_refuses_false_ready_on_bad_signature(self):
        fw.set_state('enforce')
        self.cfg['scanner_enabled']=False
        (fw.ROOT/'config.json').write_text(json.dumps(self.cfg))
        with (mock.patch.object(fw,'nft'),mock.patch.object(fw,'run',return_value=self.successful)):
            report=fw.persistence_report()
        self.assertFalse(report['ready'])
        self.assertFalse(next(x for x in report['checks'] if x['name']=='Конфигурация')['ok'])

    def test_verification_refuses_false_ready_if_restore_disabled(self):
        fw.set_state('enforce')
        def run(*args,**kw):
            if args[:3]==('systemctl','is-enabled','fw-sentinel-restore.service'):
                return mock.Mock(returncode=1,stdout='disabled',stderr='')
            return self.successful
        with (mock.patch.object(fw,'nft'),mock.patch.object(fw,'run',side_effect=run)):
            report=fw.persistence_report()
        self.assertFalse(report['ready'])
        self.assertIn('disabled',str(report))

    def test_verification_refuses_false_ready_if_ingress_missing(self):
        fw.set_state('enforce')
        def run(*args,**kw):
            if args[:6]==('nft','list','chain','inet','fw_sentinel','ingress'):
                return mock.Mock(returncode=1,stdout='',stderr='No such chain')
            return self.successful
        with (mock.patch.object(fw,'nft'),mock.patch.object(fw,'run',side_effect=run)):
            report=fw.persistence_report()
        self.assertFalse(report['ready'])

    def test_disable_enforcement_keeps_observer_persistent(self):
        self._stage()
        with (mock.patch.object(fw,'nft'),mock.patch.object(fw,'run',return_value=self.successful),
              mock.patch.object(fw.autoban,'rearm_for_rules')):
            token=next(fw.ROOT.glob('.pending-*')).name[9:]
            fw.web_confirm(token)
            with mock.patch.object(fw,'build_sets_from_sources',return_value=(self.sets,[],{})):
                fw.web_mode('pause')
            self.assertEqual(fw.state()['mode'],'observe')
            self.assertIn('O_WATCH4', (fw.ROOT/'active.nft').read_text())
            fw.restore()
            self.assertEqual(fw.state()['mode'],'observe')

    def test_http_verification_restricted_and_cancel_requires_csrf(self):
        result=self._stage()
        server=ThreadingHTTPServer(('127.0.0.1',0),webui.Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        self.addCleanup(lambda:(server.shutdown(),server.server_close(),thread.join(timeout=2)))
        target=f'http://127.0.0.1:{server.server_port}'
        auth='Basic '+base64.b64encode(b'admin:SecureTestPass12').decode()
        headers={'Host':'probe.example.com','Authorization':auth}
        with mock.patch.object(fw,'persistence_report',return_value={'mode':'observe','ready':False,
                 'checks':[{'name':'test','ok':False,'description':'disabled'}],
                 'restored_this_boot':False,'last_restored_at':''}):
            req=Request(target+'/control/recovery',headers=headers)
            with urlopen(req,timeout=4) as response:
                self.assertIn('disabled',response.read().decode())
        no_auth=Request(target+'/control/recovery',headers={'Host':'probe.example.com'})
        with self.assertRaises(HTTPError) as context:urlopen(no_auth,timeout=4)
        self.assertEqual(context.exception.code,401)
        data=urlencode({'csrf':'bad','token':result['token']}).encode()
        h={**headers,'Origin':'https://probe.example.com','Content-Type':'application/x-www-form-urlencoded'}
        with self.assertRaises(HTTPError) as context:urlopen(Request(target+'/control/cancel-trial',data=data,headers=h),timeout=4)
        self.assertEqual(context.exception.code,400)
        self.assertTrue((fw.ROOT/('.pending-'+result['token'])).is_dir())
        data=urlencode({'csrf':webui.csrf(),'token':result['token']}).encode()
        with (mock.patch.object(fw,'nft'),mock.patch.object(fw,'run',return_value=self.successful)):
            with urlopen(Request(target+'/control/cancel-trial',data=data,headers=h),timeout=4) as response:
                self.assertEqual(response.status,200)
        self.assertFalse(list(fw.ROOT.glob('.pending-*')))


if __name__=='__main__':unittest.main()
