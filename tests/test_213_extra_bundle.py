"""Four optional sources, secret provision, gated activation, 120s rollback."""
import datetime as dt
import ipaddress
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import fw_sentinel as fw
import webui


class ExtraFeedActivation(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        original=fw.ROOT;fw.ROOT=self.root;self.addCleanup(setattr,fw,'ROOT',original)
        src=Path(__file__).resolve().parents[1]
        self.cfg=json.loads((src/'config.json').read_text())
        self.cfg.update(wan_interfaces=['eth0'],asn_enabled=False,scanner_enabled=False,
                        geo_enabled=False,threat_watch_enforce=True,
                        ui_base_path='/secret/',ui_public_origin='https://example.test')
        (self.root/'config.json').write_text(json.dumps(self.cfg))
        sources=json.loads((src/'sources.json').read_text())
        sources['geoip']=[];sources['cidr']={};sources['threat_ssh']={}
        sources['threat_watch']={k:v for k,v in sources['threat_watch'].items() if k in fw.EXTRA_THREAT_FEEDS}
        (self.root/'sources.json').write_text(json.dumps(sources))
        for name,body in [('allow.txt','1.1.1.1\n'),('vpn-clients.txt',''),('manual-bans.txt',''),('asn.txt','')]:
            (self.root/name).write_text(body)
        fw.set_state('enforce')
        (self.root/'active.nft').write_text('old nft state\n')

    def prepare(self):
        api=b'203.0.113.10\n2001:db8::10\n'
        with (mock.patch.object(fw,'download_abuseipdb_blacklist',return_value=api),
              mock.patch.object(fw,'urls_download',return_value=b'198.51.100.11\n')):
            fw.prepare_extra_feeds()

    def test_all_four_sources_packaged_but_existing_policy_unchanged(self):
        c=fw.sources()['threat_watch']
        self.assertTrue(all(c[name]['enabled'] for name in fw.EXTRA_THREAT_FEEDS))
        self.assertFalse(self.cfg['extra_threat_feeds_enabled'])
        self.assertEqual(fw.policy_signature(self.cfg),fw.state()['policy_signature'])
        # Even present fresh cache must not alter a confirmed policy until opt-in.
        self.prepare()
        sets,_,_=fw.build_sets_from_sources(self.cfg,False)
        self.assertFalse(sets['threat_watch'])
        self.assertEqual(fw.policy_signature(self.cfg),fw.state()['policy_signature'])

    def test_enter_key_in_root_owned_file_without_echo(self):
        with (mock.patch.object(fw.os,'isatty',return_value=True),
              mock.patch('getpass.getpass',side_effect=['DemoKey0123456789abcDEF','DemoKey0123456789abcDEF']),
              mock.patch('builtins.print') as out):
            fw.install_abuse_key()
        p=self.root/'abuseipdb.key'
        self.assertEqual(p.read_text().strip(),'DemoKey0123456789abcDEF')
        self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o600)
        self.assertNotIn('DemoKey0123456789abcDEF',str(out.call_args_list))

    def test_prepare_populates_all_four_without_nft_changes(self):
        with mock.patch.object(fw,'nft',side_effect=AssertionError('must not change nft')):
            self.prepare()
        report=fw.extras_status()
        self.assertEqual(len(report['sources']),4)
        self.assertTrue(all(report['sources'].values()))
        self.assertEqual(fw.state()['mode'],'enforce')
        self.assertEqual((self.root/'active.nft').read_text(),'old nft state\n')

    def test_unprepared_bundle_refuses_trial_without_changing_current_enforcement(self):
        cfg=self.cfg.copy();cfg.update(extra_threat_feeds_enabled=True)
        with self.assertRaisesRegex(RuntimeError,'feeds-prepare'):
            fw.validate_extra_feeds_ready(cfg)
        self.assertEqual(fw.state()['mode'],'enforce')
        self.assertEqual((self.root/'active.nft').read_text(),'old nft state\n')

    def test_full_trial_and_confirmation_enable_new_watch_addresses(self):
        self.prepare()
        with (mock.patch.object(fw.autoban,'protected_ports',return_value=({22,443,8443},{443,8443})),
              mock.patch.object(fw,'nft'),
              mock.patch.object(fw,'run',return_value=mock.Mock(returncode=0,stderr='',stdout=''))):
            trial=fw.web_quick_shield()
            self.assertFalse(fw.config().get('extra_threat_feeds_enabled'))
            staged=json.loads((self.root/('.pending-'+trial['token'])/'new.config.json').read_text())
            self.assertTrue(staged['extra_threat_feeds_enabled'])
            nft_script=(self.root/('.pending-'+trial['token'])/'new.nft').read_text()
            self.assertIn('ip saddr @watch4 counter drop',nft_script)
            self.assertIn('198.51.100.11/32',nft_script)
            with mock.patch.object(fw.autoban,'rearm_for_rules'):
                fw.web_confirm(trial['token'])
        self.assertTrue(fw.config()['extra_threat_feeds_enabled'])
        self.assertEqual(fw.state()['mode'],'enforce')
        self.assertEqual(fw.state()['policy_signature'],fw.policy_signature(fw.config()))

    def test_unconfirmed_trial_restores_old_rule_set_and_flag(self):
        self.prepare()
        with (mock.patch.object(fw.autoban,'protected_ports',return_value=({22,443,8443},{443,8443})),
              mock.patch.object(fw,'nft'),
              mock.patch.object(fw,'run',return_value=mock.Mock(returncode=0,stderr='',stdout=''))):
            trial=fw.web_quick_shield()
            fw.rollback(trial['token'])
        self.assertFalse(fw.config()['extra_threat_feeds_enabled'])
        self.assertEqual((self.root/'active.nft').read_text(),'old nft state\n')
        self.assertEqual(fw.state()['policy_signature'],fw.policy_signature(fw.config()))

    def test_stale_one_source_refuses_full_activation(self):
        self.prepare()
        p=self.root/'cache/sources/threat_watch_ipsum_level5.meta.json'
        info=json.loads(p.read_text())
        info['updated']=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=5)).isoformat()
        p.write_text(json.dumps(info))
        self.assertFalse(fw.extras_status()['ready'])
        with self.assertRaisesRegex(RuntimeError,'ipsum_level5'):
            fw.validate_extra_feeds_ready({**self.cfg,'extra_threat_feeds_enabled':True})


if __name__=='__main__':unittest.main()
