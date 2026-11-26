"""2.0.17 source registry, credential privacy, safe bulk IP import."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import fw_sentinel as fw
import webui
import provider_keys

BASE=Path(__file__).resolve().parents[1]

import i18n  # noqa: E402

def setUpModule():  # these checks read the Russian texts
    i18n.FORCED = 'ru'


def tearDownModule():
    i18n.FORCED = None


class NewFeatures217(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        old=fw.ROOT;fw.ROOT=self.root;self.addCleanup(setattr,fw,'ROOT',old)
        old=webui.TOKEN_FILE;webui.TOKEN_FILE=self.root/'ui-token';self.addCleanup(setattr,webui,'TOKEN_FILE',old)
        (self.root/'ui-token').write_text('testpassword')
        (self.root/'config.json').write_text((BASE/'config.json').read_text())
        (self.root/'sources.json').write_text((BASE/'sources.json').read_text())
        for name,body in (('manual-bans.txt','9.9.9.9\n'),('allow.txt','8.8.8.8\n'),('vpn-clients.txt','1.1.1.1\n'),('asn.txt','')):
            (self.root/name).write_text(body)

    def test_duplicate_import_blacklist_skips_conflicts_and_invalid(self):
        r=fw.change_entries_bulk('ban','9.9.9.9/32\n3.3.3.3, 3.3.3.3 8.8.8.8;1.1.1.1\nNOT-IP\n10.0.0.1')
        self.assertEqual([r[k] for k in ('added','already','conflicts','invalid')],[1,2,2,2])
        self.assertEqual((self.root/'manual-bans.txt').read_text().count('3.3.3.3'),1)
        again=fw.change_entries_bulk('ban','3.3.3.3,3.3.3.3,9.9.9.9')
        self.assertEqual(again['added'],0)
        self.assertEqual(again['already'],3)
        self.assertNotIn('8.8.8.8',(self.root/'manual-bans.txt').read_text())

    def test_allowlist_normalizes_ipv6_and_respects_ban(self):
        r=fw.change_entries_bulk('allow','2001:4860:4860:0:0:0:0:8888\n2001:4860:4860::8888\n9.9.9.9\n1.2.3.4')
        self.assertEqual([r[k] for k in ('added','already','conflicts','invalid')],[2,1,1,0])
        self.assertEqual((self.root/'allow.txt').read_text().count('2001:4860:4860::8888'),1)
        self.assertNotIn('9.9.9.9',(self.root/'allow.txt').read_text())

    def test_one_transaction_when_active(self):
        (self.root/'state.json').write_text(json.dumps({'mode':'observe','policy_signature':'match'}))
        (self.root/'active.nft').write_text('old rules')
        fake_sets={'manual':fw.line_networks(self.root/'manual-bans.txt'),
                   'trusted':fw.line_networks(self.root/'allow.txt')}
        with mock.patch.object(fw,'policy_signature',return_value='match'), \
             mock.patch.object(fw,'build_sets_from_sources',return_value=(fake_sets,[],{})), \
             mock.patch.object(fw,'render_rules',return_value='new rules'), \
             mock.patch.object(fw,'nft') as mocked:
            r=fw.change_entries_bulk('ban','2.2.2.2,3.3.3.3,2001:4860:4860::8888')
        self.assertEqual(r['added'],3)
        self.assertEqual(mocked.call_count,2)
        self.assertEqual(mocked.call_args_list[0].kwargs,{'check_only':True})
        applied=mocked.call_args_list[1].args[0]
        self.assertIn('add element inet fw_sentinel ban4 { 2.2.2.2, 3.3.3.3 }',applied)
        self.assertIn('add element inet fw_sentinel ban6 { 2001:4860:4860::8888 }',applied)

    def test_reject_pending_no_file_changes(self):
        (self.root/'.pending-aabb').mkdir()
        old=(self.root/'manual-bans.txt').read_text()
        with self.assertRaisesRegex(RuntimeError,'неподтверждённые'):
            fw.change_entries_bulk('ban','2.2.2.2')
        self.assertEqual((self.root/'manual-bans.txt').read_text(),old)

    def test_credentials_never_in_html_or_common_configs(self):
        key='S3cr3t_WhyMustBeHidden123'
        provider_keys.set_key(self.root,'greynoise',key)
        self.assertTrue(provider_keys.enabled(self.root,'greynoise'))
        self.assertEqual((provider_keys.path_for(self.root,'greynoise').stat().st_mode & 0o777),0o600)
        with mock.patch.object(fw,'run',return_value=mock.Mock(returncode=1)):
            html=webui.sources_page()
        self.assertNotIn(key,html)
        self.assertIn('GreyNoise',html)
        self.assertIn('Ключ сохранён',html)
        provider_keys.disable(self.root,'greynoise')
        self.assertFalse(provider_keys.enabled(self.root,'greynoise'))

    def test_source_catalog_is_gated_and_government_is_context(self):
        j=json.loads((BASE/'sources.json').read_text())
        self.assertGreaterEqual(len(j['advanced_feeds']),12)
        self.assertEqual(j['advanced_feeds']['ru_gov_c24be']['confidence'],'context')
        self.assertFalse(json.loads((BASE/'config.json').read_text())['advanced_feed_pack_enabled'])
        cfg=json.loads((BASE/'config.json').read_text())
        a=fw.policy_signature(cfg)
        cfg['advanced_feed_pack_enabled']=True
        self.assertNotEqual(a,fw.policy_signature(cfg))

    def test_form_shows_both_bulk_fields_and_not_expanded(self):
        html=webui.access_page()
        self.assertIn('action="/bulk/ban"',html)
        self.assertIn('action="/bulk/allow"',html)
        self.assertIn('name="ips"',html)
        self.assertIn('Ручные списки IP',html)

if __name__=='__main__':unittest.main()
