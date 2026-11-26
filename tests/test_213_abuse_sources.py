import datetime as dt
import ipaddress
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import fw_sentinel as fw


class AbuseSourceTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=Path(self.tmp.name)
        self.original=fw.ROOT
        fw.ROOT=self.root
        self.spec={'url':'https://api.abuseipdb.com/api/v2/blacklist', 'format':'abuseipdb', 'enabled':True, 'confidence_minimum':90}
        self.cfg=dict(fw.config()) if (self.root/'config.json').exists() else json.loads((Path(__file__).resolve().parents[1]/'config.json').read_text())
        (self.root/'sources.json').write_text(json.dumps({'geoip':[],'cidr':{},'threat_ssh':{},'threat_watch':{'abuseipdb_blacklist90':self.spec}}))
        (self.root/'asn.txt').write_text('')
        (self.root/'manual-bans.txt').write_text('')
        (self.root/'allow.txt').write_text('')
        (self.root/'vpn-clients.txt').write_text('')
        self.cfg.update({'asn_enabled':False,'scanner_enabled':False,'geo_enabled':False,'extra_threat_feeds_enabled':True})

    def tearDown(self):
        fw.ROOT=self.original
        self.tmp.cleanup()

    def set_key(self,value='A'*32,mode=0o600):
        path=self.root/'abuseipdb.key'
        path.write_text(value)
        os.chmod(path,mode)

    def test_key_never_in_sources_or_config(self):
        self.assertNotIn('A'*32,(self.root/'sources.json').read_text())
        self.assertNotIn('abuseipdb',json.dumps(self.cfg))

    def test_api_requires_key_and_rejects_world_readable(self):
        with self.assertRaisesRegex(ValueError,'missing'):
            fw.download_abuseipdb_blacklist(self.cfg,self.spec)
        self.set_key(mode=0o644)
        with self.assertRaisesRegex(ValueError,'private'):
            fw.download_abuseipdb_blacklist(self.cfg,self.spec)

    def test_api_refuses_alternate_host_and_low_score(self):
        self.set_key()
        with self.assertRaisesRegex(ValueError,'official HTTPS'):
            fw.download_abuseipdb_blacklist(self.cfg,dict(self.spec,url='https://evil.example/a'))
        with self.assertRaisesRegex(ValueError,'90-100'):
            fw.download_abuseipdb_blacklist(self.cfg,dict(self.spec,confidence_minimum=10))

    def test_encrypted_download_with_no_redirects(self):
        self.set_key()
        class FakeResponse:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,length):
                self.limit=length
                return b'198.51.100.90\n2001:db8::a\n'
        class FakeOpener:
            def open(self,req,timeout):
                self.url=req.full_url
                self.key=req.headers['Key']
                self.accept=req.headers['Accept']
                self.timeout=timeout
                return FakeResponse()
        opener=FakeOpener()
        with mock.patch.object(fw.urllib.request,'build_opener',return_value=opener) as factory:
            output=fw.download_abuseipdb_blacklist(self.cfg,self.spec)
        self.assertIn(b'198.51.100.90',output)
        self.assertEqual(opener.key,'A'*32)
        self.assertEqual(opener.accept,'text/plain')
        self.assertIn('confidenceMinimum=90',opener.url)
        self.assertIn('plaintext',opener.url)
        self.assertEqual(factory.call_args[0][0].__class__.__name__,'NoRedirect')

    def test_blacklist_requires_valid_data_and_obeys_ttl(self):
        self.set_key()
        with mock.patch.object(fw,'download_abuseipdb_blacklist',return_value=b'203.0.113.9\n2001:db8::9\n'):
            sets,issues,_=fw.build_sets_from_sources(self.cfg,refresh=True)
        self.assertFalse([e for e in issues if not e.startswith("geo_ru:")])
        self.assertIn(ipaddress.ip_network('203.0.113.9/32'),sets['threat_watch'])
        self.assertIn(ipaddress.ip_network('2001:db8::9/128'),sets['threat_watch'])
        cached,_issues,_=fw.build_sets_from_sources(self.cfg,refresh=False)
        self.assertEqual(sets,cached)
        meta=self.root/'cache/sources/threat_watch_abuseipdb_blacklist90.meta.json'
        data=json.loads(meta.read_text());data['updated']=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(hours=75)).isoformat()
        meta.write_text(json.dumps(data))
        stale,_,_=fw.build_sets_from_sources(self.cfg,refresh=False)
        self.assertFalse(stale['threat_watch'])

    def test_disabled_source_never_calls_api(self):
        spec=dict(self.spec,enabled=False)
        (self.root/'sources.json').write_text(json.dumps({'geoip':[],'cidr':{},'threat_ssh':{},'threat_watch':{'abuseipdb_blacklist90':spec}}))
        with mock.patch.object(fw,'download_abuseipdb_blacklist',side_effect=AssertionError('unexpected')):
            sets,issues,_=fw.build_sets_from_sources(self.cfg,refresh=True)
        self.assertFalse([e for e in issues if not e.startswith("geo_ru:")])
        self.assertFalse(sets['threat_watch'])

    def test_new_disabled_sources_preserve_confirmed_policy_signature(self):
        old=json.loads((self.root/'sources.json').read_text())
        old['threat_watch']={}
        (self.root/'sources.json').write_text(json.dumps(old))
        base=fw.policy_signature(self.cfg)
        old['threat_watch']['abuseipdb_blacklist90']=dict(self.spec,enabled=False)
        (self.root/'sources.json').write_text(json.dumps(old))
        self.assertEqual(base,fw.policy_signature(self.cfg))
        old['threat_watch']['abuseipdb_blacklist90']['enabled']=True
        (self.root/'sources.json').write_text(json.dumps(old))
        self.assertNotEqual(base,fw.policy_signature(self.cfg))

    def test_missing_key_makes_warning_not_enforce_changes(self):
        sets,issues,_=fw.build_sets_from_sources(self.cfg,refresh=True)
        self.assertEqual([],sets['threat_watch'])
        self.assertTrue(any('API key missing' in x for x in issues))


if __name__=='__main__': unittest.main()
