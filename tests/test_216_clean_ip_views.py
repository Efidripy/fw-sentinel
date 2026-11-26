"""2.0.16: compact copy, unified filtered blocks, safe lazy reputation reads."""
from __future__ import annotations
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import fw_sentinel as fw
import autoban
import webui
import ipintel

import i18n  # noqa: E402

def setUpModule():  # these checks read the Russian texts
    i18n.FORCED = 'ru'


def tearDownModule():
    i18n.FORCED = None


class CleanBlocks216(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        self.root=Path(t.name)
        prior=fw.ROOT;fw.ROOT=self.root;self.addCleanup(setattr,fw,'ROOT',prior)
        prior_token=webui.TOKEN_FILE;webui.TOKEN_FILE=self.root/'ui-token'
        self.addCleanup(setattr,webui,'TOKEN_FILE',prior_token)
        (self.root/'ui-token').write_text('testpassword')
        base=Path(__file__).resolve().parents[1]
        cfg=json.loads((base/'config.json').read_text())
        cfg.update(ui_base_path='/fws-secret-path/',ui_public_origin='https://probe.example.test')
        (self.root/'config.json').write_text(json.dumps(cfg))
        for file,val in [('manual-bans.txt','9.9.9.9\n'),('allow.txt','8.8.8.8\n'),
                         ('vpn-clients.txt',''),('asn.txt',''),('sources.json','{"cidr":{}}')]:
            (self.root/file).write_text(val)
        self.today=dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')
        self.old=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=2)).isoformat(timespec='seconds')

    def events(self, *rows):
        con=fw.db()
        try:
            con.executemany('INSERT INTO events(timestamp,ip,port,proto,reason,verdict) VALUES (?,?,?,?,?,?)',rows)
            con.commit()
        finally:con.close()

    def test_includes_all_causes_with_no_auto_network(self):
        self.events((self.today,'1.1.1.1',22,'TCP','WATCH4','drop'),
                    (self.today,'1.1.1.1',22,'TCP','WATCH4','drop'),
                    (self.today,'2.2.2.2',90,'TCP','SCAN4','drop'),
                    (self.today,'3.3.3.3',90,'TCP','ASN4','drop'),
                    (self.today,'4.4.4.4',22,'TCP','GEO4','drop'),
                    (self.today,'5.5.5.5',200,'TCP','AUTO4','drop'),
                    (self.old,'6.6.6.6',22,'TCP','WATCH4','drop'))
        bans=[('7.7.7.7',0,9999999999,'[1,2,3,4,5,6]',3)]
        with mock.patch.object(autoban,'list_bans_detailed',return_value=bans), mock.patch.object(ipintel,'lookup',side_effect=AssertionError('NO API at page load')):
            all_html=webui.access_page({'type':['all']})
            self.assertIn('9.9.9.9',all_html)
            for ip in ['1.1.1.1','2.2.2.2','3.3.3.3','4.4.4.4','5.5.5.5','7.7.7.7']:
                self.assertIn(ip,all_html)
            self.assertNotIn('6.6.6.6',all_html)
            self.assertIn('data-intel-on-open="1.1.1.1"',all_html)
            self.assertNotIn('data-intel-ip="1.1.1.1"',all_html)
            bases=webui.access_page({'type':['feeds']})
            self.assertIn('1.1.1.1',bases)
            self.assertIn('2.2.2.2',bases)
            self.assertNotIn('3.3.3.3',bases)
            asn=webui.access_page({'type':['asn']})
            self.assertIn('3.3.3.3',asn)
            self.assertNotIn('1.1.1.1',asn)
            auto=webui.access_page({'type':['auto']})
            self.assertIn('7.7.7.7',auto)
            self.assertNotIn('1.1.1.1',auto)
            manual=webui.access_page({'type':['manual']})
            self.assertIn('9.9.9.9',manual)
            self.assertNotIn('7.7.7.7',manual)
            self.assertIn('АВТОБАН №3',all_html)
            self.assertIn('РУЧНОЙ',all_html)

    def test_sql_counts_by_ip_and_reason_last24h(self):
        self.events((self.today,'1.1.1.1',22,'TCP','WATCH4','drop'),
                    (self.today,'1.1.1.1',443,'TCP','SCAN4','drop'),
                    (self.today,'1.1.1.1',443,'TCP','WATCH4','observe'),
                    (self.old,'1.1.1.1',22,'TCP','WATCH4','drop'))
        values=fw.recent_drop_causes(limit=20)
        self.assertEqual(len(values),1)
        self.assertEqual(values[0][1],2)
        self.assertEqual(set(values[0][3].split(',')),{'SCAN4','WATCH4'})
        self.assertEqual(webui._block_categories(values[0][3]),{'watch','scan'})
        self.assertEqual(webui._block_categories('ASN4,WATCH4'),{'asn','watch'})
        self.assertEqual(webui._block_categories('SSHREP4'),{'sshrep'})
        self.assertEqual(webui._block_categories('SSH'),{'ssh_limit'})

    def test_paginated_filters_preserve_secret_path_and_no_huge_page(self):
        self.events(*[(self.today,'21.22.23.'+str(i),443,'TCP','WATCH4','drop') for i in range(1,85)])
        with mock.patch.object(autoban,'list_bans_detailed',return_value=[]):
            page=webui.access_page({'type':['feeds'],'page':['2']})
        self.assertIn('/fws-secret-path/access?type=feeds&amp;page=3',page)
        self.assertIn('/fws-secret-path/access?type=feeds&amp;page=1',page)
        self.assertEqual(page.count('class="block-intel"'),40)
        self.assertIn('2 / 3',page)
        self.assertIn('aria-current="page">Базы угроз',page)

    def test_compact_headings_and_collapse(self):
        with mock.patch.object(fw,'run',return_value=mock.Mock(returncode=1)):
            overview=webui.overview()
        self.assertIn('<h2>Отброшенные пакеты</h2>',overview)
        self.assertNotIn('3 колонки IP',overview)
        self.assertNotIn('Показывает, наблюдает ли Sentinel',overview)
        listing=webui.access_page()
        self.assertIn('<details class="manual-lists"><summary>Ручные списки IP</summary>',listing)
        self.assertNotIn('<details class="manual-lists" open',listing)
        self.assertEqual(listing.count('data-intel-on-open="9.9.9.9"'),1)
        self.assertIn('window.fwsIntelScan',webui.ACCESS_INTEL_LAZY_SCRIPT)

if __name__=='__main__':unittest.main()
