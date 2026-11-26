"""2.0.6: live verdict tabs, full history aggregation and paged IP/port drill-down."""
import base64
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest import mock
from urllib.error import HTTPError
from urllib.request import Request,urlopen
from urllib.parse import urlencode
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import fw_sentinel as fw
import webui

import i18n  # noqa: E402

def setUpModule():  # these checks read the Russian texts
    i18n.FORCED = 'ru'


def tearDownModule():
    i18n.FORCED = None


class GroupedHistory(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.old=fw.ROOT;fw.ROOT=Path(self.temp.name);self.addCleanup(setattr,fw,'ROOT',self.old)
        self.oldtoken=webui.TOKEN_FILE;webui.TOKEN_FILE=fw.ROOT/'ui-token';self.addCleanup(setattr,webui,'TOKEN_FILE',self.oldtoken)
        (fw.ROOT/'ui-token').write_text('MyLongTestPass')
        (fw.ROOT/'config.json').write_text(json.dumps({'version':'2.0.6','ui_base_path':'/secret/',
            'ui_public_origin':'https://panel.example','ui_port':1488,'geo_enabled':False,'geo_ports':[443,8443],
            'ssh_ports':[22],'wan_interfaces':['eth0'],'vpn_ports':[443,8443],'ssh_rate_per_minute':10}))
        for f in ('allow.txt','manual-bans.txt','vpn-clients.txt','asn.txt'):
            (fw.ROOT/f).write_text('')
        (fw.ROOT/'sources.json').write_text('{"cidr":{}}')

    def seed(self, events):
        c=fw.db()
        c.executemany('INSERT INTO events(timestamp,ip,port,proto,reason,verdict) VALUES (?,?,?,?,?,?)',events)
        c.commit();c.close()

    def sample(self):
        self.seed([
          ('2026-11-25T18:05:00+00:00','198.51.100.8',443,'TCP','WATCH4','observe'),
          ('2026-11-25T18:06:00+00:00','198.51.100.8',443,'TCP','WATCH4','observe'),
          ('2026-11-25T18:07:00+00:00','198.51.100.8',22,'TCP','SCAN4','drop'),
          ('2026-11-25T18:08:00+00:00','198.51.100.8',8443,'UDP','PASS','pass'),
          ('2026-11-25T18:09:00+00:00','2001:db8::2',443,'TCP','WATCH6','observe'),
          ('2026-11-25T18:10:00+00:00','2001:db8::2',443,'TCP','SCAN6','drop'),
        ])

    def test_full_history_not_just_last_500(self):
        events=[('2026-11-25T18:00:00+00:00','198.51.100.12',443,'TCP','WATCH4','observe')]
        events += [('2026-11-25T18:01:00+00:00','198.51.100.13',443,'TCP','PASS','pass')]*650
        self.seed(events)
        groups,more=fw.event_groups(limit=30)
        self.assertEqual(len(groups),2)
        self.assertEqual({g['ip']:g['total'] for g in groups},{'198.51.100.12':1,'198.51.100.13':650})
        self.assertFalse(more)
        self.assertEqual(groups[0]['ip'],'198.51.100.13')

    def test_port_counts_reasons_and_independent_verdicts(self):
        self.sample()
        groups,_=fw.event_groups(ip='198.51.100.8')
        self.assertEqual(len(groups),1)
        grp=groups[0]
        self.assertEqual((grp['total'],grp['drop'],grp['observe'],grp['pass']),(4,1,2,1))
        self.assertEqual({r['port']:r['total'] for r in grp['ports']},{443:2,22:1,8443:1})
        self.assertEqual(grp['ports'][0]['port'],443)
        self.assertEqual(grp['ports'][0]['reasons'],'WATCH4')
        self.assertEqual(grp['first'],'2026-11-25T18:05:00+00:00')
        self.assertEqual(grp['last'],'2026-11-25T18:08:00+00:00')
        self.assertEqual(fw.event_groups(ip='198.51.100.8',verdict='drop')[0][0]['total'],1)
        self.assertEqual(fw.event_groups(ip='198.51.100.8',verdict='observe')[0][0]['total'],2)

    def test_pagination_caps_groups(self):
        events=[('2026-11-25T18:00:00+00:00',f'198.51.100.{i}',443,'TCP','WATCH4','observe') for i in range(1,80)]
        self.seed(events)
        first,more=fw.event_groups(limit=30,page=1)
        second,more2=fw.event_groups(limit=30,page=2)
        third,more3=fw.event_groups(limit=30,page=3)
        self.assertEqual((len(first),len(second),len(third)),(30,30,19))
        self.assertTrue(more);self.assertTrue(more2);self.assertFalse(more3)
        self.assertTrue(set(x['ip'] for x in first).isdisjoint(x['ip'] for x in second))

    def test_ports_limit_does_not_explode_html(self):
        self.seed([('2026-11-25T18:00:00+00:00','198.51.100.20',port,'TCP','SCAN4','drop') for port in range(1,62)])
        groups,_=fw.event_groups(ports_limit=20)
        self.assertEqual(len(groups[0]['ports']),20)
        self.assertTrue(groups[0]['ports_more'])
        self.assertIn('Подробнее по этому IP',webui.events_page({}))
        self.assertIn('198.51.100.20',webui.events_page({}))
        group,_=fw.event_groups(ip='198.51.100.20',ports_limit=200)
        self.assertEqual(len(group[0]['ports']),61)

    def test_sql_input_validation(self):
        self.sample()
        for kw in ({'page':0},{'page':False},{'limit':501},{'ports_limit':0},{'verdict':'delete'},
                   {'ip':"198.51.100.8' OR 1=1 --"}):
            with self.subTest(kw=kw),self.assertRaises(ValueError):fw.event_groups(**kw)

    def test_missing_db_returns_empty_without_creating_files(self):
        groups,more=fw.event_groups();self.assertFalse(groups);self.assertFalse(more)
        self.assertFalse((fw.ROOT/'events.sqlite3').exists())

    def test_events_page_renders_safe_grouped_html_and_filter(self):
        self.sample()
        html=webui.events_page({'verdict':['drop'],'page':['1']})
        self.assertIn('История по IP',html)
        self.assertIn('<details class="ip-group">',html)
        self.assertIn('Порт',html)
        self.assertIn('Всего пакетов:',html)
        self.assertIn('Красные · DROP',html)
        self.assertIn('value="drop" selected',html)
        self.assertIn('/secret/events',html)
        self.assertNotIn('198.51.100.12',html)
        self.assertIn('22',html)

    def test_live_filter_keeps_250ms_cadence_and_bounded_buffer(self):
        with mock.patch.object(fw,'run',return_value=mock.Mock(returncode=1)):
            html=webui.overview()
        self.assertIn('data-live-filter="all"',html)
        self.assertIn('data-live-filter="observe"',html)
        self.assertIn('data-live-filter="drop"',html)
        self.assertIn('pollMs()',html)
        self.assertIn('BUFFER_MAX=300',html)
        self.assertIn('VISIBLE_MAX=70',html)
        self.assertIn('fetch("/secret/api/live"+',html)

    def test_event_page_query_is_not_mutating_firewall(self):
        self.sample()
        with mock.patch.object(fw,'nft',side_effect=AssertionError('called nft')):
            webui.events_page({})
            fw.event_groups(verdict='drop')

    def test_exact_ip_search_from_history(self):
        self.sample()
        html=webui.events_page({'ip':['2001:db8::2']})
        self.assertIn('2001:db8::2',html)
        self.assertNotIn('<span class="ip-main">198.51.100.8</span>',html)

    def test_reject_html_from_reasons(self):
        self.seed([('2026-11-25T18:00:00+00:00','198.51.100.8',443,'TCP','<script>alert(1)</script>','observe')])
        html=webui.events_page({})
        self.assertNotIn('<script>alert(1)</script>',html)
        self.assertIn('&lt;script&gt;',html)

if __name__=='__main__':unittest.main()
