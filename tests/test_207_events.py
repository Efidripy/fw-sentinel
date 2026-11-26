"""2.0.7: actual IP numeric ordering, safe ban workflow, on-demand geolocation."""
from pathlib import Path
import base64
import json
import sqlite3
import tempfile
import threading
import unittest
from unittest import mock
from http.server import ThreadingHTTPServer
from urllib.parse import urlencode
from urllib.request import Request,urlopen
from urllib.error import HTTPError
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import fw_sentinel as fw
import webui
import ipmeta

PREFIX='/fws-secret-path/'
DOMAIN='https://probe.example.com'

import i18n  # noqa: E402

def setUpModule():  # these checks read the Russian texts
    i18n.FORCED = 'ru'


def tearDownModule():
    i18n.FORCED = None


class Events207(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.oldroot=fw.ROOT;self.oldtoken=webui.TOKEN_FILE
        fw.ROOT=Path(self.temp.name);webui.TOKEN_FILE=fw.ROOT/'ui-token'
        self.addCleanup(setattr,fw,'ROOT',self.oldroot)
        self.addCleanup(setattr,webui,'TOKEN_FILE',self.oldtoken)
        (fw.ROOT/'ui-token').write_text('abcdEFG12345')
        (fw.ROOT/'config.json').write_text(json.dumps({'version':'2.0.7','ui_base_path':PREFIX,
            'ui_public_origin':DOMAIN,'geo_enabled':False,'ui_port':1488,'ssh_ports':[22],
            'wan_interfaces':['eth0'],'geo_ports':[443], 'vpn_ports':[443]}))
        for name in ('manual-bans.txt','allow.txt','vpn-clients.txt','asn.txt'):
            (fw.ROOT/name).write_text('')
        (fw.ROOT/'sources.json').write_text('{"cidr":{}}')
        ipmeta.LAST_REQUEST=0

    def seed(self):
        data=[('1.1.1.1',2),('8.8.8.9',1),('8.8.8.10',3),('2001:4860::8888',4)]
        con=fw.db()
        for ip,n in data:
            for i in range(n):
                con.execute('INSERT INTO events(timestamp,ip,port,proto,reason,verdict) VALUES (?,?,?,?,?,?)',
                    ('2026-11-25T20:00:00+00:00',ip,443,'TCP','WATCH','observe'))
        con.commit();con.close()

    def test_ip_sort_numeric_and_not_textual(self):
        self.seed()
        f=lambda order:[g['ip'] for g in fw.event_groups(sort=order)[0]]
        self.assertEqual(f('ip_asc'),['1.1.1.1','8.8.8.9','8.8.8.10','2001:4860::8888'])
        self.assertEqual(f('ip_desc'),['2001:4860::8888','8.8.8.10','8.8.8.9','1.1.1.1'])
        self.assertEqual(f('count_desc'),['2001:4860::8888','8.8.8.10','1.1.1.1','8.8.8.9'])
        self.assertEqual(f('count_asc'),['8.8.8.9','1.1.1.1','8.8.8.10','2001:4860::8888'])
        for bad in ('COUNT(*)', '', 'ip_key;DROP TABLE events'):
            with self.assertRaises(ValueError):fw.event_groups(sort=bad)

    def test_page_forms_sort_and_metadata_script(self):
        self.seed()
        html=webui.events_page({'sort':['count_desc'],'verdict':['observe']})
        for key in ('count_asc','count_desc','recent'):
            self.assertIn(f'value="{key}"',html)
        self.assertNotIn('value="ip_',html)
        self.assertIn('value="count_desc" selected',html)
        self.assertIn('name="ip"',html)
        self.assertIn(f'action="{PREFIX}ban/preview"',html)
        self.assertIn('data-meta-ip="8.8.8.10"',html)
        self.assertIn('fetch(endpoint+',html)
        self.assertIn('const endpoint="'+PREFIX+'api/ip-info"',html)
        # The page does not call the external provider for all listed addresses.
        with mock.patch.object(ipmeta,'lookup',side_effect=AssertionError('remote lookup')):
            webui.events_page({})

    def test_sort_is_preserved_on_page_links(self):
        con=fw.db()
        for i in range(1,35):
            con.execute('INSERT INTO events(timestamp,ip,port,proto,reason,verdict) VALUES (?,?,?,?,?,?)',
                ('2026-11-25T20:00:00Z',f'8.8.0.{i}',443,'TCP','WATCH','observe'))
        con.commit();con.close()
        html=webui.events_page({'sort':['count_asc'],'page':['1'],'verdict':['observe']})
        self.assertIn('sort=count_asc',html)
        self.assertIn('page=2',html)
        self.assertIn('verdict=observe',html)

    def test_metadata_parsing_and_cache(self):
        response={'success':True,'ip':'8.8.8.8','region':'California','city':'Mountain View',
           'country':'United States','connection':{'asn':15169,'isp':'Google LLC'}}
        with mock.patch.object(ipmeta,'_fetch',return_value=ipmeta._parse(response,'8.8.8.8')) as fetch:
            first=ipmeta.lookup('8.8.8.8',fw.ROOT)
            second=ipmeta.lookup('8.8.8.8',fw.ROOT)
        self.assertEqual(fetch.call_count,1)
        self.assertEqual(first['asn'],15169)
        self.assertEqual(first['region'],'California')
        self.assertEqual(first['isp'],'Google LLC')
        self.assertTrue(second['cached'])
        self.assertFalse(first['cached'])
        with self.assertRaises(ValueError):ipmeta.lookup('127.0.0.1',fw.ROOT)
        with self.assertRaises(ValueError):ipmeta.lookup('8.8.8.8/24',fw.ROOT)
        with self.assertRaises(ipmeta.IPInfoError):ipmeta._parse({'ip':'9.9.9.9','success':True},'8.8.8.8')

    def test_rate_limit_and_daily_quota_fail_closed(self):
        with mock.patch.object(ipmeta,'_fetch',return_value={'ip':'8.8.8.8'}):
            ipmeta.lookup('8.8.8.8',fw.ROOT)
        with self.assertRaises(ipmeta.IPInfoError):ipmeta.lookup('1.1.1.1',fw.ROOT)
        import time
        day=time.strftime('%Y-%m-%d',time.gmtime())
        with sqlite3.connect(fw.ROOT/'ip-metadata.sqlite3') as db:
            db.execute('UPDATE quotas SET count=? WHERE day=?',(ipmeta.MAX_PER_DAY,day))
        ipmeta.LAST_REQUEST=0
        with self.assertRaisesRegex(ipmeta.IPInfoError,'Дневной лимит'):
            ipmeta.lookup('1.1.1.1',fw.ROOT)

class HTTP207(Events207):
    def setUp(self):
        super().setUp();self.seed()
        self.patch=mock.patch.object(fw,'run',return_value=mock.Mock(returncode=1))
        self.patch.start();self.addCleanup(self.patch.stop)
        self.server=ThreadingHTTPServer(('127.0.0.1',0),webui.Handler)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.addCleanup(self.close_server)
        self.url=f'http://127.0.0.1:{self.server.server_port}'
        self.auth='Basic '+base64.b64encode(b'admin:abcdEFG12345').decode()
    def close_server(self):
        self.server.shutdown();self.server.server_close();self.thread.join(2)
    def request(self,path,post=None,host='probe.example.com',origin=DOMAIN,auth=True):
        headers={'Host':host}
        if auth:headers['Authorization']=self.auth
        if post is not None:
            post={'csrf':webui.csrf(),**post}
            headers['Origin']=origin
            headers['Content-Type']='application/x-www-form-urlencoded'
        return urlopen(Request(self.url+path,data=urlencode(post).encode() if post is not None else None,headers=headers),timeout=4)

    def test_get_metadata_requires_auth_and_returns_json(self):
        with self.assertRaises(HTTPError) as error:
            self.request('/api/ip-info?ip=8.8.8.8',auth=False)
        self.assertEqual(error.exception.code,401)
        with mock.patch.object(ipmeta,'lookup',return_value={'ip':'8.8.8.8','asn':15169,'isp':'Google','country':'US'}):
            response=self.request('/api/ip-info?ip=8.8.8.8')
            self.assertEqual(response.status,200)
            self.assertEqual(json.loads(response.read())['asn'],15169)
            self.assertEqual(json.loads(self.request(PREFIX+'api/ip-info?ip=8.8.8.8').read())['isp'],'Google')

    def test_preview_then_confirm_ban_and_protected_ip(self):
        resp=self.request('/ban/preview',post={'ip':'8.8.8.9'}).read().decode()
        self.assertIn('Подтверждение постоянной блокировки',resp)
        self.assertIn(f'action="{PREFIX}ban/confirm"',resp)
        self.assertNotIn('8.8.8.9',(fw.ROOT/'manual-bans.txt').read_text())
        with self.assertRaises(HTTPError) as err:
            self.request('/ban/confirm',post={'ip':'8.8.8.9'})
        self.assertEqual(err.exception.code,400)
        self.request('/ban/confirm',post={'ip':'8.8.8.9','confirm':'yes'})
        self.assertIn('8.8.8.9',(fw.ROOT/'manual-bans.txt').read_text())
        for file,ip in (('allow.txt','1.1.1.1'),('vpn-clients.txt','9.9.9.9')):
            (fw.ROOT/file).write_text(ip+'\n')
            with self.assertRaises(HTTPError) as err:
                self.request('/ban/preview',post={'ip':ip})
            self.assertEqual(err.exception.code,400)
        with self.assertRaises(HTTPError) as err:
            self.request('/ban/preview',post={'ip':'8.8.8.10'},origin='https://attacker.example')
        self.assertEqual(err.exception.code,403)

if __name__=='__main__':unittest.main()
