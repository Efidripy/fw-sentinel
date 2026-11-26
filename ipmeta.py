#!/usr/bin/env python3
"""On-demand, bounded IP metadata for the web UI (not used for firewall verdicts).

An opened event card triggers one HTTPS lookup via ipwho.is. Results are cached
in a private SQLite file; at most 200 *new* lookups/day and one lookup/second.
No automatic requests for live radar events. Geolocation is approximate.
"""
from __future__ import annotations
from i18n import tr
import ipaddress
import json
from pathlib import Path
import sqlite3
import threading
import time
from urllib.request import Request, ProxyHandler, build_opener
from urllib.error import HTTPError, URLError

LOCK=threading.Lock()
LAST_REQUEST=0.0
MAX_PER_DAY=200  # below provider's published 1000/day free budget
CACHE_SECONDS=7*86400
NEGATIVE_SECONDS=3600

class IPInfoError(Exception):
    """Expected API/cache failure that should not expose internal details."""


def _clean(value, length=120):
    if value is None:return ''
    if not isinstance(value,(str,int)):return ''
    value=' '.join(str(value).split())
    return ''.join(ch for ch in value if ch.isprintable())[:length]


def _connect(root):
    root=Path(root)
    path=root/'ip-metadata.sqlite3'
    con=sqlite3.connect(path,timeout=2)
    con.execute('PRAGMA busy_timeout=1500')
    con.execute('CREATE TABLE IF NOT EXISTS ip_info(ip TEXT PRIMARY KEY, fetched INTEGER NOT NULL, payload TEXT NOT NULL)')
    con.execute('CREATE TABLE IF NOT EXISTS quotas(day TEXT PRIMARY KEY, count INTEGER NOT NULL)')
    return con


def _parse(data, requested):
    if not isinstance(data,dict) or data.get('success') is not True:
        raise IPInfoError(tr('The provider has no information about this IP','Провайдер не располагает сведениями об этом IP'))
    if str(data.get('ip',''))!=requested:
        raise IPInfoError(tr('The provider’s response does not match the request','Ответ провайдера не соответствует запросу'))
    conn=data.get('connection') or {}
    if not isinstance(conn,dict):conn={}
    try:
        asn=int(conn.get('asn',0) or 0)
        if not 0<=asn<=4294967295:asn=0
    except (ValueError,TypeError):asn=0
    return {
        'ip':requested,'asn':asn or None,
        'isp':_clean(conn.get('isp') or conn.get('org'),100),
        'country':_clean(data.get('country'),80),
        'region':_clean(data.get('region'),80),
        'city':_clean(data.get('city'),80),
        'provider':'ipwho.is','cached':False,
    }


def _fetch(address):
    # No caller supplied host, scheme or path => prevents SSRF/redirect abuse.
    url='https://ipwho.is/'+str(address)
    req=Request(url,headers={'User-Agent':'FW-Sentinel-IP-Metadata/2.0.7','Accept':'application/json'})
    # Deliberately avoid ambient HTTP_PROXY when looking up sensitive IPs.
    # urllib follows redirects by default; reject them to keep fixed API host.
    from urllib.request import HTTPRedirectHandler
    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs):return None
    opener=build_opener(ProxyHandler({}),NoRedirect())
    try:
        with opener.open(req,timeout=3) as response:
            if response.status!=200:raise IPInfoError(tr('External source error','Ошибка внешнего источника'))
            raw=response.read(16385)
            if len(raw)>16384:raise IPInfoError(tr('The source response is too large','Ответ источника слишком большой'))
    except (TimeoutError,OSError,HTTPError,URLError) as err:
        if isinstance(err,HTTPError) and err.code==429:
            raise IPInfoError(tr('The provider’s request limit has been reached','Достигнут лимит запросов провайдера')) from None
        raise IPInfoError(tr('The IP information service is temporarily unavailable','Сервис информации об IP временно недоступен')) from None
    try:
        return _parse(json.loads(raw),str(address))
    except (ValueError,UnicodeDecodeError):
        raise IPInfoError(tr('Invalid response from the source','Недопустимый ответ источника')) from None


def lookup(ip,root):
    """Return IP ASN/ISP/geolocation after validating IP; no policy changes."""
    global LAST_REQUEST
    try:address=ipaddress.ip_address(ip)
    except ValueError:raise ValueError(tr('Invalid IPv4 or IPv6 address','Некорректный IPv4 или IPv6')) from None
    if not address.is_global or address.is_multicast:
        raise ValueError(tr('Information is available only for public IP addresses','Доступна информация только о публичных IP'))
    ip=str(address)
    with LOCK:
        con=_connect(root)
        try:
            now=int(time.time())
            row=con.execute('SELECT fetched,payload FROM ip_info WHERE ip=?',(ip,)).fetchone()
            if row and now-int(row[0])<CACHE_SECONDS:
                try:
                    obj=json.loads(row[1]);obj['cached']=True;return obj
                except (ValueError,TypeError,KeyError):pass
            if time.monotonic()-LAST_REQUEST<1.0:
                raise IPInfoError(tr('Only one new IP per second is allowed — try again shortly','Не чаще одного нового IP в секунду — повторите чуть позже'))
            day=time.strftime('%Y-%m-%d',time.gmtime())
            used=con.execute('SELECT count FROM quotas WHERE day=?',(day,)).fetchone()
            if used and used[0]>=MAX_PER_DAY:
                raise IPInfoError(tr('The daily IP lookup limit has been reached','Дневной лимит определения IP исчерпан'))
            LAST_REQUEST=time.monotonic()
            # Count attempts (including failures): cap persists across process restarts.
            con.execute('INSERT INTO quotas(day,count) VALUES (?,1) ON CONFLICT(day) DO UPDATE SET count=count+1',(day,))
            con.execute('DELETE FROM quotas WHERE day<?',(day,))
            con.execute('DELETE FROM ip_info WHERE fetched<?',(now-30*86400,))
            con.commit()
            data=_fetch(address)
            con.execute('INSERT INTO ip_info(ip,fetched,payload) VALUES (?,?,?) ON CONFLICT(ip) DO UPDATE SET fetched=excluded.fetched,payload=excluded.payload',
                        (ip,now,json.dumps(data,ensure_ascii=False)))
            con.commit()
            return data
        finally:con.close()
