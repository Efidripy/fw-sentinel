#!/usr/bin/env python3
"""Read-only IP reputation enrichment for the admin UI; never drives firewall policy.

Successful remote observations remain cached indefinitely per IP. Failures are
backed off, quotas are persisted across restarts, no credentials reach the UI.
"""
from __future__ import annotations
from i18n import tr
import ipaddress
import os
import json
import sqlite3
import threading
import time
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, ProxyHandler, HTTPRedirectHandler, build_opener
from urllib.error import HTTPError, URLError

import ipmeta

_LOCK=threading.Lock()
_LAST_REMOTE=0.0
DAILY_LIMIT=100  # reserve most of free plan for external use
MIN_INTERVAL=1.5
RETRY_FAILURE=3600

class IntelError(Exception):
    pass

def _db(root):
    root=Path(root)
    file=root/'ip-intel.sqlite3'
    conn=sqlite3.connect(file,timeout=3)
    os.chmod(file,0o600)
    conn.execute('PRAGMA busy_timeout=2000')
    conn.execute('''CREATE TABLE IF NOT EXISTS intel (
       ip TEXT PRIMARY KEY, geo_checked INTEGER NOT NULL DEFAULT 0,
       abuse_checked INTEGER NOT NULL DEFAULT 0, geo_json TEXT, abuse_json TEXT,
       geo_retry_after INTEGER NOT NULL DEFAULT 0,
       abuse_retry_after INTEGER NOT NULL DEFAULT 0)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS daily_quota (
       day TEXT PRIMARY KEY, attempts INTEGER NOT NULL)''')
    return conn

def _parse_ip(raw):
    try: addr=ipaddress.ip_address(raw)
    except ValueError: raise ValueError(tr('Invalid IPv4/IPv6 address','Некорректный IPv4/IPv6')) from None
    if not addr.is_global or addr.is_multicast:
        raise ValueError(tr('Information is available only for public IPs','Информация доступна только для публичных IP'))
    return addr

def _key(root):
    key_file=Path(root)/'abuseipdb.key'
    try:
        st=key_file.stat()
        if st.st_mode & 0o077:raise IntelError(tr('AbuseIPDB API key permissions must be 0600','Права на AbuseIPDB API key должны быть 0600'))
        key=key_file.read_text(encoding='ascii').strip()
    except FileNotFoundError:
        raise IntelError(tr('AbuseIPDB key is not configured','Ключ AbuseIPDB не настроен')) from None
    if not (32 <= len(key) <= 256) or not key.isascii() or not key.isalnum():
        raise IntelError(tr('Invalid AbuseIPDB key format','Неправильный формат ключа AbuseIPDB'))
    return key

class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None

def _fetch_abuse(ip,root):
    key=_key(root)
    url='https://api.abuseipdb.com/api/v2/check?'+urlencode({'ipAddress':ip,'maxAgeInDays':90})
    request=Request(url,headers={'Key':key,'Accept':'application/json','User-Agent':'FW-Sentinel-IP-Intel/2.0.16'})
    opener=build_opener(ProxyHandler({}),_NoRedirect())
    try:
        with opener.open(request,timeout=5) as response:
            if response.status!=200:raise IntelError(tr('AbuseIPDB: response error','AbuseIPDB: ошибка ответа'))
            raw=response.read(16385)
            if len(raw)>16384:raise IntelError(tr('AbuseIPDB: response is too large','AbuseIPDB: ответ слишком велик'))
    except HTTPError as exc:
        if exc.code==429:raise IntelError(tr('AbuseIPDB: daily limit reached','AbuseIPDB: дневной лимит исчерпан')) from None
        raise IntelError((tr('AbuseIPDB: HTTP error','AbuseIPDB: HTTP ошибка')+' ')+str(exc.code)) from None
    except (URLError,OSError,TimeoutError):
        raise IntelError(tr('AbuseIPDB: service unavailable','AbuseIPDB: сервис недоступен')) from None
    try:
        data=json.loads(raw)['data']
        if not isinstance(data,dict) or str(_parse_ip(data.get('ipAddress')))!=ip:raise ValueError()
        score=data['abuseConfidenceScore']
        if type(score) is not int or not 0<=score<=100:raise ValueError()
        reports=data.get('totalReports',0)
        if type(reports) is not int or reports<0:reports=0
    except (ValueError,KeyError,TypeError):
        raise IntelError(tr('AbuseIPDB: invalid data','AbuseIPDB: некорректные данные')) from None
    return {'score':score,'reports':min(reports,1_000_000_000),
            'checked_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
            'window_days':90}

def _result(ip, row):
    # tuple: geo_checked, abuse_checked, geo_json, abuse_json, geo_retry_after, abuse_retry_after
    out={'ip':ip,'asn':None,'isp':'','country':'','region':'',
         'score':None,'reports':None,'checked_at':'','cached':True,
         'geo_available':bool(row[0]),'abuse_available':bool(row[1])}
    if row[0] and row[2]:
        try:
            geo=json.loads(row[2])
            out.update({k:geo.get(k) for k in ('asn','isp','country','region')})
        except (ValueError,TypeError):pass
    if row[1] and row[3]:
        try:
            abuse=json.loads(row[3]);out.update({k:abuse.get(k) for k in ('score','reports','checked_at')})
        except (ValueError,TypeError):pass
    return out

def cached(ip,root):
    ip=str(_parse_ip(ip))
    con=_db(root)
    try:
        row=con.execute('SELECT geo_checked,abuse_checked,geo_json,abuse_json,geo_retry_after,abuse_retry_after FROM intel WHERE ip=?',(ip,)).fetchone()
        return _result(ip,row) if row else None
    finally:con.close()

def cached_many(ips,root):
    """{ip: known info} straight from the cache: no network, no quota, no pacing."""
    ips=list(ips)
    if not ips or not (Path(root)/'ip-intel.sqlite3').is_file():return {}
    try:
        con=_db(root)
        try:
            rows=con.execute('SELECT ip,geo_checked,abuse_checked,geo_json,abuse_json,geo_retry_after,abuse_retry_after '
                             f'FROM intel WHERE ip IN ({",".join("?"*len(ips))})',ips).fetchall()
        finally:con.close()
    except (sqlite3.Error,OSError):return {}
    return {row[0]:_result(row[0],row[1:]) for row in rows if row[1] or row[2]}

def _reuse_legacy(conn,root,ip):
    """Reuse old successful geolocation/AbuseIPDB cache without a new HTTP call."""
    sources=(('ip-metadata.sqlite3','ip_info','geo_checked','geo_json'),
             ('abuseipdb-check.sqlite3','ip_checks','abuse_checked','abuse_json'))
    for filename,table,checked,payload_col in sources:
        path=Path(root)/filename
        if not path.is_file():continue
        try:
            old=sqlite3.connect(f'file:{path}?mode=ro',uri=True,timeout=2)
            try:
                row=old.execute(f'SELECT payload FROM {table} WHERE ip=?',(ip,)).fetchone()
            finally:old.close()
            if not row:continue
            payload=json.loads(row[0])
            if not isinstance(payload,dict):continue
            if checked=='geo_checked':
                if 'country' not in payload and 'asn' not in payload:continue
            else:
                if type(payload.get('score')) is not int or not 0<=payload['score']<=100:continue
            conn.execute(f'UPDATE intel SET {checked}=1,{payload_col}=? WHERE ip=? AND {checked}=0',
                         (json.dumps(payload,ensure_ascii=False),ip))
        except (sqlite3.Error,TypeError,ValueError,UnicodeDecodeError,OSError):
            pass


def lookup(ip,root):
    """At most one successful lookup per IP/provider, permanently cached.

    Failures retry only after cooldown. A hard, persistent per-day budget also
    limits cross-session crawls. The API key is only read server-side.
    """
    global _LAST_REMOTE
    addr=_parse_ip(ip);ip=str(addr)
    with _LOCK:
        conn=_db(root)
        try:
            now=int(time.time())
            conn.execute('INSERT OR IGNORE INTO intel(ip) VALUES(?)',(ip,))
            _reuse_legacy(conn,root,ip)
            conn.commit()
            row=conn.execute('SELECT geo_checked,abuse_checked,geo_json,abuse_json,geo_retry_after,abuse_retry_after FROM intel WHERE ip=?',(ip,)).fetchone()
            want_geo=not row[0] and row[4]<=now
            want_abuse=not row[1] and row[5]<=now
            if not (want_geo or want_abuse):return _result(ip,row)
            if time.monotonic()-_LAST_REMOTE<MIN_INTERVAL:
                return _result(ip,row)
            day=time.strftime('%Y-%m-%d',time.gmtime(now))
            used=conn.execute('SELECT attempts FROM daily_quota WHERE day=?',(day,)).fetchone()
            if used and used[0]>=DAILY_LIMIT:return _result(ip,row)
            # Decrement local daily quota ONCE per IP enrichment attempt, not page visit.
            conn.execute('INSERT INTO daily_quota(day,attempts) VALUES(?,1) ON CONFLICT(day) DO UPDATE SET attempts=attempts+1',(day,))
            conn.execute('DELETE FROM daily_quota WHERE day<?',(day,))
            conn.commit()
            _LAST_REMOTE=time.monotonic()
            changed=False
            if want_geo:
                try:
                    geo=ipmeta._fetch(addr)
                    conn.execute('UPDATE intel SET geo_checked=1,geo_json=?,geo_retry_after=0 WHERE ip=?',
                                 (json.dumps(geo,ensure_ascii=False),ip))
                except (ipmeta.IPInfoError,ValueError,OSError):
                    conn.execute('UPDATE intel SET geo_retry_after=? WHERE ip=?',(now+RETRY_FAILURE,ip))
                changed=True
            if want_abuse:
                try:
                    abuse=_fetch_abuse(ip,root)
                    conn.execute('UPDATE intel SET abuse_checked=1,abuse_json=?,abuse_retry_after=0 WHERE ip=?',
                                 (json.dumps(abuse,ensure_ascii=False),ip))
                except (IntelError,OSError,ValueError):
                    conn.execute('UPDATE intel SET abuse_retry_after=? WHERE ip=?',(now+RETRY_FAILURE,ip))
                changed=True
            if changed:conn.commit()
            return _result(ip,conn.execute('SELECT geo_checked,abuse_checked,geo_json,abuse_json,geo_retry_after,abuse_retry_after FROM intel WHERE ip=?',(ip,)).fetchone())
        finally:conn.close()
