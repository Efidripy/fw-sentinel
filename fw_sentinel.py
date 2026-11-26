#!/usr/bin/env python3
"""FW Sentinel 2.0.21: conservative nftables observer / policy manager.
No destructive flush ruleset. Default observe. Python standard library only.
"""
from __future__ import annotations
from i18n import tr
import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import hmac
import http.client
import ipaddress
import io
import bisect
import itertools
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

import autoban
import i18n
import provider_keys

VERSION = '2.0.21'
ROOT = Path(os.environ.get('FWS_ROOT', '/opt/fw-sentinel'))
TABLE = 'fw_sentinel'
FAMILY = 'inet'
MAX_LINES = 300000
# Advanced feeds are bounded separately from small/mandatory security feeds.
# NERD Scan now exceeds the general 300k record cap (its download is ~6 MB).
MAX_ADVANCED_LINES = 1_200_000
NERD_SCAN_URL = 'https://nerd.cesnet.cz/nerd/data/bl_scan.txt'
THREATVIEW_URL = 'https://threatview.io/Downloads/IP-High-Confidence-Feed.txt'
# Added threat feeds are packaged enabled, but apply only after a separate
# confirmed firewall policy change. Existing confirmed nftables remain intact.
EXTRA_THREAT_FEEDS = (
    'abuseipdb_blacklist90', 'ipsum_level5', 'emerging_compromised', 'greensnow_attackers'
)
EXTRA_FEED_TTL_HOURS = 72



def config():
    i18n.load(ROOT)
    return json.loads((ROOT / 'config.json').read_text(encoding='utf-8'))


def sources():
    return json.loads((ROOT / 'sources.json').read_text(encoding='utf-8'))


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')


def atomic_write(path: Path, data: str, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(data)
            f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        with contextlib.suppress(FileNotFoundError): os.unlink(tmp)


def run(*args, input=None, check=True, timeout=45):
    return subprocess.run(args, input=input, text=True, capture_output=True, timeout=timeout, check=check)


PROGRESS=None  # set by the panel's apply job only


def apply_step(percent, text):
    if PROGRESS:PROGRESS(percent,text)


def nft(batch: str, check_only=False):
    # Full snapshots contain a table transaction followed by independent host batches.
    # Only the big host sets are split off; every other batch stays one atomic call.
    starts=[i for i in (batch.find(f'\nadd element inet {TABLE} {name} ') for name in ('scanhost4','watchhost4')) if i>=0]
    start=min(starts) if starts else -1
    main=batch if start<0 else batch[:start+1]
    batches='' if start<0 else batch[start+1:]
    def load(text, check=False):
        args=['nft']+(['-c'] if check else [])+['-f','-']
        p=run(*args,input=text,check=False,timeout=300)
        if p.returncode:raise RuntimeError('nft: '+(p.stderr.strip() or p.stdout.strip()))
    load(main,check_only)
    if check_only:return
    skipped=ROOT/'bulk-skipped'
    # A full snapshot replaces the table, so it also settles whether the big lists are in.
    if main.startswith('add table '):skipped.unlink(missing_ok=True)
    if not batches:return
    count=sum(line.count(',')+1 for line in batches.splitlines() if line.strip())
    try:
        with open('/proc/meminfo',encoding='ascii') as f:
            available=next(int(line.split()[1])*1024 for line in f if line.startswith('MemAvailable:'))
    except (OSError,ValueError,IndexError,StopIteration):available=None
    if available is not None and available < count*150+100*1024*1024:
        print('WARNING: insufficient MemAvailable; advanced host sets skipped, main rules applied',file=sys.stderr)
        atomic_write(skipped,f'{count}\n')
        return
    chunks=[line for line in batches.splitlines(keepends=True) if line.strip()]
    for number,line in enumerate(chunks,1):
        apply_step(78+16*number//len(chunks),f'{tr("Large lists: batch","Большие списки: порция")} {number} {tr("of","из")} {len(chunks)}')
        load(line)



def lock(name='.lock'):
    ROOT.mkdir(parents=True, exist_ok=True)
    fd = os.open(ROOT / name, os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    return fd


def line_networks(path: Path, *, addresses_only=False):
    if not path.exists(): return []
    nets = []
    for no, raw in enumerate(path.read_text(encoding='utf-8-sig').splitlines(), 1):
        value = raw.partition('#')[0].strip()
        if not value: continue
        try: net = ipaddress.ip_network(value, strict=False)
        except ValueError as e: raise ValueError(f'{path}:{no}: {e}') from e
        if addresses_only and net.prefixlen != net.max_prefixlen:
            raise ValueError(f'{path}:{no}: {tr("a single IP is required, not a subnet","необходим одиночный IP, а не подсеть")}')
        if net.prefixlen == 0: raise ValueError(f'{path}:{no}: /{tr("0 is forbidden","0 запрещена")}')
        nets.append(net)
    return nets


class CompactNetworks:
    """Advanced IPv4 hosts as integers, other networks as ipaddress objects."""
    def __init__(self):
        self.hosts=set();self.nets=[]
    def add(self,net):
        if net.version==4 and net.prefixlen==32:self.hosts.add(int(net.network_address))
        else:self.nets.append(net)
    def __len__(self):return len(self.hosts)+len(self.nets)
    def __bool__(self):return bool(self.hosts or self.nets)


def compact_cache(path):
    result=CompactNetworks()
    if not path.exists():return result
    with path.open(encoding='utf-8-sig') as f:
        for no,raw in enumerate(f,1):
            value=raw.partition('#')[0].strip()
            if not value:continue
            try:net=ipaddress.ip_network(value,strict=False)
            except ValueError as e:raise ValueError(f'{path}:{no}: {e}') from e
            if net.prefixlen==0:raise ValueError(f'{path}:{no}: /0 forbidden')
            result.add(net)
    return result


def compact_normalize(value):
    value.nets=[n for v in (4,6) for n in collapse(value.nets,v)]
    ranges=[(int(n.network_address),int(n.broadcast_address)) for n in value.nets if n.version==4]
    if ranges:
        starts=[r[0] for r in ranges]
        value.hosts={ip for ip in value.hosts if (i:=bisect.bisect_right(starts,ip)-1)<0 or ip>ranges[i][1]}
    return value


def compact_coverage(value,family):
    return coverage(value.nets,family)+(len(value.hosts) if family==4 else 0)


def write_compact_cache(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix='.'+path.name+'.',dir=path.parent)
    digest=hashlib.sha256()
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'w',encoding='utf-8',newline='\n') as f:
            for item in itertools.chain(value.nets,(str(ipaddress.IPv4Address(x))+'/32' for x in value.hosts)):
                line=str(item)+'\n';f.write(line);digest.update(line.encode())
            f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        with contextlib.suppress(FileNotFoundError):os.unlink(tmp)
    return digest.hexdigest()


def collapse(nets, v):
    return list(ipaddress.collapse_addresses([x for x in nets if x.version == v]))


def emit_nets(nets):
    return '\n'.join(map(str, nets)) + ('\n' if nets else '')


# A downloaded block list must never cut off these: loopback, private, CGNAT,
# link-local, multicast and reserved IPv4. IPv6 must stay inside 2000::/3.
SPECIAL_V4 = tuple((int(n.network_address), int(n.broadcast_address)) for n in map(ipaddress.ip_network, (
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
    '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/3')))
# Largest union one block list may cover (about 1.6% of IPv4; IPv6 in /64 units, one /20).
MAX_FEED_COVERAGE = {4: 2**26, 6: 2**44}


def touches_special(net):
    if net.version == 6: return net.prefixlen < 3 or int(net.network_address) >> 125 != 1
    low, high = int(net.network_address), int(net.broadcast_address)
    return any(low <= end and high >= start for start, end in SPECIAL_V4)


def coverage(nets, family):
    return sum(n.num_addresses if family == 4 else max(1, n.num_addresses // 2**64)
               for n in nets if n.version == family)


def urls_download(urls, limit, progress=None):
    """HTTPS only. Optional callback reports actual received bytes/Content-Length."""
    for url in urls:
        if not url.startswith('https://'): continue
        try:
            req=urllib.request.Request(url,headers={'User-Agent':f'FW-Sentinel/{VERSION}'})
            with urllib.request.urlopen(req,timeout=25) as r:
                if r.geturl().split(':',1)[0].lower()!='https':raise ValueError('non HTTPS redirect')
                if progress is None:
                    data=r.read(limit+1)
                else:
                    length=r.headers.get('Content-Length')
                    total=int(length) if length and length.isdecimal() else None
                    if total is not None and total>limit:raise ValueError('source too large')
                    chunks=[];received=0
                    progress(0,total)
                    while True:
                        part=r.read(min(65536,limit+1-received))
                        if not part:break
                        received+=len(part)
                        if received>limit:raise ValueError('source too large')
                        chunks.append(part);progress(received,total)
                    data=b''.join(chunks)
                if len(data)>limit:raise ValueError('source too large')
                return data
        except (OSError, urllib.error.URLError, http.client.HTTPException, ValueError) as e:
            print(f'[source] {url}: {e}',file=sys.stderr)
    raise RuntimeError('All source mirrors failed')


def download_abuseipdb_blacklist(cfg, spec):
    """Fetch official free-tier high-confidence blacklist, never exposing the key.

    Dedicated source and redirect refusal prevent a user-editable source URL
    from accidentally transmitting the Key header to a different host.
    """
    import stat
    key_path=ROOT/'abuseipdb.key'
    try:
        info=key_path.stat()
        if not stat.S_ISREG(info.st_mode) or (info.st_mode & 0o077):
            raise ValueError('AbuseIPDB API key file must be private (chmod 600)')
        key=key_path.read_text(encoding='ascii').strip()
    except FileNotFoundError as exc:
        raise ValueError('AbuseIPDB API key missing: /opt/fw-sentinel/abuseipdb.key') from exc
    if not re.fullmatch(r'[A-Za-z0-9]{20,160}',key):
        raise ValueError('AbuseIPDB API key has unexpected format')
    if spec.get('url')!='https://api.abuseipdb.com/api/v2/blacklist':
        raise ValueError('AbuseIPDB API URL must be the official HTTPS endpoint')
    if type(spec.get('confidence_minimum',90)) is not int or spec.get('confidence_minimum',90)<90 or spec.get('confidence_minimum',90)>100:
        raise ValueError('AbuseIPDB minimum confidence must be 90-100')
    url=f'https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum={spec.get("confidence_minimum",90)}&plaintext'
    request=urllib.request.Request(url,headers={'Key':key,'Accept':'text/plain','User-Agent':f'FW-Sentinel/{VERSION}'})
    # urllib follows redirects and may forward request headers; never do that
    # with a secret. 3xx from the provider becomes an ordinary update failure.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,req,fp,code,msg,headers,newurl):
            return None
    opener=urllib.request.build_opener(NoRedirect())
    max_bytes=min(5_000_000,int(cfg['max_feed_bytes']))
    with opener.open(request,timeout=20) as response:
        data=response.read(max_bytes+1)
        if len(data)>max_bytes:raise ValueError('AbuseIPDB blacklist larger than allowed')
        return data


def source_cache_if_fresh(name,max_stale_hours,*,compact=False):
    """A volatile IP blacklist must never silently survive beyond its TTL."""
    path=ROOT/'cache'/'sources'/f'{name}.txt'
    meta=path.with_suffix('.meta.json')
    try:
        updated=dt.datetime.fromisoformat(json.loads(meta.read_text(encoding='utf-8'))['updated'])
        if updated.tzinfo is None:return []
        age=(dt.datetime.now(dt.timezone.utc)-updated).total_seconds()
        if age<0 or age>max_stale_hours*3600:return []
    except (OSError,ValueError,TypeError,KeyError):return []
    return compact_cache(path) if compact else line_networks(path)


def proto_fields(b):
    """Simple bounded protobuf reader for V2Ray GeoIPList."""
    pos = 0
    def varint():
        nonlocal pos
        val = shift = 0
        for _ in range(10):
            if pos >= len(b): raise ValueError('truncated protobuf')
            c = b[pos]; pos += 1
            val |= (c & 127) << shift
            if c < 128: return val
            shift += 7
        raise ValueError('oversized varint')
    while pos < len(b):
        key = varint(); num, wire = key >> 3, key & 7
        if wire == 0: val = varint()
        elif wire == 2:
            length = varint()
            if length > len(b) - pos: raise ValueError('truncated protobuf field')
            val = b[pos:pos+length]; pos += length
        elif wire in (1,5):
            size = 8 if wire == 1 else 4
            if len(b)-pos < size: raise ValueError('truncated fixed field')
            val = b[pos:pos+size]; pos += size
        else: raise ValueError(f'unknown protobuf wire type {wire}')
        yield num, wire, val


def parse_geoip(data, tag='ru'):
    out, found = [], False
    for num, wire, entry in proto_fields(data):
        if num != 1 or wire != 2: continue
        fields = list(proto_fields(entry))
        codes = [x.decode('utf-8') for n,w,x in fields if n == 1 and w == 2]
        if not codes or codes[0].lower() != tag.lower(): continue
        found = True
        for n,w,part in fields:
            if n != 2 or w != 2: continue
            addr = b''; prefix = None
            for nn,ww,v in proto_fields(part):
                if nn == 1 and ww == 2: addr = bytes(v)
                if nn == 2 and ww == 0: prefix = v
            if len(addr) not in (4,16) or prefix is None: raise ValueError('invalid CIDR')
            out.append(ipaddress.ip_network((addr,prefix),strict=False))
    if not found: raise ValueError(f'geo category {tag} missing')
    for subnet in out:
        if subnet.prefixlen < (8 if subnet.version == 4 else 16):
            raise ValueError(f'too broad geo prefix: {subnet}')
    return out


def parse_cidr(data, min4=8, min6=16, progress=None):
    text = data.decode('utf-8-sig')
    result, ignored = [], []
    lines=text.splitlines()
    for i, raw in enumerate(lines,1):
        if progress and (i%12000==0):progress(i,len(lines))
        value = raw.partition('#')[0].strip()
        if not value: continue
        if i > MAX_LINES: raise ValueError('too many CIDR entries')
        net = ipaddress.ip_network(value, strict=False)
        if net.prefixlen < (min4 if net.version == 4 else min6):
            ignored.append(str(net)); continue
        result.append(net)
    if progress:progress(len(lines),len(lines))
    if not result: raise ValueError('empty/invalid CIDR feed')
    return result, ignored


def parse_spamhaus_drop(data, min4=8, min6=16):
    """Spamhaus DROP is JSON Lines: CIDR objects plus a metadata/copyright object.
    Store the original copyright-bearing downloaded file alongside the normalized cache.
    """
    result=[]; ignored=[]; metadata=False
    for row in data.decode('utf-8-sig').splitlines():
        if not row.strip(): continue
        obj=json.loads(row)
        if not isinstance(obj,dict):raise ValueError('Spamhaus row is not an object')
        cidr=obj.get('cidr')
        if cidr is None:
            if 'copyright' in obj or 'timestamp' in obj:metadata=True
            continue
        network=ipaddress.ip_network(cidr,strict=True)
        if network.prefixlen < (min4 if network.version==4 else min6):
            ignored.append(str(network));continue
        result.append(network)
    if not result:raise ValueError('empty Spamhaus DROP list')
    if not metadata:raise ValueError('Spamhaus DROP copyright/timestamp metadata missing')
    return result,ignored


def parse_dshield(data, min4=8, min6=16):
    """DShield block.txt: TSV startIP/endIP/prefix/count/org/country/contact."""
    result=[];ignored=[]
    for row in data.decode('utf-8-sig').splitlines():
        if not row or row.lstrip().startswith('#'):continue
        fields=row.split('\t')
        if len(fields)<3:raise ValueError('DShield malformed TSV')
        network=ipaddress.ip_network(fields[0].strip()+'/'+fields[2].strip(),strict=True)
        if str(network.broadcast_address)!=fields[1].strip():raise ValueError('DShield range mismatch')
        if network.prefixlen < (min4 if network.version==4 else min6):ignored.append(str(network));continue
        result.append(network)
    if not result:raise ValueError('empty DShield list')
    return result,ignored


def parse_misp_networks(data, min4=8, min6=16, progress=None):
    """MISP warninglist is JSON with a bounded list of IP/CIDR entries."""
    obj=json.loads(data)
    if not isinstance(obj,dict) or not isinstance(obj.get('list'),list):
        raise ValueError('MISP list.json is malformed')
    if len(obj['list'])>MAX_LINES:raise ValueError('MISP feed contains too many entries')
    out=[];ignored=[]
    for raw in obj['list']:
        if not isinstance(raw,str) or len(raw)>60:raise ValueError('Invalid MISP entry')
        try:net=ipaddress.ip_network(raw.strip(),strict=False)
        except ValueError:raise ValueError('MISP contains a non-IP entry') from None
        if net.prefixlen < (min4 if net.version==4 else min6) or not net.network_address.is_global:
            ignored.append(str(net));continue
        out.append(net)
    if progress:progress(len(obj['list']),len(obj['list']))
    if not out:raise ValueError('MISP list has no valid routable IP networks')
    return out,ignored


class AdvancedSkipped(list):
    """Backward-compatible ignored CIDR list with bad-row diagnostics."""
    def __init__(self):
        super().__init__()
        self.invalid_count = 0
        self.invalid_samples = []


def parse_advanced_cidr(data, min4=8, min6=16, *, max_lines=MAX_LINES, skip_invalid=False, progress=None):
    """Bounded CIDR parser with optional recovery from isolated corrupt rows.

    Strict parsing remains the default for mandatory sources. Only the
    ThreatView IP feed uses skip_invalid; NERD Scan only raises its row cap.
    """
    text=data.decode('utf-8-sig')
    lines=text.splitlines()
    if len(lines)>max_lines:
        raise ValueError(f'too many CIDR entries ({len(lines)} > {max_lines})')
    valid=[];ignored=AdvancedSkipped();nonempty=0
    for number,raw in enumerate(lines,1):
        if progress and (number%12000==0):progress(number,len(lines))
        value=raw.partition('#')[0].strip()
        if not value:continue
        nonempty+=1
        try:net=ipaddress.ip_network(value,strict=False)
        except ValueError:
            if not skip_invalid:raise ValueError(f'Invalid IP/CIDR at line {number}: {value[:50]!r}') from None
            ignored.invalid_count+=1
            if len(ignored.invalid_samples)<3:ignored.invalid_samples.append(f'{number}: {value[:50]!r}')
            continue
        if net.prefixlen < (min4 if net.version==4 else min6):
            ignored.append(str(net));continue
        valid.append(net)
    # Refuse a corrupted/HTML/feed-replaced download; a few malformed address
    # strings are not grounds to discard 25k otherwise valid threat records.
    if progress:progress(len(lines),len(lines))
    if skip_invalid and ignored.invalid_count>max(25,int(nonempty*0.001)):
        raise ValueError(f'too many invalid CIDR rows: {ignored.invalid_count}/{nonempty}')
    if not valid:raise ValueError('empty/invalid CIDR feed')
    return valid,ignored


def parse_compact_advanced(data,spec,cfg,progress=None):
    url=spec.get('url','');limit=MAX_ADVANCED_LINES if url==NERD_SCAN_URL else MAX_LINES
    skip=url==THREATVIEW_URL;ignored=AdvancedSkipped();result=CompactNetworks();nonempty=0
    total=data.count(b'\n')+(bool(data) and not data.endswith(b'\n'))
    if url in (NERD_SCAN_URL,THREATVIEW_URL) and total>limit:
        raise ValueError(f'too many CIDR entries ({total} > {limit})')
    for number,raw in enumerate(io.TextIOWrapper(io.BytesIO(data),encoding='utf-8-sig'),1):
        if progress and number%12000==0:progress(number,total)
        value=raw.partition('#')[0].strip()
        if not value:continue
        if number>limit:raise ValueError('too many CIDR entries')
        nonempty+=1
        try:net=ipaddress.ip_network(value,strict=False)
        except ValueError:
            if not skip:raise ValueError(f'Invalid IP/CIDR at line {number}: {value[:50]!r}') from None
            ignored.invalid_count+=1
            if len(ignored.invalid_samples)<3:ignored.invalid_samples.append(f'{number}: {value[:50]!r}')
            continue
        if (net.prefixlen < cfg['min_scanner_prefix_v4' if net.version==4 else 'min_scanner_prefix_v6']
                or not net.network_address.is_global or net.is_multicast):
            ignored.append(str(net));continue
        result.add(net)
    if progress:progress(total,total)
    if skip and ignored.invalid_count>max(25,int(nonempty*0.001)):
        raise ValueError(f'too many invalid CIDR rows: {ignored.invalid_count}/{nonempty}')
    if not result:raise ValueError('No public routable IPs in feed')
    return result,ignored


def parse_advanced_source(data, spec, cfg, progress=None, *, compact=False):
    fmt=spec.get('format','cidr')
    if compact and fmt=='cidr' and spec.get('confidence') in ('scanner','threat'):
        return parse_compact_advanced(data,spec,cfg,progress)
    limits=(cfg['min_scanner_prefix_v4'],cfg['min_scanner_prefix_v6'])
    if fmt=='misp_json':result,ignored=parse_misp_networks(data,*limits,progress=progress)
    elif fmt=='cidr':
        url=spec.get('url','')
        if url in (NERD_SCAN_URL,THREATVIEW_URL):
            result,ignored=parse_advanced_cidr(data,*limits,
                max_lines=MAX_ADVANCED_LINES if url==NERD_SCAN_URL else MAX_LINES,
                skip_invalid=(url==THREATVIEW_URL),progress=progress)
        else:
            result,ignored=parse_cidr(data,*limits,progress=progress)
    else:raise ValueError('Unsupported advanced feed format')
    # O(n) filtering, no membership in the ever-growing list of networks.
    public=[]
    for net in result:
        if net.network_address.is_global and not net.is_multicast:public.append(net)
        else:ignored.append(str(net))
    if not public:raise ValueError('No public routable IPs in feed')
    return public,ignored


def _advanced_sync_status_path():
    return ROOT/'cache'/'sources'/'advanced-sync-status.json'


def _read_advanced_sync_status():
    try:
        data=json.loads(_advanced_sync_status_path().read_text(encoding='utf-8'))
        if not isinstance(data,dict):return {}
        return {k:v for k,v in data.items() if isinstance(v,dict)}
    except (OSError,TypeError,ValueError):
        return {}


def _write_advanced_sync_status(data):
    # Dedicated diagnostic metadata: never contains API keys or downloaded IPs.
    atomic_write(_advanced_sync_status_path(),json.dumps(data,ensure_ascii=False,indent=2))


def _advanced_cache_count(name,max_stale_hours=168):
    """Fast read-only cache summary: don't parse FireHOL on every UI visit."""
    base=ROOT/'cache'/'sources'/f'advanced_{name}'
    cached=base.with_suffix('.txt')
    meta=base.with_suffix('.meta.json')
    if not cached.is_file() or not meta.is_file():return 0
    try:
        j=json.loads(meta.read_text(encoding='utf-8'))
        updated=dt.datetime.fromisoformat(j['updated'])
        if updated.tzinfo is None:return 0
        age=(dt.datetime.now(dt.timezone.utc)-updated).total_seconds()
        if age<0 or age>max_stale_hours*3600:return 0
        count=j['count']
        return count if type(count) is int and 0<=count<=MAX_ADVANCED_LINES else 0
    except (OSError,ValueError,TypeError,KeyError):return 0


def advanced_source_status():
    catalog=sources().get('advanced_feeds',{})
    previous=_read_advanced_sync_status()
    result={}
    for name,spec in sorted(catalog.items()):
        count=_advanced_cache_count(name,168)
        last=previous.get(name,{})
        result[name]={
            'name':spec.get('name',name),
            'group':spec.get('group','THREAT'),
            'confidence':spec.get('confidence','context'),
            'count':count,
            'enabled':bool(spec.get('enabled',False)),
            'last_attempt':last.get('at'),
            'last_status':last.get('status','not-checked'),
            'last_error':last.get('error',''),
            'last_warning':last.get('warning',''),
        }
    return result


def prepare_advanced_feeds(selected=None):
    """Download/cache selected open feeds without touching nftables.

    Status is printed live to stderr and persisted per source. A SIGINT leaves
    previously verified caches untouched and records the interrupted source.
    """
    ROOT.mkdir(parents=True,exist_ok=True)
    fd=os.open(ROOT/'.advanced-feed.lock',os.O_CREAT|os.O_RDWR,0o600)
    fcntl.flock(fd,fcntl.LOCK_EX)
    try:
        cfg=config()
        catalog=sources().get('advanced_feeds',{})
        if selected is not None and selected not in catalog:
            raise ValueError((tr('Unknown list:','Неизвестная база:')+' ')+selected)
        planned=[(n,v) for n,v in catalog.items() if v.get('enabled',False) and (selected is None or n==selected)]
        if selected is not None and not planned:
            raise ValueError((tr('Source disabled in catalog:','Источник выключен в каталоге:')+' ')+selected)
        previous=_read_advanced_sync_status()
        result={}
        total=len(planned)
        for index,(name,spec) in enumerate(planned,1):
            if not re.fullmatch(r'[a-z0-9_]{2,55}',name):raise ValueError('Bad source ID')
            started=time.monotonic()
            print(f'[{index}/{total}] {name}: {tr("downloading/checking...","загрузка/проверка...")}',file=sys.stderr,flush=True)
            try:
                nets,used,issues=acquire_source('advanced_'+name,[spec['url']],
                    lambda data,sp=spec:parse_advanced_source(data,sp,cfg,compact=sp.get('confidence') in ('scanner','threat')),cfg,
                    min_refresh_seconds=3600 if spec.get('group')=='THREAT' else 86400,
                    max_stale_hours=168,compact=spec.get('confidence') in ('scanner','threat'))
                info={'count':len(nets),'status':used,'issues':issues}
            except KeyboardInterrupt:
                previous[name]={'at':now(),'status':'interrupted','error':tr('Interrupted by user','Прервано пользователем')}
                _write_advanced_sync_status(previous)
                print(f'[{index}/{total}] {name}: {tr("interrupted. Caches saved.","прервано. Кэши сохранены.")}',file=sys.stderr,flush=True)
                raise
            except (ValueError,OSError,RuntimeError) as exc:
                info={'count':0,'status':'failed','issues':[str(exc)]}
            result[name]=info
            errors=[str(x)[:300] for x in info['issues']]
            failed=bool(not info['count'] or info['status']=='failed')
            previous[name]={'at':now(),'status':info['status'],
                            'error':('; '.join(errors)[:650] if failed else ''),
                            'warning':('; '.join(errors)[:650] if not failed else '')}
            _write_advanced_sync_status(previous)
            elapsed=time.monotonic()-started
            label=(tr('WARNING','ВНИМАНИЕ') if failed else tr('OK (with warnings)','OK (с замечаниями)') if errors else 'OK')
            print(f'[{index}/{total}] {name}: {label}, {info["count"]} {tr("networks,","сетей,")} '
                  f'{elapsed:.1f} {tr("s, source=","с, источник=")}{info["status"]}',file=sys.stderr,flush=True)
            for msg in errors[:3]:
                print(f'    {msg}',file=sys.stderr,flush=True)
        return result
    finally:
        os.close(fd)


def parse_ripe(data, asn, limits):
    j = json.loads(data)
    info = j['data']
    if j.get('status') != 'ok' or str(info['resource']).upper().removeprefix('AS') != asn.removeprefix('AS'):
        raise ValueError('wrong RIPEstat ASN response')
    nets=[]
    for item in info['prefixes']:
        n=ipaddress.ip_network(item['prefix'],strict=False)
        if n.prefixlen >= limits[0 if n.version==4 else 1]: nets.append(n)
    return nets


# Dropping private ranges and a few broken rows is routine for public feeds: kept in
# the data and the CLI output, not shown in the panel (stored old text included).
ROUTINE_NOTE=re.compile(r'[A-Za-z0-9_]+: (?:(?:broad(?:/non-public)? subnets|private/reserved networks) omitted: \d+'
                        r'|malformed IP/CIDR rows skipped: \d+(?: \(examples [^)]*(?:\)|$))?)(?:; )?')


def notable(text):
    return ROUTINE_NOTE.sub('',str(text or '')).strip('; ')


def acquire_source(name, urls, transform, cfg, *, mandatory=False, loader=None, preserve_original=False, min_refresh_seconds=0, max_stale_hours=None, compact=False):
    """Atomic vetted-cache update; on failure use previous verified cache regardless of age."""
    cache_file=ROOT/'cache'/'sources'/f'{name}.txt'
    marker=ROOT/'cache'/'sources'/f'{name}.meta.json'
    old=compact_cache(cache_file) if compact else line_networks(cache_file)
    issues=[]; fresh=None; used='cache'
    age_seconds=None
    if marker.exists():
        try:
            updated=dt.datetime.fromisoformat(json.loads(marker.read_text(encoding='utf-8'))['updated'])
            age_seconds=max(0,(dt.datetime.now(dt.timezone.utc)-updated).total_seconds())
        except (OSError,KeyError,ValueError,TypeError):pass
    if old and min_refresh_seconds and age_seconds is not None and age_seconds<min_refresh_seconds:
        return old,'cache-fresh',issues
    expired=bool(old and max_stale_hours is not None and
                 (age_seconds is None or age_seconds>float(max_stale_hours)*3600))
    compared=[] if expired else old
    try:
        data=loader() if loader else urls_download(urls,int(cfg['max_feed_bytes']))
        parsed, ignored=transform(data)
        if ignored: issues.append(f'{name}: broad/non-public subnets omitted: {len(ignored)}')
        bad=getattr(ignored,'invalid_count',0)
        if bad:
            samples='; '.join(getattr(ignored,'invalid_samples',[])[:3])
            issues.append(f'{name}: malformed IP/CIDR rows skipped: {bad}'+
                          (f' (examples {samples})' if samples else ''))
        if compact:
            if not isinstance(parsed,CompactNetworks):
                converted=CompactNetworks()
                for net in parsed:converted.add(net)
                parsed=converted
            before=len(parsed)
            parsed.hosts.difference_update([x for x in parsed.hosts if any(a<=x<=b for a,b in SPECIAL_V4)])
            parsed.nets=[x for x in parsed.nets if not touches_special(x)]
            if len(parsed)<before:issues.append(f'{name}: private/reserved networks omitted: {before-len(parsed)}')
            current=compact_normalize(parsed)
            if not current and not mandatory:raise ValueError('empty new set')
            for family,limit in MAX_FEED_COVERAGE.items():
                limit=int(cfg.get(f'max_feed_coverage_v{family}',limit))
                cur=compact_coverage(current,family)
                if cur>limit:raise ValueError(f'IPv{family}: feed covers too much address space ({cur} > {limit})')
                if compared:
                    prev=compact_coverage(compact_normalize(compared),family)
                    if prev and not (float(cfg['min_keep_fraction'])*prev <= cur <= float(cfg['max_growth_factor'])*prev):
                        raise ValueError(f'{family}: suspicious feed coverage change {prev}->{cur}')
        else:
            # Every list except the geo allow-list ends up in DROP rules.
            blocking=not name.startswith('geo')
            if blocking:
                safe=[x for x in parsed if not touches_special(x)]
                if len(safe)<len(parsed):
                    issues.append(f'{name}: private/reserved networks omitted: {len(parsed)-len(safe)}')
                parsed=safe
            current=[x for v in (4,6) for x in collapse(parsed,v)]
            if not current and not mandatory: raise ValueError('empty new set')
            if blocking:
                for family,limit in MAX_FEED_COVERAGE.items():
                    limit=int(cfg.get(f'max_feed_coverage_v{family}',limit))
                    if coverage(current,family)>limit:
                        raise ValueError(f'IPv{family}: feed covers too much address space ({coverage(current,family)} > {limit})')
            if compared:
                for family in (4,6):
                    a=[x for x in current if x.version==family]
                    b=[x for x in compared if x.version==family]
                    if not b: continue
                    # Exact coverage by union (rather than count) for IPv4; approximate IPv6 with /64 units.
                    prev,cur=coverage(b,family),coverage(a,family)
                    if prev and not (float(cfg['min_keep_fraction'])*prev <= cur <= float(cfg['max_growth_factor'])*prev):
                        raise ValueError(f'{family}: suspicious feed coverage change {prev}->{cur}')
        fresh=current; used='fresh'
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, http.client.HTTPException) as e:
        issues.append(f'{name}: {e}'+(' (cached set preserved)' if old else ' (NO CACHE)'))
        if old and marker.exists():
            try:
                updated=dt.datetime.fromisoformat(json.loads(marker.read_text(encoding='utf-8'))['updated'])
                age=(dt.datetime.now(dt.timezone.utc)-updated).days
                if age>=int(cfg.get('warn_stale_after_days',14)):
                    issues.append(f'{name}: cached data is {age} days old (still preserved for safety)')
            except (OSError,KeyError,ValueError):pass
        if expired:
            issues.append(f'{name}: volatile threat feed expired; stale IPs NOT blocked')
        if not old and mandatory: raise RuntimeError(f'Required source unavailable: {name}') from e
    if fresh is not None:
        if preserve_original:
            # Original includes Spamhaus date and copyright; do not strip attribution.
            atomic_write(cache_file.with_suffix('.original.jsonl'),data.decode('utf-8'))
        if compact:digest=write_compact_cache(cache_file,fresh)
        else:
            content=emit_nets(fresh);atomic_write(cache_file,content);digest=hashlib.sha256(content.encode()).hexdigest()
        atomic_write(marker,json.dumps({'updated':now(),'count':len(fresh),'sha256':digest},ensure_ascii=False))
        return fresh,used,issues
    return ([] if expired else old),used,issues


def build_sets_from_sources(cfg, refresh=True):
    src=sources(); issues=[]; fresh_stats={}
    if refresh:
        geo,where,w=acquire_source('geo_ru',src['geoip'],lambda d:(parse_geoip(d,cfg['geo_tag']),[]),cfg, mandatory=bool(cfg['geo_enabled']))
        issues+=w; fresh_stats['geo_ru']=where
    else: geo=line_networks(ROOT/'cache'/'sources'/'geo_ru.txt')
    if cfg['geo_enabled'] and (len([x for x in geo if x.version==4])<int(cfg['min_ru_ipv4']) or len([x for x in geo if x.version==6]) < int(cfg['min_ru_ipv6'])):
        raise RuntimeError('RU geobase unavailable or implausibly small; refusing change')
    scanners=[]; asn_nets=[]
    if cfg.get('scanner_enabled',True):
        for name,url in src['cidr'].items():
            if refresh:
                n,where,w=acquire_source('cidr_'+name,[url],lambda d:parse_cidr(d,cfg['min_scanner_prefix_v4'],cfg['min_scanner_prefix_v6']),cfg)
                issues+=w; fresh_stats[name]=where
            else:n=line_networks(ROOT/'cache'/'sources'/f'cidr_{name}.txt')
            scanners+=n
    if cfg.get('asn_enabled',True):
        for raw in (ROOT/'asn.txt').read_text(encoding='utf-8').splitlines():
            asn=raw.partition('#')[0].strip().upper()
            if not asn:continue
            if not re.fullmatch(r'AS[0-9]{1,10}',asn):raise ValueError(f'Invalid ASN: {asn}')
            num=asn[2:]
            urls=[f'https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}']
            def asn_transform(d, a=asn):
                try: return parse_ripe(d,a,(cfg['min_scanner_prefix_v4'],cfg['min_scanner_prefix_v6'])),[]
                except (ValueError,KeyError,TypeError) as e: raise ValueError(str(e))
            if refresh:
                n,where,w=acquire_source('asn_'+asn,urls,asn_transform,cfg)
                # fallback RIPE -> ipverse for no valid cache; when a cached list exists, leave it alone until next update
                if not n:
                    def fallback_data(number=num):
                        last=None
                        for base in (f'https://raw.githubusercontent.com/ipverse/as-ip-blocks/master/as/{number}',
                                     f'https://cdn.jsdelivr.net/gh/ipverse/as-ip-blocks@master/as/{number}'):
                            try:
                                a=urls_download([base+'/ipv4-aggregated.txt'],int(cfg['max_feed_bytes']))
                                b=urls_download([base+'/ipv6-aggregated.txt'],int(cfg['max_feed_bytes']))
                                return a+b'\n'+b
                            except RuntimeError as err:last=err
                        raise RuntimeError(str(last or 'ipverse unavailable'))
                    x,where2,w2=acquire_source('asn_'+asn,[],lambda d:parse_cidr(d,cfg['min_scanner_prefix_v4'],cfg['min_scanner_prefix_v6']),cfg,loader=fallback_data)
                    n=x; issues+=w2;where=where2
                issues+=w;fresh_stats[asn]=where
            else:n=line_networks(ROOT/'cache'/'sources'/f'asn_{asn}.txt')
            asn_nets+=n
    # Additional feeds are segregated: never merge reputation data into broad scanner bans.
    ssh_attacks=[]; watch=[]
    for kind, bucket in (('threat_ssh',ssh_attacks),('threat_watch',watch)):
        for name,spec in src.get(kind,{}).items():
            if not spec.get('enabled',True):continue
            if name in EXTRA_THREAT_FEEDS and not cfg.get('extra_threat_feeds_enabled',False):continue
            if not re.fullmatch(r'[a-z0-9_]{2,55}',name):raise ValueError('unsafe threat source ID')
            fmt=spec.get('format','cidr')
            def transform(data, fmt=fmt):
                if fmt=='cidr':return parse_cidr(data,cfg['min_scanner_prefix_v4'],cfg['min_scanner_prefix_v6'])
                if fmt=='spamhaus_drop':return parse_spamhaus_drop(data,cfg['min_scanner_prefix_v4'],cfg['min_scanner_prefix_v6'])
                if fmt=='dshield':return parse_dshield(data,cfg['min_scanner_prefix_v4'],cfg['min_scanner_prefix_v6'])
                raise ValueError('unsupported threat feed format: '+fmt)
            cache_name=kind+'_'+name
            stale_hours=72 if name in ('blocklist_ssh','blocklist_bots','dshield_attackers',*EXTRA_THREAT_FEEDS) else 336
            if fmt=='abuseipdb' and kind!='threat_watch':
                raise ValueError('AbuseIPDB source can only be used for threat_watch')
            if refresh:
                if fmt=='abuseipdb':
                    transform=lambda data: parse_cidr(data,cfg['min_scanner_prefix_v4'],cfg['min_scanner_prefix_v6'])
                    loader=lambda spec=spec: download_abuseipdb_blacklist(cfg,spec)
                else:loader=None
                nets,where,w=acquire_source(cache_name,[spec['url']],transform,cfg,
                    loader=loader,preserve_original=(fmt=='spamhaus_drop'),
                    min_refresh_seconds=86400 if fmt in ('spamhaus_drop','abuseipdb') else 0,
                    max_stale_hours=stale_hours)
                issues+=w;fresh_stats[cache_name]=where
            else:
                nets=(source_cache_if_fresh(cache_name,stale_hours) if name in EXTRA_THREAT_FEEDS else
                      line_networks(ROOT/'cache'/'sources'/f'{cache_name}.txt'))
            bucket.extend(nets)
    # Optional curated open feed pack. Context lists (incl. government networks)
    # are never mixed into the threat DROP set unless explicitly classified.
    # Changing this gate requires a new confirmed policy and signature.
    government=[];scan_hosts=set();watch_hosts=set()
    if cfg.get('advanced_feed_pack_enabled',False):
        for name,spec in src.get('advanced_feeds',{}).items():
            if not spec.get('enabled',False):continue
            if not re.fullmatch(r'[a-z0-9_]{2,55}',name):raise ValueError('Bad source ID')
            cache_id='advanced_'+name
            if refresh:
                nets,used,w=acquire_source(cache_id,[spec['url']],
                    lambda data,sp=spec:parse_advanced_source(data,sp,cfg,compact=sp.get('confidence') in ('scanner','threat')),cfg,
                    min_refresh_seconds=3600 if spec.get('group')=='THREAT' else 86400,
                    max_stale_hours=168,compact=spec.get('confidence') in ('scanner','threat'))
                fresh_stats[cache_id]=used;issues+=w
            else:nets=source_cache_if_fresh(cache_id,168,compact=spec.get('confidence') in ('scanner','threat'))
            if isinstance(nets,CompactNetworks):
                if spec.get('group')!='RU-GOV':
                    (scan_hosts if spec.get('confidence')=='scanner' else watch_hosts).update(nets.hosts)
                nets=nets.nets
            if spec.get('group')=='RU-GOV':government+=nets
            elif spec.get('confidence')=='scanner':scanners+=nets
            elif spec.get('confidence')=='threat':watch+=nets
            # Broad/context feeds are intentionally never enforced.
    return {'geo':geo,'scanners':scanners,'asn':asn_nets,'threat_ssh':ssh_attacks,'threat_watch':watch,
            'government':government,'scanners_hosts':scan_hosts,'threat_watch_hosts':watch_hosts,**local_sets()},issues,fresh_stats


def local_sets():
    # manual bans are an independent set; NEVER derive permanent ban from external list or log.
    manual=line_networks(ROOT/'manual-bans.txt',addresses_only=True)
    trusted=line_networks(ROOT/'allow.txt')
    vpn_clients=line_networks(ROOT/'vpn-clients.txt',addresses_only=True)
    if any(x.prefixlen==0 for x in trusted):raise ValueError('Whitelist /0 prohibited')
    return {'manual':manual,'trusted':trusted,'vpn_clients':vpn_clients}


def nft_set(name, typ, nets):
    vals=emit_nets(nets).splitlines()
    return f'  set {name} {{ type {typ}; flags interval; auto-merge;'+(' elements = { '+', '.join(vals)+' };' if vals else '')+' }\n'


def render_rules(cfg, sets, enforce=False):
    """Isolated inet table, no flush ruleset. Input SSH meter, prerouting ingress filtering before Docker DNAT."""
    wan=cfg.get('wan_interfaces',[])
    if not wan: raise ValueError('wan_interfaces not set; run install/detect WAN before observe/enable')
    if any(not re.fullmatch(r'[A-Za-z0-9_.:@-]{1,15}',x) for x in wan): raise ValueError('Invalid WAN interface')
    # Never interpolate unvalidated values into nft commands.
    auto_safe_tcp,auto_safe_udp=autoban.validate(cfg)
    if cfg.get('autoban_enabled',False):
        auto_safe_tcp,auto_safe_udp=autoban.protected_ports(cfg,discover=True)
    ports=cfg.get('geo_ports',[]); ssh=cfg.get('ssh_ports',[])
    vpn_ports=cfg.get('vpn_ports',[443,8443])
    for x in ports+ssh+vpn_ports:
        if type(x) is not int or not (1<=x<=65535):raise ValueError(f'Invalid port: {x}')
    rate=int(cfg.get('ssh_rate_per_minute',10));burst=int(cfg.get('ssh_rate_burst',10))
    if rate<1 or rate>10000 or burst<1 or burst>1000:raise ValueError('SSH rate invalid')
    # Protect VPN from accidental SSH-rate or SSH-reputation rules on the same port.
    ssh_safe=sorted(set(ssh)-set(vpn_ports))
    mode_drop = enforce
    extended={**sets}
    for key in ('vpn_clients','threat_ssh','threat_watch','asn'):
        extended.setdefault(key,[])
    nets={key:{v:collapse(items,v) for v in (4,6)} for key,items in extended.items() if not key.endswith('_hosts')}
    lines=[f'add table inet {TABLE}',f'delete table inet {TABLE}',f'table inet {TABLE} {{']
    for n,label in [('allow','trusted'),('ban','manual'),('scan','scanners'),('asn','asn'),('ru','geo'),
                    ('vpn','vpn_clients'),('sshbad','threat_ssh'),('watch','threat_watch')]:
        for v in (4,6):lines.append(nft_set(f'{n}{v}',('ipv4_addr' if v==4 else 'ipv6_addr'),nets[label][v]).rstrip())
    lines.extend(['  set scanhost4 { type ipv4_addr; }','  set watchhost4 { type ipv4_addr; }'])
    # Port-scan auto bans are EPHEMERAL; the kernel times out each IP after 24h.
    # Protected port sets are dynamically refreshed by the observer. Neither
    # existing VPN ports nor discovered listening/Docker ports are banned.
    if cfg.get('autoban_enabled',False):
        for ver in (4,6):
            lines.append(f'  set auto{ver} {{ type {"ipv4_addr" if ver==4 else "ipv6_addr"}; flags timeout; }}')
        if autoban.trap_ports(cfg) or cfg.get('ssh_watch_enabled',False):
            for ver in (4,6):
                lines.append(f'  set trap{ver} {{ type {"ipv4_addr" if ver==4 else "ipv6_addr"}; flags timeout; }}')
        if cfg.get('ssh_watch_enabled',False):
            for ver in (4,6):
                lines.append(f'  set sshtrust{ver} {{ type {"ipv4_addr" if ver==4 else "ipv6_addr"}; flags timeout; }}')
        for name,ports in (('autosafetcp',auto_safe_tcp),('autosafeudp',auto_safe_udp)):
            text=', '.join(map(str,sorted(ports)))
            lines.append(f'  set {name} {{ type inet_service;'+(f' elements = {{ {text} }};' if text else '')+' }')
    ifaces='{ '+', '.join('"'+i+'"' for i in wan)+' }'
    lines.extend(['  chain ingress {','    type filter hook prerouting priority -150; policy accept;',
                  '    iifname "lo" accept',f'    iifname != {ifaces} accept',
                  '    fib daddr type != local accept',
                  '    ct state established,related accept'])
    # Passive, bounded telemetry only: sampled TCP SYN to VPN ports, no verdict and
    # no payload inspection. A 'pass' event means only 'not dropped by Sentinel',
    # NOT successful VPN authentication or downstream firewall acceptance.
    live_enabled=bool(cfg.get('live_pass_logging_enabled',True)) and bool(cfg.get('logging_enabled',True))
    live_rate=cfg.get('live_pass_log_rate_per_sec',2)
    if type(live_rate) is not int or not (1<=live_rate<=10):
        raise ValueError('live_pass_log_rate_per_sec must be integer 1..10')
    log_vpn_ports=sorted(set(vpn_ports))
    log_ports='{ '+', '.join(map(str,log_vpn_ports))+' }' if log_vpn_ports else ''
    def passive_sample(prefix,label):
        if live_enabled and log_ports:
            lines.append(f'    {prefix} limit rate {live_rate}/second burst 4 packets log prefix "FWS P_{label}: "')
    tcpvpn=f'ct state new tcp flags syn tcp dport {log_ports}' if log_ports else ''
    if live_enabled and log_ports:
        passive_sample(f'{tcpvpn} ip saddr @allow4','TRUSTED')
        passive_sample(f'{tcpvpn} ip6 saddr @allow6','TRUSTED')
    lines.extend(['    ip saddr @allow4 accept','    ip6 saddr @allow6 accept'])
    if cfg.get('ssh_watch_enabled',False):
        lines.extend(['    ip saddr @sshtrust4 ip saddr != @ban4 accept','    ip6 saddr @sshtrust6 ip6 saddr != @ban6 accept'])
    # Manual bans take precedence. The static admin allowlist is above these rules;
    # an optional vpn-clients.txt entry is ONLY a GEO exception, never a bypass
    # for confirmed scanning / reputation rules.
    def guarded(prefix, reason):
        action = 'counter drop' if mode_drop else 'counter'
        if cfg.get('logging_enabled',True):lines.append(f'    {prefix} limit rate {int(cfg.get("log_rate_per_sec",3))}/second burst 6 packets log prefix "FWS {"D" if mode_drop else "O"}_{reason}: "')
        lines.append(f'    {prefix} {action}')
    if cfg.get('manual_bans_enabled',True):
        guarded('ip saddr @ban4','BAN4');guarded('ip6 saddr @ban6','BAN6')
    # vpn_clients geo bypass is appended AFTER scanner/ASN/watch verdicts.
    # Auto-ban verdicts only for non-service ports; no VPN ports and no known
    # protected VPN client addresses. Trusted addresses were accepted above.
    if cfg.get('autoban_enabled',False):
        for ver in (4,6):
            proto='ip' if ver==4 else 'ip6'
            base=f'{proto} saddr @auto{ver} {proto} saddr != @vpn{ver}'
            for transport,port_set in (('tcp','autosafetcp'),('udp','autosafeudp')):
                prefix=f'meta l4proto {transport} {transport} dport != @{port_set} {base}'
                guarded(prefix,f'AUTO{ver}')
    # A trap ban closes everything except the panel port, so an admin who walked
    # into a trap can still open the panel and lift it.
    if cfg.get('autoban_enabled',False) and (autoban.trap_ports(cfg) or cfg.get('ssh_watch_enabled',False)):
        origin=re.search(r':(\d{1,5})$',str(cfg.get('ui_public_origin','')))
        panel=int(origin.group(1)) if origin else 443
        if not 1<=panel<=65535:raise ValueError('Invalid panel port')
        for ver in (4,6):
            proto='ip' if ver==4 else 'ip6'
            guarded(f'meta l4proto {{ tcp, udp }} th dport != {panel} {proto} saddr @trap{ver} {proto} saddr != @vpn{ver}',f'AUTO{ver}')
    # Specific scanner and ASN verdicts run BEFORE broader watch feeds, so an
    # address in multiple sets gets the more specific reason and not yellow+red.
    # Opt-in global reputation DROP applies to ALL destination ports, VPN included.
    if cfg.get('scanner_enabled',True):
        guarded('ip saddr @scan4','SCAN4');guarded('ip saddr @scanhost4','SCAN4');guarded('ip6 saddr @scan6','SCAN6')
    if cfg.get('asn_enabled',True):
        guarded('ip saddr @asn4','ASN4');guarded('ip6 saddr @asn6','ASN6')
    if cfg.get('threat_watch_enabled',True):
        for v in (4,6):
            for prefix in ([f'ip saddr @watch4',f'ip saddr @watchhost4'] if v==4 else ['ip6 saddr @watch6']):
                if mode_drop and cfg.get('threat_watch_enforce',False):
                    guarded(prefix,f'WATCH{v}')
                else:
                    if cfg.get('logging_enabled',True):
                        lines.append(f'    {prefix} limit rate {int(cfg.get("log_rate_per_sec",3))}/second burst 6 packets log prefix "FWS O_WATCH{v}: "')
                    lines.append(f'    {prefix} counter')
    # Optional static VPN exceptions bypass ONLY geo filtering; never scanners
    # or reputation lists. Dynamic VPN IPs need not be registered anywhere.
    if vpn_ports:
        vp='{ '+', '.join(map(str,sorted(set(vpn_ports))))+' }'
        passive_sample(f'{tcpvpn} ip saddr @vpn4','VPN')
        passive_sample(f'{tcpvpn} ip6 saddr @vpn6','VPN')
        lines.extend([f'    meta l4proto {{ tcp, udp }} th dport {vp} ip saddr @vpn4 accept',
                      f'    meta l4proto {{ tcp, udp }} th dport {vp} ip6 saddr @vpn6 accept'])
    geo_mode=cfg.get('geo_mode','ru_only')
    if geo_mode not in ('ru_only','non_ru_only'):
        raise ValueError('geo_mode must be ru_only or non_ru_only')
    if cfg.get('geo_enabled',False) and ports:
        p='{ '+', '.join(map(str, sorted(set(ports))))+' }'
        mismatch='!=' if geo_mode=='ru_only' else ''
        guarded(f'meta l4proto {{ tcp, udp }} th dport {p} ip saddr {mismatch} @ru4'.replace('  ',' '),'GEO4')
        guarded(f'meta l4proto {{ tcp, udp }} th dport {p} ip6 saddr {mismatch} @ru6'.replace('  ',' '),'GEO6')
    # Sample only addresses not marked suspicious. In observe mode scanner/geo
    # counters cannot cause a later 'good' event for the same packet.
    if live_enabled and log_ports:
        for v in (4,6):
            proto='ip' if v==4 else 'ip6'
            cond=f'{tcpvpn}'
            if cfg.get('manual_bans_enabled',True):cond+=f' {proto} saddr != @ban{v}'
            if cfg.get('scanner_enabled',True):
                cond+=f' {proto} saddr != @scan{v}'
                if v==4:cond+=' ip saddr != @scanhost4'
            if cfg.get('asn_enabled',True):cond+=f' {proto} saddr != @asn{v}'
            if cfg.get('threat_watch_enabled',True):
                cond+=f' {proto} saddr != @watch{v}'
                if v==4:cond+=' ip saddr != @watchhost4'
            if cfg.get('geo_enabled',False):
                # Green samples must not be marked safe when they would match geo policy.
                cond+=f' {proto} saddr '+('@ru' if geo_mode=='ru_only' else '!= @ru')+str(v)
            passive_sample(cond,'PASS')
    # A bounded sample of new TCP SYNs to unknown ports. The Python observer
    # counts DISTINCT destination ports (6 a minute or 8 an hour); repeats never count twice.
    # An individual 443/8443 client cannot trigger this detector.
    if cfg.get('autoban_enabled',False) and cfg.get('logging_enabled',True):
        for ver in (4,6):
            proto='ip' if ver==4 else 'ip6'
            test=f'ct state new tcp flags syn tcp dport != @autosafetcp {proto} saddr != @vpn{ver} {proto} saddr != @auto{ver}'
            lines.append(f'    {test} limit rate 12/second burst 40 packets log prefix "FWS O_PROBE: "')
    lines+=['  }','  chain ssh_guard {','    type filter hook input priority -20; policy accept;',
             '    iifname "lo" accept',f'    iifname != {ifaces} accept',
             '    ct state established,related accept',
             '    ip saddr @allow4 accept','    ip6 saddr @allow6 accept']
    if cfg.get('ssh_watch_enabled',False):
        lines.extend(['    ip saddr @sshtrust4 ip saddr != @ban4 accept','    ip6 saddr @sshtrust6 ip6 saddr != @ban6 accept'])
    if cfg.get('threat_ssh_enabled',True) and ssh_safe:
        sp='{ '+', '.join(map(str,ssh_safe))+' }'
        bad_drop=mode_drop and cfg.get('threat_ssh_enforce',False)
        for v in (4,6):
            prefix=f'tcp dport {sp} ct state new {"ip" if v==4 else "ip6"} saddr @sshbad{v}'
            if cfg.get('logging_enabled',True):
                lines.append(f'    {prefix} limit rate 2/second burst 5 packets log prefix "FWS {"D" if bad_drop else "O"}_SSHREP{v}: "')
            lines.append(f'    {prefix} counter'+(' drop' if bad_drop else ''))
    if cfg.get('ssh_rate_enabled',True) and ssh_safe:
        p='{ '+', '.join(map(str, ssh_safe))+' }' 
        for v in (4,6):
            proto='ip' if v==4 else 'ip6'
            test=f'tcp dport {p} ct state new tcp flags syn meter fws_ssh{v} size 65535 {{ {proto} saddr timeout 5m limit rate over {rate}/minute burst {burst} packets }}'
            lines.append(f'    {test} jump ssh_excess')
    lines+=['  }','  chain ssh_excess {']
    if cfg.get('logging_enabled',True):
        lines.append(f'    limit rate 2/second burst 4 packets log prefix "FWS {"D" if mode_drop else "O"}_SSH: "')
    lines.append('    counter '+('drop' if mode_drop else 'return'))
    lines+=['  }','}']
    for name,key in (('scanhost4','scanners_hosts'),('watchhost4','threat_watch_hosts')):
        batch=[]
        for ip in sets.get(key,()):
            batch.append(str(ipaddress.IPv4Address(ip)))
            if len(batch)==20000:
                lines.append(f'add element inet {TABLE} {name} {{ '+', '.join(batch)+' }');batch=[]
        if batch:lines.append(f'add element inet {TABLE} {name} {{ '+', '.join(batch)+' }')
    return '\n'.join(lines)+'\n'



# WEB POLICY CONTROL -- exact fixed fields only; no shell syntax and no arbitrary command execution.
# Policy drafts never change kernel rules. Unconfirmed enforcement ALWAYS rolls back through systemd.
WEB_BOOL_FIELDS = (
    'manual_bans_enabled', 'scanner_enabled', 'asn_enabled', 'ssh_rate_enabled', 'threat_ssh_enabled',
    'threat_ssh_enforce', 'threat_watch_enabled', 'threat_watch_enforce', 'logging_enabled',
    'live_pass_logging_enabled', 'autoban_enabled', 'ssh_watch_enabled', 'extra_threat_feeds_enabled', 'advanced_feed_pack_enabled',
)
WEB_GEO_MODES=('off','ru_only','non_ru_only')
WEB_ROLLBACK_SECONDS=120
WEB_LOAD_SECONDS=900  # rollback safety net while rules are still loading


def ensure_no_pending():
    if any(ROOT.glob('.pending-*')):
        raise RuntimeError(tr('There are unconfirmed rules: confirm them or wait for automatic rollback','Есть неподтверждённые правила: подтвердите или дождитесь автоотката'))


def policy_from_web(current, selections):
    allowed=set(WEB_BOOL_FIELDS)|{'geo_choice','autoban_exclude_tcp_ports','autoban_exclude_udp_ports','autoban_trap_ports'}
    if not set(selections)<=allowed or not set(WEB_BOOL_FIELDS)|{'geo_choice'}<=set(selections):
        raise ValueError('Invalid policy controls')
    if selections['geo_choice'] not in WEB_GEO_MODES:
        raise ValueError('Invalid geographic mode')
    if any(selections[k] not in (True,False) for k in WEB_BOOL_FIELDS):
        raise ValueError('Invalid boolean policy control')
    cfg=dict(current)
    for key in WEB_BOOL_FIELDS:cfg[key]=selections[key]
    # Fixed 6/60/1440 trigger. Service-port exclusions may be edited in UI.
    for k in ('autoban_exclude_tcp_ports','autoban_exclude_udp_ports','autoban_trap_ports'):
        if k in selections:cfg[k]=selections[k]
    autoban.validate(cfg)
    cfg['geo_enabled']=selections['geo_choice']!='off'
    cfg['geo_mode']='ru_only' if selections['geo_choice']=='off' else selections['geo_choice']
    if cfg['threat_watch_enforce'] and not cfg['threat_watch_enabled']:
        raise ValueError(tr('Enable WATCH reputation lists first','Сначала включите репутационные списки WATCH'))
    if cfg['threat_ssh_enforce'] and not cfg['threat_ssh_enabled']:
        raise ValueError(tr('SSH reputation must be enabled before it can be blocked','SSH-репутацию нужно включить перед её блокировкой'))
    if cfg.get('autoban_enabled',False) and not cfg['logging_enabled']:
        raise ValueError(tr('AUTO-BAN requires kernel logging to be enabled','AUTO-BAN требует включённого журнала ядра'))
    if cfg['live_pass_logging_enabled'] and not cfg['logging_enabled']:
        raise ValueError(tr('Green radar requires logging to be enabled','Зелёный радар требует включённого журналирования'))
    return cfg


def policy_draft():
    file=ROOT/'web-policy-draft.json'
    if not file.exists():return None
    try:
        data=json.loads(file.read_text(encoding='utf-8'))
        if not isinstance(data,dict) or data.get('base_signature')!=policy_signature(config()):
            return None
        cfg=data['candidate']
        # Draft is treated as untrusted: accept only fixed, validated values.
        if not isinstance(cfg,dict):return None
        expected=dict(config())
        options={key:cfg[key] for key in WEB_BOOL_FIELDS}
        options['geo_choice']=('off' if not cfg['geo_enabled'] else cfg['geo_mode'])
        for key in ('autoban_exclude_tcp_ports','autoban_exclude_udp_ports','autoban_trap_ports'):
            if key in cfg:options[key]=cfg[key]
        if policy_from_web(expected,options)!=cfg:return None
        return data
    except (OSError,ValueError,KeyError,TypeError):return None


def web_stage(selections):
    fd=lock()
    try:
        ensure_no_pending()
        cfg=policy_from_web(config(),selections)
        # Check syntax without reconfiguring nft. Existing cached data must support the new choice.
        apply_step(5,tr('Step 1 of 2, checking: reading IP lists','Шаг 1 из 2, проверка: читаем IP-базы'))
        sets,issues,_=build_sets_from_sources(cfg,False)
        apply_step(25,tr('Step 1 of 2, checking: building rules','Шаг 1 из 2, проверка: собираем правила'))
        preview=render_rules(cfg,sets,enforce=True)
        apply_step(35,tr('Step 1 of 2, checking: nftables is checking rules','Шаг 1 из 2, проверка: nftables проверяет правила'))
        nft(preview,check_only=True)
        overlap=audit_vpn(cfg,sets)
        if any('manual' in labels for _,labels in overlap):
            raise RuntimeError(tr('Some VPN clients have manual bans: resolve the conflicts first','В списке VPN-клиентов есть ручные баны: сначала разберите конфликты'))
        data={'base_signature':policy_signature(config()),'candidate':cfg,
              'created':now(),'vpn_warnings':overlap[:40],'source_warnings':issues[:20]}
        atomic_write(ROOT/'web-policy-draft.json',json.dumps(data,indent=2,ensure_ascii=False))
        return data
    finally:os.close(fd)


def extras_status():
    """Read-only, bounded freshness and key-status check for the admin UI."""
    result={}
    src=sources().get('threat_watch',{})
    for name in EXTRA_THREAT_FEEDS:
        spec=src.get(name,{})
        cache_name='threat_watch_'+name
        try:
            entries=source_cache_if_fresh(cache_name,EXTRA_FEED_TTL_HOURS) if spec.get('enabled',False) else []
            count=len(entries)
        except (ValueError,OSError):count=0
        result[name]=count
    key=ROOT/'abuseipdb.key'
    try:
        import stat
        st=key.stat()
        key_ready=stat.S_ISREG(st.st_mode) and not (st.st_mode&0o077)
    except OSError:key_ready=False
    return {'key_ready':bool(key_ready),'sources':result,'ready':all(result.values())}


def install_abuse_key():
    """Prompt on the server terminal; never echo, log, or write into shell history."""
    import getpass
    if not os.isatty(0):raise ValueError(tr('This command requires an interactive SSH terminal','Команда требует интерактивный терминал SSH'))
    first=getpass.getpass((tr('New AbuseIPDB key (hidden):','Новый ключ AbuseIPDB (не отображается):')+' ')).strip()
    if not re.fullmatch(r'[A-Za-z0-9]{20,160}',first):raise ValueError(tr('Invalid key format','Некорректный формат ключа'))
    second=getpass.getpass((tr('Repeat key:','Повторить ключ:')+' ')).strip()
    if not hmac.compare_digest(first,second):raise ValueError(tr('Keys do not match','Ключи не совпадают'))
    atomic_write(ROOT/'abuseipdb.key',first+'\n',mode=0o600)
    print(tr('AbuseIPDB key saved with 0600 permissions. The value is not displayed.','Ключ AbuseIPDB сохранён: права 0600. Значение не выводится.'))


def prepare_extra_feeds():
    """Fetch only the four new sources. Never change config or live nftables."""
    fd=lock('.sync.lock')
    try:
        ensure_no_pending()
        cfg=config();catalog=sources().get('threat_watch',{})
        results={};warnings=[]
        for name in EXTRA_THREAT_FEEDS:
            spec=catalog.get(name,{})
            if not spec.get('enabled',False):
                warnings.append(name+(': '+tr('source is disabled in the catalog','источник выключен в каталоге')))
                results[name]=0
                continue
            fmt=spec.get('format','cidr')
            if fmt=='abuseipdb':
                transform=lambda data:parse_cidr(data,cfg['min_scanner_prefix_v4'],cfg['min_scanner_prefix_v6'])
                loader=lambda spec=spec:download_abuseipdb_blacklist(cfg,spec)
            elif fmt=='cidr':
                transform=lambda data:parse_cidr(data,cfg['min_scanner_prefix_v4'],cfg['min_scanner_prefix_v6'])
                loader=None
            else:
                warnings.append(name+(': '+tr('unsupported format','неподдерживаемый формат')))
                results[name]=0
                continue
            nets,status,issues=acquire_source('threat_watch_'+name,[spec['url']],transform,cfg,
                loader=loader,min_refresh_seconds=86400 if fmt=='abuseipdb' else 0,
                max_stale_hours=EXTRA_FEED_TTL_HOURS)
            warnings+=issues
            # Do not count stale cache as success.
            results[name]=len(source_cache_if_fresh('threat_watch_'+name,EXTRA_FEED_TTL_HOURS))
            print(f'{name}: {results[name]} {tr("entries (status","записей (статус")} {status})')
        for warning in warnings: print(tr('WARNING:','ПРЕДУПРЕЖДЕНИЕ:'),warning,file=sys.stderr)
        if not all(results.values()):
            raise RuntimeError(tr('Not all additional lists were loaded. Active protection was NOT changed; try again later.','Не все дополнительные базы загружены. Действующая защита НЕ изменена; повторите позже.'))
        print(tr('Four lists are ready. To apply DROP, enable enhanced protection in the web panel.','Четыре базы подготовлены. Чтобы применить DROP, активируйте усиленную защиту в веб-панели.'))
    finally:os.close(fd)


def validate_extra_feeds_ready(cfg):
    if cfg.get('extra_threat_feeds_enabled',False):
        report=extras_status()
        if not report['ready']:
            missing=[name for name,count in report['sources'].items() if not count]
            raise RuntimeError(tr('Additional lists are not ready (','Дополнительные базы не готовы (')+', '.join(missing)+('). '+tr('Run: sudo fw-sentinel feeds-prepare','Запустите: sudo fw-sentinel feeds-prepare')))


def lockout_reason(client, cfg, sets):
    """Why the admin who applies these rules could lose access; '' when they cannot."""
    try:address=ipaddress.ip_address(str(client or '').strip())
    except ValueError:return tr('could not determine your IP','не удалось определить ваш IP')
    if not address.is_global:return tr('could not determine your IP','не удалось определить ваш IP')
    if any(address in n for n in sets.get('trusted',[])):return ''
    checks=[('manual',cfg.get('manual_bans_enabled',True)),('scanners',cfg.get('scanner_enabled',True)),
            ('asn',cfg.get('asn_enabled',True)),
            ('threat_watch',cfg.get('threat_watch_enabled',True) and cfg.get('threat_watch_enforce',False)),
            ('threat_ssh',cfg.get('threat_ssh_enabled',True) and cfg.get('threat_ssh_enforce',False))]
    if any(on and matches_set(address,sets,name) for name,on in checks):
        return f'{tr("your IP","ваш IP")} {address} {tr("is on blocklists","есть в блокирующих списках")}'
    if cfg.get('geo_enabled',False):
        in_geo=any(address in n for n in sets.get('geo',[]))
        if in_geo == (cfg.get('geo_mode','ru_only')=='non_ru_only'):return f'{tr("your IP","ваш IP")} {address} {tr("is blocked by the geo filter","отсекает геофильтр")}'
    if cfg.get('autoban_enabled',False):
        with contextlib.closing(db()) as con:
            autoban.init_db(con);con.commit()
            if any(row[0]==str(address) for row in autoban.active_bans(con)):return f'{tr("your IP","ваш IP")} {address} {tr("is currently automatically banned","сейчас в автобане")}'
    return ''


def web_activate(client=None):
    fd=lock()
    token=uuid.uuid4().hex
    pending=ROOT/f'.pending-{token}'
    unit=f'fws-rollback-{token}'
    safety=unit+'-load'
    applied=False
    try:
        ensure_no_pending()
        draft=policy_draft()
        if draft is None:raise RuntimeError(tr('The draft is outdated. Save and check the settings again','Черновик устарел. Сохраните и проверьте настройки ещё раз'))
        cfg=draft['candidate']
        if not cfg.get('ssh_ports'):raise RuntimeError(tr('SSH ports are not set','Порты SSH не определены'))
        validate_extra_feeds_ready(cfg)
        apply_step(42,tr('Step 2 of 2, loading: reading IP lists','Шаг 2 из 2, загрузка: читаем IP-базы'))
        sets,issues,stats=build_sets_from_sources(cfg,False)
        if not sets.get('trusted'):
            raise RuntimeError(tr('No trusted administrator IP! Add one on the Access page','Нет доверенного IP администратора! Добавьте его на странице «Доступ»'))
        # Geo client exceptions only protect IPs in vpn-clients.txt; unknown users may be cut off.
        if cfg['geo_enabled'] and not sets['vpn_clients']:
            raise RuntimeError(tr('The geo filter cannot be enabled without vpn-clients.txt: protect user IPs first','Геофильтр нельзя включить без vpn-clients.txt: защитите IP пользователей сначала'))
        apply_step(60,tr('Step 2 of 2, loading: building rules','Шаг 2 из 2, загрузка: собираем правила'))
        new=render_rules(cfg,sets,enforce=True)
        apply_step(68,tr('Step 2 of 2, loading: nftables is checking rules','Шаг 2 из 2, загрузка: nftables проверяет правила'))
        nft(new,check_only=True)
        pending.mkdir(mode=0o700)
        old=ROOT/'active.nft'
        if old.exists():atomic_write(pending/'old.nft',old.read_text(encoding='utf-8'))
        atomic_write(pending/'old.state.json',json.dumps(state(),indent=2,ensure_ascii=False))
        atomic_write(pending/'old.config.json',json.dumps(config(),indent=2,ensure_ascii=False)+'\n')
        atomic_write(pending/'new.nft',new)
        atomic_write(pending/'new.config.json',json.dumps(cfg,indent=2,ensure_ascii=False)+'\n')
        def watchdog(name,seconds):
            p=run('systemd-run','--quiet','--collect','--unit='+name,
                  f'--on-active={seconds}s','/usr/local/sbin/fw-sentinel','rollback',token,
                  check=False)
            if p.returncode:raise RuntimeError((tr('Rollback timer unavailable:','Таймер отката недоступен:')+' ')+p.stderr)
        # Loading a large ruleset takes minutes and must not eat the confirmation
        # window: a long safety timer covers the load, the 120 s start after it.
        watchdog(safety,WEB_LOAD_SECONDS)
        applied=True
        apply_step(76,tr('Loading rules into the kernel','Загружаем правила в ядро'))
        nft(new)
        apply_step(95,tr('Checking that you will not lose access','Проверяем, что вы не потеряете доступ'))
        # Old temporary bans remain live only when both the old and staged
        # policies require enforcement. They never alter policy confirmation.
        if state().get('mode')=='enforce' and cfg.get('autoban_enabled',False):
            with db() as con:autoban.rearm(con,sys.modules[__name__],cfg)
        watchdog(unit,WEB_ROLLBACK_SECONDS)
        # A failed check only keeps the manual confirmation; it never breaks the apply.
        try:reason=lockout_reason(client,cfg,sets)
        except Exception as exc:reason=(tr('access check failed:','проверка доступа не удалась:')+' ')+type(exc).__name__
        deadline=int(time.time())+WEB_ROLLBACK_SECONDS
        # 'auto': the caller confirms at once, so the panel must not offer the buttons.
        atomic_write(pending/'web.json',json.dumps({'deadline':deadline,'created':now(),'auto':reason==''}))
        run('systemctl','stop',safety+'.timer',check=False)
        return {'token':token,'deadline':deadline,'vpn_warnings':draft['vpn_warnings'],'lockout':reason}
    except BaseException:
        if applied:
            with contextlib.suppress(Exception):rollback_locked(token)
        else:shutil.rmtree(pending,ignore_errors=True)
        # A surviving pending dir means rollback failed: the timer must still fire.
        if not pending.exists():
            for name in (unit,safety):run('systemctl','stop',name+'.timer',check=False)
        raise
    finally:os.close(fd)



# One-click UI apply: run expensive checks in an independent systemd service,
# keep the existing 120-second rollback protocol, and return HTTP immediately.
UI_APPLY_STATES=('queued','checking','activating','trial','error')


def _ui_job_file(token):
    if not re.fullmatch(r'[0-9a-f]{32}',token):
        raise ValueError(tr('Invalid apply ID','Некорректный идентификатор применения'))
    return ROOT/f'.ui-apply-{token}.json'


def _ui_job_read(token):
    path=_ui_job_file(token)
    data=json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data,dict) or data.get('status') not in UI_APPLY_STATES:
        raise ValueError(tr('Invalid job state','Неверное состояние задачи'))
    return data


def _ui_job_save(token,data):
    atomic_write(_ui_job_file(token),json.dumps(data,ensure_ascii=False,indent=2)+'\n')


def ui_apply_status(token):
    """Safe-to-publish status for an already authenticated admin; no settings/secrets."""
    data=_ui_job_read(token)
    result={key:data.get(key) for key in ('status','message','deadline','error','percent') if key in data}
    if data.get('created_unix'):result['elapsed']=max(0,int(time.time()-float(data['created_unix'])))
    if result['status']=='trial' and not any(ROOT.glob('.pending-'+str(data.get('trial_token','')))):
        result['status']='finished'
        result['message']=tr('Trial mode has ended; check the active policy','Пробный режим завершён; проверьте действующую политику')
    return result



def ui_apply_current():
    """Recover a running UI job after browser reload without exposing job settings."""
    candidates=sorted(ROOT.glob('.ui-apply-*.json'),key=lambda x:x.stat().st_mtime,reverse=True)
    for p in candidates[:10]:
        try:
            token=p.name[len('.ui-apply-'):-len('.json')]
            data=_ui_job_read(token)
            if data['status'] in ('queued','checking','activating') and \
                    time.time()-float(data.get('created_unix',0))<900:
                return token
        except (ValueError,TypeError,OSError,KeyError):continue
    return None


def ui_apply_start(selections, client=None):
    """Enqueue a safe policy trial; never calculate large nft sets on the HTTP thread."""
    fd=lock()
    token=uuid.uuid4().hex
    try:
        ensure_no_pending()
        # Cheap structural validation and copy of the exact submitted settings.
        policy_from_web(config(),selections)
        if not line_networks(ROOT/'allow.txt'):
            raise RuntimeError(tr('Before changing rules, add a trusted SSH IP to the access list','Перед изменением правил укажите доверенный SSH-IP в списке доступа'))
        for candidate in ROOT.glob('.ui-apply-*.json'):
            try:
                job=json.loads(candidate.read_text(encoding='utf-8'))
                if job.get('status') in ('queued','checking','activating'):
                    created=float(job.get('created_unix',0))
                    if time.time()-created<900:
                        raise RuntimeError(tr('A check is already in progress — wait for the result','Проверка уже идёт — дождитесь её результата'))
            except (OSError,ValueError,TypeError):pass
        job={'status':'queued','message':tr('Waiting for the check to start','Ожидаем запуска проверки'),
             'created_unix':time.time(),'base_signature':policy_signature(config()),
             'selections':selections,'client':client}
        _ui_job_save(token,job)
        unit='fw-sentinel-apply-'+token
        try:
            result=run('systemd-run','--quiet','--collect','--unit='+unit,
                       '/usr/local/sbin/fw-sentinel','ui-apply-worker',token,
                       timeout=12,check=False)
            if result.returncode:
                raise RuntimeError((tr('Could not start the check:','Не удалось запустить проверку:')+' ')+(result.stderr or '').strip()[:160])
        except (OSError,subprocess.TimeoutExpired,RuntimeError):
            _ui_job_file(token).unlink(missing_ok=True)
            raise
        return token
    finally:os.close(fd)


def ui_apply_worker(token):
    """Standalone subprocess job; does NOT run in the HTTP server process."""
    job=_ui_job_read(token)
    if job['status']!='queued':raise RuntimeError(tr('The job has already been started','Задача уже была запущена'))
    def publish(status,message,**extra):
        job.update(status=status,message=message,**extra)
        _ui_job_save(token,job)
    global PROGRESS
    # The status stays what the phase set; only the percentage and the text move.
    PROGRESS=lambda percent,text:publish(job['status'],text,percent=percent)
    try:
        if job.get('base_signature')!=policy_signature(config()):
            raise RuntimeError(tr('Settings have changed since you clicked the button. Apply them again.','Настройки изменились с момента нажатия кнопки. Повторите применение.'))
        publish('checking',tr('Checking IP lists and nftables rules','Проверяем IP-базы и правила nftables'))
        web_stage(job['selections'])
        publish('activating',tr('Check passed; loading rules','Проверка пройдена; загружаем правила'))
        trial=web_activate(job.get('client'))
        if trial.get('lockout')=='':
            publish('activating',tr('Rules loaded, saving','Правила загружены, сохраняем'),percent=97)
            web_confirm(trial['token'])
            message=tr('Rules applied and saved','Правила применены и сохранены')
        else:message=f'{tr("Confirm within 120 seconds:","Подтвердите за 120 секунд:")} {trial.get("lockout") or tr("check access","проверьте доступ")}'
        publish('trial',message,trial_token=trial['token'],deadline=trial['deadline'])
    except Exception as exc:
        # A failed check must not touch confirmed rules. web_activate performs
        # its own rollback if an activation step failed.
        PROGRESS=None  # a rollback reload must not overwrite the error
        publish('error',tr('Rules were NOT applied','Правила НЕ применены'),error=(type(exc).__name__+': '+str(exc))[:360])
        raise
    finally:PROGRESS=None


def web_quick_shield(client=None):
    """Stage + provisionally activate aggressive policy with independent rollback.

    No source-IP allowlisting of dynamic VPN clients. The operator explicitly
    accepts blocking source addresses in scanner/WATCH sets even on VPN ports.
    Only static trusted ADMIN addresses bypass these verdicts. Auto-ban based
    on port sweep still excludes VPN and service ports by destination.
    """
    if not line_networks(ROOT/'allow.txt'):
        raise RuntimeError(tr('Add your static SSH IP to the trusted list before enabling protection','Добавьте свой статичный SSH-IP в белый список перед включением защиты'))
    cfg=config()
    selections={key:bool(cfg.get(key,False)) for key in WEB_BOOL_FIELDS}
    selections.update({
        'manual_bans_enabled':True,
        'scanner_enabled':True,
        'asn_enabled':False,
        'ssh_rate_enabled':True,
        'threat_ssh_enabled':True,
        'threat_ssh_enforce':True,
        'threat_watch_enabled':True,
        'threat_watch_enforce':True,
        'logging_enabled':True,
        'live_pass_logging_enabled':True,
        'autoban_enabled':True,
        'extra_threat_feeds_enabled':True,
        'geo_choice':'off',
        'autoban_exclude_tcp_ports':cfg.get('autoban_exclude_tcp_ports',list(autoban.PORT_DEFAULT_TCP)),
        'autoban_exclude_udp_ports':cfg.get('autoban_exclude_udp_ports',list(autoban.PORT_DEFAULT_UDP)),
    })
    web_stage(selections)  # cached source validation + nft -c; no kernel changes
    trial=web_activate(client) # 120-second independent systemd rollback
    if trial.get('lockout')=='':
        web_confirm(trial['token']);trial['confirmed']=True
    return trial


def web_abort(token):
    """Explicitly cancel the temporary policy and restore previous confirmed state."""
    if not re.fullmatch(r'[a-f0-9]{32}',token):raise ValueError(tr('Invalid cancellation code','Некорректный код отмены'))
    fd=lock()
    try:
        pending=ROOT/f'.pending-{token}'
        if not (pending/'web.json').is_file():raise RuntimeError(tr('Trial mode has already ended','Пробный режим уже завершён'))
        rollback_locked(token)
    finally:os.close(fd)
    run('systemctl','stop','fws-rollback-'+token+'.timer',check=False)
    return True


def boot_id():
    try:return Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    except OSError:return ''


def persistence_report():
    """READ ONLY readiness check. Does not reload nft, reboot, or change any policy.

    Validation is not proof of recovery on a *future* boot. A real recovery is
    separately recorded by restore() together with the kernel boot ID.
    """
    st=state();cfg=config();mode=st.get('mode','off')
    checks=[]
    def add(name,ok,description):
        checks.append({'name':name,'ok':bool(ok),'description':description})
    pending=list(ROOT.glob('.pending-*'))
    add(tr('Confirmation','Подтверждение'),not pending,
        tr('A 120-second check is pending','Есть незавершённая 120-секундная проверка') if pending else tr('No unconfirmed rules','Неподтверждённых правил нет'))
    add(tr('Filtering mode','Режим фильтрации'),mode=='enforce',f'{tr("Saved mode:","Сохранённый режим:")} {mode}')
    snapshot=ROOT/'active.nft'
    exists=snapshot.is_file() and bool(snapshot.stat().st_size)
    add(tr('Rules snapshot','Снимок правил'),exists,tr('active.nft saved','active.nft сохранён') if exists else tr('No confirmed rules file','Нет файла подтверждённых правил'))
    add(tr('Configuration','Конфигурация'),st.get('policy_signature')==policy_signature(cfg),
        tr('Signature matches','Подпись совпадает') if st.get('policy_signature')==policy_signature(cfg) else
        tr('Signature does not match: settings or source catalog changed','Подпись не совпадает: настройки или каталог источников изменены'))
    if exists:
        try:nft(snapshot.read_text(encoding='utf-8'),check_only=True);checked=True;detail='nft -c: OK'
        except (RuntimeError,OSError,subprocess.TimeoutExpired) as err:checked=False;detail='nft -c: '+str(err)[:240]
    else:checked=False;detail=tr('Snapshot not found','Не найден снимок')
    add(tr('nft -c check','Проверка nft -c'),checked,detail)
    for unit,kind in [('fw-sentinel-restore.service','is-enabled'),
                      ('fw-sentinel-guard.timer','is-enabled'),
                      ('fw-sentinel-guard.timer','is-active')]:
        try:
            result=run('systemctl',kind,unit,check=False,timeout=8)
            ok=result.returncode==0
            value=(result.stdout or result.stderr).strip()[:80]
        except (OSError,subprocess.TimeoutExpired) as err:ok=False;value=type(err).__name__
        add(unit+' '+kind,ok,value)
    try:
        result=run('nft','-t','list','table','inet',TABLE,check=False,timeout=8)
        table_ok=result.returncode==0
        if table_ok:
            table_ok=all(run('nft','list','chain','inet',TABLE,chain,check=False,timeout=8).returncode==0
                         for chain in ('ingress','ssh_guard','ssh_excess'))
    except (OSError,subprocess.TimeoutExpired):table_ok=False
    add(tr('Table and chains in the kernel','Таблица и цепочки в ядре'),table_ok,
        tr('Table and 3 required chains are present','Таблица и 3 обязательные цепочки присутствуют') if table_ok else
        tr('Table is missing or damaged: check guard','Таблица отсутствует или повреждена: проверьте guard'))
    try:
        last=json.loads((ROOT/'last-restore.json').read_text(encoding='utf-8'))
        confirmed_this_boot=(last.get('boot_id')==boot_id() and last.get('mode')=='enforce'
                             and table_ok)
        restored_at=str(last.get('timestamp') or '') if confirmed_this_boot else ''
    except (OSError,ValueError,TypeError,AttributeError):
        confirmed_this_boot=False;restored_at=''
    return {'mode':mode,'ready':all(c['ok'] for c in checks),
            'checks':checks,'restored_this_boot':confirmed_this_boot,
            'last_restored_at':restored_at}


def web_confirm(token):
    if not re.fullmatch(r'[a-f0-9]{32}',token):raise ValueError(tr('Invalid confirmation code','Некорректный код подтверждения'))
    fd=lock();unit='fws-rollback-'+token
    try:
        pending=ROOT/f'.pending-{token}'
        marker=pending/'web.json'
        if not marker.is_file():raise RuntimeError(tr('No change awaiting confirmation','Нет ожидающего подтверждения изменения'))
        meta=json.loads(marker.read_text())
        if time.time()>meta['deadline']:
            rollback_locked(token)
            raise RuntimeError(tr('Confirmation timed out: the previous policy was restored','Время подтверждения истекло: прежняя политика восстановлена'))
        newcfg=(pending/'new.config.json').read_text(encoding='utf-8')
        new=(pending/'new.nft').read_text(encoding='utf-8')
        try:
            if run('nft','-t','list','table','inet',TABLE,check=False).returncode or any(
                run('nft','list','chain','inet',TABLE,chain,check=False).returncode
                for chain in ('ingress','ssh_guard','ssh_excess')):
                raise RuntimeError(tr('The nftables table or a required chain disappeared during the check; confirmation is not allowed','Таблица или обязательная цепочка nftables пропала во время проверки; подтверждение запрещено'))
            nft(new,check_only=True)
            atomic_write(ROOT/'config.json',newcfg)
            atomic_write(ROOT/'active.nft',new)
            set_state('enforce')
            autoban.rearm_for_rules(sys.modules[__name__],config(),'enforce')
            shutil.rmtree(pending)
            (ROOT/'web-policy-draft.json').unlink(missing_ok=True)
        except Exception:
            rollback_locked(token)
            raise
    finally:os.close(fd)
    run('systemctl','stop',unit+'.timer',check=False)
    return True


def web_mode(action):
    # START = passive observe, PAUSE = turn drops off but keep observer, STOP = remove only our table.
    if action in ('start','pause'):
        observe()
    elif action=='stop':
        disable()
    else:raise ValueError('Unknown control mode')

def state():
    path=ROOT/'state.json'
    if not path.exists():return {'mode':'off','updated':None,'issues':[]}
    return json.loads(path.read_text(encoding='utf-8'))


def policy_signature(cfg):
    # A config change MUST go through observe + confirmed enable, not a silent nightly sync.
    policy_keys=('wan_interfaces','ssh_ports','geo_enabled','geo_mode','geo_ports','vpn_ports','geo_tag',
                 'manual_bans_enabled','scanner_enabled','asn_enabled','logging_enabled','log_rate_per_sec',
                 'ssh_rate_enabled','ssh_rate_per_minute','ssh_rate_burst',
                 'threat_ssh_enabled','threat_watch_enabled','threat_ssh_enforce',
                 'live_pass_logging_enabled','live_pass_log_rate_per_sec')
    payload={name:cfg.get(name) for name in policy_keys}
    # Watch enforcement is opt-in; preserve previous signatures when disabled.
    if cfg.get('threat_watch_enforce',False):
        payload['threat_watch_enforce']=True
    # Keep signatures for previous confirmed policies stable when auto-ban is OFF.
    # Enabling it changes the signature and requires staged, confirmed activation.
    if cfg.get('extra_threat_feeds_enabled',False):
        payload['extra_threat_feeds_enabled']=True
    if cfg.get('advanced_feed_pack_enabled',False):
        payload['advanced_feed_pack_enabled']=True
    if cfg.get('ssh_watch_enabled',False):payload['ssh_watch_enabled']=True
    if cfg.get('autoban_enabled',False):
        payload['autoban']={'enabled':True,
            'tcp':cfg.get('autoban_exclude_tcp_ports',list(autoban.PORT_DEFAULT_TCP)),
            'udp':cfg.get('autoban_exclude_udp_ports',list(autoban.PORT_DEFAULT_UDP))}
        if cfg.get('autoban_trap_ports'):payload['autoban']['trap']=cfg['autoban_trap_ports']
    # Source changes that can affect active rules require approval, but a release
    # can add NEW DISABLED feeds without invalidating the existing confirmed
    # policy, stopping the monitor, or silently changing the live nft table.
    catalog=sources()
    for kind in ('threat_ssh','threat_watch'):
        if kind in catalog:
            catalog[kind]={name:spec for name,spec in catalog[kind].items()
                           if spec.get('enabled',True) and
                           (name not in EXTRA_THREAT_FEEDS or cfg.get('extra_threat_feeds_enabled',False))}
    if not cfg.get('advanced_feed_pack_enabled',False):
        catalog.pop('advanced_feeds',None)
    payload['source_catalog']=catalog
    return hashlib.sha256(json.dumps(payload,sort_keys=True).encode()).hexdigest()


def set_state(mode,issues=None,meta=None):
    s={'mode':mode,'updated':now(),'issues':issues or [],'feeds':meta or {},
       'policy_signature':policy_signature(config())}
    atomic_write(ROOT/'state.json',json.dumps(s,ensure_ascii=False,indent=2))


def snapshot_valid():return (ROOT/'active.nft').exists()


def apply_rules(batch, mode):
    nft(batch,check_only=True)
    try:nft(batch)
    except BaseException:
        previous=ROOT/'active.nft'
        if previous.exists():
            with contextlib.suppress(Exception):
                nft(previous.read_text(encoding='utf-8'))
                autoban.rearm_for_rules(sys.modules[__name__],config(),state().get('mode','off'))
        raise
    # Dynamic bans are rebuilt with their REMAINING TTL; never grant a fresh day.
    autoban.rearm_for_rules(sys.modules[__name__],config(),mode)
    atomic_write(ROOT/'active.nft',batch)


def policy_inputs():
    return [(ROOT/n).read_text(encoding='utf-8') if (ROOT/n).exists() else None
            for n in ('config.json','sources.json','asn.txt')]


def refresh(reload=True):
    # Downloads hold only the sync lock: the panel, autoban and guard keep working.
    sync_fd=lock('.sync.lock');fd=None
    try:
        ensure_no_pending()
        before=policy_inputs()
        cfg=config();sets,issues,stats=build_sets_from_sources(cfg,True)
        fd=lock()
        ensure_no_pending()
        if policy_inputs()!=before:
            raise RuntimeError('Settings changed during download: run fw-sentinel sync again')
        sets.update(local_sets())  # bans/allows may have changed meanwhile
        status=state();current=status.get('mode','off')
        if reload and current in ('observe','enforce'):
            if status.get('policy_signature') != policy_signature(cfg):
                raise RuntimeError('Policy settings changed: use fw-sentinel observe, inspect, then fw-sentinel enable for confirmed activation')
            batch=render_rules(cfg,sets,enforce=current=='enforce')
            apply_rules(batch,current)
        set_state(current,issues,stats)
        print(f'Sync OK. Sources: {len(stats)}; warnings: {len(issues)}; mode: {current}')
        for issue in issues: print('WARN:',issue)
    finally:
        if fd is not None:os.close(fd)
        os.close(sync_fd)


def observe():
    fd=lock()
    try:
        ensure_no_pending()
        cfg=config(); sets,issues,stats=build_sets_from_sources(cfg,False)
        batch=render_rules(cfg,sets,enforce=False)
        apply_rules(batch,'observe');set_state('observe',issues,stats)
        print('OBSERVE: no packets dropped by FW Sentinel. Monitoring enabled.')
    finally:os.close(fd)


def detect_ssh_ports():
    """Ports SSH really accepts on; empty when unknown. Ubuntu's ssh.socket overrides sshd_config."""
    ports=set()
    try:
        out=run('systemctl','show','ssh.socket','-p','ActiveState','-p','Listen',check=False).stdout
        if 'ActiveState=active' in out:
            ports={int(p) for p in re.findall(r'^Listen=.*:(\d+) \(Stream\)$',out,re.M)}
        if not ports:
            out=run('sshd','-T',check=False).stdout
            ports={int(p) for p in re.findall(r'^port (\d+)$',out,re.M)}
    except Exception:ports=set()  # advisory only: it must never break the panel or the installer
    session=os.environ.get('SSH_CONNECTION','').split()
    if len(session)==4 and session[3].isdecimal():ports.add(int(session[3]))
    return sorted(p for p in ports if 0<p<65536)


def bulk_warning():
    path=ROOT/'bulk-skipped'
    if not path.is_file():return ''
    return ((f'{tr("Not enough free memory: large lists (","Не хватило свободной памяти: большие списки (")}{path.read_text().strip()} {tr("addresses) were not loaded.","адресов) не загружены.")} '
            ''+tr('The rest of the protection is working.','Остальная защита работает.')))


def ssh_port_warning(cfg):
    configured=cfg.get('ssh_ports',[])
    missing=sorted(set(detect_ssh_ports())-set(configured))
    if not missing:return ''
    return ((f'{tr("SSH listens on port","SSH принимает порт")} {", ".join(map(str,missing))}, {tr("but ssh_ports is set to","а в настройках ssh_ports =")} {configured}: '
            ''+tr('SSH protection is targeting the wrong ports. Fix ssh_ports in /opt/fw-sentinel/config.json','защита SSH смотрит не туда. Исправьте ssh_ports в /opt/fw-sentinel/config.json')+' '
            ''+tr('and enable protection again.','и включите защиту заново.')))


def ssh_client():
    raw=os.environ.get('SSH_CONNECTION','').split()
    if not raw:return None
    try:return ipaddress.ip_address(raw[0])
    except ValueError:return None


def enforce():
    fd=lock()
    token=uuid.uuid4().hex
    pending=ROOT/f'.pending-{token}'
    unit=f'fws-rollback-{token}'
    applied=False
    safety=unit+'-load'
    try:
        ensure_no_pending()
        cfg=config(); sets,issues,stats=build_sets_from_sources(cfg,False)
        if not sets['trusted']: raise RuntimeError('No trusted admin IPs. Add at least one via fw-sentinel allow IP.')
        client=ssh_client()
        if client and not any(client in n for n in sets['trusted']):
            raise RuntimeError(f'Current SSH IP {client} is not on allowlist. Add it first.')
        if not cfg.get('ssh_ports'):raise RuntimeError('Configure real SSH port(s) first')
        print_vpn_audit(cfg,sets)
        # Geographic restriction is opt-in and has to be enabled consciously in config.json.
        new=render_rules(cfg,sets,enforce=True)
        nft(new,check_only=True)
        pending.mkdir(mode=0o700)
        old=ROOT/'active.nft'
        if old.exists(): atomic_write(pending/'old.nft',old.read_text(encoding='utf-8'))
        atomic_write(pending/'old.state.json',json.dumps(state(),ensure_ascii=False))
        # systemd timer executes even if SSH disconnects; refuse to apply if it cannot start.
        p=run('systemd-run','--quiet','--collect','--unit='+safety,f'--on-active={WEB_LOAD_SECONDS}s',
              '/usr/local/sbin/fw-sentinel','rollback',token,check=False)
        if p.returncode: raise RuntimeError('rollback watchdog unavailable: '+p.stderr)
        applied=True
        nft(new)
        p=run('systemd-run','--quiet','--collect','--unit='+unit,'--on-active=120s',
              '/usr/local/sbin/fw-sentinel','rollback',token,check=False)
        if p.returncode:raise RuntimeError('rollback watchdog unavailable: '+p.stderr)
        print(tr('ENFORCE temporarily enabled. Type exactly: YES','ENFORCE temporarily enabled. Type exactly: да'),flush=True)
        print('You have 90 seconds. If SSH drops, systemd will restore previous rules.',flush=True)
        import select
        ready,_,_=select.select([sys.stdin],[],[],90)
        value=sys.stdin.readline().strip() if ready else ''
        if value!=tr('YES','да'):
            rollback_locked(token)
            print('Not confirmed: previous rules restored.')
            return
        atomic_write(ROOT/'active.nft',new)
        set_state('enforce',issues,stats)
        autoban.rearm_for_rules(sys.modules[__name__],config(),'enforce')
        shutil.rmtree(pending,ignore_errors=True)
        print('ENFORCE confirmed; snapshot saved.')
    except BaseException:  # Ctrl+C included
        if applied:
            with contextlib.suppress(Exception):rollback_locked(token)
        else:shutil.rmtree(pending,ignore_errors=True)
        raise
    finally:
        # A surviving pending dir means rollback failed: the timer must still fire.
        if not pending.exists():
            for name in (unit,safety):run('systemctl','stop',name+'.timer',check=False)
        os.close(fd)


def rollback_locked(token):
    pending=ROOT/f'.pending-{token}'
    if not pending.is_dir():return
    old=pending/'old.nft'
    if old.exists():
        batch=old.read_text(encoding='utf-8'); nft(batch)
        atomic_write(ROOT/'active.nft',batch)
    else:
        p=run('nft','delete','table',FAMILY,TABLE,check=False)
        if p.returncode and 'No such file' not in p.stderr:raise RuntimeError(p.stderr)
        (ROOT/'active.nft').unlink(missing_ok=True)
    previous=json.loads((pending/'old.state.json').read_text(encoding='utf-8'))
    oldcfg=pending/'old.config.json'
    if oldcfg.exists():atomic_write(ROOT/'config.json',oldcfg.read_text(encoding='utf-8'))
    atomic_write(ROOT/'state.json',json.dumps(previous,ensure_ascii=False,indent=2))
    shutil.rmtree(pending)
    if previous.get('mode')=='enforce':
        autoban.rearm_for_rules(sys.modules[__name__],config(),'enforce')


def rollback(token):
    if not re.fullmatch(r'[0-9a-f]{32}',token):raise ValueError('invalid token')
    fd=lock()
    try: rollback_locked(token);print('Rollback handled:',token)
    finally:os.close(fd)


def disable():
    fd=lock()
    try:
        ensure_no_pending()
        p=run('nft','delete','table',FAMILY,TABLE,check=False)
        if p.returncode and 'No such file' not in p.stderr:raise RuntimeError(p.stderr)
        (ROOT/'active.nft').unlink(missing_ok=True)
        set_state('off');print('FW Sentinel rules OFF (other firewalls remain unchanged).')
    finally:os.close(fd)


def guard():
    """Re-arm only a confirmed active policy if another service flushed our nft table.
    Never changes a policy in progress or enables anything when state is off.
    """
    fd=lock()
    try:
        mode=state().get('mode','off')
        if mode not in ('observe','enforce') or not snapshot_valid():return
        if any(ROOT.glob('.pending-*')):return
        intact=run('nft','-t','list','table','inet',TABLE,check=False).returncode==0
        if intact:
            intact=all(run('nft','list','chain','inet',TABLE,name,check=False).returncode==0
                       for name in ('ingress','ssh_guard','ssh_excess'))
        if intact:return
        snapshot=(ROOT/'active.nft').read_text(encoding='utf-8')
        nft(snapshot,check_only=True)
        nft(snapshot)
        autoban.rearm_for_rules(sys.modules[__name__],config(),mode)
        print(f'Guard: restored missing inet {TABLE} ({mode}).')
    finally:os.close(fd)


def restore():
    fd=lock()
    try:
        # Unconfirmed changes must never reappear after restart.
        for pending in ROOT.glob('.pending-*'):
            if re.fullmatch(r'\.pending-[0-9a-f]{32}',pending.name):rollback_locked(pending.name[9:])
        if snapshot_valid():
            batch=(ROOT/'active.nft').read_text(encoding='utf-8')
            nft(batch,check_only=True);nft(batch)
            current_mode=state().get('mode','off')
            autoban.rearm_for_rules(sys.modules[__name__],config(),current_mode)
            atomic_write(ROOT/'last-restore.json',json.dumps({
                'timestamp':now(),'mode':current_mode,'boot_id':boot_id(),
                'snapshot_sha256':hashlib.sha256(batch.encode('utf-8')).hexdigest()
            },ensure_ascii=False))
            print('Last confirmed policy restored.')
        else:print('No confirmed policy; no firewall changes.')
    finally:os.close(fd)


def matches_set(address,sets,name):
    return ((address.version==4 and int(address) in sets.get(name+'_hosts',()))
            or any(address in n for n in sets.get(name,[])))


def audit_vpn(cfg,sets):
    """Only configured/known clients: discovered connections cannot be identified as VPN users reliably."""
    results=[]
    for network in sets.get('vpn_clients',[]):
        address=network.network_address
        matched=[name for name in ('manual','scanners','asn','threat_ssh','threat_watch')
                 if matches_set(address,sets,name)]
        in_ru=any(address in n for n in sets.get('geo',[]))
        if cfg.get('geo_enabled',False) and (in_ru if cfg.get('geo_mode','ru_only')=='non_ru_only' else not in_ru):
            matched.append('blocked RU by geofilter' if cfg.get('geo_mode','ru_only')=='non_ru_only' else 'outside RU geofilter')
        if matched:results.append((str(address),matched))
    return results


def print_vpn_audit(cfg,sets):
    overlap=audit_vpn(cfg,sets)
    if not sets.get('vpn_clients'):
        print('VPN client list is empty: unknown client IPs may match external lists; observe real traffic before enabling.')
    for ip,labels in overlap[:35]:
        print('VPN CLIENT MATCH:',ip,','.join(labels),'(manual ban overrides exemption)' if 'manual' in labels else '(VPN-only exemption)')
    if len(overlap)>35:print('... additional matches:',len(overlap)-35)
    return overlap


def change_entry(kind,ip,add=True):
    """Atomic-ish single-IP policy change; keep persisted snapshot synchronized."""
    address=ipaddress.ip_address(ip)
    if not address.is_global:raise ValueError('Only global unicast IPs are accepted')
    fd=lock()
    try:
        ensure_no_pending()
        if kind not in ('ban','allow','vpn'):raise ValueError('invalid list type')
        file=ROOT/('manual-bans.txt' if kind=='ban' else 'allow.txt' if kind=='allow' else 'vpn-clients.txt')
        old_text=file.read_text(encoding='utf-8-sig') if file.exists() else ''
        others=line_networks(file)
        if kind=='vpn' and add and any(address in n for n in line_networks(ROOT/'manual-bans.txt',addresses_only=True)):
            raise ValueError('This IP is manually banned; unban explicitly before adding a VPN exception')
        if kind=='ban' and add and any(address in n for n in line_networks(ROOT/'vpn-clients.txt',addresses_only=True)):
            raise ValueError('Cannot manually ban a protected VPN client IP; remove VPN exception explicitly first')
        if kind=='ban' and add and any(address in n for n in line_networks(ROOT/'allow.txt')):
            raise ValueError('Cannot ban trusted administrator IP')
        if kind=='allow' and not add and len(others)<2:
            raise ValueError('Cannot remove the last trusted IP')
        single=ipaddress.ip_network(str(address))
        if add:
            if any(address in n for n in others):return False
            content=old_text+'\n'*(not old_text.endswith('\n'))+str(address)+'  # '+now()+'\n'
            changed=others+[single]
        else:
            if single not in others:return False
            def other(line):
                value=line.partition('#')[0].strip()
                return not value or ipaddress.ip_network(value,strict=False)!=single
            content='\n'.join(filter(other,old_text.splitlines()))+'\n'
            changed=[n for n in others if n!=single]
        mode=state().get('mode','off')
        active=mode in ('observe','enforce')
        new_snapshot=None
        original_snapshot=(ROOT/'active.nft').read_text(encoding='utf-8') if snapshot_valid() else None
        if active:
            cfg=config()
            if state().get('policy_signature') != policy_signature(cfg):
                raise RuntimeError('Policy settings changed; observe/enable before editing active lists')
            sets,_,_=build_sets_from_sources(cfg,False)
            sets['manual' if kind=='ban' else 'trusted' if kind=='allow' else 'vpn_clients']=changed
            new_snapshot=render_rules(cfg,sets,mode=='enforce')
            nft(new_snapshot,check_only=True)
            name=('ban' if kind=='ban' else 'allow' if kind=='allow' else 'vpn')+str(address.version)
            verb='add' if add else 'delete'
            nft(f'{verb} element inet {TABLE} {name} {{ {address} }}\n')
        try:
            atomic_write(file,content)
            if new_snapshot is not None:atomic_write(ROOT/'active.nft',new_snapshot)
            if kind=='ban' and add:
                if active and cfg.get('ssh_watch_enabled',False):
                    result=run('nft','delete','element','inet',TABLE,'sshtrust'+str(address.version),'{',str(address),'}',check=False)
                    if result.returncode and 'No such file' not in result.stderr and 'No such element' not in result.stderr:raise RuntimeError(result.stderr)
                con=db()
                try:
                    autoban.init_db(con)
                    con.execute('DELETE FROM ssh_trust WHERE ip=?',(str(address),))
                    con.commit()
                finally:con.close()
        except (OSError,ValueError,RuntimeError,sqlite3.Error):
            if active:
                if original_snapshot is not None:
                    with contextlib.suppress(Exception):nft(original_snapshot)
                    with contextlib.suppress(Exception):atomic_write(ROOT/'active.nft',original_snapshot)
            with contextlib.suppress(Exception):atomic_write(file,old_text)
            raise
        return True
    finally:os.close(fd)



def change_entries_bulk(kind, raw):
    """Import a bounded batch of individual public IPs; ignore duplicates.

    An active nft policy is updated in one nft batch, rather than one command per
    IP. Refuse conflicting entries without silently changing the opposite list.
    """
    if kind not in ('ban','allow'):
        raise ValueError(tr('Only trusted and block lists are supported','Поддерживается только белый и чёрный список'))
    if not isinstance(raw,str) or not raw.strip() or len(raw)>120000:
        raise ValueError(tr('Paste an IP list of up to 120 000 characters','Вставьте список IP длиной до 120 000 символов'))
    lines=[line.partition('#')[0] for line in raw.splitlines()]
    tokens=[a for a in re.split(r'[\s,;]+','\n'.join(lines)) if a]
    if len(tokens)>1200:
        raise ValueError(tr('A maximum of 1200 addresses is allowed at a time','За один раз допускается не более 1200 адресов'))
    invalid=[];parsed=[];seen=set();repeated=0
    for token in tokens:
        try:
            try:ip=ipaddress.ip_address(token)
            except ValueError:
                # Accept single-host CIDR syntax, not a whole subnet.
                net=ipaddress.ip_network(token,strict=True)
                if net.prefixlen!=net.max_prefixlen:raise ValueError('Subnet not allowed')
                ip=net.network_address
            if not ip.is_global:raise ValueError('IP not globally routable')
        except ValueError:
            invalid.append(token[:72]);continue
        canonical=str(ip)
        if canonical in seen:
            repeated+=1;continue
        seen.add(canonical);parsed.append(ip)
    fd=lock()
    try:
        ensure_no_pending()
        file=ROOT/('manual-bans.txt' if kind=='ban' else 'allow.txt')
        old_text=file.read_text(encoding='utf-8') if file.exists() else ''
        current=line_networks(file,addresses_only=(kind=='ban'))
        conflicts=[];already=repeated;added=[]
        opposite=line_networks(ROOT/('allow.txt' if kind=='ban' else 'manual-bans.txt'),addresses_only=(kind=='allow'))
        vpn=line_networks(ROOT/'vpn-clients.txt',addresses_only=True) if kind=='ban' else []
        for ip in parsed:
            if any(ip in net for net in current):
                already+=1
            elif any(ip in net for net in opposite) or any(ip in net for net in vpn):
                conflicts.append(str(ip))
            else:
                added.append(ip)
        result={'added':len(added),'already':already,'invalid':len(invalid),
                'conflicts':len(conflicts),'invalid_examples':invalid[:12],
                'conflict_examples':conflicts[:12]}
        if not added:return result
        new_text=old_text+('\n' if old_text and not old_text.endswith('\n') else '')
        new_text+=''.join(f'{str(ip)}  {tr("# import","# импорт")} {now()}\n' for ip in added)
        active=state().get('mode','off') in ('observe','enforce')
        previous_snapshot=(ROOT/'active.nft').read_text(encoding='utf-8') if snapshot_valid() else None
        if active and previous_snapshot is None:
            raise RuntimeError(tr('No confirmed rules snapshot: IP import stopped without changes','Нет подтверждённого снимка правил: импорт IP остановлен без изменений'))
        new_snapshot=None
        if active:
            cfg=config()
            if state().get('policy_signature')!=policy_signature(cfg):
                raise RuntimeError(tr('Settings have changed. Confirm the protection policy first.','Настройки изменились. Сначала подтвердите политику защиты.'))
            sets,_,_=build_sets_from_sources(cfg,False)
            sets['manual' if kind=='ban' else 'trusted']=current+[ipaddress.ip_network(str(ip)) for ip in added]
            new_snapshot=render_rules(cfg,sets,state().get('mode')=='enforce')
            nft(new_snapshot,check_only=True)
            commands=[]
            for version in (4,6):
                ips=[str(ip) for ip in added if ip.version==version]
                if ips:
                    target=('ban' if kind=='ban' else 'allow')+str(version)
                    commands.append(f'add element inet {TABLE} {target} {{ '+', '.join(ips)+' }')
            # One atomic nft transaction; no transient firewall reload.
            nft('\n'.join(commands)+'\n')
        try:
            atomic_write(file,new_text)
            if new_snapshot is not None:atomic_write(ROOT/'active.nft',new_snapshot)
        except (OSError,ValueError):
            if active:
                if previous_snapshot is not None:
                    with contextlib.suppress(Exception):nft(previous_snapshot)
                    with contextlib.suppress(Exception):atomic_write(ROOT/'active.nft',previous_snapshot)
                else:
                    raise RuntimeError(tr('Could not restore the rules snapshot. Check nftables manually.','Не удалось восстановить снимок правил. Проверьте nftables вручную.'))
            with contextlib.suppress(Exception):atomic_write(file,old_text)
            raise
        return result
    finally:os.close(fd)

def db():
    path=ROOT/'events.sqlite3'
    connection=sqlite3.connect(path,timeout=5)
    connection.execute('PRAGMA journal_mode=WAL')
    connection.execute('''CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, ip TEXT NOT NULL,
      port INTEGER, proto TEXT, reason TEXT NOT NULL, verdict TEXT NOT NULL)''')
    connection.execute('CREATE INDEX IF NOT EXISTS events_t ON events(timestamp DESC)')
    connection.execute('CREATE INDEX IF NOT EXISTS events_ip ON events(ip)')
    autoban.init_db(connection)
    connection.execute("CREATE INDEX IF NOT EXISTS events_drop_ip ON events(ip,id) WHERE verdict='drop'")
    present={row[1] for row in connection.execute('PRAGMA table_info(events)')}
    for column,kind in (('hits','INTEGER NOT NULL DEFAULT 1'),('first_seen','TEXT'),
                        ('ports',"TEXT NOT NULL DEFAULT ''")):
        if column not in present:
            try:connection.execute(f'ALTER TABLE events ADD COLUMN {column} {kind}')
            except sqlite3.OperationalError as exc:
                if 'duplicate column' not in str(exc):raise  # another process won the race
    connection.execute('CREATE TABLE IF NOT EXISTS drop_totals '
                       '(ip TEXT PRIMARY KEY,hits INTEGER NOT NULL,first_seen TEXT,last_seen TEXT)')
    return connection


PASS_KEEP=dt.timedelta(hours=1)
MAX_EVENT_ROWS=500000
MAX_ROW_PORTS=50
# Auto-ban markers stay as rows of their own, they are never merged away.
MERGEABLE="verdict!='pass' AND reason NOT LIKE 'AUTO_BAN%'"


def row_ports(port,proto,hits,listed):
    """{'443/TCP': count} of one row; None = count unknown (merged before counts were kept)."""
    if not listed:return {f'{port}/{proto or ""}':hits} if port is not None else {}
    found={}
    for item in listed.split():
        tag,_,count=item.partition(':')
        found[tag]=int(count) if count else None
    return found


def add_ports(total,more):
    for tag,count in more.items():
        before=total.pop(tag,0)  # re-insert: most recent port goes last
        total[tag]=None if before is None or count is None else before+count


def pack_ports(ports):
    return ' '.join(tag if count is None else f'{tag}:{count}'
                    for tag,count in list(ports.items())[-MAX_ROW_PORTS:])


def store_event(con,event):
    """drop/observe keep one row per address and verdict; pass rows stay raw."""
    stamp,ip,port,proto,reason,verdict=event
    hits,first,ports,old=1,stamp,{},[]
    if verdict!='pass':
        old=con.execute('SELECT id,timestamp,port,proto,hits,first_seen,ports FROM events '
                        f'WHERE ip=? AND verdict=? AND {MERGEABLE} ORDER BY id',(ip,verdict)).fetchall()
        for _,seen,old_port,old_proto,count,since,listed in old:
            hits+=count;first=min(first,since or seen)
            add_ports(ports,row_ports(old_port,old_proto,count,listed))
    add_ports(ports,row_ports(port,proto,1,''))
    # Insert before delete: the id must grow, the live feed reads "id > cursor".
    con.execute('INSERT INTO events(timestamp,ip,port,proto,reason,verdict,hits,first_seen,ports) '
                'VALUES (?,?,?,?,?,?,?,?,?)',(*event,hits,first,pack_ports(ports)))
    con.executemany('DELETE FROM events WHERE id=?',[(row[0],) for row in old])
    if verdict=='drop':
        # Lifetime counter per blocked address: pruning never touches this table.
        con.execute('INSERT INTO drop_totals(ip,hits,first_seen,last_seen) VALUES (?,1,?,?) '
                    'ON CONFLICT(ip) DO UPDATE SET hits=hits+1,last_seen=excluded.last_seen',(ip,stamp,stamp))


def compact_events(con):
    """Merge duplicates left by older versions; a no-op once the history is clean."""
    groups=con.execute(f'SELECT ip,verdict FROM events WHERE {MERGEABLE} '
                       'GROUP BY ip,verdict HAVING COUNT(*)>1').fetchall()
    for ip,verdict in groups:
        rows=con.execute('SELECT id,timestamp,port,proto,reason,hits,first_seen,ports FROM events '
                         f'WHERE ip=? AND verdict=? AND {MERGEABLE} ORDER BY id',(ip,verdict)).fetchall()
        ports={}
        for row in rows:add_ports(ports,row_ports(row[2],row[3],row[5],row[7]))
        con.execute('UPDATE events SET hits=?,first_seen=?,ports=? WHERE id=?',
                    (sum(r[5] for r in rows),min(r[6] or r[1] for r in rows),pack_ports(ports),rows[-1][0]))
        con.executemany('DELETE FROM events WHERE id=?',[(r[0],) for r in rows[:-1]])
    if not con.execute('SELECT 1 FROM drop_totals LIMIT 1').fetchone():
        con.execute("INSERT INTO drop_totals SELECT ip,SUM(hits),MIN(COALESCE(first_seen,timestamp)),"
                    "MAX(timestamp) FROM events WHERE verdict='drop' GROUP BY ip")
    con.commit()


def drop_total():
    """(logged hits, addresses) over the whole life of the journal."""
    path=ROOT/'events.sqlite3'
    if not path.is_file():return 0,0
    con=sqlite3.connect(f'file:{path}?mode=ro',uri=True,timeout=3)
    try:return con.execute('SELECT COALESCE(SUM(hits),0),COUNT(*) FROM drop_totals').fetchone()
    except sqlite3.OperationalError as exc:
        if 'no such table' in str(exc):return 0,0
        raise
    finally:con.close()


def prune_events(con,retention_days):
    clock=dt.datetime.now(dt.timezone.utc)
    cutoff=lambda age:(clock-age).isoformat(timespec='seconds')
    con.execute("DELETE FROM events WHERE verdict='pass' AND timestamp < ?",(cutoff(PASS_KEEP),))
    con.execute('DELETE FROM events WHERE timestamp < ?',(cutoff(dt.timedelta(days=retention_days)),))
    # Hard cap guards against multi-million-record databases during packet floods.
    con.execute('DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY id DESC LIMIT -1 OFFSET ?)',
                (MAX_EVENT_ROWS,))


def port_breakdown(rows):
    """Per-port view; a count is None only for history merged before counts were kept."""
    found={}
    for port,proto,verdict,reason,stamp,hits,listed in rows:
        if listed:
            keys=[((int(n),p or None),count) for tag,count in row_ports(port,proto,hits,listed).items()
                  for n,_,p in [tag.partition('/')]]
        else:keys=[((port,proto),hits)]
        for key,count in keys:
            item=found.setdefault(key,{'port':key[0],'proto':key[1],'total':0,'drop':0,'observe':0,
                                       'pass':0,'last':'','reasons':set()})
            for field in ('total',verdict):
                item[field]=None if count is None or item[field] is None else item[field]+count
            item['last']=max(item['last'],stamp);item['reasons'].add(reason)
    for item in found.values():item['reasons']=','.join(sorted(item['reasons']))
    return sorted(found.values(),key=lambda i:(-(i['total'] or 0),-1 if i['port'] is None else i['port']))


LOG_RE=re.compile(r'FWS (?P<kind>(?:[DO]_(?:BAN[46]|SCAN[46]|GEO[46]|SSH|SSHREP[46]|WATCH[46]|AUTO[46]|PROBE)|P_(?:PASS|VPN|TRUSTED))):',re.I)

def parse_kernel(line):
    if 'FWS ' not in line or 'SRC=' not in line:return None
    kind = LOG_RE.search(line)
    src = re.search(r'(?:^|\s)SRC=(\S+)',line)
    dst = re.search(r'(?:^|\s)DPT=(\d+)',line)
    proto=re.search(r'(?:^|\s)PROTO=(\S+)',line)
    if not kind or not src:return None
    try:ip=ipaddress.ip_address(src.group(1))
    except ValueError:return None
    tag=kind.group('kind').upper()
    verdict='drop' if tag.startswith('D_') else 'pass' if tag.startswith('P_') else 'observe'
    return (now(),str(ip),int(dst.group(1)) if dst else None,proto.group(1) if proto else None,tag[2:],verdict)


def monitor_ssh():
    con=db();con.execute('PRAGMA busy_timeout=30000')
    p=None
    try:
        detector=autoban.Detector(sys.modules[__name__],con)
        p=subprocess.Popen(['journalctl','-f','-n','0','-o','cat','_UID=0','SYSLOG_IDENTIFIER=sshd','SYSLOG_IDENTIFIER=sshd-session'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1)
        for line in p.stdout:
            event=autoban.parse_ssh(line)
            if not event:continue
            kind,ip,method=event
            try:
                if kind=='accepted':autoban.trust_ssh(sys.modules[__name__],con,ip,method)
                else:detector.handle(ip,0,ssh=True)
            except Exception as exc:
                con.rollback()
                print('SSH event skipped:',type(exc).__name__,str(exc)[:160],flush=True)
        raise RuntimeError('journalctl SSH stream ended unexpectedly')
    finally:
        if p is not None and p.poll() is None:p.terminate()
        con.close()


def start_ssh_watch():
    import threading
    def ssh_worker():
        try:monitor_ssh()
        except BaseException as exc:
            print('SSH monitor failed:',str(exc)[:180],flush=True)
            os._exit(1)
    threading.Thread(target=ssh_worker,daemon=True).start()


def monitor():
    con=db();con.execute('PRAGMA busy_timeout=30000')
    p=subprocess.Popen(['journalctl','-k','-f','-n','0','-o','cat'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1)
    detector=autoban.Detector(sys.modules[__name__],con)
    retention=min(365,max(1,int(config().get('event_retention_days',90))))
    pruned=0.0
    try:
        compact_events(con)
        for line in p.stdout:
            event=parse_kernel(line)
            if event:
                try:
                    store_event(con,event)
                    if time.monotonic()-pruned>=60:
                        prune_events(con,retention);pruned=time.monotonic()
                    con.commit()
                except sqlite3.OperationalError as exc:
                    # A busy database costs one event, not the whole monitor.
                    if 'locked' not in str(exc):raise
                    con.rollback()
                    print('EVENT skipped:',exc,flush=True)
                    continue
                if event[5]=='observe' and event[4]=='PROBE':
                    try:detector.handle(event[1],event[2],event[3] or '')
                    except Exception as exc:
                        print('AUTO-BAN skipped:',type(exc).__name__,str(exc)[:160],flush=True)
        # journalctl may terminate normally after a log-rotation/API error.
        # A normal return would leave systemd Restart=on-failure unable to
        # revive the monitor; fail explicitly, preserving the live VPN rules.
        code=p.poll()
        raise RuntimeError(f'journalctl kernel log stream ended unexpectedly (exit={code})')
    finally:
        if p.poll() is None:p.terminate()
        con.close()


def live_events(since=0, limit=60):
    """Read-only bounded event tail, no kernel subprocess or firewall mutations."""
    if type(since) is not int or since<0 or since>2**63-1:raise ValueError('Invalid cursor')
    if type(limit) is not int or not (1<=limit<=100):raise ValueError('Invalid limit')
    path=ROOT/'events.sqlite3'
    if not path.is_file():return []
    con=sqlite3.connect(f'file:{path}?mode=ro',uri=True,timeout=2)
    try:
        if since:
            records=con.execute('SELECT id,timestamp,ip,port,proto,reason,verdict,hits FROM events WHERE id>? ORDER BY id ASC LIMIT ?', (since,limit)).fetchall()
        else:
            records=list(reversed(con.execute('SELECT id,timestamp,ip,port,proto,reason,verdict,hits FROM events ORDER BY id DESC LIMIT ?', (limit,)).fetchall()))
        return records
    except sqlite3.OperationalError as e:
        if 'no such table' in str(e):return []
        raise
    finally:con.close()


def event_groups(*, page=1, limit=30, ip=None, verdict='all', ports_limit=20, sort='recent'):
    """Bounded IP-oriented security event report from the *full* retained history.

    Counts are sampled/logged packets, not authenticated users or connections.
    No firewall operations and no write operations are performed here.
    """
    if type(page) is not int or not 1 <= page <= 100000:
        raise ValueError('Invalid page')
    if type(limit) is not int or not 1 <= limit <= 50:
        raise ValueError('Invalid page size')
    if type(ports_limit) is not int or not 1 <= ports_limit <= 250:
        raise ValueError('Invalid port limit')
    if verdict not in ('all', 'observe', 'drop', 'pass'):
        raise ValueError('Invalid event filter')
    sort_options = {'recent': 'MAX(id) DESC',
                    'ip_asc': 'ip_key(ip) ASC', 'ip_desc': 'ip_key(ip) DESC',
                    'count_desc': 'SUM(hits) DESC, MAX(id) DESC',
                    'count_asc': 'SUM(hits) ASC, MAX(id) DESC'}
    if sort not in sort_options:
        raise ValueError('Invalid event sort')
    if ip:
        ip = str(ipaddress.ip_address(ip))
    path=ROOT/'events.sqlite3'
    if not path.exists():
        return [], False
    con=sqlite3.connect(f'file:{path}?mode=ro', uri=True, timeout=3)
    try:
        # SQLite's default TEXT order is wrong for IPs: .10 comes before .9.
        # Keep IPv4 before IPv6 and compare each address by its packed bytes.
        def ip_key(raw):
            try:
                addr = ipaddress.ip_address(raw)
                return bytes((addr.version,)) + addr.packed
            except ValueError:
                return b'\xff' + str(raw).encode('utf-8', errors='replace')[:64]
        con.create_function('ip_key', 1, ip_key, deterministic=True)
        con.execute('PRAGMA query_only=ON')
        conditions=[];arguments=[]
        if ip:
            conditions.append('ip=?');arguments.append(ip)
        if verdict!='all':
            conditions.append('verdict=?');arguments.append(verdict)
        where=(' WHERE '+' AND '.join(conditions)) if conditions else ''
        sums=("SUM(CASE WHEN verdict='drop' THEN hits ELSE 0 END),"
              "SUM(CASE WHEN verdict='observe' THEN hits ELSE 0 END),"
              "SUM(CASE WHEN verdict='pass' THEN hits ELSE 0 END)")
        sql=(f'SELECT ip,SUM(hits),MIN(COALESCE(first_seen,timestamp)),MAX(timestamp),{sums},MAX(id) '
             f'FROM events{where} GROUP BY ip ORDER BY {sort_options[sort]}, ip ASC LIMIT ? OFFSET ?')
        offset=(page-1)*limit
        rows=con.execute(sql,(*arguments,limit+1,offset)).fetchall()
        has_more=len(rows)>limit
        result=[]
        counted=con.execute("SELECT 1 FROM sqlite_master WHERE name='drop_totals'").fetchone()
        for addr,total,first,last,dropped,watched,passed,last_id in rows[:limit]:
            lifetime=con.execute('SELECT hits FROM drop_totals WHERE ip=?',(addr,)).fetchone() if counted else None
            detail_conditions=['ip=?'];detail_args=[addr]
            if verdict!='all':
                detail_conditions.append('verdict=?');detail_args.append(verdict)
            detail_where=' WHERE '+' AND '.join(detail_conditions)
            ports=port_breakdown(con.execute(
                f'SELECT port,proto,verdict,reason,timestamp,hits,ports FROM events{detail_where}',
                detail_args))
            result.append({'ip':addr,'total':total,'first':first,'last':last,
                           'drop':dropped,'observe':watched,'pass':passed,'last_id':last_id,
                           'lifetime':lifetime[0] if lifetime else 0,
                           'ports_more':len(ports)>ports_limit,'ports':ports[:ports_limit]})
        return result,has_more
    except sqlite3.OperationalError as error:
        if 'no such table' in str(error):return [],False
        raise
    finally:
        con.close()


def recent_drop_ips(limit=24, hours=24):
    '''Last 24h: top IPs by sampled logged DROP events, not kernel packet total.'''
    if type(limit) is not int or not 1<=limit<=100:raise ValueError('Invalid limit')
    if type(hours) is not int or not 1<=hours<=168:raise ValueError('Invalid hours')
    path=ROOT/'events.sqlite3'
    if not path.is_file():return []
    cutoff=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(hours=hours)).isoformat(timespec='seconds')
    con=sqlite3.connect(f'file:{path}?mode=ro',uri=True,timeout=3)
    try:
        con.execute('PRAGMA query_only=ON')
        return con.execute('''SELECT ip,SUM(hits),MAX(timestamp) FROM events
            WHERE verdict='drop' AND timestamp>=?
            GROUP BY ip ORDER BY SUM(hits) DESC, MAX(timestamp) DESC, ip ASC LIMIT ?''',
            (cutoff,limit)).fetchall()
    except sqlite3.OperationalError as exc:
        if 'no such table' in str(exc):return []
        raise
    finally:con.close()



def recent_drop_causes(limit=250, hours=24):
    # Recent sampled DROP events; do not expand nft sets.
    if type(limit) is not int or not 1<=limit<=1000:raise ValueError('Invalid limit')
    if type(hours) is not int or not 1<=hours<=168:raise ValueError('Invalid hours')
    path=ROOT/'events.sqlite3'
    if not path.is_file():return []
    cutoff=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(hours=hours)).isoformat(timespec='seconds')
    con=sqlite3.connect(f'file:{path}?mode=ro',uri=True,timeout=3)
    try:
        con.execute('PRAGMA query_only=ON')
        return con.execute('''SELECT ip,SUM(hits),MAX(timestamp),GROUP_CONCAT(DISTINCT reason)
              FROM events WHERE verdict='drop' AND timestamp>=?
              GROUP BY ip ORDER BY SUM(hits) DESC,MAX(timestamp) DESC,ip ASC LIMIT ?''',
              (cutoff,limit)).fetchall()
    except sqlite3.OperationalError as exc:
        if 'no such table' in str(exc):return []
        raise
    finally:con.close()


def hits(limit=40):
    con=db()
    try:return con.execute('SELECT timestamp,ip,port,proto,reason,verdict FROM events ORDER BY id DESC LIMIT ?', (min(max(1,limit),500),)).fetchall()
    finally:con.close()


def status():
    s=state();cfg=config()
    p=run('nft','-t','list','table','inet',TABLE,check=False)
    on=p.returncode==0
    print('FW Sentinel',VERSION,'| mode:',s['mode'],'| nft table:', 'present' if on else 'absent')
    print('UI: http://127.0.0.1:'+str(cfg['ui_port']),'| interfaces:',','.join(cfg['wan_interfaces']))
    print('SSH:',cfg['ssh_ports'],'| per-IP:',cfg.get('ssh_rate_per_minute',10),'/min | burst:',cfg.get('ssh_rate_burst',10))
    if bulk_warning():print('WARNING:',bulk_warning())
    mismatch=ssh_port_warning(cfg)
    if mismatch:print('WARN:',mismatch)
    overlap=sorted(set(cfg.get('ssh_ports',[])) & set(cfg.get('vpn_ports',[443,8443])))
    if overlap:print('WARN: SSH rate/reputation bypass on VPN ports',overlap,'(protect VPN users)')
    print('VPN ports:',cfg.get('vpn_ports',[443,8443]),'| saved client IPs:',len(line_networks(ROOT/'vpn-clients.txt',addresses_only=True)))
    print('Additional threats: SSH', 'DROP opt-in' if cfg.get('threat_ssh_enforce') else 'OBSERVE', '| global sources:', 'DROP' if cfg.get('threat_watch_enforce') and state().get('mode')=='enforce' else 'OBSERVE')
    print('Geo RU:', 'ENABLED' if cfg['geo_enabled'] else 'OFF','| Geo ports:',cfg['geo_ports'])
    active=len(autoban.list_bans(ROOT))
    print('Auto-ban:', 'ON' if cfg.get('autoban_enabled',False) else 'OFF', f'| 6 ports / 60 sec or 8 / hour / 24h→7d→30d→180d→365d | active: {active} (first 100)')
    print('Last sync:',s.get('updated'))
    for w in s.get('issues',[]):print('WARN:',w)


def menu():
    actions={'1':lambda:status(), '2':lambda:print('\n'.join(map(str,hits(25)))),
             '3':lambda:refresh(), '4':lambda:observe(), '5':lambda:enforce(),
             '6':lambda:disable(), '7':lambda:change_entry('ban',input('Ban IP: ').strip(),True),
             '8':lambda:change_entry('ban',input('Unban IP: ').strip(),False)}
    while True:
        print(f'\n=== FW SENTINEL {VERSION} ===\n1 Status | 2 Events | 3 Sync | 4 Observe | 5 Enforce (rollback) | 6 Disable | 7 Ban | 8 Unban | 0 Exit')
        x=input('> ').strip()
        if x=='0':return
        if x in actions:
            try:actions[x]()
            except Exception as e:print('ERROR:',e)



# --- Single-source UI refresh: download/cache only. NEVER call nft() here. ---

FEED_REFRESH_STATES=('queued','download','parse','validate','done','warning','error')

def feed_source_registry():
    """Known catalog IDs only: no URL or command supplied by the HTTP caller."""
    src=sources();cfg=config();items={}
    for name,spec in src.get('advanced_feeds',{}).items():
        key='advanced_'+name
        if re.fullmatch(r'[a-z0-9_]{2,70}',key):
            items[key]={'name':spec.get('name',name),'group':spec.get('group','THREAT'),
                        'kind':'advanced','spec':spec,'enabled':bool(spec.get('enabled',False))}
    for name,url in src.get('cidr',{}).items():
        key='cidr_'+name
        if re.fullmatch(r'[a-z0-9_]{2,70}',key):
            items[key]={'name':name.replace('_',' ').title(),'group':'SCAN','kind':'cidr','url':url,'enabled':True}
    for kind,group in (('threat_ssh','SSH'),('threat_watch','WATCH')):
        for name,spec in src.get(kind,{}).items():
            key=kind+'_'+name
            if re.fullmatch(r'[a-z0-9_]{2,70}',key):
                items[key]={'name':name.replace('_',' ').title(),'group':group,'kind':kind,
                            'spec':spec,'enabled':bool(spec.get('enabled',True))}
    items['geo_ru']={'name':'GeoIP RU','group':'GEO','kind':'geo','enabled':True}
    try:asn_lines=(ROOT/'asn.txt').read_text(encoding='utf-8').splitlines()
    except OSError:asn_lines=[]
    for line in asn_lines:
        asn=line.partition('#')[0].strip().upper()
        if re.fullmatch(r'AS[0-9]{1,10}',asn):
            items['asn_'+asn]={'name':asn,'group':'ASN','kind':'asn','asn':asn,'enabled':True}
    return items


def _feed_job_path():
    return ROOT/'cache'/'sources'/'.ui-feed-refresh.json'


def feed_refresh_status():
    try:
        data=json.loads(_feed_job_path().read_text(encoding='utf-8'))
        if not isinstance(data,dict) or data.get('state') not in FEED_REFRESH_STATES:return {}
        # Explicit allowlist: never expose a URL, credential or server pathname.
        return {k:data[k] for k in ('source','state','percent','message','bytes','total_bytes','id','finished','error','warning') if k in data}
    except (OSError,ValueError,TypeError):return {}


def feed_refresh_catalog():
    catalog=feed_source_registry()
    known={}
    previous=_read_advanced_sync_status()
    cache_dir=ROOT/'cache'/'sources'
    for key,info in catalog.items():
        meta=cache_dir/(key+'.meta.json');count=0;updated=''
        if meta.exists():
            try:
                data=json.loads(meta.read_text(encoding='utf-8'))
                if type(data.get('count')) is int:count=max(0,data['count'])
                updated=str(data.get('updated',''))
            except (OSError,ValueError,TypeError):pass
        diagnostics=previous.get(key.removeprefix('advanced_'),{}) if info['kind']=='advanced' else {}
        known[key]={'id':key,'name':info['name'],'group':info['group'],'enabled':info['enabled'],
                    'count':count,'updated':updated,'status':diagnostics.get('status',''),
                    'warning':notable(diagnostics.get('warning','')),'error':diagnostics.get('error','')}
    # Legacy caches not found in the current source registry are still visible
    # in the SAME table, without suggesting a non-existent update endpoint.
    if cache_dir.exists():
        for meta in cache_dir.glob('*.meta.json'):
            key=meta.name[:-len('.meta.json')]
            if key in known or not re.fullmatch(r'[A-Za-z0-9_-]{2,80}',key):continue
            try:
                data=json.loads(meta.read_text(encoding='utf-8'))
                count=data.get('count',0)
                if type(count) is not int:count=0
                known[key]={'id':key,'name':key,'group':tr('ARCHIVE','АРХИВ'),'enabled':False,
                            'count':count,'updated':str(data.get('updated','')),
                            'status':'','warning':'','error':''}
            except (ValueError,OSError,TypeError):pass
    return dict(sorted(known.items(),key=lambda kv:(kv[1]['group'],kv[1]['name'].lower())))


def feed_refresh_start(source):
    catalog=feed_source_registry()
    if source not in catalog:raise ValueError(tr('Unknown list','Неизвестная база'))
    if not catalog[source]['enabled']:raise ValueError(tr('Source is disabled in the catalog','Источник отключён в каталоге'))
    if not re.fullmatch(r'[a-zA-Z0-9_]{2,70}',source):raise ValueError(tr('Invalid list ID','Неверный идентификатор базы'))
    ROOT.mkdir(parents=True,exist_ok=True)
    fd=lock()
    try:
        old=feed_refresh_status()
        if old.get('state') in ('queued','download','parse','validate') and \
                time.time()-float(json.loads(_feed_job_path().read_text()).get('created',0))<1200:
            raise RuntimeError(tr('Another list is already being updated','Уже обновляется другая база'))
        token=uuid.uuid4().hex
        initial={'id':token,'source':source,'state':'queued','percent':0,
                 'message':tr('Queued','В очереди'),'bytes':0,'created':time.time()}
        atomic_write(_feed_job_path(),json.dumps(initial,ensure_ascii=False))
        try:
            unit='fw-sentinel-feed-'+token
            result=run('systemd-run','--quiet','--collect','--unit='+unit,
                       '/usr/local/sbin/fw-sentinel','feed-refresh-worker',token,
                       timeout=12,check=False)
            if result.returncode:raise RuntimeError((tr('Could not start the update:','Не удалось запустить обновление:')+' ')+(result.stderr or '')[:160])
        except (OSError,RuntimeError,subprocess.TimeoutExpired):
            _feed_job_path().unlink(missing_ok=True)
            raise
        return token
    finally:os.close(fd)


def feed_refresh_worker(token):
    """Runs via systemd-run, independently from HTTP UI and its timeout."""
    state_path=_feed_job_path()
    job=json.loads(state_path.read_text(encoding='utf-8'))
    if job.get('id')!=token or job.get('state')!='queued':raise RuntimeError(tr('Invalid job','Неверная задача'))
    name=job['source'];catalog=feed_source_registry()
    if name not in catalog or not catalog[name]['enabled']:raise ValueError(tr('Source is disabled','Источник отключён'))
    info=catalog[name];cfg=config();last_update=0.0;last_pct=-1
    def publish(stage,percent,message,**details):
        nonlocal last_update,last_pct
        percent=max(0,min(100,int(percent)))
        now_mono=time.monotonic()
        if (stage==job.get('state') and percent==last_pct and
                now_mono-last_update<0.75):return
        job.update(state=stage,percent=percent,message=message,**details)
        atomic_write(state_path,json.dumps(job,ensure_ascii=False))
        last_update=now_mono;last_pct=percent
    def on_bytes(amount,total):
        pct=5+int(58*amount/total) if total else 5
        message=(f'{tr("Downloaded","Скачано")} {amount/1024/1024:.2f} {tr("MiB","МиБ")}'
                 +(f' {tr("of","из")} {total/1024/1024:.2f} {tr("MiB","МиБ")}' if total else (' · '+tr('size unknown','размер неизвестен'))))
        publish('download',pct,message,bytes=amount,total_bytes=total)
    def on_lines(n,total):
        publish('parse',68+int(22*n/max(1,total)),f'{tr("Checked","Проверено")} {n:,} {tr("of","из")} {total:,} {tr("entries","записей")}')
    lockfd=None
    try:
        if info['kind']=='advanced':
            lockfd=os.open(ROOT/'.advanced-feed.lock',os.O_CREAT|os.O_RDWR,0o600)
            fcntl.flock(lockfd,fcntl.LOCK_EX)
        publish('download',5,tr('Connecting to source','Соединение с источником'))
        kind=info['kind']
        def loader(urls):return urls_download(urls,int(cfg['max_feed_bytes']),progress=on_bytes)
        if kind=='advanced':
            spec=info['spec'];urls=[spec['url']]
            transform=lambda b:parse_advanced_source(b,spec,cfg,progress=on_lines,compact=spec.get('confidence') in ('scanner','threat'))
            old_meta_source=name[len('advanced_'):]
        elif kind=='cidr':
            urls=[info['url']]
            transform=lambda b:parse_cidr(b,cfg['min_scanner_prefix_v4'],cfg['min_scanner_prefix_v6'],progress=on_lines)
        elif kind in ('threat_ssh','threat_watch'):
            spec=info['spec'];urls=[spec['url']];fmt=spec.get('format','cidr')
            if fmt=='cidr':transform=lambda b:parse_cidr(b,cfg['min_scanner_prefix_v4'],cfg['min_scanner_prefix_v6'],progress=on_lines)
            elif fmt=='spamhaus_drop':transform=lambda b:parse_spamhaus_drop(b,cfg['min_scanner_prefix_v4'],cfg['min_scanner_prefix_v6'])
            elif fmt=='dshield':transform=lambda b:parse_dshield(b,cfg['min_scanner_prefix_v4'],cfg['min_scanner_prefix_v6'])
            elif fmt=='abuseipdb':
                transform=lambda b:parse_cidr(b,cfg['min_scanner_prefix_v4'],cfg['min_scanner_prefix_v6'],progress=on_lines)
                loader=lambda urls:download_abuseipdb_blacklist(cfg,spec)
            else:raise ValueError(tr('Unsupported format','Неподдерживаемый формат'))
        elif kind=='geo':
            urls=sources()['geoip'];transform=lambda b:(parse_geoip(b,cfg['geo_tag']),[])
        elif kind=='asn':
            asn=info['asn']
            urls=[f'https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}']
            transform=lambda b:(parse_ripe(b,asn,(cfg['min_scanner_prefix_v4'],cfg['min_scanner_prefix_v6'])),[])
        else:raise ValueError(tr('Unsupported source','Неподдерживаемый источник'))
        def transforming(data):
            publish('parse',68,tr('Download complete, parsing IP addresses','Скачано, разбираем IP-адреса'))
            answer=transform(data)
            publish('validate',94,tr('Checking and saving cache','Проверка и сохранение кэша'))
            return answer
        # Force a network check on every explicit button click: no cache-fresh shortcut.
        result,used,issues=acquire_source(name,urls,transforming,cfg,loader=lambda:loader(urls),
                                           min_refresh_seconds=0,max_stale_hours=168 if kind=='advanced' else None,
                                           compact=kind=='advanced' and spec.get('confidence') in ('scanner','threat'),
                                           preserve_original=(kind in ('threat_ssh','threat_watch') and
                                                              info['spec'].get('format')=='spamhaus_drop'))
        warning='; '.join(issues)[:500]
        if kind=='advanced':
            previous=_read_advanced_sync_status()
            previous[old_meta_source]={'at':now(),'status':used,
                                       'error':warning if used!='fresh' else '',
                                       'warning':warning if used=='fresh' else ''}
            _write_advanced_sync_status(previous)
        if used!='fresh':
            publish('error',100,tr('Update failed; previous cache retained','Обновить не удалось; прежний кэш сохранён'),error=warning,finished=now())
        else:
            shown=notable(warning)
            publish('warning' if shown else 'done',100,
                    f'{tr("Done:","Готово:")} {len(result):,} {tr("IPs/networks","IP/сетей")}'+((' · '+tr('warnings','есть замечания')) if shown else ''),
                    finished=now(),warning=shown)
    except Exception as exc:
        publish('error',100,tr('Update failed; active rules were not changed','Ошибка обновления; действующие правила не менялись'),
                error=(type(exc).__name__+': '+str(exc))[:500],finished=now())
        raise
    finally:
        if lockfd is not None:os.close(lockfd)


def main():
    ap=argparse.ArgumentParser(description='FW Sentinel '+VERSION)
    ap.add_argument('--version',action='version',version='FW Sentinel '+VERSION)
    sub=ap.add_subparsers(dest='command',required=True)
    for x in ('status','sync','observe','enable','disable','restore','guard','monitor','menu','hits','audit-vpn','verify-restore','abuse-key-set','feeds-prepare','feeds-status','feeds-catalog-status'):
        sub.add_parser(x)
    feed=sub.add_parser('feeds-catalog-sync');feed.add_argument('source',nargs='?',help=tr('Database ID to update only one database','ID базы, если нужно обновить только одну'))
    prov=sub.add_parser('provider');prov.add_argument('action',choices=('set','disable','status'));prov.add_argument('id',nargs='?')
    for x in ('ban','unban','allow','unallow','vpn-add','vpn-remove','auto-unban'):
        z=sub.add_parser(x);z.add_argument('ip')
    z=sub.add_parser('ui-apply-worker');z.add_argument('token')
    z=sub.add_parser('feed-refresh-worker');z.add_argument('token')
    z=sub.add_parser('rollback');z.add_argument('token')
    z=sub.add_parser('render');z.add_argument('--enforce',action='store_true')
    z=sub.add_parser('check');z.add_argument('ip')
    args=ap.parse_args()
    command=args.command
    if command=='auto-unban':print('Removed' if autoban.revoke(sys.modules[__name__],args.ip) else 'Not active')
    elif command=='abuse-key-set':install_abuse_key()
    elif command=='feeds-prepare':prepare_extra_feeds()
    elif command=='feeds-status':print(json.dumps(extras_status(),ensure_ascii=False,indent=2))
    elif command=='feeds-catalog-sync':
        try:
            print(json.dumps(prepare_advanced_feeds(args.source),ensure_ascii=False,indent=2))
        except KeyboardInterrupt:
            print(tr('Update interrupted. Existing caches and nftables were not changed.','Обновление прервано. Существующие кэши и nftables не изменены.'),file=sys.stderr)
            sys.exit(130)
    elif command=='feeds-catalog-status':print(json.dumps(advanced_source_status(),ensure_ascii=False,indent=2))
    elif command=='provider':
        if args.action=='status':
            print(json.dumps(provider_keys.status(ROOT),ensure_ascii=False,indent=2))
        else:
            if args.id not in provider_keys.BY_ID:raise ValueError(tr('A valid source ID is required','Нужен корректный ID источника'))
            if args.action=='set':
                import getpass
                value=getpass.getpass((tr('Key','Ключ')+' ')+args.id+': ')
                if value:provider_keys.set_key(ROOT,args.id,value);print(tr('Saved','Сохранено'))
                else:provider_keys.disable(ROOT,args.id);print(tr('Empty key: source disabled','Пустой ключ: источник выключен'))
            else:provider_keys.disable(ROOT,args.id);print(tr('Source disabled','Источник выключен'))
    elif command=='status':status()
    elif command=='sync':refresh()
    elif command=='observe':observe()
    elif command=='enable':enforce()
    elif command=='disable':disable()
    elif command=='restore':restore()
    elif command=='guard':guard()
    elif command=='verify-restore':
        report=persistence_report()
        print(json.dumps(report,ensure_ascii=False,indent=2))
        if not report['ready']:sys.exit(2)
    elif command=='monitor':start_ssh_watch();monitor()
    elif command=='menu':menu()
    elif command=='audit-vpn':
        cfg=config();sets,_,_=build_sets_from_sources(cfg,False);print_vpn_audit(cfg,sets)
    elif command=='hits':
        for item in hits():print(*[str(x or '-') for x in item],sep='\t')
    elif command=='ui-apply-worker':ui_apply_worker(args.token)
    elif command=='feed-refresh-worker':feed_refresh_worker(args.token)
    elif command=='rollback':rollback(args.token)
    elif command in ('ban','unban','allow','unallow','vpn-add','vpn-remove'):
        kind='vpn' if command.startswith('vpn-') else 'ban' if 'ban' in command else 'allow'
        print('Updated' if change_entry(kind,args.ip,command in ('ban','allow','vpn-add')) else 'No changes')
    elif command=='render':
        cfg=config();sets,issues,_=build_sets_from_sources(cfg,False)
        print(render_rules(cfg,sets,args.enforce))
        for w in issues:print('WARN:',w,file=sys.stderr)
    elif command=='check':
        a=ipaddress.ip_address(args.ip);sets,_,_=build_sets_from_sources(config(),False)
        for label in ('trusted','vpn_clients','manual','scanners','asn','geo','threat_ssh','threat_watch'):
            print(label, 'match' if matches_set(a,sets,label) else 'no match')


if __name__=='__main__':
    try: main()
    except (ValueError,RuntimeError,OSError,subprocess.TimeoutExpired) as exc:
        print('ERROR:',exc,file=sys.stderr);sys.exit(1)
