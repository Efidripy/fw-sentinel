"""Conservative TCP port-scan detection with escalating temporary bans.

Only kernel SYN log lines are candidate evidence. Incomplete logs can cause missed
scans, never inferred scans. Scope is local inbound traffic on the configured WAN.
"""
from __future__ import annotations
from i18n import tr
from collections import OrderedDict
import contextlib
import ipaddress
import json
import math
import os
import re
import sqlite3
import subprocess
import time

PORT_DEFAULT_TCP = (22, 53, 80, 443, 8443, 8080, 8081, 9443)
PORT_DEFAULT_UDP = (53, 123, 443, 8443, 51820)
WINDOW = 60
DISTINCT = 6
# Slow scanners stay under the fast rule; 8/hour matched no allowed traffic on 24h of live data.
SLOW_WINDOW = 3600
SLOW_DISTINCT = 8
DURATION_MINUTES = 1440  # Legacy first-offense constant; retained for existing callers.
# 1 day, 1 week, 30 days, 180 days, 365 days; repeat offenses cap at 1 year.
BAN_DURATIONS = (86400, 7*86400, 30*86400, 180*86400, 365*86400)

def ban_duration_for_strike(strike):
    if type(strike) is not int or strike < 1:raise ValueError("strike must be >=1")
    return BAN_DURATIONS[min(strike - 1, len(BAN_DURATIONS) - 1)]

def ban_duration_name(strike):
    return (tr("24 hours","24 часа"), tr("7 days","7 дней"), tr("30 days","30 дней"), tr("180 days","180 дней"), tr("365 days","365 дней"))[min(max(strike,1)-1,4)]
# One SYN to a trap port bans for an hour; later offences follow the normal ladder.
TRAP_FIRST = 3600
MAX_TRACKED = 10000
MAX_ACTIVE = 20000


def checked_ports(data, label='ports'):
    if not isinstance(data,list) or len(data)>256 or any(type(p) is not int or p<1 or p>65535 for p in data):
        raise ValueError(f'{label}: expected at most 256 distinct TCP/UDP ports 1..65535')
    if len(set(data))!=len(data):raise ValueError(f'{label}: duplicate port')
    return set(data)


def trap_ports(cfg):
    return checked_ports(cfg.get('autoban_trap_ports',[]),'autoban_trap_ports')


def protected_config_ports(cfg):
    tcp=checked_ports(cfg.get('autoban_exclude_tcp_ports',list(PORT_DEFAULT_TCP)),'autoban_exclude_tcp_ports')
    udp=checked_ports(cfg.get('autoban_exclude_udp_ports',list(PORT_DEFAULT_UDP)),'autoban_exclude_udp_ports')
    # A trap overrides the generic exclusion list, never a configured or listening service.
    tcp-=trap_ports(cfg)
    for name in ('vpn_ports','ssh_ports','geo_ports'):
        ports=checked_ports(cfg.get(name,[]),name)
        tcp.update(ports)
        udp.update(ports)
    return tcp,udp


def validate(cfg):
    # Constants are deliberate, so an admin cannot accidentally turn 6 ports into 1.
    if type(cfg.get('ssh_watch_enabled',False)) is not bool:raise ValueError('ssh_watch_enabled must be boolean')
    if cfg.get('ssh_watch_enabled',False) and not cfg.get('autoban_enabled',False):raise ValueError(tr('SSH trust requires AUTO-BAN to be enabled','SSH-доверие требует включённого AUTO-BAN'))
    if type(cfg.get('autoban_enabled',False)) is not bool:raise ValueError('autoban_enabled must be boolean')
    if type(cfg.get('autoban_udp_enabled',False)) is not bool:raise ValueError('autoban_udp_enabled must be boolean')
    if cfg.get('autoban_enabled',False) and not cfg.get('logging_enabled',True):
        raise ValueError('AUTO-BAN requires logging_enabled=true')
    if cfg.get('autoban_udp_enabled',False):
        raise ValueError('UDP auto-detection is disabled in 2.0.8: spoofable UDP sources can cause false bans')
    return protected_config_ports(cfg)


def discover_services():
    """Detect local listeners and Docker-published host ports. Fail CLOSED on error.

    Shell is never used; listeners are queried at most once per 30 seconds. If
    Docker is installed but unavailable, abstain from scanning-triggered bans.
    """
    tcp=set();udp=set()
    for flag,dest in (('-lntH',tcp),('-lnuH',udp)):
        p=subprocess.run(['ss',flag],capture_output=True,text=True,timeout=5)
        if p.returncode:raise RuntimeError('ss cannot enumerate local services: '+p.stderr[:200])
        for line in p.stdout.splitlines():
            fields=line.split()
            if len(fields)<5:continue
            # ss -H outputs: STATE Recv-Q Send-Q LOCAL PEER (local is field 3).
            match=re.search(r':(\d{1,5})$',fields[3])
            if match:
                port=int(match.group(1))
                if 1<=port<=65535:dest.add(port)
    from shutil import which
    if which('docker'):
        p=subprocess.run(['docker','ps','--format','{{.Ports}}'],capture_output=True,text=True,timeout=6)
        if p.returncode:raise RuntimeError('Docker published port enumeration failed')
        for start,end,proto in re.findall(r'(\d+)(?:-(\d+))?->\d+(?:-\d+)?/(tcp|udp)',p.stdout):
            a=int(start);b=int(end or start)
            if b<a or b-a>2048:raise RuntimeError('Docker published range too broad')
            (tcp if proto=='tcp' else udp).update(range(a,b+1))
    if len(tcp)>8192 or len(udp)>8192:raise RuntimeError('Too many exposed services to validate safely')
    return tcp,udp


def protected_ports(cfg, *, discover=True):
    tcp,udp=protected_config_ports(cfg)
    if discover:
        found_tcp,found_udp=discover_services()
        tcp.update(found_tcp);udp.update(found_udp)
    return tcp,udp


def init_db(con):
    con.execute('''CREATE TABLE IF NOT EXISTS auto_bans (
      ip TEXT PRIMARY KEY, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
      ports TEXT NOT NULL, revoked_at INTEGER)''')
    con.execute('CREATE TABLE IF NOT EXISTS auto_ban_traps (ip TEXT PRIMARY KEY)')
    con.execute('CREATE TABLE IF NOT EXISTS ssh_trust (ip TEXT PRIMARY KEY, method TEXT NOT NULL, expires_at INTEGER NOT NULL)')
    con.execute('CREATE INDEX IF NOT EXISTS auto_bans_expires ON auto_bans(expires_at)')
    # A separate lifetime counter survives expiry, revocation, and replacement of
    # auto_bans row; do not reset strikes when a user's 24h ban expires.
    con.execute('''CREATE TABLE IF NOT EXISTS auto_ban_strikes (
      ip TEXT PRIMARY KEY, strikes INTEGER NOT NULL CHECK(strikes>=1),
      last_banned_at INTEGER NOT NULL)''')
    # Idempotent migration: pre-2.0.13 existing bans become first offenses.
    con.execute('''INSERT OR IGNORE INTO auto_ban_strikes(ip,strikes,last_banned_at)
      SELECT ip,1,created_at FROM auto_bans''')
    con.execute('''CREATE TABLE IF NOT EXISTS auto_ban_history (
      id INTEGER PRIMARY KEY, ip TEXT NOT NULL, strike INTEGER NOT NULL,
      created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
      ports TEXT NOT NULL)''')
    con.execute('CREATE INDEX IF NOT EXISTS auto_ban_history_ip ON auto_ban_history(ip,created_at)')
    # Migrating from v2.0.12: retain the existing ban as offense one. The
    # WHERE NOT EXISTS guard prevents repeated seeding on every monitor start.
    con.execute('''INSERT INTO auto_ban_history(ip,strike,created_at,expires_at,ports)
      SELECT b.ip,1,b.created_at,b.expires_at,b.ports FROM auto_bans b
      WHERE NOT EXISTS (SELECT 1 FROM auto_ban_history h WHERE h.ip=b.ip)''')


def active_bans(con, at=None, limit=MAX_ACTIVE):
    at=int(time.time() if at is None else at)
    try:
        return con.execute('SELECT ip,created_at,expires_at,ports FROM auto_bans '
             'WHERE expires_at>? AND revoked_at IS NULL ORDER BY expires_at DESC LIMIT ?', (at,limit)).fetchall()
    except sqlite3.OperationalError as exc:
        if 'no such table' in str(exc):return []
        raise


def list_bans(root, limit=100):
    file=root/'events.sqlite3'
    if not file.exists():return []
    con=sqlite3.connect(f'file:{file}?mode=ro',uri=True,timeout=2)
    try:return active_bans(con,limit=limit)
    finally:con.close()


def list_bans_detailed(root,limit=100):
    # Active bans enriched with lifetime offense count; legacy DBs are readable.
    file=root/'events.sqlite3'
    if not file.exists():return []
    con=sqlite3.connect(f'file:{file}?mode=ro',uri=True,timeout=2)
    try:
        now=int(time.time())
        try:return con.execute('''SELECT b.ip,b.created_at,b.expires_at,b.ports,
             COALESCE(s.strikes,1) FROM auto_bans b
             LEFT JOIN auto_ban_strikes s ON s.ip=b.ip
             WHERE b.expires_at>? AND b.revoked_at IS NULL
             ORDER BY b.expires_at DESC LIMIT ?''',(now,limit)).fetchall()
        except sqlite3.OperationalError as exc:
            if 'no such table' not in str(exc):raise
            return [(*row,1) for row in active_bans(con,at=now,limit=limit)]
    finally:con.close()


def _nft_line(ip,remaining,fw,kind='auto'):
    addr=ipaddress.ip_address(ip)
    timeout=max(1,int(math.ceil(remaining)))
    return f'add element inet {fw.TABLE} {kind}{addr.version} {{ {addr} timeout {timeout}s }}\n'


def _nft_add(ip,remaining,fw,kind='auto'):
    fw.nft(_nft_line(ip,remaining,fw,kind))


def rearm(con,fw,cfg):
    """Restore remaining TTL after refresh/restart; never extend expiration."""
    if not cfg.get('autoban_enabled',False):return 0
    if fw.state().get('mode')!='enforce':return 0
    batch=[];now=int(time.time())
    trusted=fw.line_networks(fw.ROOT/'allow.txt')
    protected=fw.line_networks(fw.ROOT/'vpn-clients.txt',addresses_only=True)
    init_db(con);con.commit()
    trusts={row[0] for row in con.execute('SELECT ip FROM ssh_trust WHERE expires_at>?',(now,))} if cfg.get('ssh_watch_enabled',False) else set()
    traps={row[0] for row in con.execute('SELECT ip FROM auto_ban_traps')} if trap_ports(cfg) or cfg.get('ssh_watch_enabled',False) else set()
    for raw,_,expires,_ in active_bans(con,at=now):
        addr=ipaddress.ip_address(raw)
        if raw in trusts or any(addr in net for net in trusted+protected):continue
        batch.append(_nft_line(raw,expires-now,fw,'trap' if raw in traps else 'auto'))
    if cfg.get('ssh_watch_enabled',False):
        manual=fw.line_networks(fw.ROOT/'manual-bans.txt')
        for raw,expires in con.execute('SELECT ip,expires_at FROM ssh_trust WHERE expires_at>?',(now,)):
            addr=ipaddress.ip_address(raw)
            if not any(addr in net for net in manual):batch.append(_nft_line(raw,expires-now,fw,'sshtrust'))
    # One transaction: with a large ruleset every separate nft call takes seconds.
    if batch:fw.nft(''.join(batch))
    return len(batch)


def rearm_for_rules(fw,cfg,mode):
    """Call ONLY after nft batch successfully reloaded in confirmed enforce."""
    if mode!='enforce' or not cfg.get('autoban_enabled',False):return
    # A snapshot can outlive newly started services. Refresh safe destination
    # ports BEFORE restoring bans. If discovery fails, restore no bans.
    try:update_service_sets(fw,cfg)
    except (RuntimeError,OSError,subprocess.TimeoutExpired) as exc:
        print('AUTO-BAN restore skipped safely (services unavailable):',str(exc)[:180],flush=True)
        if cfg.get('ssh_watch_enabled',False):
            con=fw.db()
            try:
                init_db(con);con.commit();now=int(time.time())
                manual=fw.line_networks(fw.ROOT/'manual-bans.txt')
                batch=[_nft_line(ip,expires-now,fw,'sshtrust') for ip,expires in con.execute('SELECT ip,expires_at FROM ssh_trust WHERE expires_at>?',(now,)) if not any(ipaddress.ip_address(ip) in net for net in manual)]
                if batch:fw.nft(''.join(batch))
            finally:con.close()
        return
    con=fw.db()
    try:rearm(con,fw,cfg)
    finally:con.close()


def update_service_sets(fw,cfg,*,already_locked=False):
    """Update exclusion sets atomically, only if current confirmed policy uses them."""
    if not cfg.get('autoban_enabled',False):return
    t,u=protected_ports(cfg,discover=True)
    batch=[]
    for name,ports in (('autosafetcp',t),('autosafeudp',u)):
        batch.append(f'flush set inet {fw.TABLE} {name}')
        if ports:batch.append(f'add element inet {fw.TABLE} {name} {{ '+', '.join(map(str,sorted(ports)))+' }')
    if batch:fw.nft('\n'.join(batch)+'\n')


class Detector:
    def __init__(self,fw,con,clock=None):
        self.fw=fw;self.con=con;self.clock=clock or time.monotonic
        self.probes=OrderedDict();self.ssh_failures=OrderedDict();self.last_config=0;self.last_refresh=0
        self.cfg=None;self.protected=None;self.ready=False
        init_db(con)
        con.commit()

    def _refresh(self):
        moment=self.clock()
        if self.cfg is not None and moment-self.last_config<3:return
        self.last_config=moment
        try:
            cfg=self.fw.config()
            validate(cfg)
            enabled=bool(cfg.get('autoban_enabled',False) and cfg.get('logging_enabled',True) and
                         self.fw.state().get('mode')=='enforce' and
                         self.fw.state().get('policy_signature')==self.fw.policy_signature(cfg) and
                         not any(self.fw.ROOT.glob('.pending-*')))
            if not enabled:
                self.cfg=cfg;self.protected=None;self.ready=False;self.probes.clear();return
            if moment-self.last_refresh>=30 or self.protected is None:
                safe=protected_ports(cfg,discover=True)
                # Do not count traffic if protective port discovery or nft updates fail.
                lockfd=self.fw.lock()
                try:
                    if self.fw.state().get('mode')!='enforce':
                        self.ready=False;self.protected=None;return
                    update_service_sets(self.fw,cfg)
                finally:os.close(lockfd)
                self.protected=safe;self.last_refresh=moment
            self.cfg=cfg;self.ready=True
        except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired) as exc:
            self.cfg=None;self.ready=False;self.protected=None;self.probes.clear()
            # Fail-safe: no auto-ban if service inventory cannot be validated.
            if moment-self.last_refresh>30:
                print('AUTO-BAN DISABLED temporarily:',str(exc)[:180],flush=True)
                self.last_refresh=moment

    def handle(self,ip,port,proto='TCP',ssh=False):
        self._refresh()
        if not self.ready or proto.upper()!='TCP' or port is None:return False
        try:addr=ipaddress.ip_address(ip)
        except ValueError:return False
        if not addr.is_global or (not ssh and (port<1 or port>65535 or port in self.protected[0])):return False
        if ssh and not self.cfg.get('ssh_watch_enabled',False):return False
        trap=ssh or port in trap_ports(self.cfg)
        current=self.clock()
        key=str(addr)
        if ssh:
            failures=self.ssh_failures.setdefault(key,[])
            self.ssh_failures.move_to_end(key)
            failures[:]=[t for t in failures if current-t<600]
            failures.append(current)
            if len(self.ssh_failures)>MAX_TRACKED:self.ssh_failures.popitem(last=False)
            if len(failures)<6:return False
        ports={}
        if not ssh:
            ports=self.probes.setdefault(key,{})
            self.probes.move_to_end(key)
            for p,t in list(ports.items()):
                if current-t>=SLOW_WINDOW or p in self.protected[0]:del ports[p]
            ports[port]=current
            if len(ports)>SLOW_DISTINCT:
                oldest=min(ports,key=ports.get)
                del ports[oldest]
            if len(self.probes)>MAX_TRACKED:self.probes.popitem(last=False)
            fast=sum(current-t<WINDOW for t in ports.values())
            if not trap and fast<DISTINCT and len(ports)<SLOW_DISTINCT:return False
        # Never ban a trusted admin or known VPN client, including when a scan hit 6 ports.
        lockfd=self.fw.lock()
        try:
            if any(self.fw.ROOT.glob('.pending-*')):return False
            cfg=self.fw.config()
            if not (cfg.get('autoban_enabled',False) and self.fw.state().get('mode')=='enforce' and
                    self.fw.state().get('policy_signature')==self.fw.policy_signature(cfg)):
                return False
            if any(addr in n for path in ('allow.txt','vpn-clients.txt')
                   for n in self.fw.line_networks(self.fw.ROOT/path)):
                return False
            if self.con.execute('SELECT 1 FROM ssh_trust WHERE ip=? AND expires_at>?',(key,int(time.time()))).fetchone():return False
            if ssh and not cfg.get('ssh_watch_enabled',False):return False
            if not ssh and protected_ports(cfg,discover=True)[0].intersection([port] if trap else ports):return False
            n=int(time.time())
            row=self.con.execute('SELECT expires_at,revoked_at FROM auto_bans WHERE ip=?',(key,)).fetchone()
            # A scan ban leaves service ports open; a brute forcer is upgraded to the all-ports set.
            upgrade=ssh and not self.con.execute('SELECT 1 FROM auto_ban_traps WHERE ip=?',(key,)).fetchone()
            if row and row[0]>n and row[1] is None and not upgrade:
                self.probes.pop(key,None)
                return False
            if self.con.execute('SELECT count(*) FROM auto_bans WHERE expires_at>? AND revoked_at IS NULL',(n,)).fetchone()[0]>=MAX_ACTIVE:
                return False
            prior=self.con.execute('SELECT strikes FROM auto_ban_strikes WHERE ip=?',(key,)).fetchone()
            strike=(int(prior[0]) if prior else 0)+1
            step=strike-1 if trap else strike  # a trap ladder starts one hour below the normal one
            duration=ban_duration_for_strike(step) if step else TRAP_FIRST
            label=('AUTO_BAN_1H','AUTO_BAN_24H','AUTO_BAN_7D','AUTO_BAN_30D','AUTO_BAN_180D','AUTO_BAN_365D')[min(step,5)]
            kind='trap' if trap else 'auto'
            serialized=json.dumps(['SSH brute force'] if ssh else [port] if trap else sorted(ports))
            # Apply nft before committing state; any failure rolls back the
            # SQLite writes and removes the just-added nft element.
            _nft_add(key,duration,self.fw,kind)
            try:
                self.con.execute('INSERT OR REPLACE INTO auto_bans(ip,created_at,expires_at,ports,revoked_at) VALUES(?,?,?,?,NULL)',
                    (key,n,n+duration,serialized))
                self.con.execute('INSERT OR REPLACE INTO auto_ban_traps(ip) VALUES(?)' if trap else
                                 'DELETE FROM auto_ban_traps WHERE ip=?',(key,))
                self.con.execute('''INSERT INTO auto_ban_strikes(ip,strikes,last_banned_at) VALUES(?,?,?)
                    ON CONFLICT(ip) DO UPDATE SET strikes=excluded.strikes,last_banned_at=excluded.last_banned_at''',
                    (key,strike,n))
                self.con.execute('INSERT INTO auto_ban_history(ip,strike,created_at,expires_at,ports) VALUES(?,?,?,?,?)',
                    (key,strike,n,n+duration,serialized))
                self.con.execute('INSERT INTO events(timestamp,ip,port,proto,reason,verdict) VALUES(?,?,?,?,?,?)',
                    (self.fw.now(),key,port,'TCP',label,'observe'))
                self.con.commit()
            except sqlite3.Error:
                self.con.rollback()
                with contextlib.suppress(Exception):self.fw.nft(f'delete element inet {self.fw.TABLE} {kind}{addr.version} {{ {addr} }}\n')
                raise
            self.probes.pop(key,None)
            self.ssh_failures.pop(key,None)
            return True
        finally:os.close(lockfd)


def revoke(fw,ip):
    addr=ipaddress.ip_address(ip)
    fd=fw.lock()
    try:
        fw.ensure_no_pending()
        con=fw.db()
        try:
            init_db(con)
            row=con.execute('SELECT expires_at,revoked_at FROM auto_bans WHERE ip=?',(str(addr),)).fetchone()
            if not row or row[0]<=int(time.time()) or row[1] is not None:return False
            if fw.state().get('mode')=='enforce' and fw.config().get('autoban_enabled',False):
                # 'No such file' also covers a table loaded without trap sets.
                for kind in ('auto','trap'):
                    p=fw.run('nft','delete','element','inet',fw.TABLE,kind+str(addr.version),'{',str(addr),'}',check=False)
                    if p.returncode and 'No such file' not in p.stderr and 'No such element' not in p.stderr:
                        raise RuntimeError(p.stderr)
            con.execute('UPDATE auto_bans SET revoked_at=? WHERE ip=?',(int(time.time()),str(addr)))
            con.commit()
            return True
        finally:con.close()
    finally:os.close(fd)


# The last "from ..." belongs to sshd; usernames in failed messages are untrusted.
def parse_ssh(line):
    line=line.rstrip('\n')
    match=re.fullmatch(r'Accepted (publickey|password|keyboard-interactive(?:/pam)?) for \S+ from (\S+) port [0-9]+ ssh2(?:: .*)?',line)
    if match:method,raw=match.groups();kind='accepted'
    else:
        match=re.fullmatch(r'Failed (?:password|keyboard-interactive(?:/pam)?) for .+ from (\S+) port [0-9]+ ssh2|Invalid user .+ from (\S+) port [0-9]+',line)
        if not match:return None
        raw=match.group(1) or match.group(2);method=None;kind='failed'
    try:addr=ipaddress.ip_address(raw)
    except ValueError:return None
    if not addr.is_global:return None
    return kind,str(addr),method


def list_ssh_trust(root):
    file=root/'events.sqlite3'
    if not file.exists():return []
    con=sqlite3.connect(f'file:{file}?mode=ro',uri=True,timeout=2)
    try:
        try:return con.execute('SELECT ip,method,expires_at FROM ssh_trust WHERE expires_at>? ORDER BY expires_at DESC',(int(time.time()),)).fetchall()
        except sqlite3.OperationalError as exc:
            if 'no such table' in str(exc):return []
            raise
    finally:con.close()


def trust_ssh(fw,con,ip,method):
    addr=ipaddress.ip_address(ip);key=str(addr)
    if not addr.is_global or method not in ('publickey','password','keyboard-interactive','keyboard-interactive/pam'):return False
    fd=fw.lock()
    try:
        cfg=fw.config()
        if not (cfg.get('ssh_watch_enabled',False) and cfg.get('autoban_enabled',False) and fw.state().get('mode')=='enforce' and fw.state().get('policy_signature')==fw.policy_signature(cfg)) or any(fw.ROOT.glob('.pending-*')):return False
        if any(addr in net for net in fw.line_networks(fw.ROOT/'manual-bans.txt')):return False
        now=int(time.time());expires=now+(30*86400 if method=='publickey' else 86400)
        row=con.execute('SELECT method,expires_at FROM ssh_trust WHERE ip=?',(key,)).fetchone()
        if row and row[1]>expires:method,expires=row
        setname=f'sshtrust{addr.version}'
        fw.nft(f'add element inet {fw.TABLE} {setname} {{ {addr} timeout 1s }}\n'
               f'delete element inet {fw.TABLE} {setname} {{ {addr} }}\n'+_nft_line(key,expires-now,fw,'sshtrust'))
        for kind in ('auto','trap'):
            p=fw.run('nft','delete','element','inet',fw.TABLE,kind+str(addr.version),'{',key,'}',check=False)
            if p.returncode and 'No such file' not in p.stderr and 'No such element' not in p.stderr:raise RuntimeError(p.stderr)
        con.execute('INSERT OR REPLACE INTO ssh_trust(ip,method,expires_at) VALUES(?,?,?)',(key,method,expires))
        con.execute('UPDATE auto_bans SET revoked_at=? WHERE ip=? AND revoked_at IS NULL',(now,key))
        con.commit()
        return True
    finally:os.close(fd)


def revoke_ssh_trust(fw,ip):
    addr=ipaddress.ip_address(ip);fd=fw.lock()
    try:
        fw.ensure_no_pending();con=fw.db()
        try:
            init_db(con)
            if fw.state().get('mode')=='enforce' and fw.config().get('ssh_watch_enabled',False):
                p=fw.run('nft','delete','element','inet',fw.TABLE,'sshtrust'+str(addr.version),'{',str(addr),'}',check=False)
                if p.returncode and 'No such file' not in p.stderr and 'No such element' not in p.stderr:raise RuntimeError(p.stderr)
            changed=con.execute('DELETE FROM ssh_trust WHERE ip=?',(str(addr),)).rowcount
            con.commit();return bool(changed)
        finally:con.close()
    finally:os.close(fd)
