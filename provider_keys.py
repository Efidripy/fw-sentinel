#!/usr/bin/env python3
"""Safe provider credential vault. Never log, echo or embed secrets in HTML."""
from __future__ import annotations
import os, stat, tempfile, getpass
from i18n import tr
from pathlib import Path

PROVIDERS = (('abuseipdb', 'AbuseIPDB', 'IP-база + рейтинг', 'https://www.abuseipdb.com/register', 'feed+lookup'), ('greynoise', 'GreyNoise Community', 'Проверка сканеров', 'https://www.greynoise.io/plans', 'lookup'), ('crowdsec', 'CrowdSec CTI', 'Репутация отдельных IP', 'https://docs.crowdsec.net/u/console/ip_reputation/api_keys/', 'lookup'), ('otx', 'LevelBlue OTX', 'Индикаторы и репутация', 'https://otx.alienvault.com/', 'catalog'), ('virustotal', 'VirusTotal Public API', 'Проверка IP вручную', 'https://docs.virustotal.com/reference/public-vs-premium-api', 'catalog'), ('pulsedive', 'Pulsedive', 'Проверка индикаторов', 'https://pulsedive.com/about/api', 'catalog'), ('threatfox', 'ThreatFox / abuse.ch', 'C2-индикаторы (не входящий IP DROP)', 'https://threatfox.abuse.ch/api/', 'catalog'), ('urlhaus', 'URLhaus / abuse.ch', 'URL и домены (не IP DROP)', 'https://urlhaus.abuse.ch/api/', 'catalog'), ('phishtank', 'PhishTank', 'Фишинговые URL', 'https://www.phishtank.org/developer_info.php', 'catalog'), ('spamhaus_dqs', 'Spamhaus DQS', 'Репутационный DNS-сервис', 'https://www.spamhaus.com/data-access/free-data-query-service/', 'catalog'), ('cins', 'CINS Army', 'Доступ к community IP-базе', 'https://cinsarmy.com/list-download/', 'catalog'), ('maxmind', 'MaxMind GeoLite2', 'Локальные базы ASN/GeoIP', 'https://www.maxmind.com/en/geolite2/signup', 'catalog'), ('ipinfo', 'IPinfo Lite', 'ASN/страна', 'https://ipinfo.io/developers/lite-api', 'catalog'), ('censys', 'Censys', 'Исследование хостов', 'https://search.censys.io/', 'catalog'), ('netlas', 'Netlas', 'Поиск открытых сервисов', 'https://netlas.io/', 'catalog'), ('shodan', 'Shodan', 'Поиск открытых сервисов', 'https://www.shodan.io/', 'catalog'), ('fofa', 'FOFA', 'Поиск открытых сервисов', 'https://fofa.info/', 'catalog'))
BY_ID={p[0]:p for p in PROVIDERS}

def path_for(root, name):
    if name not in BY_ID:raise ValueError(tr('Unknown source','Неизвестный источник'))
    root=Path(root)
    return root/'abuseipdb.key' if name=='abuseipdb' else root/'provider-keys'/f'{name}.key'

def enabled(root, name):
    path=path_for(root,name)
    try:
        st=path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077:return False
        return bool(path.read_text(encoding='utf-8').strip())
    except (OSError,UnicodeError):return False

def set_key(root, name, value):
    if name not in BY_ID:raise ValueError(tr('Unknown source','Неизвестный источник'))
    if type(value) is not str or not 8<=len(value)<=1024 or not value.isprintable() or '\n' in value or '\r' in value:
        raise ValueError(tr('Key: 8–1024 printable characters','Ключ: 8–1024 печатных символов'))
    if name=='abuseipdb' and (not 32<=len(value)<=256 or not value.isascii() or not value.isalnum()):
        raise ValueError(tr('AbuseIPDB: key must contain 32–256 ASCII letters or digits','AbuseIPDB: ключ должен быть 32–256 букв/цифр ASCII'))
    root=Path(root);path=path_for(root,name)
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    os.chmod(path.parent,0o700)
    if path.is_symlink():raise ValueError(tr('Symbolic links in the key directory are not allowed','Символьная ссылка в каталоге ключей запрещена'))
    fd,tmp=tempfile.mkstemp(prefix='.key-',dir=path.parent)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'w',encoding='utf-8') as file:
            file.write(value+'\n');file.flush();os.fsync(file.fileno())
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)

def disable(root,name):
    path=path_for(root,name)
    if path.is_symlink():raise ValueError(tr('Symbolic links in the key directory are not allowed','Символьная ссылка в каталоге ключей запрещена'))
    try:path.unlink()
    except FileNotFoundError:pass

def secret(root,name):
    if not enabled(root,name):raise ValueError(tr('Source is not connected','Источник не подключён'))
    return path_for(root,name).read_text(encoding='utf-8').strip()

def status(root):
    return [{'id':id,'title':label,'purpose':purpose,'register':link,'kind':kind,'enabled':enabled(root,id),
             'integration':(tr('Working API: IP feed and reputation score','Рабочий API: IP-фид и рейтинг') if id=='abuseipdb' else tr('Key saved; API integration is not yet implemented','Ключ сохранён; интеграция API пока не реализована'))}
            for id,label,purpose,link,kind in PROVIDERS]

def prompt_all(root):
    print(('\n=== '+tr('API databases: Enter = disable, = = keep the existing key ===','API-базы: Enter = отключить, = = сохранить прежний ключ ===')))
    for id,label,*_ in PROVIDERS:
        previous=enabled(root,id)
        while True:
            try:
                v=getpass.getpass(label+((' '+tr('[connected]','[подключён]')) if previous else '')+': ')
            except (KeyboardInterrupt,EOFError):
                print(('\n'+tr('Key setup interrupted; current values retained','Настройка ключей прервана; оставлены текущие значения')))
                return
            if v=='=':
                break
            if v=='':
                disable(root,id);break
            try:set_key(root,id,v);break
            except ValueError as exc:print(exc)
    print(tr('Keys are saved only on the server; the web panel password was not changed.','Ключи сохранены только на сервере; пароль веб-панели не изменён.'))

if __name__=='__main__':
    import sys
    if sys.argv[1:]==['--setup']:prompt_all(Path('/opt/fw-sentinel'))
    else:raise SystemExit('Use --setup')
