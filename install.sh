#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
if ((EUID!=0)); then echo 'Root required: sudo bash install.sh' >&2; exit 1; fi
cd -- "$(dirname -- "$(readlink -f -- "$0")")"
for f in bin/fw-sentinel fw_sentinel.py webui.py tui.py i18n.py ipmeta.py ipintel.py credentials.py autoban.py provider_keys.py config.json sources.json allow.txt manual-bans.txt vpn-clients.txt asn.txt; do
  test -f "$f" || { echo "Missing $f" >&2; exit 1; }
done
# Validate all Python sources before changing anything on the target system.
/usr/bin/python3 -m py_compile fw_sentinel.py webui.py tui.py i18n.py autoban.py ipmeta.py ipintel.py credentials.py provider_keys.py
/bin/sh -n bin/fw-sentinel
/usr/bin/python3 fw_sentinel.py --version | grep -Fxq 'FW Sentinel 2.0.21' || {
  echo 'FW Sentinel 2.0.21 module check failed before installation' >&2
  exit 1
}
# Keep the existing allow-list untouched on an upgrade.
FWS_EXISTING=0
if test -e /opt/fw-sentinel/config.json; then FWS_EXISTING=1; fi
if test -e /usr/local/sbin/fw-sentinel && ! test -e /opt/fw-sentinel/config.json; then
  echo 'WARNING: an existing fw-sentinel command was found. The new installer will replace it.' >&2
  echo 'If v1.0 is installed, back up its settings and data first.' >&2
  exit 1
fi
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 nftables iproute2 ca-certificates util-linux
install -d -m 0700 /opt/fw-sentinel /opt/fw-sentinel/cache /opt/fw-sentinel/cache/sources
install -d -m 0755 /usr/local/lib/fw-sentinel /usr/local/sbin
# The CLI is a launcher; its real Python script and modules live together.
# This prevents ModuleNotFoundError: autoban for CLI and systemd services.
install -m 0644 fw_sentinel.py webui.py tui.py i18n.py ipmeta.py ipintel.py credentials.py autoban.py provider_keys.py /usr/local/lib/fw-sentinel/
install -m 0755 bin/fw-sentinel /usr/local/sbin/fw-sentinel
# Run the actual installed executable, not just imports from the source checkout.
if ! /usr/local/sbin/fw-sentinel --version | grep -Fxq 'FW Sentinel 2.0.21'; then
  echo 'ERROR: the installed CLI cannot load FW Sentinel modules!' >&2
  exit 1
fi
/usr/bin/python3 - <<'PY_IMPORT_SMOKE'
import sys
sys.path.insert(0, '/usr/local/lib/fw-sentinel')
import fw_sentinel, autoban, webui, ipmeta, ipintel, provider_keys
assert fw_sentinel.VERSION == '2.0.21'
assert webui.fw is fw_sentinel
print('Installed Python module check: OK')
PY_IMPORT_SMOKE
for f in sources.json asn.txt allow.txt manual-bans.txt vpn-clients.txt; do
  test -f "/opt/fw-sentinel/$f" || install -m 0600 "$f" "/opt/fw-sentinel/$f"
done
if ! test -f /opt/fw-sentinel/config.json; then
  python3 - <<'PY'
import json,subprocess
from pathlib import Path
cfg=json.loads(Path('config.json').read_text())
interfaces=set()
for family in ('-4','-6'):
    p=subprocess.run(['ip',family,'route','show','default'],capture_output=True,text=True)
    for line in p.stdout.splitlines():
        fields=line.split()
        if 'dev' in fields:
            dev=fields[fields.index('dev')+1]
            if dev!='lo':interfaces.add(dev)
cfg['wan_interfaces']=sorted(interfaces)
from fw_sentinel import detect_ssh_ports
cfg['ssh_ports']=detect_ssh_ports() or cfg['ssh_ports']
print('SSH ports:',cfg['ssh_ports'])
Path('/opt/fw-sentinel/config.json').write_text(json.dumps(cfg,ensure_ascii=False,indent=2)+'\n')
print('External interfaces found:',cfg['wan_interfaces'] or 'NOT FOUND: enter manually')
PY
  chmod 0600 /opt/fw-sentinel/config.json
fi
# Safe migration: append only NEW 2.0.21 keys; never overwrite existing user settings.
# Changes in source configuration invalidate the previous policy signature:
# the administrator must explicitly observe and confirm before new enforcement.
python3 - <<'PY_MIGRATE209'
import json,os,tempfile
from pathlib import Path
root=Path('/opt/fw-sentinel')
for name in ('config.json','sources.json'):
    target=root/name
    old=json.loads(target.read_text(encoding='utf-8'))
    fresh=json.loads(Path(name).read_text(encoding='utf-8'))
    change=False
    for key,value in fresh.items():
        if key not in old:
            old[key]=value;change=True
    if name=='sources.json':
        for category in ('threat_ssh','threat_watch','advanced_feeds'):
            old.setdefault(category,{})
            for key,value in fresh[category].items():
                if key not in old[category]:old[category][key]=value;change=True
    if name=='config.json' and old.get('version')!='2.0.21':
        old['version']='2.0.21';change=True
    if change:
        backup=target.with_suffix(target.suffix+'.before-2.0.21')
        if not backup.exists():backup.write_bytes(target.read_bytes());os.chmod(backup,0o600)
        fd,tmp=tempfile.mkstemp(prefix='.migrate-',dir=root)
        try:
            os.fchmod(fd,0o600)
            with os.fdopen(fd,'w',encoding='utf-8') as f:
                json.dump(old,f,indent=2,ensure_ascii=False);f.write('\n');f.flush();os.fsync(f.fileno())
            os.replace(tmp,target)
        finally:
            if os.path.exists(tmp):os.unlink(tmp)
        print('New settings updated:',name,'(old copy:',backup,')')
PY_MIGRATE209
# Existing configs are never rewritten: only report a wrong SSH port.
PYTHONDONTWRITEBYTECODE=1 python3 -c 'import sys; sys.path.insert(0,"/usr/local/lib/fw-sentinel"); import fw_sentinel as f; w=f.ssh_port_warning(f.config()); w and print("WARNING:",w)'
# Credential keys are stored in owner-only files. An empty entry disables that
# specific API integration; upgrades do not touch prior credentials unless the
# operator explicitly agrees to enter the key setup again.
if [[ -t 0 && "${FWS_SKIP_PROVIDER_SETUP:-0}" != "1" ]]; then
  printf '\n%s\n' 'Additional APIs (registration required): set keys now? [y/N]'
  read -r -p '> ' FWS_SET_KEYS || FWS_SET_KEYS=N
  if [[ "$FWS_SET_KEYS" =~ ^[Yy]$ ]]; then
    /usr/bin/python3 /usr/local/lib/fw-sentinel/provider_keys.py --setup
  else
    echo 'Skipped: sources without keys remain disabled.'
  fi
fi
# Explicit UI-only settings; never touch firewall state, IP lists or credentials.
# Optional installer invocation:
# sudo env FWS_UI_BASE_PATH=/secret/ FWS_UI_PUBLIC_ORIGIN=https://hostname bash install.sh
python3 - <<'PY_UI_ROUTING'
import json,os,re,tempfile
from pathlib import Path
from urllib.parse import urlsplit
p=Path('/opt/fw-sentinel/config.json')
cfg=json.loads(p.read_text(encoding='utf-8'))
base=os.environ.get('FWS_UI_BASE_PATH')
origin=os.environ.get('FWS_UI_PUBLIC_ORIGIN')
if base is not None and (len(base)>128 or not re.fullmatch(r'/(?:[A-Za-z0-9_-]+/)*',base)):
    raise SystemExit('FWS_UI_BASE_PATH must be / or /secret/ (with a trailing /)')
if origin is not None and origin and (len(origin)>255 or not re.fullmatch(r'https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?',origin)):
    raise SystemExit('FWS_UI_PUBLIC_ORIGIN must be in the form https://hostname without a path')
if origin is not None and not origin and (base or cfg.get('ui_base_path','/'))!='/':
    print('Warning: FWS_UI_PUBLIC_ORIGIN must be set when using external Nginx')
if base is not None:cfg['ui_base_path']=base
if origin is not None:cfg['ui_public_origin']=origin.lower()
if base is not None or origin is not None:
    fd,staged=tempfile.mkstemp(prefix='.ui-routing-',dir=p.parent)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'w',encoding='utf-8') as f:
            json.dump(cfg,f,indent=2,ensure_ascii=False);f.write('\n');f.flush();os.fsync(f.fileno())
        os.replace(staged,p)
    finally:
        if os.path.exists(staged):os.unlink(staged)
print('Web UI prefix:',cfg.get('ui_base_path','/'),'· origin:',cfg.get('ui_public_origin') or 'SSH/local only')
PY_UI_ROUTING
if [[ "$FWS_EXISTING" == 1 ]]; then
  echo 'Update: the current trusted IP list will not be changed.'
elif [[ -n "${SSH_CONNECTION:-}" ]]; then
  client=${SSH_CONNECTION%% *}
  if python3 - "$client" <<'PY'
import ipaddress,sys
ip=ipaddress.ip_address(sys.argv[1]);assert ip.is_global
PY
  then
    if ! grep -Fqx "$client" /opt/fw-sentinel/allow.txt; then
      printf '\n%s  # detected from SSH_CONNECTION during installation\n' "$client" >> /opt/fw-sentinel/allow.txt
      echo "Current SSH IP ($client) added to the trusted list."
    fi
  fi
else
  echo 'WARNING: SSH_CONNECTION is not set — add your IP to allow.txt manually.'
fi
# New installs: generate 12-character password. Legacy 43-character tokens
# from 2.0.1-2.0.3: rotate once; preserve other/custom credentials.
# Password stays in root-owned file and a shell variable until final summary.
mapfile -t FWS_CREDENTIALS < <(python3 /usr/local/lib/fw-sentinel/credentials.py)
if ((${#FWS_CREDENTIALS[@]}!=2)) || [[ ${#FWS_CREDENTIALS[1]} -lt 8 ]]; then
  echo 'Failed to prepare web panel credentials' >&2
  exit 1
fi
FWS_UI_ACTION=${FWS_CREDENTIALS[0]}
FWS_UI_PASSWORD=${FWS_CREDENTIALS[1]}
unset FWS_CREDENTIALS
for f in fw-sentinel-restore.service fw-sentinel-ui.service fw-sentinel-monitor.service fw-sentinel-update.service fw-sentinel-update.timer fw-sentinel-guard.service fw-sentinel-guard.timer; do
  install -m 0644 "systemd/$f" "/etc/systemd/system/$f"
done
systemctl daemon-reload
systemctl enable fw-sentinel-restore.service
# Do not run restore.service at upgrade time: it could recreate an active nft table.
# The 2.0.9 import bug left the monitor in a repeated-failure state; clear it.
systemctl reset-failed fw-sentinel-monitor.service || true
systemctl enable --now fw-sentinel-ui.service fw-sentinel-monitor.service fw-sentinel-update.timer fw-sentinel-guard.timer
# Restart only UI and monitoring, never the VPN or nftables services.
systemctl restart fw-sentinel-ui.service fw-sentinel-monitor.service
# The port is configurable; always bind to loopback (see webui.py).
FWS_UI_PORT=$(python3 - <<'PY_UI_PORT'
import json
with open('/opt/fw-sentinel/config.json',encoding='utf-8') as f:
    port=json.load(f).get('ui_port',1488)
if type(port) is not int or not 1024<=port<=65535:
    raise SystemExit('Invalid ui_port: check /opt/fw-sentinel/config.json')
print(port)
PY_UI_PORT
)
mapfile -t FWS_UI_LOCATION < <(python3 - <<'PY_UI_LOCATION'
import json
c=json.load(open('/opt/fw-sentinel/config.json',encoding='utf-8'))
print(c.get('ui_base_path','/'))
print((c.get('ui_public_origin') or '').rstrip('/'))
PY_UI_LOCATION
)
FWS_BASE=${FWS_UI_LOCATION[0]}
FWS_PUBLIC=${FWS_UI_LOCATION[1]}
printf '\n'
printf '%s\n' '=========================================================='
printf '%s\n' '         FW SENTINEL 2.0.21 — INSTALLED'
printf '%s\n' '=========================================================='
printf 'PANEL (local): http://127.0.0.1:%s%s\n' "$FWS_UI_PORT" "$FWS_BASE"
if [[ -n $FWS_PUBLIC ]]; then printf 'PANEL (HTTPS):    %s%s\n' "$FWS_PUBLIC" "$FWS_BASE"; fi
printf '%s\n' 'LOGIN:   admin'
printf 'PASSWORD:  %s\n' "$FWS_UI_PASSWORD"
printf '%s\n' 'File:    /opt/fw-sentinel/ui-token (root only, 0600)'
if [[ $FWS_UI_ACTION == rotated-legacy ]]; then
  printf '%s\n' 'IMPORTANT: the old long password from 2.0.3 has been replaced with a new one.'
elif [[ $FWS_UI_ACTION == preserved ]]; then
  printf '%s\n' 'Existing password kept (reinstallation).'
fi
printf '\n%s\n' 'Open a tunnel on your computer:'
printf 'ssh -L %s:127.0.0.1:%s USER@SERVER_IP\n' "$FWS_UI_PORT" "$FWS_UI_PORT"
printf '\n%s\n' 'Radar: 0.25 seconds, active tab only; requests do not overlap.'
printf '%s\n' 'Do not publish the password or share the installation log.'
printf '%s\n' 'DROP rules are not enabled: first sync -> observe -> audit-vpn -> enable.'
printf '%s\n' '=========================================================='
unset FWS_UI_PASSWORD FWS_UI_ACTION FWS_BASE FWS_PUBLIC FWS_UI_LOCATION
