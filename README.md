# FW Sentinel

**English** · [Русский](README.ru.md)

A small firewall guard for a Linux VPN server. It loads public threat lists into `nftables`, bans port scanners and SSH brute-forcers, and gives you a web panel that shows what is happening, live.

One Python process per job, the standard library only, no database server, no containers.

> **Status: beta.** It drops network traffic. Start in `observe` mode, keep your provider's console at hand, and read [Limitations](#limitations) first.

## Why

A fresh VPS with a public address is scanned within minutes. The usual answers are either a heavy security stack that does not fit a 1 GB box, or a pile of shell scripts that nobody dares to touch because a mistake locks you out.

FW Sentinel is built around three ideas:

1. **You cannot lock yourself out by accident.** Rules are checked with `nft -c` before loading, the previous policy is saved, and a systemd timer rolls back an unconfirmed change.
2. **See before you block.** `observe` mode logs what *would* happen without dropping anything.
3. **Stay out of the way.** It manages a single table (`inet fw_sentinel`). Your VPN, web server and other firewall rules are not touched.

## What it does

| Feature | How it works |
| --- | --- |
| Threat lists | Known mass scanners, Spamhaus DROP, Blocklist.de, DShield, FireHOL, ThreatView, NERD and others, refreshed daily. Private and reserved ranges are removed; a list that suddenly covers too much of the internet is rejected. |
| ASN and country filters | Block chosen autonomous systems. Optionally limit chosen ports to one country. |
| Port-scan autoban | 6 different closed TCP ports within 60 s, or 8 within an hour (slow scanners). |
| Trap ports | One touch of a port you never use bans the address. |
| SSH protection | A successful login makes the address trusted (key: 30 days, password: 24 hours). 6 failed attempts in 10 minutes, or 10 in 24 hours, ban it. |
| Escalating bans | 24 h → 7 days → 30 days → 180 days → 365 days. Trap and SSH bans start at 1 hour. |
| Manual lists | Trusted, VPN client and banned addresses, one by one or in bulk. |
| Web panel | Live traffic feed, per-address history with ports and counters, country / provider / abuse score, list and policy management. English and Russian. |
| Survives reboots | The last confirmed policy is restored at boot; a watchdog re-applies it if the table disappears. |

## How it works

```
public feeds ──► fw-sentinel sync ──► cache ──► rules ──► nft -c ──► nftables (table inet fw_sentinel)
                                                                         │
kernel log ◄─────────────────────────────────────────────────────────────┘
     │
     └──► fw-sentinel monitor ──► SQLite history, autoban ──► web panel (127.0.0.1:1488)
sshd journal ──────┘
```

| Part | Job |
| --- | --- |
| `fw_sentinel.py` | Command line, feeds, rule generation, apply and rollback |
| `webui.py` | Web panel |
| `autoban.py` | Scan, trap and SSH detection, ban durations |
| `ipmeta.py`, `ipintel.py` | Country, provider and AbuseIPDB score of an address |
| `fw-sentinel-monitor.service` | Reads the kernel log and, if enabled, the sshd journal |
| `fw-sentinel-ui.service` | Runs the panel |
| `fw-sentinel-update.timer` | Daily feed refresh |
| `fw-sentinel-guard.timer` | Every minute: are the rules still there? |
| `fw-sentinel-restore.service` | Restores the confirmed policy at boot |

## Requirements

- Linux with `systemd` and `nftables`; written for Ubuntu 24.04, also running on Ubuntu 26.04
- Python 3.12 or newer, standard library only
- Root access
- Memory: with all large lists enabled (about 520,000 addresses) one measured server used about 70 MB in the kernel and peaked near 290 MB while applying. Large single-address lists are skipped, with a warning, when free memory is too low.

## Install

```bash
git clone https://github.com/Efidripy/fw-sentinel.git
cd fw-sentinel
sudo bash install.sh
```

The installer **does not enable blocking**. It installs the services, adds the address of your current SSH session to the trusted list, and prints the panel login (`admin`) and a generated password, also stored in `/opt/fw-sentinel/ui-token` (root only).

Then go step by step:

```bash
sudo fw-sentinel sync        # download the lists
sudo fw-sentinel observe     # log only, drop nothing
sudo fw-sentinel audit-vpn   # would any of your VPN clients be blocked?
sudo fw-sentinel enable      # block, with a confirmation timer
```

Before `enable`, make sure your own static address is in the trusted list:

```bash
sudo fw-sentinel allow 203.0.113.10
```

## Web panel

The panel listens on `127.0.0.1:1488` only. The simplest and safest way in is an SSH tunnel:

```bash
ssh -L 1488:127.0.0.1:1488 root@YOUR_SERVER
```

Then open `http://127.0.0.1:1488/`.

To publish it behind nginx on a secret path, see [`nginx/fw-sentinel-location.conf.example`](nginx/fw-sentinel-location.conf.example) and tell the panel its address:

```bash
sudo env FWS_UI_BASE_PATH=/your-secret-path/ FWS_UI_PUBLIC_ORIGIN=https://panel.example.com bash install.sh
```

Restrict that location by IP address or VPN. The panel runs as root, has no request rate limit, and must not be open to the whole internet.

| Page | What is there |
| --- | --- |
| Overview | Mode, counters, one-click protection, live feed (refresh from 0.25 to 10 s), top dropped addresses |
| IP log | History grouped by address: ports, counters, first and last seen |
| IP lists | Active bans by reason, trusted and VPN addresses, SSH-trusted addresses, bulk import |
| Threat sources | Every list with its size and update time, refresh per source, API keys |
| Protection settings | Choose lists, autoban, trap ports, SSH protection, then apply |

The interface is English by default; the button in the header switches to Russian.

**Applying from the panel** saves the rules at once when your address (`X-Real-IP` from nginx) is trusted or matches no blocking rule. Otherwise, or when the address is unknown, you have 120 seconds to confirm before the previous policy returns.

## Commands

Run with `sudo fw-sentinel <command>`.

| Command | Action |
| --- | --- |
| `status` | Current mode and counters |
| `sync` | Download and apply fresh lists |
| `observe` / `enable` / `disable` | Log only / block / remove the table (emergency stop) |
| `ban`, `unban`, `allow`, `unallow`, `vpn-add`, `vpn-remove` `<ip>` | Manage the manual lists |
| `auto-unban <ip>` | Lift an automatic ban |
| `check <ip>` | Which lists contain this address |
| `audit-vpn` | VPN clients that a blocking list would catch |
| `hits` | Recorded events |
| `render [--enforce]` | Print the generated rules without loading them |
| `verify-restore` | Is the confirmed policy ready to survive a reboot? |
| `feeds-prepare`, `feeds-status` | The four extra feeds |
| `feeds-catalog-sync [id]`, `feeds-catalog-status` | The large additional catalogue |
| `abuse-key-set` | Store an AbuseIPDB API key |
| `provider set\|disable\|status [id]` | Keys of other providers |
| `menu` | Text menu |

## Settings

Defaults are in [`config.json`](config.json) and are copied to `/opt/fw-sentinel/config.json` on the first install; an upgrade only adds new keys. Most of them are switches in the panel.

| Key | Meaning |
| --- | --- |
| `ssh_ports`, `wan_interfaces` | Detected at install; check them |
| `vpn_ports` | Ports your VPN listens on |
| `scanner_enabled`, `asn_enabled`, `geo_enabled` | Scanner lists, `asn.txt`, country filter |
| `extra_threat_feeds_enabled`, `advanced_feed_pack_enabled` | Extra and large lists |
| `autoban_enabled`, `autoban_trap_ports` | Port-scan autoban and trap ports |
| `autoban_exclude_tcp_ports`, `autoban_exclude_udp_ports` | Ports that never count as scanning |
| `ssh_watch_enabled` | SSH trust and brute-force ban (needs autoban and `enable`) |
| `event_retention_days` | How long the history is kept |

Listening services, SSH and VPN ports are never counted as scanning, whatever the exclusion lists say.

## API keys

All blocking works without any key. An AbuseIPDB key adds its list and the abuse score in the panel. The panel can also store keys for other providers, but **only AbuseIPDB is integrated today**. Keys stay on your server.

## Upgrade, emergency stop, removal

Upgrade: `git pull && sudo bash install.sh`. Settings, lists, history and password are kept.

Emergency stop, from SSH or the provider console:

```bash
sudo fw-sentinel disable
```

Removal:

```bash
sudo fw-sentinel disable
sudo systemctl disable --now fw-sentinel-ui fw-sentinel-monitor fw-sentinel-restore fw-sentinel-update.timer fw-sentinel-guard.timer
sudo rm -r /etc/systemd/system/fw-sentinel-* /usr/local/lib/fw-sentinel /usr/local/sbin/fw-sentinel
sudo rm -r /opt/fw-sentinel   # settings, lists and history
sudo systemctl daemon-reload
```

## Limitations

- Public lists are other people's data, fetched without version pinning. Broad lists may include shared (NAT, carrier) addresses of real users. Use `observe` and `audit-vpn` first.
- Connections that are already established are normally not cut by new rules.
- A port-scan ban needs only a SYN packet, so a forged source address can get a third party banned. Open and service ports are excluded from that ban.
- Logging is rate limited, so counters are a lower bound under heavy traffic.
- Automated tests replace `nft` and `systemd` with stand-ins. Verify the behaviour on your own server.

## Development

```bash
python3 -m unittest discover -s tests   # Linux or WSL
bash -n install.sh
```

## License

[MIT](LICENSE). The threat lists belong to their publishers and have their own terms.
