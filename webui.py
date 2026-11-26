#!/usr/bin/env python3
"""Local-only, authenticated FW Sentinel administration UI. No third-party dependencies."""
from __future__ import annotations
import base64
from i18n import tr
import hashlib
import hmac
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import time
import json
import secrets
import re
from urllib.parse import parse_qs, urlsplit, urlencode

import fw_sentinel as fw
import i18n
import autoban
import ipmeta
import ipintel
import provider_keys

TOKEN_FILE=fw.ROOT/'ui-token'

CSS='''
:root{color-scheme:dark;--bg:#080e19;--panel:#101c2e;--line:#253550;--text:#e9f2ff;--muted:#91a8c4;--green:#54deae;--yellow:#ffce66;--red:#ff758e;--cyan:#72c8ff}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 20% -10%,#162b45 0,transparent 55%),var(--bg);color:var(--text);font:14px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}a{color:var(--cyan)}
header{display:flex;align-items:center;justify-content:space-between;padding:21px 0;border-bottom:1px solid var(--line);gap:20px}header .brand{display:flex;align-items:center;gap:12px}header h1{margin:0;font-size:20px;letter-spacing:.3px}nav{display:flex;gap:18px;flex-wrap:wrap}nav a{text-decoration:none;color:var(--muted)}nav a:hover{color:#fff}nav form{margin:0}nav .lang-btn{padding:2px 8px;font-size:11px}.control-forms{display:flex;flex-wrap:wrap;align-items:center;gap:9px}.control-forms form{margin:0}.control-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.control-choice{display:flex;align-items:center;gap:10px;padding:11px 13px;border:1px solid var(--line);border-radius:8px;background:#0c192b}.control-choice input{min-width:auto;width:17px;height:17px;margin:0}.control-choice:has(input:checked){border-color:#4e89b5}.control-choice span{flex:1}.control-panel{background:linear-gradient(130deg,#12233a,#101927);border:1px solid #426086;border-radius:14px;padding:20px;margin:18px 0}.control-panel h3{margin:0 0 12px}.control-panel form{display:block}.control-panel form button{margin:8px 0 0}.control-panel form input[type=text]{width:100%}.confirm-box{padding:18px;border:1px solid #a78349;border-radius:10px;background:#292015;color:#ffdf9b}.confirm-box form{display:flex}.small-note{font-size:12px;color:#aec4df}.control-panel .block-button{display:block;margin-top:15px}.control-actions{display:flex;gap:10px;flex-wrap:wrap}.control-actions form{display:inline-flex}.policy-tile{padding:12px;border:1px solid #29425e;border-radius:8px;background:#0b1727}.policy-tile summary{cursor:pointer}@media(max-width:620px){.control-grid{grid-template-columns:1fr}}
main{max-width:1180px;padding:0 24px 70px;margin:auto}h2{margin:36px 0 14px;font-size:19px}p,.sub{color:var(--muted)}.sub{font-size:12px}.dot{color:var(--green);font-size:26px}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin-top:28px}.card{background:linear-gradient(150deg,#13233b,var(--panel));border:1px solid var(--line);border-radius:14px;padding:22px;min-width:0}.label{font-size:12px;letter-spacing:.7px;text-transform:uppercase;color:var(--muted)}.num{font-size:30px;font-weight:700;margin:9px 0 0}.tag{display:inline-block;padding:4px 10px;border-radius:99px;font-weight:650;font-size:12px;background:#23364d;color:var(--cyan)}.good{color:var(--green)}.caution{color:var(--yellow)}.bad{color:var(--red)}.wide{grid-column:span 2}table{border-collapse:collapse;width:100%;font-size:13px}td,th{border-bottom:1px solid var(--line);padding:12px 10px;text-align:left;white-space:nowrap}th{color:var(--muted);font-weight:500;text-transform:uppercase;font-size:11px;letter-spacing:.5px}.scroll{overflow-x:auto}.tools{display:flex;flex-wrap:wrap;gap:12px;align-items:center}form{display:flex;gap:7px;align-items:center;flex-wrap:wrap}input{background:#081425;border:1px solid #355070;border-radius:8px;color:var(--text);padding:10px 12px;min-width:185px}button{background:#22618b;border:1px solid #3685bd;border-radius:8px;color:white;padding:10px 14px;font-weight:600;cursor:pointer}button:hover{background:#3177a3}button:disabled{opacity:.48;cursor:not-allowed}.danger-btn{background:#67243d;border-color:#9a3a56}.danger-btn:hover{background:#873750}.muted{color:var(--muted)}.warning{border-color:#775e33;background:#291e18;color:#ffda89;padding:12px 16px;border-radius:9px;margin-top:18px}.hint{background:#101d2e;padding:13px;border:1px solid var(--line);border-radius:9px}.section-row{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}.empty{text-align:center;padding:26px;color:var(--muted)}code{font:12px ui-monospace,SFMono-Regular,Consolas,monospace;color:#a8defe}
/* Cinema-style, read-only live security telemetry */
.radar{position:relative;overflow:hidden;padding:18px 20px;background:linear-gradient(135deg,#091b27,#0c1325);border:1px solid #294258;border-radius:13px;box-shadow:inset 0 0 65px #1f42501a}
.radar::before{content:'';pointer-events:none;position:absolute;inset:0;background:repeating-linear-gradient(to bottom,transparent 0,transparent 22px,#61c6df06 23px);opacity:.9}
.radar-head{position:relative;display:flex;gap:12px;flex-wrap:wrap;align-items:center;justify-content:space-between}
.radar-title{font:600 13px ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:1px;color:#8bffdb}
.radar-controls{display:flex;align-items:center;gap:12px;flex-wrap:wrap}.radar button{font:600 12px ui-monospace,monospace;padding:7px 11px;background:#143047;border-color:#295877}
.radar-status{font:12px ui-monospace,monospace;color:#96b2c7}
.live-led{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 12px var(--green);margin-right:5px}
.live-paused .live-led{background:var(--yellow);box-shadow:none}
.live-list{position:relative;min-height:180px;max-height:350px;overflow:auto;margin-top:14px;display:flex;flex-direction:column;gap:5px}
.live-entry{display:grid;grid-template-columns:87px 100px minmax(120px,1fr) 82px 100px;gap:11px;align-items:center;background:#ffffff08;padding:8px 12px;border-left:3px solid var(--yellow);border-radius:4px;font:12px ui-monospace,SFMono-Regular,Consolas,monospace;animation:popin .26s ease-out}
.live-entry.pass{border-color:var(--green);color:var(--green)}.live-entry.drop{border-color:var(--red);color:var(--red)}.live-entry.observe{border-color:var(--yellow);color:var(--yellow)}
.live-entry .live-time{color:#94aec3}.live-entry .live-address{overflow-wrap:anywhere}.live-entry .live-detail{color:#bccfdf;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.live-legend{position:relative;display:flex;gap:16px;flex-wrap:wrap;margin-top:12px;font-size:11px;color:#a3b4c7}.live-legend b{font-weight:600}
/* Read-only live radar verdict filters and compact, paginated IP event groups */
.radar-filter{display:flex;gap:5px;align-items:center;flex-wrap:wrap}
.radar .radar-filter button{background:#102237;border-color:#38516c;color:#aac1d4;min-width:76px}
.radar .radar-filter button[aria-pressed="true"]{background:#244363;color:white;border-color:#7ba7cc;box-shadow:inset 0 0 0 1px #648eb1}
.radar .radar-filter button[data-live-filter="observe"][aria-pressed="true"]{color:var(--yellow);border-color:#ba9650}
.radar .radar-filter button[data-live-filter="drop"][aria-pressed="true"]{color:var(--red);border-color:#c56a84}
.event-tools{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.event-tools select{padding:10px 12px;border:1px solid #355070;border-radius:8px;color:var(--text);background:#081425}
.events-list{display:flex;flex-direction:column;gap:10px}
.ip-group{background:linear-gradient(150deg,#13233b,var(--panel));border:1px solid var(--line);border-radius:12px;overflow:hidden}
.ip-group[open]{border-color:#436184}
.ip-group summary{cursor:pointer;display:flex;gap:15px;flex-wrap:wrap;align-items:center;padding:16px 18px;list-style:none}
.ip-group summary::-webkit-details-marker{display:none}
.ip-group summary:before{content:'▸';color:var(--cyan)}.ip-group[open] summary:before{content:'▾'}
.ip-group summary:hover{background:#ffffff07}
.ip-main{font:700 14px ui-monospace,SFMono-Regular,Consolas,monospace;color:#dcefff}
.ip-count{font-weight:650;color:var(--text)}
.ip-stats{display:flex;gap:10px;flex-wrap:wrap;margin-left:auto;font-size:12px}
.ip-stats span{white-space:nowrap}
.ip-details{padding:0 18px 18px;border-top:1px solid var(--line)}
.ip-details table{margin-top:8px}.ip-details td{white-space:normal}
.events-pager{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin:15px 0}
.events-pager a{display:inline-block;padding:9px 15px;border:1px solid #385c7c;border-radius:8px;text-decoration:none}
.events-pager a:hover{background:#193b59}
@media(max-width:700px){.ip-stats{margin-left:0;width:100%}.ip-group summary{gap:8px}.radar-filter{width:100%}}

/* Per-IP security actions and on-demand external IP information */
.ip-meta{display:flex;gap:11px;align-items:center;flex-wrap:wrap;background:#0d2031;border:1px solid #2c4962;border-radius:8px;padding:10px 12px;margin:10px 0}
.ip-meta span{font-size:12px;color:#bed1e1;overflow-wrap:anywhere}.ip-meta strong{color:#9cdbfb}
.ip-meta button{font-size:12px;padding:6px 10px}
.ip-action{padding:10px 0;display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.ip-action form{margin:0}
.ip-action .danger-btn{padding:8px 12px}
.event-tools label{font-size:12px;color:var(--muted)}

@keyframes popin{from{opacity:0;transform:translateY(-5px)}to{opacity:1;transform:translateY(0)}}
@media(max-width:700px){.live-entry{grid-template-columns:65px minmax(90px,1fr) 86px;gap:7px;font-size:11px}.live-entry .live-type{display:none}.live-entry .live-detail{grid-column:2 / 4;grid-row:2}}
@media(max-width:900px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.wide{grid-column:span 2}}@media(max-width:540px){.grid{grid-template-columns:1fr}.wide{grid-column:span 1}header{flex-direction:column;align-items:flex-start}.num{font-size:24px}}
/* 2.0.16: three ACTUAL side-by-side IP cards, not three table fields. */
.blocked-ip-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;width:100%;align-items:stretch}
.blocked-ip-card{display:flex;flex-direction:column;gap:10px;min-width:0;padding:14px;border:1px solid #2d5948;background:#0b1d1b;box-shadow:inset 2px 0 #287556}
.blocked-ip-card:hover{border-color:#57bd8b;background:#0c2620}
.blocked-ip-card.hit{border-color:#ff7b87;background:#2a1a1d}
.blocked-ip-top{display:flex;justify-content:space-between;align-items:flex-start;gap:8px;flex-wrap:wrap}
.blocked-ip-address{font-size:14px;font-weight:800;color:#78e8b5;text-decoration:none;overflow-wrap:anywhere}
.blocked-ip-address:hover{text-decoration:underline;color:#bbffdd}
.blocked-ip-count{display:inline-flex;align-items:center;gap:7px;white-space:nowrap;font-variant-numeric:tabular-nums;color:#ff8190;font-weight:800;font-size:15px}
.blocked-ip-count::before{content:'DROP';color:#a9c9ba;font-size:10px;letter-spacing:.5px;font-weight:500}
.blocked-ip-card .ip-intel{margin-top:0;flex:1}
.blocked-ip-bottom{border-top:1px solid #25483d;padding-top:8px;color:#9cbaa9;font-size:11px}
.blocked-ip-bottom time{color:#d8eadd;white-space:nowrap}
.blocked-ip-empty{grid-column:1/-1;padding:28px 15px;text-align:center;color:#8fb4a5;border:1px dashed #2d5948}
@media(max-width:1050px){.blocked-ip-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:670px){.blocked-ip-grid{grid-template-columns:minmax(0,1fr)}}
.ip-intel{display:block;font-size:11px;line-height:1.6;color:#85b69d;white-space:normal;margin-top:3px;overflow-wrap:anywhere}
.ip-intel .score{font-weight:800;color:#71e8ab}
.ip-intel .score.mid{color:#f9ca70}.ip-intel .score.high{color:#ff7b87}
.block-hub{margin:12px 0 20px}
.block-hub .primary{border:1px solid #397b60;background:#0b1b18;padding:15px;margin:10px 0}
.block-hub .primary .scroll{overflow-x:auto}
.block-hub table{width:100%}
.block-hub td{white-space:normal;vertical-align:top}
.block-hub .ip-entry{min-width:220px}
.block-hub .secondary{font-size:11px;color:var(--muted)}
.manual-lists{border:1px solid var(--line);padding:12px 16px;margin:22px 0;background:#0d1918}
.manual-lists>summary{cursor:pointer;font-size:14px;font-weight:800;color:var(--green);padding:5px 0}
.manual-lists>summary:hover{text-decoration:underline}
@media(max-width:650px){.ip-intel{font-size:11px}.block-hub .scroll table{min-width:570px}}

'''


# Presentation-only terminal skin. No new network requests or dependencies.
CSS += r'''
.shield-state{border:1px solid #4c926d;background:#0b231c;padding:14px 18px;margin:12px 0;color:#9af3be}
.shield-state.trial{border-color:#ddad4d;background:#2b210d;color:#ffe3a3}
.shield-state.off{border-color:#5a6b70;background:#122026;color:#b4c6c8}
.shield-state strong{display:block;font-size:15px;color:inherit;margin-bottom:5px}
.shield-state .control-actions{display:flex;flex-wrap:wrap;align-items:center;gap:10px;margin:12px 0 0}.shield-state .control-actions form{margin:0}.shield-state a{color:#85e5c3}
.shield-state a.good-btn{display:inline-block;border:1px solid #47b684;border-radius:2px;padding:9px 14px;font:700 12px ui-monospace,Consolas,monospace;line-height:normal;text-decoration:none}
.shield-state .danger-btn{background:#783143;border-color:#e06f84}
.shield-state .good-btn{background:#166d46;border-color:#47b684;color:#f1fffa;font-weight:800}
.shield-state .good-btn:hover{background:#21895b}
.shield-state .trial-count{font-size:20px;font-weight:800;color:#ffe09c;font-variant-numeric:tabular-nums}
.restore-check td{white-space:normal}.restore-check .ok{color:#6ff0af}.restore-check .fail{color:#ff8b92}
/* FW Sentinel Shell UI — accessible terminal theme, functional controls unchanged */
:root{
  color-scheme:dark;--bg:#070c11;--panel:#0b1419;--line:#25433d;
  --text:#dae9e4;--muted:#89aba3;--green:#5ae3aa;--yellow:#f6c86c;
  --red:#ff7384;--cyan:#7bdcd7;--shade:#112821;--shell-ink:#9cddc2
}
html{scroll-behavior:smooth}
body{
  min-height:100vh;color:var(--text);font:13px/1.6 ui-monospace,SFMono-Regular,Consolas,'Liberation Mono',monospace;
  background:#070b0e;
  background-image:linear-gradient(90deg,rgba(31,84,67,.045) 1px,transparent 1px),
                   linear-gradient(rgba(31,84,67,.037) 1px,transparent 1px);
  background-size:32px 32px;
  font-variant-ligatures:none
}
body::before{
  content:'';position:fixed;inset:0;pointer-events:none;z-index:50;opacity:.2;
  background:repeating-linear-gradient(0deg,transparent,transparent 4px,rgba(0,0,0,.15) 5px)
}
main{max-width:1420px;padding:20px 26px 48px;margin:0 auto}
.shell-chrome{border:1px solid #346453;background:#0c171a;box-shadow:0 15px 58px #0006}
.shell-windowbar{display:flex;justify-content:space-between;gap:12px;align-items:center;
  background:linear-gradient(90deg,#16352c,#0d191b);padding:8px 16px;border-bottom:1px solid #315c4c;
  color:#91ddbb;font-size:11px;letter-spacing:1.2px;text-transform:uppercase}
.shell-lamps{display:inline-flex;gap:7px;align-items:center;flex-shrink:0}
.shell-lamps span{display:inline-block;width:9px;height:9px;border-radius:50%;background:#ff7b83;box-shadow:0 0 8px #ff7b8329}
.shell-lamps span:nth-child(2){background:#f2c36c;box-shadow:0 0 8px #f2c36c22}
.shell-lamps span:nth-child(3){background:#62dfa7;box-shadow:0 0 8px #62dfa722}
.shell-window-name{flex:1;text-align:center}.shell-window-tag{color:#67b497}
header{margin:0;padding:16px 18px;display:flex;align-items:center;justify-content:space-between;
  border-bottom:1px solid #24483b;gap:20px;background:#0a1416}
header h1{font-size:17px;font-weight:800;letter-spacing:1px;color:#e8fff5;white-space:nowrap}
header .brand{gap:10px}header .brand .dot{font-size:20px;color:#61e4a6}
header .brand small{font-size:11px;color:#6ea68f}
header nav{gap:5px;flex-wrap:wrap}
header nav a{display:inline-block;padding:6px 10px;color:#88beae;text-decoration:none;
  border:1px solid transparent;font-size:12px;letter-spacing:.1px}
header nav a::before{content:'./';color:#477f68}
header nav a:hover,header nav a:focus-visible{color:#bfffe2;background:#102e25;border-color:#346a53}
header nav a[aria-current="page"]{color:#091b14;background:#65e0a8;border-color:#65e0a8;font-weight:800}
header nav a[aria-current="page"]::before{color:#267256}
.shell-prompt{padding:11px 18px;background:#081114;display:flex;gap:8px;align-items:center;flex-wrap:wrap;
  border-bottom:1px solid #27483f;color:#bdcfc6;font-size:12px}
.shell-prompt .shell-host{color:#62e2ad;font-weight:800}
.shell-prompt .shell-tilde{color:#82cad9}
.shell-prompt .shell-command{color:#dfefdf}
.shell-caret{color:#61dfa5;animation:blink 1.2s step-end infinite}
.shell-terminal-status{margin-left:auto;color:#6aab94;font-size:10px;letter-spacing:.8px}
.terminal-footer{display:flex;gap:10px;justify-content:space-between;flex-wrap:wrap;
  border:1px solid #254839;border-top:2px solid #4cb98a;background:#0a1717;
  color:#719e8b;padding:11px 14px;margin:26px 0 8px;font-size:11px}
.terminal-footer strong{color:var(--green)}
h2{color:#b8f9da;font-size:16px;font-weight:800;letter-spacing:.25px;
  margin:32px 0 15px;padding-bottom:8px;border-bottom:1px solid #23443b}
h2::before{content:'> ';color:#51cf96}
h3{color:#dbf5e8;font-size:14px;font-weight:750}
p,.sub{color:#8daea5;line-height:1.65}.sub{font-size:11px}
a{color:#81e6c6;text-underline-offset:3px}a:hover{color:#d3ffea}
.grid{gap:10px;margin-top:15px}.card,.ip-group,.control-panel,.policy-tile{
  background:#0d171a;border:1px solid #2b4e42;border-radius:0;box-shadow:inset 3px 0 0 #325b47}
.card{padding:18px 18px 16px;transition:border-color .12s ease}
.card:hover{border-color:#43876b}.card .num{line-height:1.35;font-size:26px;overflow-wrap:anywhere;
  font-weight:800;margin:11px 0 0;color:#edf9f1}
.card .num.good{color:var(--green)}.card .num.caution{color:var(--yellow)}.card .num.bad{color:var(--red)}
.card .label{color:#86baa8;font-size:11px;letter-spacing:1.2px}
.card .label::before{content:'// ';color:#509b78}
.card.wide{min-height:128px}
.tag{border-radius:2px;border:1px solid #2d7258;padding:4px 9px;
  background:#112b23;color:#8cf3bd;font-size:11px;letter-spacing:.5px;font-weight:750}
.tag::before{content:'[ ';color:#66b58b}.tag::after{content:' ]';color:#66b58b}
.good{color:var(--green)}.bad{color:var(--red)}.caution{color:var(--yellow)}
.section-row{gap:14px}.section-row h2{flex:1;min-width:180px}
.live-head{align-items:flex-end}.live-head select{margin-bottom:15px;min-height:0;padding:5px 8px;color:#7cf4b7;cursor:pointer}
.scroll{overflow-x:auto}
table{font-size:12px;font-variant-numeric:tabular-nums}
td,th{padding:10px 9px;border-color:#244238}
thead{background:#142922}th{color:#a3d2bb;font-weight:700;letter-spacing:1px}
tbody tr:nth-child(even){background:#0c1e1a}tbody tr:hover{background:#183028}
code{color:#80e9c7;font:12px ui-monospace,SFMono-Regular,Consolas,monospace;
  background:#112922;padding:2px 4px;overflow-wrap:anywhere}
input,select,textarea,.event-tools select{border-radius:2px;color:#edfff5;background:#081711;
  border:1px solid #37705a;padding:9px 12px;min-height:39px;font:12px ui-monospace,Consolas,monospace}
input::placeholder{color:#648979}
input:focus-visible,select:focus-visible,button:focus-visible,a:focus-visible,summary:focus-visible{
  outline:2px solid #7cf4b7;outline-offset:2px}
input[type=checkbox],input[type=radio]{min-height:0;accent-color:#57d79e}
button,.radar button{border-radius:2px;background:#174632;border:1px solid #3b9568;color:#c6ffdc;
  padding:9px 14px;font:700 12px ui-monospace,Consolas,monospace;box-shadow:none}
button:hover,.radar button:hover{background:#215b40;border-color:#6fdb9d;color:#fff}
button:disabled{opacity:.45;cursor:not-allowed;background:#14241e;border-color:#34473c}
.danger-btn{background:#4a1d29;border-color:#bd5469;color:#ffe2e9}.danger-btn:hover{background:#6a2635;border-color:#ff758e}
.control-forms{gap:8px}.control-panel{margin:14px 0;padding:19px}
.control-panel h3::before{content:'$ ';color:#5bd9a6}
.control-panel .control-choice{background:#0b1a19;border:1px solid #315746;border-radius:0}
.control-choice:has(input:checked){background:#113628;border-color:#4cbe86}
.confirm-box,.warning{border:1px solid #aa844e;border-left:4px solid #f6c86c;border-radius:0;
  background:#251e13;color:#ffd98b;padding:14px}
.hint{background:#0c1919;border:1px solid #2c5142;border-radius:0}
.policy-tile{background:#0a1917;padding:12px}
/* Primary streaming console */
.radar{background:#061111;border:1px solid #36735a;border-radius:0;box-shadow:0 0 0 1px #091a15,inset 0 0 65px #0c362320;
  padding:0;overflow:hidden}
.radar::before{background:repeating-linear-gradient(to bottom,transparent 0,transparent 27px,#77df9810 28px);opacity:.32}
.radar-head{padding:14px 16px;background:#10281f;border-bottom:1px solid #315d48;align-items:center}
.radar-title{letter-spacing:.9px;color:#87ffbe;font-size:12px;font-weight:800}
.radar-status{font-size:11px;color:#a5d4bd}
.quick-shield{border:2px solid #43c989!important;background:#0a241c!important}
.quick-shield .quick-shield-btn{font-size:16px;line-height:1.4;padding:15px 19px;background:#19764f;border:2px solid #8df0b8;color:#f2fff8;font-weight:800;box-shadow:0 0 16px #2fbd7333}
.quick-shield .quick-shield-btn:hover{background:#299a68}
.radar-controls{gap:10px}.radar .radar-filter button{background:#0c2019;border-color:#335b4c;color:#a2c9b5;min-width:72px}
.radar .radar-filter button[aria-pressed="true"]{background:#2a6445;border-color:#7bdda6;color:#e4ffec;box-shadow:none}
.radar .radar-filter button[data-live-filter="drop"][aria-pressed="true"]{background:#45202a;border-color:#f46f86;color:#ff97a7}
.radar .radar-filter button[data-live-filter="observe"][aria-pressed="true"]{background:#46351c;border-color:#e2ae54;color:#ffd47d}
.live-columns{position:relative;display:grid;grid-template-columns:87px 100px minmax(120px,1fr) 82px 100px;
  gap:11px;padding:8px 15px;background:#0b1d18;border-bottom:1px solid #315849;color:#618f78;font-size:10px;letter-spacing:1px}
.live-list{min-height:200px;max-height:405px;gap:0;margin-top:0;scrollbar-color:#326e54 #071511}
.live-entry{padding:8px 12px;border-radius:0;background:transparent;
  border-left:3px solid #e3b45d;border-bottom:1px dashed #234237;color:#f6c86c;
  font-size:12px;animation:popin .26s ease-out}
.live-entry:nth-child(odd){background:#0c211921}
.live-entry:hover{background:#1b3b2a}
.live-entry.pass{color:#68edab;border-left-color:#5ae3aa}
.live-entry.drop{color:#ff7488;border-left-color:#ff7488;background:#33151b55}
.live-entry.observe{color:#f6c86c;border-left-color:#e9bd5c}
.live-entry .live-time{color:#8bb09b}.live-entry .live-detail{color:#a1b7a8}
.live-legend{margin:0;padding:12px 15px;border-top:1px solid #2e5240;background:#0b1e17;gap:18px;color:#a4bcae}
.live-led{background:#4de29d;box-shadow:0 0 0 3px #4de29d20,0 0 13px #4de29d}
.radar .sub#radar-health{margin:0;padding:9px 15px;color:#83b5a0;border-top:1px dashed #254738;background:#081512}
.live-paused .live-led{background:#f6c86c}
.empty{color:#819f92}.events-list{gap:5px}
.ip-group{box-shadow:none;border:1px solid #2a5042}
.ip-group[open]{border-color:#59aa83;box-shadow:inset 3px 0 0 #5bd9a6}
.ip-group summary{padding:12px 15px}.ip-group summary::before{color:var(--green)}
.ip-group summary:hover{background:#162e25}
.ip-main{color:#a8f4ca}.ip-count{color:#eafded}
.ip-details{border-top:1px dashed #315846;padding:12px 15px 15px}
.ip-meta{background:#0c211c;border:1px solid #315f4d;border-radius:0;padding:10px}
.ip-meta strong{color:#79eeb8}.ip-meta span{color:#a9cebc}
.events-pager a{color:#9cf2c1;border:1px solid #376b54;border-radius:0;background:#0e241b}
.events-pager a:hover{background:#1c5137}.event-tools{gap:8px}
.helpbox{margin:12px 0 18px;border:1px dashed #346651;background:#0a1b17;padding:10px 14px;color:#b3d2bf}
.helpbox summary{cursor:pointer;color:#8decba;font-size:12px;font-weight:800}
.helpbox summary::before{content:'[?] ';color:#6dc99d}
.helpbox[open] summary{margin-bottom:9px;border-bottom:1px dashed #315643;padding-bottom:9px}
.helpbox p{font-size:12px;line-height:1.7;margin:8px 0;color:#b1cbbd}
.helpbox strong,.helpbox b{color:#d0ffdf}
@keyframes blink{50%{opacity:0}}
@media(max-width:1000px){main{padding:12px}.shell-terminal-status{display:none}header{flex-wrap:wrap}header nav{width:100%}}
@media(max-width:700px){
 main{padding:8px 7px 28px}header{padding:12px}header nav{gap:1px}header nav a{padding:7px}
 .shell-windowbar{padding:8px}.shell-window-tag{display:none}.shell-prompt{padding:10px 12px}
 .card{padding:14px}.grid{gap:8px}
 .live-columns{display:none}.live-entry{grid-template-columns:70px minmax(100px,1fr) 70px;gap:7px}
 .live-entry .live-type{display:none}.live-entry .live-detail{grid-column:2 / 4;grid-row:2}
 .radar-head{padding:12px}.radar-filter{gap:3px}
 .radar .radar-filter button{min-width:0;padding:7px 9px}
 .terminal-footer{font-size:10px}
}
@media(max-width:540px){header h1{font-size:16px}.num{font-size:23px}.card .num{font-size:24px}}
@media(prefers-reduced-motion:reduce){.shell-caret{animation:none}.live-entry{animation:none}html{scroll-behavior:auto}}
'''


CSS += r"""
.block-tabs{display:flex;flex-wrap:wrap;gap:8px;margin:16px 0 8px}
.block-tabs a{border:1px solid #376951;text-decoration:none;padding:8px 12px;color:#b0e7ca}
.block-tabs a.selected{background:#235d42;border-color:#6adb9e;color:#e5ffec;font-weight:800}
.block-chip{display:inline-block;padding:2px 7px;margin-right:5px;border:1px solid #365c48;font-size:10px;white-space:nowrap}
.block-chip.bad{border-color:#8c4b55}.block-chip.caution{border-color:#8a734c}
.block-records td{vertical-align:middle;white-space:normal}
.block-records .ip-entry{min-width:195px}
.block-extra{color:#85aa94;font-size:10px;line-height:1.5;margin-top:6px}
.block-intel{font-size:11px;margin-top:6px}.block-intel summary{color:#80e5bb;cursor:pointer}
.block-intel .ip-intel{display:block;margin-top:5px;overflow-wrap:anywhere}
.block-pager{display:flex;gap:12px;margin:12px 0;align-items:center}
@media(max-width:800px){.block-records{min-width:780px}}
"""

CSS += r"""
.provider-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin-top:14px}
.provider-card{border:1px solid #2a5044;background:#0a1b18;padding:14px;min-width:0}
.provider-title{font-size:12px;margin-bottom:9px}.provider-card .small-note{margin:6px 0 10px;line-height:1.6}
.provider-actions{display:flex;flex-wrap:wrap;gap:7px}.provider-actions form{display:flex;gap:8px;flex-wrap:wrap;align-items:center;min-width:0}
.provider-actions input{min-width:0;max-width:245px}.provider-actions button{padding:7px 10px}
@media(max-width:900px){.provider-grid{grid-template-columns:1fr}}
"""

CSS += r"""
.bulk-import{margin:15px 0 0;border-top:1px solid #315142;padding-top:12px}
.bulk-import>summary{cursor:pointer;font-weight:700;color:#72eeb9}
.bulk-import form{align-items:stretch;margin-top:12px;flex-direction:column}
.bulk-import textarea{box-sizing:border-box;width:100%;max-width:100%;min-height:135px;padding:12px;background:#0a1c18;border:1px solid #3b7559;color:#c9ffdf;font:12px ui-monospace,monospace;resize:vertical}
.bulk-import button{align-self:flex-start}
"""

CSS += r"""
.feed-table{width:100%;table-layout:fixed;min-width:790px}
.feed-table th:first-child{width:31%}.feed-table th:nth-child(2){width:12%}
.feed-table th:nth-child(3){width:11%}.feed-table th:nth-child(4){width:19%}
.feed-table td{vertical-align:middle;white-space:normal;overflow-wrap:anywhere}
.feed-source{display:flex;align-items:center;gap:12px;min-width:0}
.feed-source form{flex-shrink:0;margin:0}.feed-source button{padding:7px 10px;font-size:11px;white-space:nowrap}
.feed-source button:disabled{cursor:wait;opacity:.45}
.feed-name{display:inline-block;color:#a3f4d0;font-weight:700}
.feed-id{color:#5c977d;font-size:10px;margin-top:3px}
.feed-count{font-variant-numeric:tabular-nums;font-weight:bold}
.feed-note{color:#b9a67c;font-size:10px;max-height:2.8em;overflow:hidden}
.feed-updated{font-size:11px;white-space:nowrap!important}
.feed-progress:not([hidden]){display:flex;align-items:center;flex-wrap:wrap;gap:8px;padding-top:8px;color:#88ddb7;font-size:10px}
.feed-progress progress{width:100%;height:9px;accent-color:#43c88c}
.feed-spin:not([hidden]){display:inline-block;width:13px;height:13px;border:2px solid #325c4a;border-top-color:#6ff4ba;border-radius:50%;animation:feed-spin 850ms linear infinite}
@keyframes feed-spin{to{transform:rotate(360deg)}}
@media (max-width:820px){.feed-table{min-width:820px}}
"""

def e(value):return escape(str(value),quote=True)

def base_path():
    """Browser-visible URL prefix, configured locally (never from a request header)."""
    value=fw.config().get('ui_base_path', '/')
    if not isinstance(value,str) or len(value)>128 or not re.fullmatch(r'/(?:[A-Za-z0-9_-]+/)*', value):
        raise ValueError('ui_base_path must be / or /name/.../ with a trailing slash')
    return value


def public_origin():
    """Optional exact HTTPS origin for a deliberately configured reverse proxy."""
    value=fw.config().get('ui_public_origin', '')
    if not isinstance(value,str) or (value and (len(value)>255 or not re.fullmatch(r'https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?',value))):
        raise ValueError('ui_public_origin must be an HTTPS origin without a path')
    return value.lower()


def path_for(part=''):
    """Only internal static routes are passed; never build URLs from untrusted data."""
    if part and (part.startswith('/') or '?' in part or '#' in part):
        raise ValueError('invalid internal route')
    return base_path()+part


def routed_path(path):
    """Accept a stripped path (Nginx proxy_pass with /) or an intact prefix.

    This is essential for compatibility with both reverse-proxy conventions.
    """
    base=base_path()
    if base!='/' and path.startswith(base):
        return '/'+path[len(base):]
    return path




def canonical_origin(value):
    """Accept only syntactically valid http(s) Origins; normalize default ports.

    Never compare an Origin to untrusted X-Forwarded-* headers. The expected
    origin remains pinned to the local configuration and approved Host map.
    """
    if not value or not isinstance(value, str) or len(value)>255:
        return None
    if not re.fullmatch(r'https?://[A-Za-z0-9.-]+(?::[0-9]{1,5})?', value):
        return None
    parsed=urlsplit(value.lower())
    try:
        port=parsed.port
    except ValueError:
        return None
    default=443 if parsed.scheme=='https' else 80
    if port is not None and not 1<=port<=65535:
        return None
    return parsed.scheme+'://'+parsed.hostname+((':'+str(port)) if port and port!=default else '')


def origin_allowed(origin, expected, fetch_site='', fetch_mode='', referer=None):
    """Validate browser provenance without rejecting privacy-preserving browsers.

    Explicit Origin is authoritative and must match the locally configured host.
    When omitted, Fetch Metadata must not claim a cross-origin/same-site request.
    A supplied Referer must be same-origin.  In addition, EVERY POST still needs
    the server-generated CSRF token verified in Handler.do_POST. The token is the
    decisive fallback when privacy settings omit Origin and Fetch Metadata.
    """
    expected=canonical_origin(expected)
    if expected is None:
        return False
    site=fetch_site.lower().strip()
    mode=fetch_mode.lower().strip()
    if site not in ('','same-origin','none'):
        return False
    if origin == 'null':
        if site!='same-origin' or mode!='navigate':return False
    elif origin is not None:
        return canonical_origin(origin)==expected
    if mode not in ('','navigate'):
        return False
    if referer:
        try:
            candidate=urlsplit(referer)
            if candidate.username is not None or candidate.password is not None:
                return False
            referer_origin=canonical_origin(candidate.scheme+'://'+candidate.netloc)
        except ValueError:
            return False
        if referer_origin!=expected:
            return False
    return True


def live_health():
    """Only used by the separate 10-second health endpoint, not 250ms polling."""
    try:
        monitor=fw.run('systemctl','is-active','fw-sentinel-monitor.service',check=False,timeout=4).returncode==0
    except (OSError,ValueError,TimeoutError):monitor=False
    try:
        table=fw.run('nft','-t','list','table','inet',fw.TABLE,check=False,timeout=4).returncode==0
    except (OSError,ValueError,TimeoutError):table=False
    try:
        last=fw.live_events(0,1)
        last_seen=last[-1][1] if last else None
    except (OSError,fw.sqlite3.Error):last_seen=None
    return {'monitor_active':monitor,'table_active':table,
            'mode':fw.state().get('mode','off'),'last_event_utc':last_seen}



def ctx():
    st=fw.state();cfg=fw.config();feed=fw.ROOT/'cache'/'sources'
    # A staged 120-second trial has kernel DROP rules, even though persistent
    # state is intentionally still 'observe' until confirmation. Never show
    # the misleading 'no DROP' banner during this period.
    import time
    for candidate in fw.ROOT.glob('.pending-*'):
        marker=candidate/'web.json'
        try:
            if marker.is_file() and float(json.loads(marker.read_text())['deadline'])>time.time():
                st={**st,'mode':'trial'}
                break
        except (OSError,KeyError,TypeError,ValueError,json.JSONDecodeError):
            pass
    count=len(list(feed.glob('*.txt'))) if feed.exists() else 0
    ban=len(fw.line_networks(fw.ROOT/'manual-bans.txt',addresses_only=True))
    allow=len(fw.line_networks(fw.ROOT/'allow.txt'))
    p=fw.run('nft','-t','list','table','inet',fw.TABLE,check=False)
    return st,cfg,count,ban,allow,p.returncode==0


def doc(body,title=None,message='',script=None):
    title=title or tr('Overview','Обзор')
    notice=f'<div class="warning">{e(message)}</div>' if message else ''
    # Server-generated scripts only; preserving the strict CSP and existing CSRF logic.
    nonce=secrets.token_urlsafe(20) if script else ''
    scripts=f'<script nonce="{nonce}">{i18n.localize(script)}</script>' if script else ''
    csp=("default-src 'none'; style-src 'unsafe-inline'; connect-src 'self'; "
         + (f"script-src 'nonce-{nonce}'; " if script else "")
         + "form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
    pages=[('',tr('Overview','Обзор'),tr('Summary','Сводка')),('events',tr('Events','События'),tr('IP log','Журнал IP')),('access',tr('Access','Доступ'),tr('IP lists','Списки IP')),
           ('sources',tr('Sources','Источники'),tr('Threat feeds','Базы угроз')),('control',tr('Control','Управление'),tr('Protection settings','Настройки защиты'))]
    nav=''.join(f'<a href="{e(path_for(route))}"'+
                (' aria-current="page"' if page_title==title else '')+
                f'>{e(label)}</a>' for route,page_title,label in pages)
    command={tr('Overview','Обзор'):'status --watch',tr('Events','События'):'events --group ip',
             tr('Access','Доступ'):'access --manage',tr('Sources','Источники'):'sources --list',
             tr('Control','Управление'):'control --interactive'}.get(title,'status')
    other,other_name=('en','English') if i18n.language()=='ru' else ('ru','Русский')
    switch=form('language',f'<input type="hidden" name="lang" value="{other}">',other_name,'lang-btn') if TOKEN_FILE.is_file() else ''
    return f'''<!doctype html><html lang="{i18n.language()}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="same-origin"><meta http-equiv="Content-Security-Policy" content="{csp}"><title>FW Sentinel | {e(title)}</title><style>{CSS}</style></head><body><main>
    <div class="shell-chrome"><div class="shell-windowbar"><span class="shell-lamps" aria-hidden="true"><span></span><span></span><span></span></span><span class="shell-window-name">FW SENTINEL // SECURE TERMINAL</span><span class="shell-window-tag">WEB CONSOLE v2.0.21</span></div>
    <header><a class="brand" href="{e(path_for(''))}" title="{tr("Go to overview","На главную")}" style="text-decoration:none;color:inherit"><span class="dot" aria-hidden="true">◆</span><h1>FW SENTINEL <small class="muted">2.0.21</small></h1></a><nav aria-label="{tr("Panel sections","Разделы панели")}">{nav}{switch}</nav></header>
    <div class="shell-prompt"><span class="shell-host">sentinel@localhost</span><span class="shell-tilde">:~$</span><span class="shell-command">fw-sentinel {e(command)}</span><span class="shell-caret" aria-hidden="true">▋</span><span class="shell-terminal-status">AUTHENTICATED // TLS VIA PROXY OR SSH</span></div></div>
    {notice}{body}
    <footer class="terminal-footer"><span><strong>FW SENTINEL</strong> // LOCAL ADMIN 127.0.0.1:1488</span><span>{tr("Kernel logs may be rate-limited · Do not expose port 1488 to the Internet","Kernel logs may be rate-limited · Не открывайте порт 1488 в Интернет")}</span></footer>
    </main>{scripts}</body></html>'''


def bare_page(message):
    # Shown before authentication: no menu, product name or version.
    return '<!doctype html><html lang="ru"><meta charset="utf-8"><title>'+e(message)+'</title><p>'+e(message)+'</p>'


def csrf():
    return hashlib.sha256(TOKEN_FILE.read_bytes()+b'\0fws-csrf').hexdigest()


def form(action,fields,button,cls=''):
    return f'<form method="post" action="{e(path_for(action))}"><input type="hidden" name="csrf" value="{csrf()}">{fields}<button class="{cls}" type="submit">{e(button)}</button></form>'


LIVE_RATES=('0.25','0.5','0.75','1','2','4','6','8','10')  # seconds between feed polls


def live_rate_options():
    return ''.join(f'<option value="{v}">{tr("Refresh","Обновление")} {v.replace(".",",") if i18n.language()=="ru" else v} {tr("s","сек")}</option>' for v in LIVE_RATES)


def live_panel():
    return ('''<section class="radar" aria-label="'''+tr('Incoming connection radar','Радар входящих соединений')+'''">
    <div class="radar-head"><div class="radar-title">◉ LIVE TRAFFIC / FW SENTINEL <span class="live-led"></span></div>
    <div class="radar-controls"><div class="radar-filter" role="group" aria-label="'''+tr('Radar event filter','Фильтр событий радара')+'''"><button type="button" data-live-filter="all" aria-pressed="true">'''+tr('All','Все')+'''</button><button type="button" data-live-filter="observe" aria-pressed="false">'''+tr('Observe','Наблюдение')+'''</button><button type="button" data-live-filter="drop" aria-pressed="false">'''+tr('Blocked','Заблокированы')+'''</button></div><span class="radar-status" id="live-status" aria-live="polite">'''+tr('Connecting…','Подключаемся…')+'''</span><button type="button" id="live-pause">Ⅱ '''+tr('Pause feed','Пауза ленты')+'''</button></div></div>
    <div class="live-columns" aria-hidden="true"><span>'''+tr('TIME','ВРЕМЯ')+'''</span><span>'''+tr('RESULT','РЕЗУЛЬТАТ')+'''</span><span>SOURCE IP</span><span>'''+tr('PORT','ПОРТ')+'''</span><span>'''+tr('RULE','ПРАВИЛО')+'''</span></div>
    <div id="live-stream" class="live-list" role="log" aria-live="off"><p class="empty">'''+tr('Waiting for live events from the kernel log…','Ожидаем реальные события из журнала ядра…')+'''</p></div>
    <div class="live-legend"><span class="good">● <b>'''+tr('Passed:','Пропущены:')+'''</b> <span id="live-pass">0</span> '''+tr('sampled packets','выборочных пакетов')+'''</span>
    <span class="bad">● <b>'''+tr('Blocked:','Заблокированы:')+'''</b> <span id="live-drop">0</span> '''+tr('DROP events','событий DROP')+'''</span>
    <span class="caution">● <b>'''+tr('Observed:','Под наблюдением:')+'''</b> <span id="live-observe">0</span> '''+tr('without blocking','без блокировки')+'''</span></div>
    <p class="sub" id="radar-health" aria-live="polite">'''+tr('Checking monitoring service…','Проверяем службу мониторинга…')+'''</p>
    </section><details class="helpbox"><summary>'''+tr('What do the colors mean, and why is the feed sometimes empty?','Что означают цвета и почему лента иногда пустая?')+'''</summary><p><b class="good">'''+tr('Green','Зелёный')+'''</b> — '''+tr('an incoming packet passed Sentinel rules; this does not confirm VPN authentication.','входящий пакет прошёл правила Sentinel; это не подтверждение VPN-авторизации.')+''' <b class="caution">'''+tr('Yellow','Жёлтый')+'''</b> — '''+tr('a suspicious packet was logged but not blocked by this rule.','подозрительный пакет попал в журнал, но не был заблокирован этим правилом.')+''' <b class="bad">'''+tr('Red','Красный')+'''</b> — '''+tr('a Sentinel rule performed a DROP. An IP may appear many times. The feed shows only logged packets (some events are rate-limited); existing VPN connections may not appear. Pausing the feed','правило Sentinel выполнило DROP. Один IP может встречаться много раз. Лента показывает только зарегистрированные пакеты (часть событий ограничена по частоте); старые VPN-соединения могут не появляться. Пауза ленты')+''' <strong>'''+tr('does not disable the firewall','не выключает firewall')+'''</strong>.</p></details>''')


LIVE_SCRIPT = "(()=>{\n'use strict';\nconst list=document.getElementById('live-stream');\nif(!list)return;\nconst status=document.getElementById('live-status');\nconst pause=document.getElementById('live-pause');\nconst buttons=Array.from(document.querySelectorAll('[data-live-filter]'));\nconst counters={pass:document.getElementById('live-pass'),drop:document.getElementById('live-drop'),observe:document.getElementById('live-observe')};\nconst rate=document.getElementById('live-rate');\ntry{const saved=localStorage.getItem('fws-live-rate');if(saved&&Array.from(rate.options).some(o=>o.value===saved))rate.value=saved;}catch(_e){}\nconst pollMs=()=>Number(rate.value)*1000||250;\nconst RETRY_MS=1000, BUFFER_MAX=300, VISIBLE_MAX=70;\nconst prefix={pass:'ПРОПУЩЕН',drop:'БЛОК',observe:'НАБЛЮДЕНИЕ'};\nlet cursor=0,paused=false,pending=false,shown=0,timer=null,failures=0,aborter=null,filter='all';\nlet buffer=[];\nfunction active(){return !paused&&!document.hidden;}\nfunction clearTimer(){if(timer!==null){clearTimeout(timer);timer=null;}}\nfunction schedule(delay=pollMs()){clearTimer();if(active())timer=setTimeout(tick,delay);}\nfunction normalizeVerdict(value){return ['pass','drop','observe'].includes(value)?value:'observe';}\nfunction matches(value){return filter==='all'||normalizeVerdict(value)===filter;}\nfunction placeholder(){\n if(list.querySelector('.live-entry'))return;\n const p=document.createElement('p');p.className='empty';\n p.textContent=shown?'В выбранной категории пока нет зарегистрированных событий.':'Ожидаем реальные события из журнала ядра…';\n list.replaceChildren(p);\n}\nfunction paint(ev){\n const verdict=normalizeVerdict(ev.verdict);\n const row=document.createElement('div');row.className='live-entry '+verdict;\n const tm=document.createElement('span');tm.className='live-time';tm.textContent=(ev.timestamp||'').slice(11,19)||'--:--:--';\n const kind=document.createElement('span');kind.className='live-type';kind.textContent=prefix[verdict];\n const ip=document.createElement('strong');ip.className='live-address';ip.textContent=ev.ip||'?';\n const port=document.createElement('span');port.textContent=':'+String(ev.port??'—');\n const meta=document.createElement('span');meta.className='live-detail';meta.title=(ev.proto||'')+' '+(ev.reason||'');meta.textContent=(ev.proto||'?')+' · '+(ev.reason||'—');\n row.append(tm,kind,ip,port,meta);\n if(list.querySelector('.empty'))list.replaceChildren();\n list.prepend(row);\n while(list.children.length>VISIBLE_MAX)list.lastElementChild.remove();\n}\nfunction redraw(){\n list.replaceChildren();\n for(const ev of buffer){if(matches(ev.verdict))paint(ev);}\n placeholder();\n}\nbuttons.forEach(button=>button.addEventListener('click',()=>{\n filter=button.dataset.liveFilter;\n buttons.forEach(b=>b.setAttribute('aria-pressed',String(b===button)));\n redraw();\n}));\nfunction add(ev){\n const verdict=normalizeVerdict(ev.verdict);\n buffer.push(ev);if(buffer.length>BUFFER_MAX)buffer.shift();\n counters[verdict].textContent=String(Number(counters[verdict].textContent)+1);\n if(verdict==='drop'&&window.fwsDropHit)window.fwsDropHit(ev);\n if(matches(verdict))paint(ev);\n else placeholder();\n}\nlet healthBusy=false,healthCycles=39;\nasync function updateHealth(){\n const node=document.getElementById('radar-health');\n if(!node||healthBusy)return;\n healthBusy=true;\n try{\n  const res=await fetch(__HEALTH_API_URL__,{cache:'no-store',credentials:'same-origin'});\n  if(!res.ok)throw Error('HTTP '+res.status);\n  const h=await res.json();\n  if(!h.table_active)node.textContent='Диагностика: таблица Sentinel отсутствует. Запустите наблюдение.';\n  else if(!h.monitor_active)node.textContent='Диагностика: fw-sentinel-monitor не активен. Проверьте systemctl и journalctl.';\n  else if(!h.last_event_utc)node.textContent='Монитор активен, таблица загружена; зарегистрированных событий пока нет.';\n  else node.textContent='Монитор активен · таблица загружена · последнее событие (UTC): '+h.last_event_utc.replace('T',' ').slice(0,19);\n }catch(e){node.textContent='Не удалось получить диагностику мониторинга ('+String(e.message||e)+')';}\n finally{healthBusy=false;}\n}\nasync function tick(){\n clearTimer();if(!active()||pending)return;\n pending=true;aborter=new AbortController();let next=pollMs();\n if(++healthCycles>=40){healthCycles=0;updateHealth();}\n try{\n  const res=await fetch(__LIVE_API_URL__+'?since='+cursor,{cache:'no-store',credentials:'same-origin',signal:aborter.signal});\n  if(res.status===401){paused=true;status.textContent='Сессия истекла: обновите страницу';return;}\n  if(!res.ok)throw Error('HTTP '+res.status);\n  const data=await res.json();if(!Array.isArray(data.events))throw Error('invalid data');\n  for(const ev of data.events){add(ev);shown++;cursor=Math.max(cursor,Number(ev.id)||0);}\n  if(!shown)status.textContent='LIVE '+pollMs()+' мс · ожидаем события…';\n  else status.textContent='LIVE '+pollMs()+' мс · '+shown+' событий в этой сессии';\n  failures=0;\n }catch(err){\n  if(err.name!=='AbortError'){\n   failures=Math.min(failures+1,5);next=Math.min(16000,RETRY_MS*2**(failures-1));\n   status.textContent='Нет связи · повтор через '+(next/1000)+' с';\n  }\n }finally{aborter=null;pending=false;schedule(next);}\n}\nfunction stop(){clearTimer();if(aborter)aborter.abort();}\nrate.addEventListener('change',()=>{try{localStorage.setItem('fws-live-rate',rate.value);}catch(_e){}if(timer!==null)schedule();});\npause.addEventListener('click',()=>{\n paused=!paused;pause.textContent=paused?'▶ Возобновить ленту':'Ⅱ Пауза ленты';\n status.textContent=paused?'Пауза отображения':'Подключаемся…';\n document.querySelector('.radar').classList.toggle('live-paused',paused);\n if(paused)stop();else if(!pending)tick();\n});\ndocument.addEventListener('visibilitychange',()=>{\n if(document.hidden){stop();status.textContent='Вкладка скрыта · опрос приостановлен';}\n else if(active()&&!pending)tick();\n});\nwindow.addEventListener('pagehide',stop);\nplaceholder();tick();\n})();"


def pending_trial():
    """Expose only a currently staged web action, not raw nft rules."""
    for p in fw.ROOT.glob('.pending-*'):
        if not re.fullmatch(r'\.pending-[a-f0-9]{32}',p.name):continue
        try:
            meta=json.loads((p/'web.json').read_text(encoding='utf-8'))
            if meta.get('auto'):continue
            deadline=int(meta['deadline'])
            return p.name[9:],deadline
        except (OSError,TypeError,ValueError,KeyError):continue
    return None


DROP_SUMMARY_SCRIPT = """(()=>{
'use strict';
const grid=document.getElementById('drop-ip-grid');if(!grid)return;
const URL=__DROP_SUMMARY_URL__;
let busy=false,stopped=false;
function createCard(item){
 const ip=String(item.ip||'');const count=Number(item.count)||0;
 const card=document.createElement('article');card.className='blocked-ip-card';
 const head=document.createElement('div');head.className='blocked-ip-top';
 const link=document.createElement('a');link.className='blocked-ip-address';
 link.href=__EVENTS_URL__+'?'+new URLSearchParams({ip,verdict:'drop'}).toString();link.textContent=ip;
 const badge=document.createElement('strong');badge.className='blocked-ip-count';badge.textContent=String(count);
 badge.title='Всего зарегистрировано DROP-событий по адресу, активному за 24 часа';
 head.append(link,badge);
 const intel=document.createElement('small');intel.className='ip-intel';intel.dataset.intelIp=ip;
 intel.textContent='ASN · страна · AbuseIPDB: загрузка…';
 if(item.intel)intel.dataset.intel=JSON.stringify(item.intel);
 const footer=document.createElement('div');footer.className='blocked-ip-bottom';
 footer.append(document.createTextNode('Последнее обращение (UTC): '));
 const stamp=document.createElement('time');const raw=String(item.last||'');stamp.dateTime=raw;
 stamp.textContent=raw.replace('T',' ').slice(0,19)||'—';footer.append(stamp);
 card.append(head,intel,footer);return card;
}
// LIVE feed: raise the counter of a card already on screen; hits is the row total, so repeats are safe.
window.fwsDropHit=ev=>{
 for(const card of grid.querySelectorAll('.blocked-ip-card')){
  if(card.querySelector('.blocked-ip-address').textContent!==ev.ip)continue;
  const badge=card.querySelector('.blocked-ip-count');
  const hits=Number(ev.hits)||0;if(hits<=Number(badge.textContent))return;
  badge.textContent=String(hits);
  const raw=String(ev.timestamp||''),stamp=card.querySelector('time');
  stamp.dateTime=raw;stamp.textContent=raw.replace('T',' ').slice(0,19);
  card.classList.add('hit');setTimeout(()=>card.classList.remove('hit'),700);
  return;
 }
};
async function refresh(){
 if(document.hidden||stopped||busy)return;busy=true;
 try{
  const response=await fetch(URL,{cache:'no-store',credentials:'same-origin'});
  if(!response.ok)throw Error('HTTP '+response.status);
  const data=await response.json();if(!Array.isArray(data.items))throw Error('invalid data');
  // The API returns counts descending. Each item occupies its own grid cell.
  const fragment=document.createDocumentFragment();
  for(const item of data.items.slice(0,24))fragment.append(createCard(item));
  if(!data.items.length){const message=document.createElement('div');message.className='blocked-ip-empty';message.textContent='За последние 24 часа зарегистрированных DROP-событий нет.';fragment.append(message);}
  grid.replaceChildren(fragment);if(window.fwsIntelScan)window.fwsIntelScan();
 }catch(_e){/* Preserve last visible data on temporary errors. */}
 finally{busy=false;}
}
const interval=setInterval(refresh,15000);
document.addEventListener('visibilitychange',()=>{if(!document.hidden)refresh();});
window.addEventListener('pagehide',()=>{stopped=true;clearInterval(interval);});
})();"""

IP_INTEL_SCRIPT = """(()=>{
'use strict';
const API=__IP_INTEL_URL__;
const values=new Map(),queued=new Set(),queue=[];
let busy=false,stopped=false,last=0;
function scoreClass(score){return score>=75?'score high':score>=35?'score mid':'score';}
function paint(node,value){
 node.replaceChildren();
 const asn=value&&value.asn?'AS'+value.asn:'ASN —';
 const country=value&&value.country?value.country:'страна —';
 const isp=value&&value.isp?' · '+value.isp:'';
 node.append(document.createTextNode(asn+' · '+country+isp+' · AbuseIPDB: '));
 const badge=document.createElement('strong');
 badge.className=value&&typeof value.score==='number'?scoreClass(value.score):'muted';
 badge.textContent=value&&typeof value.score==='number'?value.score+'/100':'—';
 node.append(badge);
}
function scan(){
 document.querySelectorAll('[data-intel-ip]').forEach(node=>{
  const ip=node.dataset.intelIp;
  let known=null;
  if(node.dataset.intel){try{known=JSON.parse(node.dataset.intel);}catch(_e){}}
  if(known&&known.geo_available&&known.abuse_available)values.set(ip,known);
  if(values.has(ip)){paint(node,values.get(ip));return;}
  if(known)paint(node,known);
  if(!queued.has(ip)){queued.add(ip);queue.push(ip);}
 });
}
window.fwsIntelScan=scan;
async function work(){
 if(stopped||busy||document.hidden)return;
 if(!queue.length)return;
 const gap=Date.now()-last;
 if(gap<2300)return;
 const ip=queue.shift();if(values.has(ip))return;
 busy=true;last=Date.now();
 try{
  const url=API+'?'+new URLSearchParams({ip}).toString();
  const response=await fetch(url,{cache:'no-store',credentials:'same-origin',headers:{'X-FWS-Intel':'1'}});
  if(!response.ok)throw Error('API '+response.status);
  const value=await response.json();values.set(ip,value);
  document.querySelectorAll('[data-intel-ip]').forEach(node=>{if(node.dataset.intelIp===ip)paint(node,value);});
 }catch(_error){
  // Do not retry a failed IP endlessly while this tab remains open.
  values.set(ip,{});
  document.querySelectorAll('[data-intel-ip]').forEach(node=>{if(node.dataset.intelIp===ip)paint(node,{});});
 }finally{busy=false;}
}
scan();const timer=setInterval(()=>{scan();work();},350);
window.addEventListener('pagehide',()=>{stopped=true;clearInterval(timer);});
})();"""


TRIAL_COUNTDOWN_SCRIPT = """(()=>{
const node=document.getElementById('shield-countdown');if(!node)return;
const deadline=Number(node.dataset.deadline);
function tick(){const sec=Math.max(0,Math.ceil(deadline-Date.now()/1000));
 node.textContent=sec+' сек';
 if(sec===0){node.textContent='0 сек — срок истёк, обновите страницу';}
}
tick();setInterval(tick,1000);
})();"""


def quick_profile_active(mode, cfg):
    return (mode=='enforce' and (fw.ROOT/'active.nft').is_file()
        and fw.state().get('policy_signature')==fw.policy_signature(cfg)
        and all(cfg.get(k,False) for k in (
            'manual_bans_enabled','scanner_enabled','ssh_rate_enabled',
            'threat_ssh_enabled','threat_ssh_enforce',
            'threat_watch_enabled','threat_watch_enforce','autoban_enabled'))
        and not cfg.get('geo_enabled',False) and not cfg.get('asn_enabled',False))


def shield_controls(mode, cfg):
    trial=pending_trial()
    if trial:
        token,deadline=trial
        return ((f'<div class="shield-state trial"><strong>{tr("New rules are active for 120 seconds","Новые правила включены на 120 секунд")}</strong>'
            '<p>'+tr('Check SSH and VPN. If everything works, keep the rules. Otherwise, they will automatically roll back.','Проверьте SSH и VPN. Если всё работает — оставьте правила. Иначе они автоматически откатятся.')+' '
            '</p>'
            f'<div class="trial-count" id="shield-countdown" data-deadline="{deadline}">{tr("120 s","120 сек")}</div>'
            '<div class="control-actions">')
            +form('control/confirm',f'<input type="hidden" name="token" value="{e(token)}">',
                  ('✔ '+tr('KEEP RULES','ОСТАВИТЬ ПРАВИЛА')),'good-btn')
            +form('control/cancel-trial',f'<input type="hidden" name="token" value="{e(token)}">',
                  ('↩ '+tr('RESTORE PREVIOUS RULES','ВЕРНУТЬ ПРЕЖНИЕ ПРАВИЛА')),'danger-btn')+'</div></div>')
    profile=quick_profile_active(mode,cfg)
    extra=fw.extras_status()
    if profile and cfg.get('extra_threat_feeds_enabled',False):
        return (('<div class="shield-state"><strong>'+tr('Protection confirmed and active permanently','Защита подтверждена и работает постоянно')+'</strong>'
            '<p>'+tr('Rules saved.','Правила сохранены.')+' '
            ''+tr('The saved snapshot is loaded when the server reboots.','Сохранённый снимок загружается при перезагрузке сервером.')+' '
            ''+tr('Use the separate button to check recovery and service health.','Проверяйте восстановление и работоспособность служб отдельной кнопкой.')+'</p>'
            '<div class="control-actions">')
            +form('control/disable-shield','',('■ '+tr('DISABLE AUTOMATIC BLOCKING (keep observe mode)','ВЫКЛЮЧИТЬ АВТОБЛОКИРОВКИ (оставить наблюдение)')),'danger-btn')
            +f'<a class="good-btn" href="{e(path_for("control/recovery"))}">↻ {tr("CHECK RECOVERY","ПРОВЕРИТЬ ВОССТАНОВЛЕНИЕ")}</a>'
            +'</div></div>')
    return (('<div class="shield-state off"><strong>'+tr('Enable or update enhanced automatic protection with additional feeds','Активировать/обновить усиленную автозащиту с дополнительными базами')+'</strong>'
        '<p>'+tr('Rules are applied immediately. A confirmation button will appear for 120 seconds only if the new rules','Правила применяются сразу. Кнопка подтверждения на 120 секунд появится, только если новые правила')+' '
        ''+tr('could lock out your IP. A static administrator IP is required in the trusted list.','могут отрезать ваш IP. Нужен статичный IP администратора в белом списке.')+'</p>'
        '<div class="control-actions">')
        +form('control/quick-shield','',('⚡ '+tr('ENABLE AUTOMATIC PROTECTION','ВКЛЮЧИТЬ АВТОЗАЩИТУ')),'good-btn')
        +f'<a class="good-btn" href="{e(path_for("control/recovery"))}">↻ {tr("CHECK RECOVERY","ПРОВЕРИТЬ ВОССТАНОВЛЕНИЕ")}</a>'
        +'</div></div>')


def recovery_page():
    report=fw.persistence_report()
    rows=''.join('<tr><td>'+e(item['name'])+'</td><td class="'+('ok' if item['ok'] else 'fail')+'">'+
        ('OK' if item['ok'] else tr('PROBLEM','ПРОБЛЕМА'))+'</td><td>'+e(item['description'])+'</td></tr>'
        for item in report['checks'])
    label=(tr('Ready to restore the confirmed policy','Готово к восстановлению подтверждённой политики') if report['ready'] else
           tr('Recovery is not ready or automatic protection is not confirmed','Восстановление не готово либо автозащита не подтверждена'))
    proof=((tr('Actual recovery during the current boot confirmed:','Подтверждено реальное восстановление при текущей загрузке:')+' ')+report['last_restored_at']
           if report['restored_this_boot'] else
           (tr('Recovery after reboot has not yet been recorded during the current boot.','На текущей загрузке факт восстановления после перезагрузки ещё не зафиксирован.')+' '
           ''+tr('This is not a readiness check error; an actual test requires a reboot.','Это не ошибка проверки готовности; фактический тест потребует перезагрузки.')))
    return doc(('<h2>'+tr('Permanent protection and recovery check','Проверка постоянной защиты и восстановления')+'</h2>'
       '<p><b>')+e(label)+('</b>. '+tr('This check applies nothing and does not restart services:','Эта проверка ничего не применяет и не перезапускает сервисы:')+' '
       ''+tr('it checks the signed snapshot,','она проверяет подписанный снимок,')+' <code>nft -c</code>, '+tr('the boot-time recovery service,','сервис восстановления при загрузке,')+' '
       ''+tr('the watchdog timer, and whether the table is present in the kernel.','таймер сторожа и наличие таблицы в ядре.')+'</p>'
       '<div class="card scroll"><table class="restore-check"><thead><tr><th>'+tr('Check','Проверка')+'</th><th>'+tr('Result','Результат')+'</th><th>'+tr('Details','Подробности')+'</th></tr></thead><tbody>')
       +rows+'</tbody></table></div><div class="hint">'+e(proof)+('</div>'
       '<p><b>'+tr('Actual test after reboot:','Реальный тест после перезагрузки:')+'</b> '+tr('first check SSH and VPN,','сначала проверьте SSH и VPN,')+' '
       ''+tr('then schedule a reboot with access to the VPS console.','затем запланируйте перезагрузку с доступом через консоль VPS.')+' '
       ''+tr('After startup, run the check again: the last recovery time will be displayed.','После запуска повторите проверку: будет показано время последнего восстановления.')+'</p>')
       +f'<p><a href="{e(path_for("control"))}">{tr("← Back to control","← Вернуться к управлению")}</a></p>',
       tr('Recovery check','Проверка восстановления'))


def overview():
    st,cfg,feeds,ban,allow,loaded=ctx()
    mode=st.get('mode','off')
    styles={'trial':'caution','enforce':'bad','observe':'caution','off':'muted'}
    russian={'trial':tr('TEMPORARY blocking · confirm within 120 s','ВРЕМЕННАЯ блокировка · подтвердить за 120 сек'), 'enforce':tr('Filtering active','Фильтрация активна'),'observe':tr('Observe mode without blocking','Наблюдение без блокировок'),'off':tr('Off','Выключено')}
    values=[(tr('Mode','Режим'),russian.get(mode,mode),styles.get(mode,'')),
            (tr('Loaded sources','Загруженные источники'),str(feeds),'good' if feeds else 'caution'),
            (tr('Manual permanent bans','Ручные постоянные баны'),str(ban),''),(tr('Trusted IPs','Доверенные IP'),str(allow),'good')]
    cards=''.join(f'<div class="card"><div class="label">{e(k)}</div><div class="num {cls}">{e(v)}</div></div>' for k,v,cls in values)
    warnings=''.join('<li>'+e(w)+'</li>' for w in list(filter(None,map(fw.notable,st.get('issues',[]))))[:15])
    mismatch=fw.ssh_port_warning(cfg)
    recent=dropped_ip_table(fw.recent_drop_ips(24))
    status='' if loaded else ('<span class="tag">'+tr('nftables table is missing','Таблица nftables отсутствует')+'</span>')
    return doc(f'''<div class="section-row"><div><h2>{tr("Protection status","Состояние защиты")}</h2></div>{status}</div><div class="grid">{cards}</div>
    <p class="sub">AUTO-BAN: {tr('enabled','включён') if cfg.get('autoban_enabled',False) else tr('disabled','выключен')} · {tr("active bans:","активных блокировок:")} {len(autoban.list_bans(fw.ROOT,limit=20000))} · <a href="{e(path_for('access'))}">{tr("View active bans","Просмотреть активные блокировки")}</a></p>
{shield_controls(mode,cfg)}
    <div class="hint"><strong>VPN:</strong> {tr("there is no need to register dynamic client IPs. IPs from enabled scanner/WATCH lists are blocked","динамические IP клиентов регистрировать не нужно. IP из включённых сканерных/WATCH-списков блокируются")} <b>{tr("on VPN ports too","и на VPN-портах")}</b>. {tr("However, automatic bans for probing unknown ports do not affect VPN. Sentinel rules do not automatically terminate existing connections in the established state.","При этом портовый автобан за перебор неизвестных портов не затрагивает VPN. Существующие соединения в состоянии established правилами Sentinel не разрываются автоматически.")}</div>
    {f'<div class="warning"><strong>{tr("SSH port:","SSH-порт:")}</strong> {e(mismatch)}</div>' if mismatch else ''}
    {f'<div class="warning"><strong>{tr("Memory:","Память:")}</strong> {e(fw.bulk_warning())}</div>' if fw.bulk_warning() else ''}
    {f'<div class="warning"><strong>{tr("Source warnings","Замечания по источникам")}</strong><ul>{warnings}</ul></div>' if warnings else ''}
    <div class="section-row live-head"><h2>{tr("Live network event log","Живой журнал сетевых событий")}</h2><select id="live-rate" aria-label="{tr("Live feed refresh rate","Частота обновления ленты")}">{live_rate_options()}</select></div>
    {live_panel()}
    <div class="section-row"><h2>{tr("Dropped packets","Отброшенные пакеты")}</h2><a href="{e(path_for('events'))}">{tr("Detailed IP history","Подробная история IP")}</a></div><p class="sub">{tr("Last 24 hours · sorted by DROP count · refreshes every 15 s. Counts are based on the log.","За 24 часа · по числу DROP · обновление 15 с. Счётчики — по журналу.")}</p><div class="drop-summary-area">{recent}</div>
    <h2>{tr("Quick controls","Быстрое управление")}</h2><div class="control-panel"><p><b>{tr("Enable observe mode","Включить наблюдение")}</b> · <b>{tr("Disable blocking","Отключить блокировки")}</b> · <b>{tr("Stop Sentinel","Остановить Sentinel")}</b> ({tr("VPN is not affected).","VPN не затрагивается).")}</p><div class="control-actions">{form('control/start','',('▶ '+tr('Enable observe mode','Включить наблюдение'))) if mode=='off' else ('<button disabled>▶ '+tr('Enable observe mode','Включить наблюдение')+'</button>')}{form('control/pause','',('Ⅱ '+tr('Disable blocking','Отключить блокировки'))) if mode=='enforce' else ('<button disabled>Ⅱ '+tr('Disable blocking','Отключить блокировки')+'</button>')}{form('control/stop','<input type="hidden" name="confirm" value="stop">',('■ '+tr('Stop Sentinel','Остановить Sentinel')),'danger-btn') if mode!='off' else ('<button disabled>■ '+tr('Stop Sentinel','Остановить Sentinel')+'</button>')}<a href="{e(path_for('control'))}">{tr("All settings and geofilter →","Все настройки и геофильтр →")}</a></div></div>''', script=(LIVE_SCRIPT.replace('__LIVE_API_URL__',json.dumps(path_for('api/live')))
       .replace('__HEALTH_API_URL__',json.dumps(path_for('api/health')))
       + IP_INTEL_SCRIPT.replace('__IP_INTEL_URL__',json.dumps(path_for('api/ip-intel')))
       + DROP_SUMMARY_SCRIPT.replace('__DROP_SUMMARY_URL__',json.dumps(path_for('api/drop-summary')))
       .replace('__EVENTS_URL__',json.dumps(path_for('events')))
       + TRIAL_COUNTDOWN_SCRIPT))


def dropped_ip_table(rows):
    """Render a real 3-across grid of IP cards (not a table with 3 data columns)."""
    if not rows:
        return (('<div class="blocked-ip-grid" id="drop-ip-grid">'
                '<div class="blocked-ip-empty">'+tr('No DROP events logged in the past 24 hours.','За последние 24 часа зарегистрированных DROP-событий нет.')+'</div>'
                '</div>'))
    out=['<div class="blocked-ip-grid" id="drop-ip-grid">']
    known=ipintel.cached_many([row[0] for row in rows],fw.ROOT)
    for ip,count,last in rows:
        link=path_for('events')+'?'+urlencode({'ip':ip,'verdict':'drop'})
        stamp=(last or '').replace('T',' ')[:19]
        out.append('<article class="blocked-ip-card">'
                   '<div class="blocked-ip-top">'
                   f'<a class="blocked-ip-address" href="{e(link)}">{e(ip)}</a>'
                   f'<strong class="blocked-ip-count" title="{tr("Total logged DROP events for an address active in the past 24 hours","Всего зарегистрировано DROP-событий по адресу, активному за 24 часа")}">{e(count)}</strong>'
                   '</div>'
                   f'<small class="ip-intel" data-intel-ip="{e(ip)}"'
                   +(f' data-intel="{e(json.dumps(known[ip],ensure_ascii=False))}"' if ip in known else '')+('>'+tr('ASN · country · AbuseIPDB: loading…','ASN · страна · AbuseIPDB: загрузка…')+'</small>'
                   '<div class="blocked-ip-bottom">'+tr('Last seen (UTC):','Последнее обращение (UTC):')+' '
                   f'<time datetime="{e(last or "")}">{e(stamp)}</time></div>'
                   '</article>'))
    out.append('</div>')
    return ''.join(out)


def events_table(rows):
    if not rows:return ('<div class="empty">'+tr('No events yet. The log receives data only after the monitoring service starts.','Событий пока нет. Журнал получает данные только после запуска службы мониторинга.')+'</div>')
    out=[('<table><thead><tr><th>'+tr('Time (UTC)','Время (UTC)')+'</th><th>IP</th><th>'+tr('Port','Порт')+'</th><th>'+tr('Protocol','Протокол')+'</th><th>'+tr('Reason','Причина')+'</th><th>'+tr('Mode','Режим')+'</th></tr></thead><tbody>')]
    for tm,ip,port,proto,reason,verdict in rows:
        out.append(f'<tr><td>{e(tm.replace("T"," ")[:19])}</td><td><code>{e(ip)}</code></td><td>{e(port or "—")}</td><td>{e(proto or "—")}</td><td>{e(reason)}</td><td class="{"bad" if verdict=="drop" else "good" if verdict=="pass" else "caution"}">{"DROP" if verdict=="drop" else "PASS" if verdict=="pass" else "OBSERVE"}</td></tr>')
    out.append('</tbody></table>');return ''.join(out)


EVENTS_SCRIPT = """(()=>{
'use strict';
const root=document.querySelector('.events-list');if(!root)return;
const endpoint=__INFO_ENDPOINT__;
function resolve(panel){
 if(!panel||panel.dataset.loaded==='1')return;
 panel.dataset.loaded='1';
 const out=panel.querySelector('[data-meta-text]');const ip=panel.dataset.metaIp;
 out.textContent='Определяем сеть и регион…';
 const controller=new AbortController();
 const timeout=setTimeout(()=>controller.abort(),5500);
 fetch(endpoint+'?ip='+encodeURIComponent(ip),{cache:'no-store',credentials:'same-origin',signal:controller.signal})
  .then(async response=>{const data=await response.json();if(!response.ok)throw Error(data.error||'HTTP '+response.status);return data;})
  .then(data=>{
   const parts=[];
   if(data.asn)parts.push('AS'+data.asn);
   if(data.isp)parts.push('Провайдер: '+data.isp);
   if(data.country)parts.push(data.country);
   if(data.region)parts.push(data.region);
   if(data.city)parts.push(data.city);
   out.textContent=parts.join(' · ')||'Сведения отсутствуют';
   if(data.cached)out.title='Из локального кэша';
  })
  .catch(err=>{out.textContent='Не удалось получить сведения: '+err.message+' · Нажмите «Обновить сведения»';panel.dataset.loaded='0';})
  .finally(()=>clearTimeout(timeout));
}
root.addEventListener('toggle',ev=>{
 const details=ev.target;
 if(!(details instanceof HTMLDetailsElement)||!details.classList.contains('ip-group')||!details.open)return;
 resolve(details.querySelector('[data-meta-ip]'));
},true);
root.addEventListener('click',ev=>{
 const button=ev.target.closest('[data-meta-retry]');
 if(!button)return;
 const panel=button.closest('[data-meta-ip]');
 if(panel){panel.dataset.loaded='0';resolve(panel);}
});
})();"""


def events_page(query):
    ip=(query.get('ip') or [''])[0].strip()
    verdict=(query.get('verdict') or ['all'])[0]
    if verdict not in ('all','observe','drop','pass'):
        verdict='all'
    sort=(query.get('sort') or ['recent'])[0]
    if sort not in ('recent','count_asc','count_desc'):sort='recent'
    raw_page=(query.get('page') or ['1'])[0]
    try:
        page=int(raw_page)
        if not 1<=page<=100000:raise ValueError()
    except ValueError:page=1
    notice=''
    if ip:
        try:ip=str(ipaddress.ip_address(ip))
        except ValueError:
            notice=('<div class="warning">'+tr('Enter a valid IPv4 or IPv6 address.','Введите корректный IPv4 или IPv6 адрес.')+'</div>')
            ip=''
    selected=lambda value:' selected' if verdict==value else ''
    sort_sel=lambda value:' selected' if sort==value else ''
    form_html=(f'<form method="get" action="{e(path_for("events"))}" class="event-tools">'
               f'<input name="ip" placeholder="{tr("Search IP history for all time","Поиск по IP за всё время")}" value="{e(ip)}" maxlength="45">'
               f'<select name="verdict" aria-label="{tr("Event filter","Фильтр событий")}">'
               f'<option value="all"{selected("all")}>{tr("All events","Все события")}</option>'
               f'<option value="observe"{selected("observe")}>{tr("Orange · observe","Оранжевые · наблюдение")}</option>'
               f'<option value="drop"{selected("drop")}>{tr("Red · DROP","Красные · DROP")}</option>'
               f'<option value="pass"{selected("pass")}>{tr("Green · PASS","Зелёные · PASS")}</option>'
               f'</select>'
               f'<label for="event-sort">{tr("Sort:","Сортировка:")}</label><select id="event-sort" name="sort" aria-label="{tr("Sort","Сортировка")}">'
               f'<option value="recent"{sort_sel("recent")}>{tr("Most recently active","Последние активные")}</option>'
               f'<option value="count_desc"{sort_sel("count_desc")}>{tr("Events ↓ (most → fewest)","События ↓ (много → мало)")}</option>'
               f'<option value="count_asc"{sort_sel("count_asc")}>{tr("Events ↑ (fewest → most)","События ↑ (мало → много)")}</option>'
               f'</select><button>{tr("Apply filters","Применить фильтры")}</button></form>')
    groups,more=fw.event_groups(page=page,limit=30,ip=ip or None,verdict=verdict,sort=sort,
                                ports_limit=200 if ip else 20)
    cards=[]
    for group in groups:
        ipval=e(group['ip'])
        stats=(f'<span>{tr("Total packets:","Всего пакетов:")} <b class="ip-count">{group["total"]}</b></span>'
               f'<span class="caution">{tr("Observe:","Наблюдение:")} {group["observe"]}</span>'
               f'<span class="bad">DROP: {group["drop"]}</span>'
               f'<span class="good">PASS: {group["pass"]}</span>'
               +(f'<span class="bad">{tr("Total attempts:","Долбился за всё время:")} <b>{group["lifetime"]}</b></span>' if group['lifetime'] else ''))
        port_rows=[]
        shown=lambda value:'—' if value is None else value
        for item in group['ports']:
            reason=', '.join(item['reasons'].split(',')[:6])
            port_rows.append(f'<tr><td><code>{e(item["port"] if item["port"] is not None else "—")}</code></td>'
                f'<td>{e(item["proto"] or "—")}</td>'
                f'<td><strong>{shown(item["total"])}</strong></td>'
                f'<td class="caution">{shown(item["observe"])}</td><td class="bad">{shown(item["drop"])}</td>'
                f'<td class="good">{shown(item["pass"])}</td><td>{e(reason)}</td>'
                f'<td>{e((item["last"] or "").replace("T"," ")[:19])}</td></tr>')
        if group['ports_more']:
            if ip:
                more_text=('<p class="sub">'+tr('Showing the 200 most active ports. The rest are hidden to prevent overloading the interface.','Показаны 200 наиболее активных портов. Остальные скрыты для защиты интерфейса от перегрузки.')+'</p>')
            else:
                link=path_for('events')+'?'+urlencode({'ip':group['ip'],'verdict':verdict,'sort':sort})
                more_text=f'<p class="sub">{tr("Showing the 20 most active ports.","Показаны 20 наиболее активных портов.")} <a href="{e(link)}">{tr("More details for this IP","Подробнее по этому IP")}</a></p>'
        else:more_text=''
        metadata=(f'<div class="ip-meta" data-meta-ip="{ipval}"><strong>{tr("ASN / provider / region","ASN / провайдер / регион")}</strong>'
                  f'<span data-meta-text>{tr("Open the card to look up the address","Откройте карточку для определения адреса")}</span>'
                  f'<button type="button" data-meta-retry>{tr("Refresh information","Обновить сведения")}</button></div>')
        ban_form=form('ban/preview', f'<input type="hidden" name="ip" value="{ipval}">',
                      tr('Ban this IP…','Заблокировать этот IP…'), 'danger-btn')
        action=(f'<div class="ip-action">{ban_form}<span class="small-note">'
                f'{tr("Trusted and VPN addresses must be checked; the ban requires confirmation.","Проверка доверенных и VPN-адресов обязательна; бан только после подтверждения.")}</span></div>')
        cards.append(f'<details class="ip-group"><summary><span class="ip-main">{ipval}</span>'
                     f'<span class="ip-stats">{stats}</span>'
                     f'<span class="sub">{tr("Last:","Последний:")} {e((group["last"] or "").replace("T"," ")[:19])} UTC</span>'
                     f'</summary><div class="ip-details"><p class="sub">{tr("First:","Первый:")} {e((group["first"] or "").replace("T"," ")[:19])} UTC · '
                     f'{tr("last:","последний:")} {e((group["last"] or "").replace("T"," ")[:19])} UTC. '
                     f'{tr("Counts reflect logged packets only. Up to 50 of the address’s most recent ports are stored.","Числа отражают только зарегистрированные пакеты. Хранится до 50 последних портов адреса.")}</p>'
                     f'<div class="scroll"><table><thead><tr><th>{tr("Port","Порт")}</th><th>{tr("Protocol","Протокол")}</th><th>{tr("Packets","Пакетов")}</th>'
                     f'<th>{tr("Observe","Наблюдение")}</th><th>DROP</th><th>PASS</th><th>{tr("Reasons","Причины")}</th><th>{tr("Last (UTC)","Последний (UTC)")}</th></tr></thead>'
                     f'<tbody>{"".join(port_rows)}</tbody></table></div>{metadata}{action}{more_text}</div></details>')
    if not cards:
        cards=[('<div class="card empty">'+tr('No events in the saved history match this filter yet.','По этому фильтру пока нет событий в сохранённой истории.')+'</div>')]
    total_hits,total_ips=fw.drop_total()
    def link_to(p):
        params={'page':p,'verdict':verdict,'sort':sort}
        if ip:params['ip']=ip
        return e(path_for('events')+'?'+urlencode(params))
    pagination=('<div class="events-pager">'+
                (f'<a href="{link_to(page-1)}">{tr("← Back","← Назад")}</a>' if page>1 else '<span></span>')+
                f'<span class="sub">{tr("Page","Страница")} {page} · {tr("up to 30 IPs","до 30 IP")}</span>'+
                (f'<a href="{link_to(page+1)}">{tr("Next →","Далее →")}</a>' if more else '<span></span>')+
                '</div>')
    return doc(f'<div class="section-row"><h2>{tr("IP history","История по IP")}</h2>{form_html}</div>'
               f'<p>{tr("IPs are grouped · expand an address to view its ports. Counts are based on the log, not connections.","IP сгруппированы · разверните адрес для просмотра портов. Счётчики — по журналу, не по подключениям.")}</p>'
               f'<p class="bad">{tr("Blocked all time:","Отбито за всё время:")} <b>{total_hits}</b> {tr("attempts from","обращений от")} <b>{total_ips}</b> {tr("addresses.","адресов.")}</p>{notice}'
               f'{pagination}<div class="events-list">{"".join(cards)}</div>{pagination}', tr('Events','События'),
               script=EVENTS_SCRIPT.replace('__INFO_ENDPOINT__',json.dumps(path_for('api/ip-info'))))



def ports_from_form(value):
    if not isinstance(value,str) or len(value)>1500:raise ValueError(tr('Port list is too long','Слишком длинный список портов'))
    parts=[v for v in re.split(r'[,;\s]+',value.strip()) if v]
    if any(not x.isdecimal() or len(x)>5 for x in parts):
        raise ValueError(tr('Ports must be integers separated by commas','Порты должны быть целыми числами, через запятую'))
    ports=[int(x) for x in parts]
    autoban.checked_ports(ports)
    return ports


def autoban_control_panel(cfg):
    """The full list moved to /access. Show counts and routing here only."""
    rows=autoban.list_bans_detailed(fw.ROOT,limit=100)
    return (('<div class="control-panel"><h3>'+tr('Automatic bans — escalating durations','Автоматические баны — нарастающие сроки')+'</h3>'
        '<p>'+tr('Automatic ban for TCP port probing: 6 different ports in 60 seconds or 8 in an hour; a trap port triggers an immediate ban, initially for 1 hour. Port probing ban durations:','Автобан за перебор TCP-портов: 6 разных за 60 секунд или 8 разных за час; порт-ловушка — сразу, первый раз на 1 час. Сроки перебора:')+' '
        ''+tr('24 hours → 7 days → 30 days → 180 days → 365 days.','24 часа → 7 дней → 30 дней → 180 дней → 365 дней.')+' '
        ''+tr('Active temporary bans:','Активных временных блокировок:')+' <b>')+e(len(rows))+'</b>.</p>'
        '<p><a href="'+e(path_for('access'))+('">'+tr('Open the IP ban center and remove a ban →','Открыть центр блокировок IP и снять бан →')+'</a></p></div>'))



UI_APPLY_PROGRESS_SCRIPT = """(()=>{
'use strict';
const panel=document.getElementById('ui-apply-status');if(!panel)return;
const url=__UI_APPLY_STATUS_URL__;
const bar=document.getElementById('ui-apply-bar'),meta=document.getElementById('ui-apply-meta'),spin=document.getElementById('ui-apply-spin');
let stopped=false,busy=false;
async function tick(){
 if(stopped||busy)return;busy=true;
 try{
  const response=await fetch(url,{cache:'no-store',credentials:'same-origin'});
  if(!response.ok)throw Error('HTTP '+response.status);
  const data=await response.json();
  panel.textContent=String(data.message||'Проверка выполняется…');
  const percent=Number.isFinite(data.percent)?Math.min(100,Math.max(0,data.percent)):0;
  const seconds=Number.isFinite(data.elapsed)?data.elapsed:0;
  bar.value=percent;meta.textContent=percent+'% · прошло '+Math.floor(seconds/60)+' мин '+(seconds%60)+' с';
  if(data.status==='trial'||data.status==='finished'){
   stopped=true;window.location.replace(__UI_CONTROL_URL__);return;
  }
  if(data.status==='error'){
   stopped=true;panel.className='bad';
   panel.textContent=String(data.error||data.message||'Проверка не прошла');
   bar.hidden=true;meta.hidden=true;spin.hidden=true;
  }
 }catch(err){panel.textContent='Ожидаем ответ сервера…';}
 finally{busy=false;}
}
const timer=setInterval(()=>{if(!stopped)tick();else clearInterval(timer)},1700);
tick();window.addEventListener('pagehide',()=>{stopped=true;clearInterval(timer)});
})();"""


def control_page(message='',job=None):
    st=fw.state();cfg=fw.config();mode=st.get('mode','off')
    job=job or fw.ui_apply_current()
    pending=[]
    for p in fw.ROOT.glob('.pending-*'):
        if not re.fullmatch(r'\.pending-[a-f0-9]{32}',p.name):continue
        m=p/'web.json'
        if m.exists():
            try:
                info=json.loads(m.read_text(encoding='utf-8'))
                if info.get('auto'):continue
                pending.append((p.name[9:],max(0,int(info['deadline'])-int(__import__('time').time()))))
            except (OSError,ValueError,KeyError,TypeError):pass
    job_info=None
    if job:
        try:job_info=fw.ui_apply_status(job)
        except (OSError,ValueError,KeyError,TypeError):job_info=None
    job_active=bool(job_info and job_info['status'] in ('queued','checking','activating'))
    draft=fw.policy_draft()
    selected=draft['candidate'] if draft else cfg
    geo=('off' if not selected.get('geo_enabled',False) else selected.get('geo_mode','ru_only'))
    geo_items=[('off',tr('Off: allow both Russian and non-Russian IPs','Выключен: разрешать и РФ, и не-РФ')),
               ('ru_only',tr('Russian IPs only on VPN ports','Только РФ на VPN-портах')),
               ('non_ru_only',tr('Non-Russian IPs only on VPN ports','Только не-РФ на VPN-портах'))]
    radios=''.join(f'<label class="control-choice"><input type="radio" name="geo_choice" value="{key}"'+
        (' checked' if geo==key else '')+f'><span>{e(label)}</span></label>' for key,label in geo_items)
    features=[
        ('manual_bans_enabled',tr('Enforce permanent blocklist','Применять постоянный чёрный список'),tr('IPs from the IP Lists tab. Works only when blocking is enforced','IP из вкладки «Списки IP». Работает только в режиме реальной блокировки')),
        ('scanner_enabled',tr('Block known scanner IPs','Блокировать IP известных сканеров'),tr('Networks from OpenFilters, CyberOK and other lists; false positives are possible','Сети из OpenFilters, CyberOK и других списков; возможно ложное совпадение')),
        ('asn_enabled',tr('Block networks of selected ASNs','Блокировать сети выбранных ASN'),tr('ASN is a provider’s autonomous system number; the list comes from asn.txt, independently of scanner lists','ASN — номер автономной сети провайдера; список из asn.txt, независимо от сканеров')),
        ('ssh_rate_enabled',tr('Limit new SSH connections','Ограничить новые SSH-подключения'),tr('Up to 10 new attempts per minute per IP with burst allowance; VPN ports are excluded','До 10 новых попыток в минуту на IP с burst; VPN-порты исключены')),
        ('threat_ssh_enabled',tr('Observe SSH attacks','Наблюдать атаки на SSH'),tr('Events from SSH attack lists: logging only, no blocking','События из списков атак на SSH: только журнал, без блокировки')),
        ('threat_ssh_enforce',tr('Block IPs from SSH lists','Блокировать IP из SSH-списков'),tr('Enforced blocking on SSH ports may restrict remote administration','Реальные блокировки на SSH-портах: могут ограничить удалённое администрирование')),
        ('threat_watch_enabled',tr('Fetch WATCH reputation lists','Получать репутационные списки WATCH'),tr('Spamhaus, DShield, OpenDBL and others; observe only unless blocking is enabled separately','Spamhaus, DShield, OpenDBL и другие; без отдельной галочки только наблюдение')),
        ('threat_watch_enforce',tr('BLOCK IPs from WATCH lists on all ports','БЛОКИРОВАТЬ IP из WATCH-списков на всех портах'),tr('Aggressive policy: DROP also applies to VPN ports 443/8443; false positives and NAT/CDN may affect clients','Агрессивная политика: DROP в том числе на VPN 443/8443; ложные совпадения, NAT/CDN могут затронуть клиентов')),
        ('logging_enabled',tr('Log network events','Записывать сетевые события'),tr('Required for IP history and the live log; packet logging is rate-limited','Нужен для истории IP и живого журнала; запись пакетов ограничена по частоте')),
        ('live_pass_logging_enabled',tr('Show passed packets in the LIVE log','Показывать прошедшие пакеты в LIVE-журнале'),tr('Sampled new TCP SYN packets on VPN ports; not a count of active users','Выборочные новые TCP SYN на VPN-портах; не число активных пользователей')),
        ('autoban_enabled',tr('Automatically ban port scanning','Автоматически блокировать сканирование портов'),tr('6 different unknown TCP ports in 60 seconds or 8 in an hour → 24 h / 7 d / 30 d / 180 d / 365 d for repeat detections; separate from manual bans','6 разных неизвестных TCP-портов за 60 секунд или 8 за час → 24 ч / 7 д / 30 д / 180 д / 365 д за повторные срабатывания; отдельно от ручных блокировок')),
        ('ssh_watch_enabled',tr('SSH: trust after login and ban for brute force','SSH: доверие после входа и бан за перебор'),tr('Successful key login: trust for 30 days; password login: 24 hours. 6 failures in 10 minutes: ban on all ports except the web panel port. Requires auto-ban to be enabled','Успешный вход по ключу: доверие 30 дней, по паролю: 24 часа. 6 неудач за 10 минут: бан на всех портах кроме панели. Нужен включённый автобан')),
        ('extra_threat_feeds_enabled',tr('Additional feeds: AbuseIPDB, IPsum, Emerging Threats, GreenSnow','Дополнительные базы: AbuseIPDB, IPsum, Emerging Threats, GreenSnow'),tr('Affect DROP after confirmation','Влияют на DROP после подтверждения')),
        ('advanced_feed_pack_enabled',tr('Advanced free IP feeds','Расширенные бесплатные IP-базы'),tr('Separate catalog: NERD, FireHOL, RU-SCAN, GOV, and others. Must be downloaded first; government networks are for reference only','Отдельный каталог: NERD, FireHOL, RU-SCAN, GOV и др. Требуется предварительная загрузка; госcети только справочно')),
    ]
    toggles=''.join('<label class="control-choice"><input type="checkbox" name="'+key+'" value="1"'+
        (' checked' if selected.get(key,False) else '')+'><span><b>'+e(label)+'</b><br><span class="small-note">'+e(desc)+'</span></span></label>'
        for key,label,desc in features)
    warning=''
    if draft and draft.get('vpn_warnings'):
        warning=('<div class="warning">'+tr('Known client addresses match potential bans:','Известные клиентские адреса совпадают с потенциальными запретами:')+'<ul>')+''.join(
            f'<li><code>{e(ip)}</code>: {e(", ".join(labels))}</li>' for ip,labels in draft['vpn_warnings'][:12])+'</ul></div>'
    extra_report=fw.extras_status()
    extra_names={'abuseipdb_blacklist90':'AbuseIPDB 90+',
                 'ipsum_level5':'IPsum Level 5',
                 'emerging_compromised':'Emerging Threats',
                 'greensnow_attackers':'GreenSnow'}
    extra_info=' · '.join(e(extra_names[k])+': '+(str(n)+(' '+tr('IPs/networks','IP/сетей')) if n else tr('not loaded','не загружена'))
                        for k,n in extra_report['sources'].items())
    extra_panel=(('<div class="control-panel"><h3>'+tr('Additional threat feeds','Дополнительные базы угроз')+'</h3>'
       '<p>'+tr('Four high-risk IP lists for stronger protection. New data will not block anyone until the new policy is confirmed.','Четыре высокорисковых IP-списка для усиленной защиты. Новые данные не блокируют никого до подтверждения новой политики.')+' '
       ''+tr('Enabling this also blocks matching IPs from accessing VPN ports 443/8443.','Включение запрещает доступ в том числе к VPN-портам 443/8443 для совпавших IP.')+'</p>'
       '<p class="small-note">')+extra_info+('</p>'
       '<p class="small-note">'+tr('API key:','API-ключ:')+' ')+(tr('stored on the server','записан на сервере') if extra_report['key_ready'] else tr('not set','не установлен'))+('. '
       ''+tr('SSH commands:','Команды SSH:')+' <code>sudo fw-sentinel abuse-key-set</code> ('+tr('once), then','один раз), затем')+' '
       '<code>sudo fw-sentinel feeds-prepare</code> '+tr('and enable the desired option and click Apply rules.','и включить нужный пункт и нажать «Применить правила».')+'</p>'
       '</div>'))
    pending_html=shield_controls(mode,cfg) if pending_trial() else ''
    start_form=form('control/start','',('▶ '+tr('Enable observe mode','Включить наблюдение')))
    pause_form=form('control/pause','',('Ⅱ '+tr('Disable blocking','Отключить блокировки')))
    stop_form=form('control/stop','<input type="hidden" name="confirm" value="stop">',('■ '+tr('Stop Sentinel','Остановить Sentinel')),'danger-btn')
    progress_html=''
    if job_info:
        if job_active:
            progress_html=(('<div class="control-panel"><h3><span id="ui-apply-spin" class="feed-spin"></span> '+tr('Applying rules','Применение правил')+'</h3>'
                           '<p id="ui-apply-status" role="status">')+e(job_info.get('message',tr('Checking settings…','Проверяем настройки…')))+'</p>'
                           '<progress id="ui-apply-bar" max="100" value="'+str(int(job_info.get('percent',0)))+('" style="width:100%;height:11px;accent-color:#43c88c" aria-label="'+tr('Rule application progress','Ход применения правил')+'"></progress>'
                           '<p id="ui-apply-meta" class="small-note"></p>'
                           '<p class="small-note">'+tr('With large feeds, this takes a couple of minutes. You can close this page; the process will continue.','С большими базами это занимает пару минут. Страницу можно закрыть, применение продолжится.')+'</p>'
                           '</div>'))
        elif job_info.get('status')=='error':
            progress_html=(('<div class="warning"><b>'+tr('Application rejected','Применение отклонено')+'</b><p>')
                           +e(job_info.get('error',tr('Validation error','Ошибка проверки')))+'</p></div>')
        elif job_info.get('status')=='finished':
            progress_html=(('<div class="control-panel"><p>'+tr('Trial application complete. Check the current protection mode.','Пробное применение завершилось. Проверьте текущий режим защиты.')+'</p></div>'))
    apply_script=(UI_APPLY_PROGRESS_SCRIPT.replace('__UI_APPLY_STATUS_URL__',
                  json.dumps(path_for('api/ui-apply-status')+'?'+urlencode({'job':job})))
                  .replace('__UI_CONTROL_URL__',json.dumps(path_for('control')))) if job_active else ''
    return doc(f'''<h2>{tr("Protection settings and controls","Настройки и управление защитой")}</h2><p>{tr("Firewall settings. The VPN will not be restarted.","Настройки firewall. VPN не перезапускается.")}</p>
    <div class="control-panel protection-status"><h3>{tr("Protection status and controls","Состояние и управление защитой")}</h3>
      <p><b class="{'good' if quick_profile_active(mode,cfg) else 'caution' if mode=='observe' else 'bad' if mode=='enforce' else 'muted'}">{e(tr('ENHANCED AUTOMATIC PROTECTION · ALWAYS ON','УСИЛЕННАЯ АВТОЗАЩИТА · ВКЛЮЧЕНА ПОСТОЯННО') if quick_profile_active(mode,cfg) else tr('BLOCKING ENABLED · CUSTOM RULES','БЛОКИРОВКИ ВКЛЮЧЕНЫ · ИНДИВИДУАЛЬНЫЕ ПРАВИЛА') if mode=='enforce' else tr('OBSERVE MODE ONLY · NO DROP','ТОЛЬКО НАБЛЮДЕНИЕ · БЕЗ DROP') if mode=='observe' else tr('SENTINEL STOPPED','SENTINEL ОСТАНОВЛЕН'))}</b></p>
      {pending_html}
      <div class="control-actions">{start_form if mode=='off' else ('<button disabled>▶ '+tr('Enable observe mode','Включить наблюдение')+'</button>')}{pause_form if mode=='enforce' else ('<button disabled>Ⅱ '+tr('Disable blocking','Отключить блокировки')+'</button>')}{stop_form if mode!='off' else ('<button disabled>■ '+tr('Stop Sentinel','Остановить Sentinel')+'</button>')}</div>
      <p class="small-note">{tr("Disabling DROP does not stop the VPN. Automatic rollback applies if new rules could cut off your IP.","Отключение DROP не останавливает VPN. Автооткат действует, если новые правила могут отрезать ваш IP.")}</p></div>
    {progress_html}
    <div class="control-panel"><h3>{tr("Advanced filtering settings","Дополнительные настройки фильтрации")}</h3>
      <form method="post" action="{e(path_for('control/apply-now'))}"><input type="hidden" name="csrf" value="{csrf()}">
       <h4>{tr("Geographic filtering on ports","География на портах")} {e(', '.join(map(str,cfg.get('geo_ports',[443,8443]))))}</h4>
       <div class="control-grid">{radios}</div><h4>{tr("Features to enable","Какие функции включить")}</h4><div class="control-grid">{toggles}</div>
       <h4>{tr("Ports to always exclude from scan detection","Порты, которые никогда не считать сканированием")}</h4><p class="small-note">{tr("Additional exclusions. VPN, SSH, and open services are excluded automatically.","Дополнительные исключения. VPN, SSH и открытые сервисы исключаются автоматически.")}</p>
       <label>{tr("Additional TCP ports","Дополнительные TCP-порты")} <input type="text" name="autoban_exclude_tcp_ports" maxlength="1500" value="{e(', '.join(map(str,selected.get('autoban_exclude_tcp_ports',list(autoban.PORT_DEFAULT_TCP)))))}"></label>
       <label>{tr("Additional UDP ports","Дополнительные UDP-порты")} <input type="text" name="autoban_exclude_udp_ports" maxlength="1500" value="{e(', '.join(map(str,selected.get('autoban_exclude_udp_ports',list(autoban.PORT_DEFAULT_UDP)))))}"></label>
       <h4>{tr("Trap ports (TCP)","Порты-ловушки (TCP)")}</h4><p class="small-note">{tr("A single connection to a trap port results in a 1-hour ban on all ports except the web panel port (443), so you can log in from the same address and lift the ban. A repeat attempt results in a 24-hour ban, with longer bans after that. Ports running services will not become traps. Requires auto-ban to be enabled. Example: 22, 23, 3389, 5900.","Одно обращение к такому порту — бан на 1 час на все порты, кроме порта панели (443): с того же адреса можно зайти и снять бан. Повторно — 24 часа и дальше по нарастающей. Порты, на которых работают службы, ловушками не станут. Нужен включённый автобан. Пример: 22, 23, 3389, 5900.")}</p>
       <label>{tr("Trap ports","Порты-ловушки")} <input type="text" name="autoban_trap_ports" maxlength="1500" value="{e(', '.join(map(str,selected.get('autoban_trap_ports',[]))))}"></label>
       <button class="block-button" type="submit" {'disabled' if job_active or pending else ''}>{tr("APPLY RULES","ПРИМЕНИТЬ ПРАВИЛА")}</button>
       <p class="small-note">{tr("The check runs independently of your browser. If the new rules do not cut off your IP, they will be saved automatically. Otherwise, confirm within 120 seconds or they will be rolled back.","Проверка начнётся отдельно от браузера. Если новые правила не отрежут ваш IP, они сохранятся сами. Иначе подтвердите за 120 секунд, без подтверждения — откат.")}</p>
      </form></div>
    {warning}
    {extra_panel}
    {autoban_control_panel(cfg)}
    <div class="warning">{tr("The geographic filter may disconnect VPN clients with dynamic IPs. Check access before confirming.","Геофильтр может отключить VPN-клиентов с динамическими IP. Проверяйте доступ до подтверждения.")}</div>
    <details class="helpbox"><summary>{tr("Help: which switches block traffic and which only observe?","Справка: какие переключатели блокируют трафик, а какие только наблюдают?")}</summary>
    <p><strong>{tr("Block traffic","Блокируют")}</strong> ({tr("only in active protection mode): manual blocklist, scanners, ASN, SSH limit, SSH reputation blocking, geographic filter, AUTO-BAN.","только при активном режиме защиты): ручной чёрный список, сканеры, ASN, SSH-лимит, блокировка по SSH-репутации, геофильтр, AUTO-BAN.")} <strong>{tr("Observe only:","Только наблюдают:")}</strong> {tr("reputation feeds without WATCH blocking enabled, logging, and green events. Changes take effect after clicking Apply rules; confirmation is then required within 120 seconds.","репутационные базы без включённой блокировки WATCH, журналирование и зелёные события. Изменения вступают в силу после нажатия «Применить правила»; затем требуется подтверждение в течение 120 секунд.")}</p>
    <p><strong>{tr("Pause feed","Пауза ленты")}</strong> {tr("does not disable firewall rules.","не отключает правила firewall.")} <strong>{tr("Disable blocking","Отключить блокировки")}</strong> {tr("puts Sentinel in observe mode and does not automatically re-enable blocking.","переводит Sentinel в наблюдение и не включает их обратно автоматически.")} <strong>{tr("Stop Sentinel","Остановить Sentinel")}</strong> {tr("removes only its own nftables table. SSH, Nginx, and VPN are not restarted.","удаляет только его таблицу nftables. SSH, Nginx и VPN не перезапускаются.")}</p></details>
    <p class="sub">{tr("Mode:","Режим:")} {e(mode)}</p>''',tr('Control','Управление'),message=message,script=(TRIAL_COUNTDOWN_SCRIPT if pending_trial() else '')+apply_script)



ACCESS_INTEL_LAZY_SCRIPT = """(()=>{
'use strict';
document.querySelectorAll('.block-intel').forEach(box=>{
 box.addEventListener('toggle',()=>{
  if(!box.open)return;
  const target=box.querySelector('[data-intel-on-open]');
  if(!target||target.dataset.done)return;
  const ip=target.dataset.intelOnOpen;
  target.dataset.done='1';
  const small=document.createElement('small');small.className='ip-intel';small.dataset.intelIp=ip;
  small.textContent='Загрузка данных IP…';target.append(small);
  if(window.fwsIntelScan)window.fwsIntelScan();
 });
});
})();"""


def _block_categories(reasons):
    """Distinct reasons from sampled DROP records (not current feed membership)."""
    parts={x.strip().upper() for x in (reasons or '').split(',') if x.strip()}
    result=set()
    if any(x.startswith('WATCH') for x in parts):result.add('watch')
    if any(x.startswith('SCAN') for x in parts):result.add('scan')
    if any(x.startswith('SSHREP') for x in parts):result.add('sshrep')
    if 'SSH' in parts:result.add('ssh_limit')
    if any(x.startswith('ASN') for x in parts):result.add('asn')
    if any(x.startswith('GEO') for x in parts):result.add('geo')
    if any(x.startswith('BAN') for x in parts):result.add('old_manual')
    if any(x.startswith('AUTO') for x in parts):result.add('old_auto')
    return result


def _block_views(query=None):
    # Do not enumerate entire external threat feeds
    query=query or {}
    kind=(query.get('type') or ['all'])[0]
    if kind not in ('all','auto','manual','feeds','asn'):kind='all'
    try:page=int((query.get('page') or ['1'])[0])
    except (ValueError,TypeError):page=1
    page=min(max(1,page),1000)
    entries={}
    def entry(ip):
        if ip not in entries:entries[ip]={'ip':ip,'types':set(),'count':0,'last':'','ports':'','strike':0,'expiry':0}
        return entries[ip]
    manual=fw.line_networks(fw.ROOT/'manual-bans.txt',addresses_only=True)
    active=autoban.list_bans_detailed(fw.ROOT,limit=500)
    now=int(time.time())
    for net in manual:
        if net.prefixlen != net.max_prefixlen:continue
        it=entry(str(net.network_address));it['types'].add('manual')
    for ip,started,expiry,ports,strike in active:
        if expiry<=now:continue
        it=entry(ip);it['types'].add('auto');it['expiry']=expiry
        it['ports']=ports;it['strike']=strike
    # Journal-only IPs are last-24h evidence, NOT a full or guaranteed-current feed membership list.
    for ip,count,last,reasons in fw.recent_drop_causes(limit=400,hours=24):
        cats=_block_categories(reasons)
        if not cats:cats.add('other')
        it=entry(ip)
        # Current active ban wins over old DROP history; historical reasons do
        # not imply the IP still has that type of active ban.
        if 'manual' in it['types']:cats.discard('old_manual')
        if 'auto' in it['types']:cats.discard('old_auto')
        it['types'].update(cats);it['count']=count;it['last']=last or '' 
    # Multi-category IPs appear once per tab, with all relevant badges.
    filtered=[v for v in entries.values() if kind=='all' or (kind=='feeds' and bool({'watch','scan','sshrep'} & v['types'])) or kind in v['types']]
    filtered.sort(key=lambda v:(-v['count'],-int(v['expiry'] or 0),v['ip']))
    pagesize=40
    total=len(filtered)
    return kind,page,total,filtered[(page-1)*pagesize:page*pagesize],manual


def access_page(query=None):
    # Manual/auto bans plus recent logged reputation/ASN drops
    kind,page,total,entries,manual=_block_views(query)
    allow=fw.line_networks(fw.ROOT/'allow.txt')
    vpn=fw.line_networks(fw.ROOT/'vpn-clients.txt',addresses_only=True)
    titles=[('all',tr('All','Все')),('auto',tr('Auto-bans','Автобаны')),('feeds',tr('Threat feeds','Базы угроз')),('asn','ASN'),('manual',tr('Manual','Ручные'))]
    tabs=''.join('<a class="block-tab'+(' selected' if kind==key else '')+'"'
         +' href="'+e(path_for('access')+'?'+urlencode({'type':key}))+'"'
         +(' aria-current="page"' if kind==key else '')+'>'+e(title)+'</a>'
         for key,title in titles)
    def listbox(nets,action):
        if not nets:return ('<p class="muted">'+tr('Empty','Пусто')+'</p>')
        out=['<div class="scroll"><table><tbody>']
        for net in nets:
            ip=str(net.network_address)
            remove=(form(action,f'<input type="hidden" name="ip" value="{e(ip)}">',tr('Remove','Убрать'),'danger-btn')
                    if net.prefixlen==net.max_prefixlen else ('<span class="muted">'+tr('Subnet: via file','Подсеть: через файл')+'</span>'))
            out.append(f'<tr><td><code>{e(ip if net.prefixlen==net.max_prefixlen else str(net))}</code></td><td>{remove}</td></tr>')
        return ''.join(out)+'</tbody></table></div>'
    now=int(time.time())
    labels={'auto':(tr('AUTO-BAN','АВТОБАН'),'caution'),'manual':(tr('MANUAL','РУЧНОЙ'),'bad'),
            'watch':('WATCH','bad'),'scan':('SCAN','bad'),'sshrep':(tr('SSH REPUTATION','SSH-РЕПУТАЦИЯ'),'bad'),'ssh_limit':(tr('SSH LIMIT','SSH-ЛИМИТ'),'caution'),
            'asn':('ASN','caution'),'geo':(tr('GEO','ГЕО'),'caution'),
            'old_auto':(tr('AUTO · LOG','AUTO · ЖУРНАЛ'),'bad'),'old_manual':(tr('BAN · LOG','BAN · ЖУРНАЛ'),'bad'),
            'other':('DROP','bad')}
    out=[]
    for v in entries:
        ip=v['ip'];types=v['types'];count=v['count']
        tags=' '.join(f'<span class="block-chip {labels[t][1]}">{labels[t][0]+(" №"+str(v["strike"]) if t=="auto" else "")}</span>'
                      for t in ('manual','auto','watch','scan','sshrep','ssh_limit','asn','geo','old_manual','old_auto','other') if t in types)
        if 'manual' in types:status=tr('Indefinite','Бессрочно')
        elif 'auto' in types:status=f'{max(0,(v["expiry"]-now+59)//60)} {tr("min","мин")}'
        else:status=tr('Log · 24 h','Журнал · 24 ч')
        stamp=v['last'].replace('T',' ')[:19] if v['last'] else '—'
        if 'manual' in types:
            action=form('unban',f'<input type="hidden" name="ip" value="{e(ip)}">',tr('Lift ban','Снять бан'),'danger-btn')
        elif 'auto' in types:
            action=form('control/auto-unban/preview',f'<input type="hidden" name="ip" value="{e(ip)}">',tr('Lift auto-ban','Снять автобан'))
        else:
            url=path_for('events')+'?'+urlencode({'ip':ip,'verdict':'drop'})
            action='<a href="'+e(url)+('">'+tr('IP history','История IP')+'</a>')
        port_list=', '.join(tr('SSH brute force','перебор SSH') if x=='SSH brute force' else str(x) for x in json.loads(v['ports'])) if v['ports'] else ''
        details=f'<div class="block-extra">{((tr("Ports:","Порты:")+" ")+e(port_list)+" · ") if port_list else ""}{tr("Last:","Последний:")} {e(stamp)} UTC</div>'
        # Fetch external intelligence only on explicit expansion; not for hundreds of IPs at once.
        intelligence=f'<details class="block-intel"><summary>{tr("ASN · country · AbuseIPDB","ASN · страна · AbuseIPDB")}</summary><div data-intel-on-open="{e(ip)}"></div></details>'
        out.append('<tr><td class="ip-entry"><code class="bad">'+e(ip)+'</code>'+intelligence+'</td>'+
                   '<td>'+tags+details+'</td><td>'+e(status)+'</td><td>'+str(count)+'</td><td>'+action+'</td></tr>')
    listing=(('<div class="scroll"><table class="block-records"><thead><tr><th>'+tr('IP address','IP-адрес')+'</th><th>'+tr('Reason','Причина')+'</th>'
             '<th>'+tr('Duration','Срок')+'</th><th>'+tr('DROP in 24 h','DROP за сутки')+'</th><th>'+tr('Action','Действие')+'</th></tr></thead><tbody>')+''.join(out)+'</tbody></table></div>'
             if out else ('<p class="muted">'+tr('No addresses in this category.','В этой категории адресов нет.')+'</p>'))
    pagesize=40
    max_page=max(1,(total+pagesize-1)//pagesize)
    pagination=''
    if max_page>1:
        pagination='<div class="block-pager">'
        for p,text in ((page-1,tr('← Back','← Назад')),(page+1,tr('Next →','Вперёд →'))):
            if 1<=p<=max_page:
                url=path_for('access')+'?'+urlencode({'type':kind,'page':p})
                pagination+=f'<a href="{e(url)}">{text}</a>'
        pagination+=f'<span>{page} / {max_page}</span></div>'
    trusts=autoban.list_ssh_trust(fw.ROOT)
    trust_rows=''.join('<tr><td><code>'+e(ip)+'</code></td><td>'+(tr('Key','по ключу') if method=='publickey' else tr('Password','по паролю'))+'</td><td>'+e(time.strftime('%Y-%m-%d %H:%M UTC',time.gmtime(expires)))+'</td><td>'+form('ssh-trust/remove',f'<input type="hidden" name="ip" value="{e(ip)}">',tr('Remove','Убрать'))+'</td></tr>' for ip,method,expires in trusts)
    trust_listing=('<table><thead><tr><th>IP</th><th>'+tr('Login','Вход')+'</th><th>'+tr('Trusted until','Доверять до')+'</th><th></th></tr></thead><tbody>')+trust_rows+'</tbody></table>' if trusts else ('<p class="muted">'+tr('None yet.','Пока нет.')+'</p>')
    field=('<input required name="ip" placeholder="'+tr('Public IP','Публичный IP')+'" maxlength="45" pattern="[^ ]+">')
    bulkfield='<textarea required name="ips" rows="6" maxlength="120000" placeholder="1.2.3.4&#10;8.8.8.8&#10;2001:4860:4860::8888"></textarea>'
    return doc(f'''<h2>{tr("IP bans","Блокировки IP")}</h2>
    <div class="block-tabs" role="navigation" aria-label="{tr("Ban categories","Категории блокировок")}">{tabs}</div>
    <p class="sub">{total} {tr("IPs · Feed-based DROP in 24 h. Counts are based on logs.","IP · По базам — DROP за 24 ч. Счётчики по журналу.")}</p>
    <section class="block-hub"><div class="primary">{listing}{pagination}</div></section>
    <section><h3>{tr("Trusted via SSH login","Доверенные по входу SSH")}</h3>{trust_listing}</section>
    <details class="manual-lists"><summary>{tr("Manual IP lists","Ручные списки IP")}</summary>
      <div class="grid"><div class="card wide"><h3>{tr("Permanent bans","Постоянные баны")}</h3>{form('ban',field,tr('Ban IP','Заблокировать IP'),'danger-btn')}{listbox(manual,'unban')}<details class="bulk-import"><summary>{tr("Add IPs to the ban list in bulk","Добавить пачку IP в блокировки")}</summary>{form('bulk/ban',bulkfield,tr('Add IP list','Добавить список IP'),'danger-btn')}</details></div>
      <div class="card wide"><h3>{tr("Trusted IPs (SSH)","Доверенные IP (SSH)")}</h3>{form('allow',field,tr('Add IP','Добавить IP'))}{listbox(allow,'unallow')}<details class="bulk-import"><summary>{tr("Add trusted IPs in bulk","Добавить пачку доверенных IP")}</summary>{form('bulk/allow',bulkfield,tr('Add IP list','Добавить список IP'))}</details></div>
      <div class="card wide"><h3>{tr("VPN client exceptions","Исключения для клиентов VPN")}</h3>{form('vpn-add',field,tr('Add IP','Добавить IP'))}{listbox(vpn,'vpn-remove')}</div>
      </div></details>
    <div class="warning">{tr("Do not ban your own SSH IP. Feed-based blocking also applies to VPN.","Не блокируйте свой SSH-IP. Блокировки по базам действуют и на VPN.")}</div>''',tr('Access','Доступ'),
    script=IP_INTEL_SCRIPT.replace('__IP_INTEL_URL__',json.dumps(path_for('api/ip-intel')))
          + ACCESS_INTEL_LAZY_SCRIPT)


FEED_REFRESH_SCRIPT = '''(()=>{
'use strict';
const url=__FEED_STATUS_URL__,home=__SOURCES_HOME__;
const rows=[...document.querySelectorAll('[data-feed-source]')];
if(!rows.length)return;
let active=false,completed=false;
const forms=[...document.querySelectorAll('.feed-refresh-form')];
function display(data){
 const running=['queued','download','parse','validate'].includes(data.state);
 forms.forEach(form=>{const button=form.querySelector('button');if(button)button.disabled=running;});
 rows.forEach(row=>{
  const match=data.source===row.dataset.feedSource;
  const area=row.querySelector('.feed-progress');if(!area)return;
  // A finished job stays saved on the server: show success only until this page reloads.
  const failed=data.state==='error';
  area.hidden=!(match&&(running||failed||(active&&!completed)));
  if(match){
    area.querySelector('progress').hidden=failed;
    area.querySelector('[data-feed-pct]').hidden=failed;
    const percent=Number.isFinite(data.percent)?Math.min(100,Math.max(0,data.percent)):0;
    const bar=area.querySelector('progress');bar.value=percent;
    area.querySelector('[data-feed-pct]').textContent=percent+'%';
    area.querySelector('[data-feed-text]').textContent=String(data.message||'');
    const spin=area.querySelector('.feed-spin');if(spin)spin.hidden=!running;
    const line=row.querySelector('[data-feed-error]');
    if(line)line.textContent=String(data.error||data.warning||'');
  }
 });
 if(running)active=true;
 if(active&&!running&&data.state&&['done','warning','error'].includes(data.state)&&!completed){
  completed=true;
  // Refresh counts and timestamps once, never reload continuously on a saved job.
  setTimeout(()=>location.replace(home+'?updated=1'),1700);
 }
}
async function poll(){
 if(document.hidden)return;
 try{
  const r=await fetch(url,{cache:'no-store',credentials:'same-origin',headers:{'X-FWS-Feed':'1'}});
  if(!r.ok)return;
  display(await r.json());
 }catch(_e){/* The status remains visible; next poll retries. */}
}
const t=setInterval(poll,1200);poll();
document.addEventListener('visibilitychange',()=>{if(!document.hidden)poll();});
window.addEventListener('pagehide',()=>clearInterval(t));
})();'''


def sources_page(message=''):
    registry=fw.feed_refresh_catalog()
    job=fw.feed_refresh_status()
    running=job.get('state') in ('queued','download','parse','validate')
    records=[]
    for key,info in registry.items():
        action=(form('sources/refresh','<input type="hidden" name="source" value="'+e(key)+'">',
                     tr('⟳ Refresh','⟳ Обновить')) if info['enabled'] else '<span class="muted">—</span>')
        action=action.replace('<form ','<form class="feed-refresh-form" ',1)
        raw_date=info.get('updated','')
        date=e(raw_date.replace('T',' ')[:19]+' UTC') if raw_date else '—'
        if info['count']:
            state=('<span class="good">'+tr('Ready','Готов')+'</span>')
        else:state=('<span class="muted">'+tr('Not loaded','Не загружен')+'</span>')
        if not info['enabled']:state=('<span class="muted">'+tr('Disabled / archived','Отключён / архив')+'</span>')
        note=fw.notable(info.get('error')) or fw.notable(info.get('warning'))
        label='<span class="feed-name">'+e(info['name'])+'</span><div class="feed-id">'+e(key)+'</div>'
        records.append('<tr data-feed-source="'+e(key)+'"><td class="feed-item"><div class="feed-source">'+action+label+('</div>'
             '<div class="feed-progress" hidden><span class="feed-spin" aria-hidden="true"></span>'
             '<span data-feed-text>'+tr('Waiting…','Ожидаем…')+'</span> <strong data-feed-pct>0%</strong>'
             '<progress max="100" value="0" aria-label="'+tr('Download progress','Прогресс загрузки')+'"></progress></div></td>'
             '<td>')+e(info['group'])+'</td><td class="feed-count">'+str(info['count'])+'</td>'
             '<td class="feed-updated">'+date+'</td><td>'+state+
             '<div class="feed-note" data-feed-error title="'+e(note[:900])+'">'+e(note[:160])+ '</div></td></tr>')
    providers=[]
    for item in provider_keys.status(fw.ROOT):
        pid=item['id'];is_on=item['enabled']
        state=('<span class="good">'+tr('Key saved','Ключ сохранён')+'</span>') if is_on else ('<span class="muted">'+tr('Disabled','Выключен')+'</span>')
        hint=e(item['integration'])
        save=form('provider/set',
            '<input type="hidden" name="provider" value="'+e(pid)+('">'
            '<input type="password" name="key" required minlength="8" maxlength="1024" '
            'autocomplete="new-password" placeholder="'+tr('API key / password','API-ключ / пароль')+'" aria-label="'+tr('Key','Ключ')+' ')+e(item['title'])+'">',
            tr('Save key','Сохранить ключ'))
        off=form('provider/disable','<input type="hidden" name="provider" value="'+e(pid)+'">',tr('Disable','Отключить'))
        providers.append('<div class="provider-card"><div class="provider-title"><b>'+e(item['title'])+'</b> · '+state+'</div>'
             '<div class="small-note">'+e(i18n.localize(item['purpose']))+' · '+hint+' · <a href="'+e(item['register'])+('" '
             'target="_blank" rel="noopener noreferrer">'+tr('Register','Регистрация')+'</a></div><div class="provider-actions">')+save+off+'</div></div>')
    notice='<p class="good">'+e(message)+'</p>' if message else ''
    note=(tr('Update in progress — progress is shown in the corresponding row.','Обновление выполняется — прогресс указан в соответствующей строке.') if running else
          tr('Click Update for the desired list. Active firewall rules are not changed.','Нажмите «Обновить» у нужной базы. Действующие правила firewall не меняются.'))
    js=FEED_REFRESH_SCRIPT.replace('__FEED_STATUS_URL__',json.dumps(path_for('api/feed-refresh-status'))).replace('__SOURCES_HOME__',json.dumps(path_for('sources')))
    return doc(f'''<h2>{tr("Threat feeds","Базы угроз")}</h2>{notice}
    <div class="control-panel"><h3>{tr("All IP sources ·","Все IP-источники ·")} {len(registry)}</h3>
    <p class="small-note">{e(note)}</p>
    <div class="scroll"><table class="feed-table"><thead><tr><th>{tr("Source / update","Источник / обновить")}</th><th>{tr("Group","Группа")}</th><th>{tr("IPs/networks","IP/сетей")}</th><th>{tr("Updated (UTC)","Обновлено (UTC)")}</th><th>{tr("Status","Состояние")}</th></tr></thead><tbody>{''.join(records)}</tbody></table></div></div>
    <details class="control-panel"><summary><b>{tr("Lists requiring registration — API keys","Базы с регистрацией — API-ключи")}</b></summary>
    <p class="small-note">{tr("Keys are hidden. An empty key disables the source. Not all services have a loader implemented.","Ключи скрыты. Пустой ключ отключает источник. Не все сервисы имеют реализованный загрузчик.")}</p>
    <div class="provider-grid">{''.join(providers)}</div></details>''', tr('Sources','Источники'),script=js)


class Handler(BaseHTTPRequestHandler):
    server_version='FW-Sentinel/2.0.21'
    timeout=30  # a stalled client must not hold a thread forever
    def send_safe_headers(self,code,length,extra=None,nonce=None,content_type='text/html; charset=utf-8'):
        self.send_response(code)
        self.send_header('Content-Type',content_type)
        self.send_header('Content-Length',str(length))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('X-Frame-Options','DENY')
        self.send_header('Referrer-Policy','same-origin')
        self.send_header('Content-Security-Policy',"default-src 'none'; style-src 'unsafe-inline'; connect-src 'self'; " + ("script-src 'nonce-"+nonce+"'; " if nonce else '') + "form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        if extra:
            for k,v in extra.items():self.send_header(k,v)
        self.end_headers()
    def respond(self,code,text,extra=None,content_type='text/html; charset=utf-8'):
        data=text.encode('utf-8')
        token=re.search(r'<script nonce="([A-Za-z0-9_-]{10,})">',text)
        try:
            self.send_safe_headers(code,len(data),extra,nonce=token.group(1) if token else None,content_type=content_type)
            self.wfile.write(data)
        except (BrokenPipeError,ConnectionResetError,ConnectionAbortedError):
            # The browser/proxy closed the response; do not attempt a second write.
            return
    def authorized(self):
        raw=self.headers.get('Authorization','')
        if not raw.startswith('Basic '):return False
        try:
            decoded=base64.b64decode(raw[6:],validate=True).decode('utf-8')
            user,sep,password=decoded.partition(':')
        except (ValueError,UnicodeDecodeError):return False
        token=TOKEN_FILE.read_text().strip()
        return bool(sep and token and user=='admin' and hmac.compare_digest(password.encode(),token.encode()))
    def allowed_origins(self):
        port=self.server.server_port
        hosts={f'127.0.0.1:{port}':f'http://127.0.0.1:{port}',
               f'localhost:{port}':f'http://localhost:{port}'}
        remote=public_origin()
        if remote:
            hosts[urlsplit(remote).netloc]=remote
        return hosts
    def gate(self):
        # Prevent DNS rebinding and accidental publication on an unapproved hostname.
        if self.headers.get('Host','').lower() not in self.allowed_origins():
            self.respond(403,bare_page(tr('Unknown Host','Неизвестный Host')));return False
        if not self.authorized():
            self.respond(401,bare_page(tr('Authentication required','Нужна авторизация')),{'WWW-Authenticate':'Basic realm="FW Sentinel Admin", charset="UTF-8"'})
            return False
        return True
    def do_GET(self):
        if not self.gate():return
        url=urlsplit(self.path);path=routed_path(url.path)
        try:
            if path=='/api/ip-intel':
                # Custom header blocks cross-site image/form abuse of external API quota.
                if (self.headers.get('X-FWS-Intel')!='1' or
                    self.headers.get('Sec-Fetch-Site','').lower() not in ('','none','same-origin')):
                    self.respond(403,json.dumps({'error':tr('Access denied','Доступ запрещён')},ensure_ascii=False),content_type='application/json; charset=utf-8');return
                raw=(parse_qs(url.query).get('ip') or [''])[0]
                try:
                    if len(raw)>45:raise ValueError(tr('Invalid IP','Неверный IP'))
                    info=ipintel.lookup(raw,fw.ROOT)
                except (ValueError,ipintel.IntelError) as err:
                    self.respond(400,json.dumps({'error':str(err)},ensure_ascii=False),content_type='application/json; charset=utf-8');return
                self.respond(200,json.dumps(info,ensure_ascii=False),content_type='application/json; charset=utf-8');return
            if path=='/api/ip-info':
                if self.headers.get('Sec-Fetch-Site','').lower() not in ('','none','same-origin'):
                    self.respond(403,json.dumps({'error':tr('Cross-site request forbidden','Запрос из другого сайта запрещён')},ensure_ascii=False),content_type='application/json; charset=utf-8');return
                raw=(parse_qs(url.query).get('ip') or [''])[0]
                try:
                    if len(raw)>45:raise ValueError(tr('Invalid IP','Неверный IP'))
                    info=ipmeta.lookup(raw,fw.ROOT)
                except (ValueError,ipmeta.IPInfoError) as err:
                    self.respond(400,json.dumps({'error':str(err)},ensure_ascii=False),content_type='application/json; charset=utf-8');return
                self.respond(200,json.dumps(info,ensure_ascii=False),content_type='application/json; charset=utf-8');return
            if path=='/api/health':
                self.respond(200,json.dumps(live_health(),ensure_ascii=False),content_type='application/json; charset=utf-8');return
            if path=='/api/feed-refresh-status':
                if (self.headers.get('X-FWS-Feed')!='1' or
                    self.headers.get('Sec-Fetch-Site','').lower() not in ('','none','same-origin')):
                    self.respond(403,'{"error":"forbidden"}',content_type='application/json; charset=utf-8');return
                self.respond(200,json.dumps(fw.feed_refresh_status(),ensure_ascii=False),content_type='application/json; charset=utf-8');return
            if path=='/api/ui-apply-status':
                if self.headers.get('Sec-Fetch-Site','').lower() not in ('','none','same-origin'):
                    self.respond(403,'{"error":"forbidden"}',content_type='application/json; charset=utf-8');return
                job=(parse_qs(url.query).get('job') or [''])[0]
                try:result=fw.ui_apply_status(job)
                except (ValueError,KeyError,OSError,TypeError):
                    self.respond(404,'{"error":"job not found"}',content_type='application/json; charset=utf-8');return
                self.respond(200,json.dumps(result,ensure_ascii=False),content_type='application/json; charset=utf-8');return
            if path=='/api/drop-summary':
                rows=fw.recent_drop_ips(limit=24)
                known=ipintel.cached_many([row[0] for row in rows],fw.ROOT)
                result=[{'ip':ip,'count':count,'last':stamp,'intel':known.get(ip)} for ip,count,stamp in rows]
                self.respond(200,json.dumps({'items':result},ensure_ascii=False),
                             content_type='application/json; charset=utf-8');return
            if path=='/api/live':
                values=parse_qs(url.query)
                raw=(values.get('since') or ['0'])[0]
                if len(raw)>19 or not raw.isdecimal() or int(raw)>2**63-1:
                    self.respond(400,'{"error":"invalid cursor"}',content_type='application/json; charset=utf-8');return
                rows=fw.live_events(int(raw),60)
                events=[dict(zip(('id','timestamp','ip','port','proto','reason','verdict','hits'),row)) for row in rows]
                self.respond(200,json.dumps({'events':events},ensure_ascii=False),content_type='application/json; charset=utf-8');return
            if path=='/':body=overview()
            elif path=='/events':body=events_page(parse_qs(url.query))
            elif path=='/access':body=access_page(parse_qs(url.query))
            elif path=='/sources':body=sources_page()
            elif path=='/control':body=control_page(job=(parse_qs(url.query).get('job') or [''])[0])
            elif path=='/control/recovery':body=recovery_page()
            else: self.respond(404,doc(('<h2>'+tr('Page not found','Страница не найдена')+'</h2>')));return
            self.respond(200,body)
        except Exception as e:self.respond(500,doc(('<h2>'+tr('Could not read data','Не удалось прочитать данные')+'</h2><p>')+e.__class__.__name__+'</p>'))
    def do_POST(self):
        if not self.gate():return
        # Basic auth is cached by browsers, so enforce same-origin and synchronizer token on all writes.
        origin=self.headers.get('Origin')
        expected=self.allowed_origins()[self.headers.get('Host','').lower()]
        site=self.headers.get('Sec-Fetch-Site','')
        mode=self.headers.get('Sec-Fetch-Mode','')
        if not origin_allowed(origin,expected,site,mode,self.headers.get('Referer')):
            # Only nonsecret request metadata; safe for the already-authenticated admin.
            details=(f'{tr("Expected:","Ожидалось:")} {e(expected)}; Origin: {e(origin or ("("+tr("none)","нет)")))}; '
                     f'Sec-Fetch-Site: {e(site or ("("+tr("none)","нет)")))}; '
                     f'Sec-Fetch-Mode: {e(mode or ("("+tr("none)","нет)")))}; '+
                     f'Host: {e(self.headers.get("Host", ("("+tr("none)","нет)"))))}')
            self.respond(403,doc(('<h2>'+tr('Origin forbidden','Origin запрещён')+'</h2><p>'+tr('Form origin check failed.','Проверка источника формы не пройдена.')+'</p>'
                '<p><code>')+details+('</code></p><p>'+tr('Check the browser address, the','Проверьте адрес в браузере, настройки')+' '
                ''+tr('ui_public_origin setting and Nginx redirects. CSRF verification remains mandatory.','ui_public_origin и перенаправления Nginx. Проверка CSRF остаётся обязательной.')+'</p>')));return
        try:
            size=int(self.headers.get('Content-Length','0'))
            allowed_size=160000 if routed_path(urlsplit(self.path).path).startswith('/bulk/') else 4096
            if not 1<=size<=allowed_size:raise ValueError(tr('Invalid form size','Некорректный размер формы'))
            if self.headers.get('Content-Type','').split(';')[0]!='application/x-www-form-urlencoded':raise ValueError('invalid form content')
            # A cleared field (ports, traps) must arrive as empty, not vanish and keep the old value.
            form_data=parse_qs(self.rfile.read(size).decode('utf-8'),strict_parsing=True,keep_blank_values=True)
            if not hmac.compare_digest((form_data.get('csrf') or [''])[0].encode(),csrf().encode()):raise ValueError('CSRF invalid')
            action=routed_path(urlsplit(self.path).path).lstrip('/')
            if action=='language':
                if set(form_data)!={'csrf','lang'}:raise ValueError(tr('Invalid fields','Недопустимые поля'))
                i18n.save(fw.ROOT,form_data['lang'][0])
                self.respond(200,overview())
                return
            if action in ('bulk/ban','bulk/allow'):
                if set(form_data)-{'csrf','ips'}:raise ValueError(tr('Invalid fields','Недопустимые поля'))
                content=(form_data.get('ips') or [''])[0]
                result=fw.change_entries_bulk('ban' if action=='bulk/ban' else 'allow',content)
                text=(f'{tr("Added:","Добавлено:")} {result["added"]} · {tr("Duplicates:","Дубли:")} {result["already"]} · '
                      f'{tr("Conflicts:","Конфликты:")} {result["conflicts"]} · {tr("Errors:","Ошибки:")} {result["invalid"]}')
                if result['conflict_examples']:
                    text+=(' · '+tr('Conflicting addresses:','Конфликтные адреса:')+' ')+', '.join(result['conflict_examples'])
                if result['invalid_examples']:
                    text+=(' · '+tr('Invalid:','Неверные:')+' ')+', '.join(result['invalid_examples'])
                self.respond(200,doc(('<h2>'+tr('Import IP addresses','Импорт IP-адресов')+'</h2><p>')+e(text)+'</p>'+
                    '<p><a href="'+e(path_for('access'))+('">'+tr('Back to lists','Вернуться к спискам')+'</a></p>'), tr('IP lists','Списки IP')))
                return
            if action=='sources/refresh':
                if set(form_data)!={'csrf','source'}:raise ValueError(tr('Invalid fields','Недопустимые поля'))
                source=(form_data.get('source') or [''])[0]
                fw.feed_refresh_start(source)
                self.respond(303,'',extra={'Location':path_for('sources')})
                return
            if action in ('provider/set','provider/disable'):
                if set(form_data)-{'csrf','provider','key'}:raise ValueError(tr('Invalid fields','Недопустимые поля'))
                provider=(form_data.get('provider') or [''])[0]
                if provider not in provider_keys.BY_ID:raise ValueError(tr('Unknown provider','Неизвестный провайдер'))
                if action=='provider/set':
                    key=(form_data.get('key') or [''])[0]
                    if key:provider_keys.set_key(fw.ROOT,provider,key);message=(tr('Key saved:','Ключ сохранён:')+' ')+provider
                    else:provider_keys.disable(fw.ROOT,provider);message=tr('Empty key: source disabled','Пустой ключ: источник отключён')
                else:provider_keys.disable(fw.ROOT,provider);message=(tr('Source disabled:','Источник отключён:')+' ')+provider
                self.respond(200,sources_page(message))
                return
            if action=='ssh-trust/remove':
                if set(form_data)!={'csrf','ip'}:raise ValueError(tr('Invalid fields','Недопустимые поля'))
                autoban.revoke_ssh_trust(fw,(form_data.get('ip') or [''])[0])
                self.respond(200,access_page());return
            if action=='ban/preview':
                addr=ipaddress.ip_address((form_data.get('ip') or [''])[0]);ip=str(addr)
                if not addr.is_global:raise ValueError(tr('A public IP is required for a ban','Для блокировки нужен публичный IP'))
                if any(addr in n for n in fw.line_networks(fw.ROOT/'allow.txt')):
                    raise ValueError(tr('A trusted administrator address cannot be banned','Адрес доверенного администратора нельзя забанить'))
                if any(addr in n for n in fw.line_networks(fw.ROOT/'vpn-clients.txt',addresses_only=True)):
                    raise ValueError(tr('A protected VPN client address cannot be banned','Адрес защищённого VPN-клиента нельзя забанить'))
                fields=f'<input type="hidden" name="ip" value="{e(ip)}"><input type="hidden" name="confirm" value="yes">'
                self.respond(200,doc(('<h2>'+tr('Confirm permanent ban','Подтверждение постоянной блокировки')+'</h2><div class="warning">'
                   '<p>'+tr('You are about to ban','Вы собираетесь забанить')+' <strong><code>')+e(ip)+('</code></strong>.</p>'
                   '<p>'+tr('If the IP is shared (NAT), the ban will affect all users of this address.','Если IP общий (NAT), блокировка затронет всех пользователей этого адреса.')+' '
                   ''+tr('The ban will only drop packets when filtering mode is active.','Бан начнёт отбрасывать пакеты только при активном режиме фильтрации.')+'</p></div>')
                   +form('ban/confirm',fields,tr('Yes, ban IP permanently','Да, заблокировать IP навсегда'),'danger-btn')
                   +'<p><a href="'+e(path_for('events'))+('">'+tr('Cancel — back to events','Отмена — вернуться к событиям')+'</a></p>'),tr('Confirm ban','Подтвердить бан')))
                return
            if action=='ban/confirm':
                if (form_data.get('confirm') or [''])[0]!='yes':raise ValueError(tr('Confirmation missing','Нет подтверждения'))
                ip=(form_data.get('ip') or [''])[0]
                changed=fw.change_entry('ban',ip,True)
                link=path_for('events')+'?'+urlencode({'ip':str(ipaddress.ip_address(ip))})
                self.respond(200,doc(('<h2>'+tr('Permanent ban','Постоянная блокировка')+'</h2><p>')+e((tr('IP banned:','IP заблокирован:')+' ')+ip if changed else (tr('IP already banned:','IP уже был заблокирован:')+' ')+ip)+'</p>'
                    +('<p>'+tr('Permanent ban saved. In observe mode, DROP is not enforced until the policy is activated.','Постоянный бан сохранён. При режиме «наблюдение» реальный DROP не включается до активации политики.')+'</p>')
                    +'<a href="'+e(link)+('">'+tr('Back to IP events','Вернуться к событиям IP')+'</a>'),tr('IP ban','Блокировка IP')))
                return
            if action.startswith('control/'):
                values=form_data
                if action=='control/quick-shield':
                    if set(values)!={'csrf'}:raise ValueError(tr('Unexpected quick enable fields','Лишние поля быстрого включения'))
                    trial=fw.web_quick_shield(self.headers.get('X-Real-IP'))
                    message=(tr('Automatic protection enabled and saved.','Автозащита включена и сохранена.') if trial.get('confirmed') else
                             tr('Automatic protection enabled TEMPORARILY (','Автозащита включена ВРЕМЕННО (')+str(trial.get('lockout',tr('check access','проверьте доступ')))+('): '+tr('check SSH and VPN access and confirm within 120 seconds.','проверьте SSH и VPN и подтвердите за 120 секунд.')))
                    self.respond(200,control_page(message))
                    return
                if action=='control/apply-now':
                    allowed={'csrf','geo_choice','autoban_exclude_tcp_ports',
                             'autoban_exclude_udp_ports','autoban_trap_ports',*fw.WEB_BOOL_FIELDS}
                    if set(values)-allowed:raise ValueError(tr('Unknown settings fields','Неизвестные поля настройки'))
                    selections={key:(values.get(key)==['1']) for key in fw.WEB_BOOL_FIELDS}
                    selections['geo_choice']=(values.get('geo_choice') or [''])[0]
                    for key in ('autoban_exclude_tcp_ports','autoban_exclude_udp_ports','autoban_trap_ports'):
                        if key in values:selections[key]=ports_from_form(values[key][0])
                    job=fw.ui_apply_start(selections,self.headers.get('X-Real-IP'))
                    self.respond(303,'',extra={'Location':path_for('control')+'?'+urlencode({'job':job})})
                    return
                if action=='control/stage':
                    allowed={'csrf','geo_choice','autoban_exclude_tcp_ports','autoban_exclude_udp_ports','autoban_trap_ports',*fw.WEB_BOOL_FIELDS}
                    if set(values)-allowed:raise ValueError(tr('Unknown settings fields','Неизвестные поля настройки'))
                    selections={key:(values.get(key)==['1']) for key in fw.WEB_BOOL_FIELDS}
                    selections['geo_choice']=(values.get('geo_choice') or [''])[0]
                    for key in ('autoban_exclude_tcp_ports','autoban_exclude_udp_ports','autoban_trap_ports'):
                        if key in values:selections[key]=ports_from_form(values[key][0])
                    fw.web_stage(selections)
                    self.respond(200,control_page(tr('Draft saved. Nothing is blocked by the new policy yet.','Черновик сохранён. Пока ничего не блокируется по новой политике.')))
                    return
                if action=='control/auto-unban/preview':
                    ip=(values.get('ip') or [''])[0]
                    addr=ipaddress.ip_address(ip)
                    if not addr.is_global:raise ValueError(tr('Invalid public IP','Некорректный публичный IP'))
                    if str(addr) not in [row[0] for row in autoban.list_bans(fw.ROOT,autoban.MAX_ACTIVE)]:
                        raise ValueError(tr('Automatic ban is no longer active','Автоматический бан больше не активен'))
                    fields='<input type="hidden" name="ip" value="'+e(addr)+'"><input type="hidden" name="confirm" value="yes">'
                    self.respond(200,doc(('<h2>'+tr('Remove automatic ban?','Снять автоматический бан?')+'</h2><p>IP: <code>')+e(addr)+('</code>. '
                        ''+tr('The current automatic ban duration is shown in the table. You can remove it early; the history of repeat violations will be retained.','Срок текущего автобана указан в таблице. Снять его можно досрочно; история повторных нарушений при этом сохраняется.')+'</p>')+
                        form('control/auto-unban',fields,tr('Confirm: remove automatic ban','Подтверждаю: снять автобан'))+
                        '<p><a href="'+e(path_for('control'))+('">'+tr('Cancel','Отмена')+'</a></p>'), tr('Confirm ban removal','Подтверждение разбана')))
                    return
                if action=='control/auto-unban':
                    if (values.get('confirm') or [''])[0]!='yes':raise ValueError(tr('Ban removal not confirmed','Нет подтверждения разбана'))
                    ip=(values.get('ip') or [''])[0]
                    changed=autoban.revoke(fw,ip)
                    self.respond(200,control_page(tr('Automatic ban removed.','Автоматический бан снят.') if changed else tr('Ban has already expired.','Бан уже истёк.')))
                    return
                if action=='control/apply':
                    if (values.get('phrase') or [''])[0]!=tr('ENABLE','ВКЛЮЧИТЬ') or (values.get('ack_clients') or [''])[0]!='yes':
                        raise ValueError(tr('To apply, enter the exact word ENABLE and confirm that VPN clients have been checked','Для применения требуется точная фраза ВКЛЮЧИТЬ и подтверждение проверки VPN-клиентов'))
                    fw.web_activate()
                    self.respond(200,control_page(tr('Trial application started. Check access and click Confirm within 120 seconds.','Пробное применение началось. Проверьте доступ и нажмите «Подтвердить» за 120 секунд.')))
                    return
                if action=='control/confirm':
                    fw.web_confirm((values.get('token') or [''])[0])
                    self.respond(200,control_page(tr('Protection enabled permanently.','Защита включена постоянно.')))
                    return
                if action=='control/cancel-trial':
                    fw.web_abort((values.get('token') or [''])[0])
                    self.respond(200,control_page(tr('Trial activation canceled, previous policy restored.','Пробное включение отменено, предыдущая политика восстановлена.')))
                    return
                if action=='control/disable-shield':
                    if set(values)!={'csrf'}:raise ValueError(tr('Unexpected disable fields','Лишние поля отключения'))
                    fw.web_mode('pause')
                    self.respond(200,control_page(tr('Automatic bans disabled. Observe mode is saved and will remain active after reboot.','Автоблокировки выключены. Наблюдение сохранено и будет работать после перезагрузки.')))
                    return
                if action in ('control/start','control/pause','control/stop'):
                    if action=='control/stop' and (values.get('confirm') or [''])[0]!='stop':
                        raise ValueError(tr('Stop not confirmed','Не подтверждён стоп'))
                    fw.web_mode(action.partition('/')[2])
                    self.respond(200,control_page(tr('Sentinel mode changed. VPN and other services were not stopped.','Режим Sentinel изменён. VPN и другие сервисы не останавливались.')))
                    return
                raise ValueError(tr('Unknown control command','Неизвестная команда управления'))
            ip=(form_data.get('ip') or [''])[0]
            if action not in ('ban','unban','allow','unallow','vpn-add','vpn-remove'):raise ValueError('unsupported action')
            if not ip or len(ip)>45:raise ValueError('invalid IP')
            kind='vpn' if action.startswith('vpn-') else 'ban' if 'ban' in action else 'allow'
            changed=fw.change_entry(kind,ip,action in ('ban','allow','vpn-add'))
            self.respond(200,doc(('<h2>'+tr('Operation completed','Операция выполнена')+'</h2><p>')+e((tr('Changed:','Изменено:')+' ') + ip if changed else tr('Already set','Уже было установлено'))+'</p><a href="'+e(path_for('access'))+('">'+tr('Back to management','Вернуться к управлению')+'</a>')))
        except (ValueError,RuntimeError,OSError,fw.subprocess.SubprocessError,fw.sqlite3.Error) as err:
            destination='sources' if routed_path(urlsplit(self.path).path).startswith(('/provider/','/sources/')) else 'control' if routed_path(urlsplit(self.path).path).startswith('/control/') else 'events' if routed_path(urlsplit(self.path).path).startswith('/ban/') else 'access'
            self.respond(400,doc(('<h2>'+tr('Operation rejected','Операция отклонена')+'</h2><p>')+e(str(err))+'</p><a href="'+e(path_for(destination))+('">'+tr('Back','Назад')+'</a>')))
    def log_message(self,format,*args):
        pass


def main():
    cfg=fw.config()
    if not TOKEN_FILE.is_file():raise SystemExit('ui-token not found; run installer')
    base_path();public_origin()
    # deliberately ignore cfg.ui_host: never bind publicly in this release
    host='127.0.0.1';port=int(cfg.get('ui_port',1488))
    if not 1024<=port<=65535:raise SystemExit('invalid ui_port')
    server=ThreadingHTTPServer((host,port),Handler)
    print(f'FW Sentinel 2.0.21 UI at http://{host}:{port} (SSH tunnel only)',flush=True)
    server.serve_forever()

if __name__=='__main__':main()
