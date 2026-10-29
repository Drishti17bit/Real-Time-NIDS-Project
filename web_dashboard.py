"""
NetShield Web Dashboard
Run with: python web_dashboard.py
For real packet capture, run the terminal as Administrator/root and install requirements.
"""
from __future__ import annotations

import os
import re
import csv
import io
import threading
import time
import platform
import sqlite3
import secrets
from functools import wraps
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, request, render_template_string, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

from state import state

ROOT = Path(__file__).resolve().parent
LOG_PATH = ROOT / "logs" / "alerts.log"
app = Flask(__name__)
app.secret_key = os.environ.get("NETSHIELD_SECRET_KEY") or secrets.token_hex(32)
USER_DB = ROOT / "netshield_users.db"

def init_user_db():
    with sqlite3.connect(USER_DB) as con:
        con.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at TEXT NOT NULL)")
        con.commit()

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Please log in to use the dashboard."}), 401
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped

init_user_db()

capture_lock = threading.Lock()
capture_thread = None
capture_stop = threading.Event()
capture_status = {"running": False, "mode": "stopped", "message": "Monitoring is stopped", "interface": None}
started_at = None

AUTH_PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>NetShield | {{ title }}</title>
<style>
:root{--bg:#F5F9FC;--panel:#FFFFFF;--powder:#D9E8F3;--line:#D4DEE7;--muted:#526A82;--text:#26364A;--slate:#45647D;--slate2:#526A82;--shadow:0 18px 55px rgba(38,54,74,.12)}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 15% 15%,#D9E8F3 0,transparent 32%),radial-gradient(circle at 85% 85%,#E8F1F7 0,transparent 30%),var(--bg);font:15px/1.55 Inter,Segoe UI,Arial,sans-serif;color:var(--text);display:grid;place-items:center;padding:24px}.auth-shell{width:min(980px,100%);display:grid;grid-template-columns:1fr 1fr;background:var(--panel);border:1px solid var(--line);border-radius:24px;overflow:hidden;box-shadow:var(--shadow);min-height:590px}.hero{padding:44px;background:linear-gradient(145deg,#45647D,#26364A);color:white;display:flex;flex-direction:column;justify-content:space-between}.brand{display:flex;gap:14px;align-items:center;font-size:22px;font-weight:800}.logo{width:62px;height:62px;flex:0 0 62px;border-radius:16px;display:grid;place-items:center;background:#D9E8F3;color:#26364A;padding:8px;box-shadow:0 8px 22px rgba(0,0,0,.14)}.shield-mark{width:100%;height:100%;overflow:visible}.shield-outline{fill:none;stroke:#45647D;stroke-width:2.4;stroke-linejoin:round;transform-origin:24px 24px;animation:shield-breathe 3.2s ease-in-out infinite}.shield-inner{fill:#829DB3;fill-opacity:.22;stroke:#526A82;stroke-width:1.2}.shield-scan{fill:none;stroke:#26364A;stroke-width:1.7;stroke-linecap:round;stroke-dasharray:4 4;animation:shield-scan 2.4s linear infinite}.shield-node{fill:#45647D;stroke:#F5F9FC;stroke-width:1.2;transform-origin:24px 23px;animation:shield-pulse 1.8s ease-in-out infinite}@keyframes shield-breathe{0%,100%{transform:scale(1);opacity:.92}50%{transform:scale(1.045);opacity:1}}@keyframes shield-scan{from{stroke-dashoffset:16;opacity:.65}50%{opacity:1}to{stroke-dashoffset:0;opacity:.65}}@keyframes shield-pulse{0%,100%{r:3.2;opacity:1}50%{r:4.1;opacity:.72}}@media(prefers-reduced-motion:reduce){.shield-outline,.shield-scan,.shield-node{animation:none!important}}.eyebrow{letter-spacing:1px;font-size:12px;color:#D9E8F3;font-weight:800}.hero h1{font-size:35px;line-height:1.12;margin:14px 0}.hero p{color:#E2EDF5;max-width:420px}.feature{border-top:1px solid #FFFFFF30;padding-top:20px;color:#D9E8F3;font-size:13px}.form-side{padding:44px;display:flex;flex-direction:column;justify-content:center}.form-side h2{font-size:27px;margin:0 0 6px}.muted{color:var(--muted);margin:0 0 24px}.field{display:block;margin:15px 0 0;font-weight:650;font-size:13px}.field input{display:block;width:100%;margin-top:7px;padding:13px 14px;border:1px solid var(--line);border-radius:10px;background:#F8FBFD;color:var(--text);outline:none}.field input:focus{border-color:var(--slate);box-shadow:0 0 0 3px #D9E8F3}.btn{margin-top:22px;width:100%;border:1px solid var(--slate);background:var(--slate);color:white;padding:13px;border-radius:10px;font-weight:750;cursor:pointer}.btn:hover{background:#26364A}.switch{text-align:center;margin-top:20px;color:var(--muted);font-size:13px}.switch a{color:var(--slate);font-weight:750}.error{background:#FBECEB;color:#923D3A;border:1px solid #E8C5C3;border-radius:9px;padding:10px 12px;font-size:13px;margin:12px 0}.security-note{font-size:11px;color:var(--muted);margin-top:18px}@media(max-width:720px){.auth-shell{grid-template-columns:1fr;max-width:480px}.hero{padding:25px;min-height:220px}.hero h1{font-size:29px}.hero .feature{display:none}.form-side{padding:28px}}
</style></head><body><div class="auth-shell"><section class="hero"><div><div class="brand"><div class="logo" aria-label="NetShield cybersecurity logo" role="img"><svg class="shield-mark" viewBox="0 0 48 48" aria-hidden="true" focusable="false"><path class="shield-outline" d="M24 4 40 10v12c0 10-6.5 17-16 22C14.5 39 8 32 8 22V10Z"/><path class="shield-inner" d="M24 12 33 15.5v6.8c0 6.3-3.7 11-9 14.2-5.3-3.2-9-7.9-9-14.2v-6.8Z"/><path class="shield-scan" d="M15 23h18M24 15v17"/><circle class="shield-node" cx="24" cy="23" r="3.2"/></svg></div><div>NetShield<div style="font-size:10px;letter-spacing:2px;font-weight:500;color:#D9E8F3">NETWORK DEFENSE</div></div></div><div style="margin-top:48px"><h1>Network Intrusion Detection System</h1><p>An intelligent network security system that captures network traffic, extracts flow-level features, detects suspicious activity using machine learning and rules, and presents real-time alerts through a security monitoring dashboard.</p></div></div><div class="feature">◈ &nbsp; Local-first monitoring &nbsp; • &nbsp; Live event visibility</div></section><section class="form-side"><h2>{{ title }}</h2><p class="muted">{{ subtitle }}</p>{% with messages = get_flashed_messages() %}{% if messages %}<div class="error">{{ messages[0] }}</div>{% endif %}{% endwith %}{% if error %}<div class="error">{{ error }}</div>{% endif %}<form method="post">{% if signup %}<label class="field">Display name<input name="username" autocomplete="name" required minlength="2" maxlength="40" placeholder="Your name"></label>{% endif %}<label class="field">Email address<input type="email" name="email" autocomplete="email" required maxlength="254" placeholder="you@example.com"></label><label class="field">Password<input type="password" name="password" autocomplete="{{ 'new-password' if signup else 'current-password' }}" required minlength="8" placeholder="At least 8 characters"></label>{% if signup %}<label class="field">Confirm password<input type="password" name="confirm_password" autocomplete="new-password" required minlength="8" placeholder="Repeat your password"></label>{% endif %}<button class="btn" type="submit">{{ 'Create account' if signup else 'Log in securely' }}</button></form><div class="switch">{{ 'Already have an account?' if signup else 'New to NetShield?' }} <a href="{{ url_for('login') if signup else url_for('signup') }}">{{ 'Log in' if signup else 'Create an account' }}</a></div><div class="security-note">Local prototype: account credentials are stored in a local SQLite database with hashed passwords. Use HTTPS and a configured secret key before exposing this app beyond your own machine.</div></section></div></body></html>"""

PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetShield | Network Security</title>
<style>
:root{--bg:#F5F9FC;--panel:#FFFFFF;--panel2:#D9E8F3;--line:#D4DEE7;--muted:#526A82;--text:#26364A;--cyan:#45647D;--green:#416D57;--red:#A83F3A;--orange:#829DB3;--yellow:#D9E8F3;--navy:#26364A;--sage:#829DB3;--sage-light:#D9E8F3;--buttermilk:#D9E8F3;--shadow:0 8px 24px rgba(38,54,74,.08)}
*{box-sizing:border-box}body{margin:0;background:var(--bg);font:15px/1.6 Inter,Segoe UI,Arial,sans-serif;color:var(--text)}
button,input,select{font:inherit}button{border:1px solid var(--line);border-radius:9px;padding:10px 13px;background:var(--buttermilk);color:#000000;cursor:pointer;font-weight:650;transition:background .15s,border-color .15s,transform .15s}button:hover{background:#E6D6A8;border-color:#A9A083}button.primary{background:var(--buttermilk);border-color:#A9A083;color:#000000}button.primary:hover{background:#E6D6A8}button.danger{background:#E6C1B8;border-color:#9F2929;color:#000000}button:disabled{opacity:.45;cursor:not-allowed}button:focus-visible,input:focus-visible,select:focus-visible,a:focus-visible{outline:3px solid #526A82;outline-offset:2px}.nav:focus-visible{border-radius:9px}.filters button{padding:8px 10px;font-size:12px}.actions{align-items:center}
.shell{display:grid;grid-template-columns:220px minmax(0,1fr);width:100%;min-height:100vh}.side{border-right:1px solid var(--line);background:var(--buttermilk);padding:24px 16px;color:#000000}.brand{display:flex;gap:10px;align-items:center;font-size:20px;font-weight:800;letter-spacing:.2px;color:#FFFFFF}.logo{display:grid;place-items:center;background:var(--buttermilk);border:1px solid #B87550;color:#29231F;width:39px;height:39px;border-radius:11px;font-size:20px}.tag{color:#3F4434;font-size:12px;letter-spacing:1.5px;margin:28px 10px 10px}.nav{display:flex;gap:10px;text-decoration:none;padding:11px 12px;border-radius:9px;color:#000000;margin:3px 0;transition:background .15s}.nav.active{background:#E8D6A8;color:#29231F;font-weight:750}.side-note{margin-top:36px;padding:14px;background:#E2BFA5;border:1px solid #80604D;border-radius:12px;color:#29231F;font-size:12px}.side-note strong{color:#000000;display:block;margin-bottom:5px}
main{padding:28px 32px;width:100%;max-width:none;min-width:0;margin:0}.top{display:flex;align-items:center;justify-content:space-between;gap:18px;margin-bottom:24px}.eyebrow{color:#426B58;font-size:12px;letter-spacing:1.7px;font-weight:800}.top h1{margin:4px 0 3px;font-size:28px;letter-spacing:-.7px;color:var(--navy)}.sub{color:var(--muted)}.actions{display:flex;gap:8px;flex-wrap:wrap}.status{display:inline-flex;align-items:center;gap:8px;padding:7px 10px;border:1px solid var(--line);border-radius:99px;color:#59604A;background:#3F4434;font-size:12px;margin-bottom:10px}.dot{width:8px;height:8px;border-radius:50%;background:#B8B09F}.dot.live{background:var(--green);box-shadow:0 0 0 3px #83A06B1C}
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;width:100%}.card{background:var(--panel);border:1px solid var(--line);border-radius:13px;padding:20px;min-width:0;box-shadow:var(--shadow)}.metric-label{font-size:13px;color:var(--muted);display:flex;justify-content:space-between;gap:8px}.metric{font-size:30px;font-weight:780;letter-spacing:-.7px;margin:12px 0 4px;color:var(--navy)}.hint{font-size:12px;color:#59604A}.cyan{color:#63734B}.red{color:var(--red)}.orange{color:var(--orange)}.yellow{color:var(--yellow)}.green{color:var(--green)}
.row2{display:grid;grid-template-columns:minmax(0,1.7fr) minmax(300px,1fr);gap:18px;margin-top:18px;width:100%}.card-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:15px}.card h2{font-size:16px;margin:0;color:var(--navy)}.pill{border:1px solid var(--line);background:var(--buttermilk);border-radius:99px;padding:4px 8px;color:var(--muted);font-size:11px}.chart{height:270px;position:relative}.chart svg{width:100%;height:100%;overflow:visible}.gridline{stroke:#E8DDCB;stroke-width:1;stroke-dasharray:3 5}.chart-label{fill:#000000;font-size:12px}.line{fill:none;stroke:#63734B;stroke-width:2.5;stroke-linecap:round;stroke-linejoin:round}.area{fill:url(#fade)}.bars{display:flex;gap:9px;align-items:end;height:155px;padding:10px 4px 0}.bar-wrap{flex:1;display:flex;flex-direction:column;align-items:center;gap:8px;height:100%;justify-content:end}.bar{width:min(30px,70%);border-radius:5px 5px 2px 2px;background:var(--buttermilk);min-height:3px}.bar-label{font-size:12px;color:#59604A}
.row3{display:grid;grid-template-columns:minmax(0,1.7fr) minmax(300px,1fr);gap:18px;margin-top:18px;width:100%}.filters{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.filters input,.filters select{background:var(--buttermilk);color:#000000;border:1px solid var(--line);border-radius:8px;padding:8px 9px;max-width:100%}
.table-wrap{overflow:auto}table{border-collapse:collapse;width:100%;min-width:580px}th{text-align:left;color:#59604A;font-size:11px;letter-spacing:1px;font-weight:750;padding:10px 8px;border-bottom:1px solid var(--line)}td{padding:13px 8px;border-bottom:1px solid #E8DDCB;font-size:13px;color:#3F4434}tbody tr:hover{background:#E9D9C8}tbody tr:last-child td{border-bottom:0}.severity{display:inline-block;border-radius:6px;padding:5px 8px;font-size:11px;font-weight:800;letter-spacing:.4px}.CRITICAL{color:#000000;background:#E6C1B8}.HIGH{color:#B85C38;background:#F3E3A2}.MEDIUM{color:#9B7B36;background:#F3E3A2}.LOW{color:#416D57;background:#E9D9C8}.INFO{color:#B85C38;background:#F4EFE6}.SIMULATION{color:#63734B;background:#3F4434}.empty{text-align:center;color:var(--muted);padding:25px}.event-list{display:flex;flex-direction:column;gap:10px}.event{display:grid;grid-template-columns:10px minmax(0,1fr);gap:10px;padding:10px 0;border-bottom:1px solid #E8DDCB}.event:last-child{border:0}.event-dot{width:8px;height:8px;border-radius:50%;background:var(--orange);margin-top:5px}.event p{margin:0;font-size:13px;color:#3F4434;overflow-wrap:anywhere}.event small{display:block;color:#59604A;font-size:11px;margin-top:4px}.footer{color:#59604A;font-size:11px;margin-top:20px;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}.notice{display:none;margin:0 0 14px;padding:10px 12px;border:1px solid #E8DDCB;background:#FFF9F0;color:#9B5C32;border-radius:9px}.notice.show{display:block}
@media(max-width:1100px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.shell{grid-template-columns:200px minmax(0,1fr)}main{padding:22px}.row2,.row3{grid-template-columns:minmax(0,1fr)}}
@media(max-width:700px){.shell{display:block}.side{display:block;padding:10px 12px;border-right:0;border-bottom:1px solid var(--line)}.side .brand{font-size:17px}.side .tag,.side-note{display:none}.side>div.nav,.side>a.nav{display:inline-flex;padding:8px 9px;font-size:12px;margin:2px}.side .logo{width:30px;height:30px}.side .brand{margin-bottom:8px}main{padding:16px}.top{align-items:flex-start;flex-direction:column}.top h1{font-size:24px}.grid{grid-template-columns:minmax(0,1fr);gap:9px}.card{padding:14px}.metric{font-size:25px}.actions{width:100%}.actions button{flex:1}.row2,.row3{grid-template-columns:minmax(0,1fr);gap:9px}.filters input{width:100%}}

/* NetShield charcoal + lime theme overrides */
body{background:#F5F9FC;color:#26364A}
.side{background:#526A82;color:#FFFFFF;border-right-color:#45647D}
.brand,.nav,.side-note strong{color:#FFFFFF}
.logo{background:#D9E8F3;border-color:#829DB3;color:#26364A}
.tag{color:#D9E8F3}
.nav.active{background:#D9E8F3;color:#26364A;font-weight:750}
.side-note{background:#D9E8F3;border-color:#829DB3;color:#26364A}
.side-note strong{color:#26364A}
main{background:#F5F9FC;color:#26364A}
.top h1{color:#26364A}
.eyebrow{color:#526A82}
.sub,.footer{color:#526A82}
.status{background:#D9E8F3;color:#26364A;border-color:#829DB3}
.card{background:#FFFFFF;color:#26364A;border-color:#D4DEE7;box-shadow:0 8px 24px rgba(38,54,74,.06)}
.metric-label,.metric,.card h2,.hint,.bar-label,.empty{color:#26364A}
.chart-label{fill:#26364A}
.gridline{stroke:#D4DEE7}
.line{stroke:#45647D}
.bar{background:#829DB3}
.pill{background:#D9E8F3;color:#26364A;border-color:#829DB3}
.filters input,.filters select{background:#FFFFFF;color:#26364A;border-color:#D4DEE7}
th{color:#526A82;border-bottom-color:#D4DEE7}
td{color:#26364A;border-bottom-color:#D4DEE7}
tbody tr:hover{background:#F0F6FA}
.event p{color:#26364A}.event small{color:#526A82}
.event{border-bottom-color:#D4DEE7}
button{background:#D9E8F3;color:#26364A;border-color:#829DB3}
button:hover,button.primary:hover{background:#C4D9E9;border-color:#526A82}
button.primary{background:#D9E8F3;color:#26364A;border-color:#829DB3}
.notice{border-color:#D4DEE7;background:#F0F6FA;color:#26364A}
 .side button.nav{width:100%;text-align:left;font-weight:500;border:1px solid transparent;background:transparent;color:#FFFFFF;justify-content:flex-start}
 .side button.nav:hover{background:#45647D;border-color:#829DB3}
 .side button.nav.active{background:#D9E8F3;color:#26364A;border-color:#829DB3;font-weight:750}
 .view-panel[hidden]{display:none!important}

/* Security overview expanded layout */
.overview-row{display:grid;grid-template-columns:minmax(0,1.35fr) minmax(280px,1fr);gap:18px;margin-top:18px}
.posture{background:linear-gradient(125deg,#FFFFFF,#F0F6FA);position:relative;overflow:hidden}
.posture-top{display:flex;justify-content:space-between;align-items:center;gap:12px}.posture-score{font-size:35px;font-weight:800;letter-spacing:-1px;color:#26364A;margin:8px 0 0}.posture-label{font-size:12px;color:#526A82}.meter{height:9px;border-radius:99px;background:#D9E8F3;overflow:hidden;margin:14px 0 8px}.meter span{display:block;height:100%;width:100%;background:linear-gradient(90deg,#829DB3,#45647D);border-radius:99px;transition:width .3s}.checklist{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin-top:16px}.check-item{border:1px solid #D4DEE7;background:#F8FBFD;border-radius:10px;padding:12px;min-width:0}.check-item strong{display:block;font-size:13px}.check-item span{font-size:11px;color:#526A82}.check-dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:#829DB3;margin-right:6px}.mini-stat{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:12px 0;border-bottom:1px solid #D4DEE7}.mini-stat:last-child{border:0}.mini-stat strong{font-size:19px}.mini-stat span{font-size:12px;color:#526A82}.overview-table{margin-top:18px}.overview-table table{min-width:0}@media(max-width:1000px){.overview-row{grid-template-columns:minmax(0,1fr)}}@media(max-width:700px){.checklist{grid-template-columns:minmax(0,1fr)}}
/* Animated NetShield cyber-shield mark; retains the existing Slate Blue + Powder Blue palette. */
.logo{position:relative;overflow:hidden;flex:0 0 39px;padding:5px;}
.shield-mark{width:100%;height:100%;overflow:visible;}
.shield-outline{fill:none;stroke:#45647D;stroke-width:2.4;stroke-linejoin:round;transform-origin:24px 24px;animation:shield-breathe 3.2s ease-in-out infinite;}
.shield-inner{fill:#829DB3;fill-opacity:.22;stroke:#526A82;stroke-width:1.2;}
.shield-scan{fill:none;stroke:#26364A;stroke-width:1.7;stroke-linecap:round;stroke-dasharray:4 4;animation:shield-scan 2.4s linear infinite;}
.shield-node{fill:#45647D;stroke:#F5F9FC;stroke-width:1.2;transform-origin:24px 23px;animation:shield-pulse 1.8s ease-in-out infinite;}
@keyframes shield-breathe{0%,100%{transform:scale(1);opacity:.92}50%{transform:scale(1.045);opacity:1}}
@keyframes shield-scan{from{stroke-dashoffset:16;opacity:.65}50%{opacity:1}to{stroke-dashoffset:0;opacity:.65}}
@keyframes shield-pulse{0%,100%{r:3.2;opacity:1}50%{r:4.1;opacity:.72}}
@media(max-width:700px){.side .logo{flex-basis:30px;padding:4px}}
@media(prefers-reduced-motion:reduce){.shield-outline,.shield-scan,.shield-node{animation:none!important}}
</style></head>
<body><div class="shell">
<aside class="side"><div class="brand"><div class="logo" aria-label="NetShield cybersecurity logo" role="img"><svg class="shield-mark" viewBox="0 0 48 48" aria-hidden="true" focusable="false"><path class="shield-outline" d="M24 4 40 10v12c0 10-6.5 17-16 22C14.5 39 8 32 8 22V10Z"/><path class="shield-inner" d="M24 12 33 15.5v6.8c0 6.3-3.7 11-9 14.2-5.3-3.2-9-7.9-9-14.2v-6.8Z"/><path class="shield-scan" d="M15 23h18M24 15v17"/><circle class="shield-node" cx="24" cy="23" r="3.2"/></svg></div><div>NetShield<div style="font-size:10px;color:#D9E8F3;font-weight:500;letter-spacing:1.4px">NETWORK DEFENSE</div></div></div>
<div class="tag">WORKSPACE</div><button type="button" class="nav active" data-view="overview" aria-current="page" onclick="setView('overview')">◈ &nbsp; Security overview</button><button type="button" class="nav" data-view="network" onclick="setView('network')">⌁ &nbsp; Network activity</button><button type="button" class="nav" data-view="threats" onclick="setView('threats')">⚑ &nbsp; Threat incidents</button><button type="button" class="nav" data-view="history" onclick="setView('history')">▤ &nbsp; Event history</button>
<div class="side-note"><strong>Protection status</strong><span id="sideStatus">Monitoring is stopped</span><div style="margin-top:10px;color:#B85C38">● Local IDS engine</div></div>
<div class="side-note"><strong>Privacy by design</strong>Network events are processed by this local application. Do not expose the dashboard publicly without adding authentication.</div>
</aside>
<main id="overview">
<div class="top"><div><div class="eyebrow">SECURITY OPERATIONS / OVERVIEW</div><h1 id="pageTitle">Network security dashboard</h1><div class="sub">Monitor traffic, inspect alerts, and review suspicious activity.</div></div><div class="actions"><span class="pill" style="align-self:center">Signed in: {{ username }}</span><button type="button" onclick="window.location.href='/logout'">Log out</button><button id="startBtn" class="primary" onclick="startMonitoring()">Start monitoring</button><button id="stopBtn" onclick="stopMonitoring()" disabled>Stop</button><button onclick="runDemo()">Run demo</button></div></div>
<div class="status"><span class="dot" id="statusDot" aria-hidden="true"></span><span id="statusText" aria-live="polite">Checking engine status…</span></div>
<div id="notice" class="notice" role="status" aria-live="polite"></div>
<section class="grid view-panel" data-view-panel="overview">
<div class="card"><div class="metric-label">PACKETS INSPECTED <span class="cyan">↗</span></div><div class="metric" id="packets">0</div><div class="hint">Observed by this running process</div></div>
<div class="card"><div class="metric-label">ARP SPOOF ALERTS <span class="orange">⚑</span></div><div class="metric orange" id="arp">0</div><div class="hint">IP-to-MAC mapping changes flagged</div></div>
<div class="card"><div class="metric-label">MITM ALERTS <span class="red">⌁</span></div><div class="metric red" id="mitm">0</div><div class="hint">Gateway MAC changes flagged</div></div>
<div class="card"><div class="metric-label">SCAN / ANOMALIES <span class="yellow">⌕</span></div><div class="metric yellow" id="anomalies">0</div><div class="hint">SYN probes, UDP and ICMP events</div></div>
</section>
<section class="overview-row view-panel" data-view-panel="overview" aria-label="Security posture and detector health">
<div class="card posture"><div class="posture-top"><div><h2>Security posture</h2><div class="posture-label">Live snapshot from the local IDS engine</div></div><span class="pill" id="postureBadge">AWAITING DATA</span></div><div class="posture-score" id="postureScore">—</div><div class="posture-label" id="postureCaption">Start monitoring or run the safe demo to populate your overview.</div><div class="meter"><span id="postureMeter" style="width:0%"></span></div><div class="checklist"><div class="check-item"><strong><span class="check-dot"></span>ARP monitor</strong><span>IP-to-MAC changes</span></div><div class="check-item"><strong><span class="check-dot"></span>MITM monitor</strong><span>Gateway MAC changes</span></div><div class="check-item"><strong><span class="check-dot"></span>Scan detection</strong><span>Port and probe signals</span></div><div class="check-item"><strong><span class="check-dot"></span>Event logging</strong><span>Local alert history</span></div></div></div>
<div class="card"><div class="card-head"><h2>Threat snapshot</h2><span class="pill">Current log</span></div><div class="mini-stat"><div><strong id="overviewCritical">0</strong><br><span>Critical events</span></div><span class="severity CRITICAL">CRITICAL</span></div><div class="mini-stat"><div><strong id="overviewHigh">0</strong><br><span>High severity</span></div><span class="severity HIGH">HIGH</span></div><div class="mini-stat"><div><strong id="overviewMedium">0</strong><br><span>Medium severity</span></div><span class="severity MEDIUM">MEDIUM</span></div><div class="mini-stat"><div><strong id="overviewTotal">0</strong><br><span>Total logged events</span></div><span class="pill">ALL TIME</span></div><p class="hint" style="margin-top:12px">Counts reflect labels in the local alert log; they are not a guarantee that the network is threat-free.</p></div>
</section>
<section class="row3 view-panel overview-table" data-view-panel="overview" aria-label="Latest security events"><div class="card"><div class="card-head"><h2>Latest security events</h2><button type="button" onclick="setView('threats')">View all incidents ↗</button></div><div class="table-wrap"><table><thead><tr><th>TIME</th><th>SEVERITY</th><th>EVENT</th></tr></thead><tbody id="overviewAlertRows"><tr><td colspan="3" class="empty">No events logged yet.</td></tr></tbody></table></div></div></section>
<section class="row2 view-panel" id="network-activity" data-view-panel="network">
<div class="card"><div class="card-head"><h2>Packet activity</h2><span class="pill" id="chartStatus">Waiting for traffic</span></div><div class="chart"><svg viewBox="0 0 600 200" preserveAspectRatio="none" aria-label="Packet activity chart"><defs><linearGradient id="fade" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="#B85C38" stop-opacity=".25"/><stop offset="1" stop-color="#B85C38" stop-opacity="0"/></linearGradient></defs><g id="chartGrid"></g><path id="chartArea" class="area" d=""></path><path id="chartLine" class="line" d=""></path><g id="chartLabels"></g></svg></div><div class="hint">Rolling samples from this dashboard session; not historical throughput.</div></div>
<div class="card"><div class="card-head"><h2>Alert severity</h2><span class="pill">Logged events</span></div><div class="bars" id="severityBars"></div><div class="hint" style="margin-top:12px">Severity is based on the existing detector log labels.</div></div>
</section>
<section class="row2 view-panel" aria-label="Protocol analytics" data-view-panel="network">
<div class="card"><div class="card-head"><h2>Protocol distribution</h2><span class="pill">Observed packets</span></div><div id="protocolBars" class="bars" role="img" aria-label="Protocol packet counts"></div><div class="hint" id="protocolSummary" style="margin-top:12px">Counts update when packet capture is active. Demo packets are synthetic.</div></div>
<div class="card"><div class="card-head"><h2>Quick actions</h2><span class="pill">Dashboard tools</span></div><div class="actions"><button type="button" onclick="exportAlerts()">Download alert CSV</button><button type="button" id="refreshToggle" onclick="toggleAutoRefresh()">Pause auto-refresh</button></div><p class="hint" style="margin-top:12px">Export the current event log for review. Pausing refresh only pauses the page updates; packet capture continues.</p></div>
</section>
<section class="row3 view-panel" id="threat-incidents" data-view-panel="threats">
<div class="card"><div class="card-head"><h2>Recent incidents</h2><div class="filters"><select id="severityFilter" aria-label="Filter by severity" onchange="renderAlerts()"><option value="ALL">All severity</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>INFO</option><option>SIMULATION</option></select><input id="search" aria-label="Search alerts by IP or event" placeholder="Search IP or event…" oninput="renderAlerts()"><select id="timeFilter" aria-label="Filter by time" onchange="renderAlerts()"><option value="ALL">Any time</option><option value="1">Last hour</option><option value="24">Last 24 hours</option></select><button type="button" onclick="resetFilters()">Reset</button><button type="button" onclick="exportAlerts()">Export CSV</button></div></div><div class="hint" id="filterSummary" aria-live="polite" style="margin-bottom:8px">Showing recent events</div><div class="table-wrap"><table><thead><tr><th>TIME</th><th>SEVERITY</th><th>EVENT</th></tr></thead><tbody id="alertRows"><tr><td colspan="3" class="empty">No events loaded yet.</td></tr></tbody></table></div></div>
</section>
<section class="row3 view-panel" id="event-history" data-view-panel="history" aria-label="Event history"><div class="card"><div class="card-head"><h2>Live event feed</h2><span class="pill" id="eventCount">0 events</span></div><div id="eventFeed" class="event-list"><div class="empty">Waiting for events…</div></div></div></section>
<div class="footer"><span>NetShield • NIDS prototype</span><span>Local dashboard • Refreshes automatically</span><span id="lastUpdated">Last updated —</span></div>
</main></div>
<script>
let allAlerts=[], samples=Array(24).fill(0), lastPacketCount=0, autoRefresh=true, refreshTimer=null, latestProtocols={};
const $=id=>document.getElementById(id);
function setView(view){document.querySelectorAll("[data-view-panel]").forEach(panel=>{panel.hidden=panel.dataset.viewPanel!==view;});document.querySelectorAll(".side .nav[data-view]").forEach(btn=>{const active=btn.dataset.view===view;btn.classList.toggle("active",active);if(active){btn.setAttribute("aria-current","page");}else{btn.removeAttribute("aria-current");}});const labels={overview:"SECURITY OPERATIONS / OVERVIEW",network:"SECURITY OPERATIONS / NETWORK ACTIVITY",threats:"SECURITY OPERATIONS / THREAT INCIDENTS",history:"SECURITY OPERATIONS / EVENT HISTORY"};document.querySelector(".eyebrow").textContent=labels[view]||labels.overview;const titles={overview:"Network security dashboard",network:"Network activity",threats:"Threat incidents",history:"Event history"};$("pageTitle").textContent=titles[view]||titles.overview;window.scrollTo({top:0,behavior:"smooth"});}
function showNotice(msg){$('notice').textContent=msg;$('notice').classList.add('show');}
function hideNotice(){$('notice').classList.remove('show');}
async function api(url, options={}){const r=await fetch(url,{headers:{'Content-Type':'application/json'},...options});const data=await r.json();if(!r.ok)throw new Error(data.error||'Request failed');return data;}
async function refresh(){
 try{
  const d=await api('/api/status'); $('packets').textContent=Number(d.stats.packets||0).toLocaleString();$('arp').textContent=d.stats.arp_alerts||0;$('mitm').textContent=d.stats.mitm_alerts||0;$('anomalies').textContent=(d.stats.port_scan_alerts||0)+(d.stats.suspicious_alerts||0);
  $('statusText').textContent=d.capture.message;$('sideStatus').textContent=d.capture.message;$('statusDot').className='dot'+(d.capture.running?' live':'');$('startBtn').disabled=d.capture.running;$('stopBtn').disabled=!d.capture.running;
  if(d.capture.running){$('chartStatus').textContent='Capturing traffic';}else{$('chartStatus').textContent=d.capture.mode==='demo'?'Demo mode':'Capture stopped';}
  if(d.capture.message && d.capture.message.startsWith('ERROR:'))showNotice(d.capture.message); else hideNotice();
  allAlerts=d.alerts||[];latestProtocols=d.protocols||{};renderAlerts();renderSeverity(d.severity||{});renderFeed(allAlerts.slice(-6).reverse());renderProtocols(latestProtocols);renderOverview(d);
  const current=Number(d.stats.packets||0);samples.push(Math.max(0,current-lastPacketCount));samples=samples.slice(-24);lastPacketCount=current;renderChart();
  $('lastUpdated').textContent='Last updated '+new Date().toLocaleTimeString();
 }catch(e){showNotice('Dashboard API error: '+e.message);}
}
function renderOverview(d){const sev=d.severity||{},total=allAlerts.length,critical=Number(sev.CRITICAL||0),high=Number(sev.HIGH||0),medium=Number(sev.MEDIUM||0),risk=critical*25+high*10+medium*3;const score=Math.max(0,100-Math.min(100,risk));$('overviewCritical').textContent=critical;$('overviewHigh').textContent=high;$('overviewMedium').textContent=medium;$('overviewTotal').textContent=total;$('postureScore').textContent=score+'/100';$('postureMeter').style.width=score+'%';const badge=$('postureBadge');if(d.capture.running){badge.textContent='MONITORING';}else{badge.textContent='ENGINE IDLE';}const caption=critical?'Critical events are present in the alert log. Review incidents now.':high?'High-severity events are logged. Review their details.':total?'No critical/high events in the current log; continue monitoring.':'No logged alerts yet. This is not a verified clean bill of health.';$('postureCaption').textContent=caption;const rows=allAlerts.slice(-5).reverse();$('overviewAlertRows').innerHTML=rows.length?rows.map(a=>`<tr><td>${esc(a.time)}</td><td><span class="severity ${a.severity}">${esc(a.severity)}</span></td><td>${esc(a.message)}</td></tr>`).join(''):'<tr><td colspan="3" class="empty">No events logged yet. Run the demo or start monitoring to populate this section.</td></tr>';}
function renderAlerts(){const sev=$('severityFilter').value,q=$('search').value.toLowerCase(),hours=$('timeFilter').value,now=Date.now();const rows=allAlerts.filter(a=>{const time=Date.parse(a.time.replace(' ','T'));const inWindow=hours==='ALL'||(!Number.isNaN(time)&&now-time<=Number(hours)*3600000&&now-time>=0);return (sev==='ALL'||a.severity===sev)&&((a.message+' '+a.time).toLowerCase().includes(q))&&inWindow;}).slice(-80).reverse();$('filterSummary').textContent=`Showing ${rows.length} matching events (maximum 80 displayed)`;$('alertRows').innerHTML=rows.length?rows.map(a=>`<tr><td>${esc(a.time)}</td><td><span class="severity ${a.severity}">${esc(a.severity)}</span></td><td>${esc(a.message)}</td></tr>`).join(''):'<tr><td colspan="3" class="empty">No matching events.</td></tr>';}
function resetFilters(){$('severityFilter').value='ALL';$('search').value='';$('timeFilter').value='ALL';renderAlerts();}
function renderProtocols(counts){const keys=['TCP','UDP','ICMP','ARP','OTHER'],max=Math.max(1,...keys.map(k=>Number(counts[k]||0)));$('protocolBars').innerHTML=keys.map(k=>`<div class="bar-wrap" title="${k}: ${Number(counts[k]||0)} packets"><div class="bar" style="height:${Math.max(3,Number(counts[k]||0)/max*100)}%"></div><div class="bar-label">${k}</div><strong style="font-size:11px">${Number(counts[k]||0).toLocaleString()}</strong></div>`).join('');const total=keys.reduce((n,k)=>n+Number(counts[k]||0),0);$('protocolSummary').textContent=`${total.toLocaleString()} packets classified in this process. Counts reset when the Python process restarts.`;}
function exportAlerts(){window.location.href='/api/alerts/export.csv';}
function toggleAutoRefresh(){autoRefresh=!autoRefresh;$('refreshToggle').textContent=autoRefresh?'Pause auto-refresh':'Resume auto-refresh';if(autoRefresh){refresh();refreshTimer=setInterval(refresh,2000);}else if(refreshTimer){clearInterval(refreshTimer);refreshTimer=null;showNotice('Auto-refresh paused. Monitoring and packet capture continue in the background.');}}
function renderFeed(items){$('eventCount').textContent=allAlerts.length+' events';$('eventFeed').innerHTML=items.length?items.map(a=>`<div class="event"><span class="event-dot" style="background:${color(a.severity)}"></span><div><p>${esc(a.message)}</p><small>${esc(a.time)} · ${esc(a.severity)}</small></div></div>`).join(''):'<div class="empty">No events logged yet.</div>';}
function renderSeverity(counts){const keys=['CRITICAL','HIGH','MEDIUM','LOW','INFO','SIMULATION'];const max=Math.max(1,...keys.map(k=>counts[k]||0));$('severityBars').innerHTML=keys.map(k=>`<div class="bar-wrap" title="${k}: ${counts[k]||0}"><div class="bar" style="height:${Math.max(3,(counts[k]||0)/max*100)}%;background:${color(k)}"></div><div class="bar-label">${k==='SIMULATION'?'SIM':k}</div></div>`).join('');}
function renderChart(){const w=600,h=200,top=15,bottom=28,usable=h-top-bottom,max=Math.max(1,...samples),pts=samples.map((v,i)=>[i*(w/(samples.length-1)),top+usable-(v/max)*usable]);const line=pts.map((p,i)=>(i?'L':'M')+p[0].toFixed(1)+','+p[1].toFixed(1)).join(' ');$('chartLine').setAttribute('d',line);$('chartArea').setAttribute('d',line+` L${w},${h-bottom} L0,${h-bottom} Z`);$('chartGrid').innerHTML=[0,1,2,3].map(i=>`<line class="gridline" x1="0" y1="${top+i*usable/3}" x2="${w}" y2="${top+i*usable/3}"/>`).join('');$('chartLabels').innerHTML=[0,1,2,3].map(i=>`<text class="chart-label" x="4" y="${top+i*usable/3-4}">${Math.round(max*(1-i/3))}</text>`).join('');}
function color(s){return ({CRITICAL:'#C86B58',HIGH:'#D6A34D',MEDIUM:'#f4d98a',LOW:'#C58A70',INFO:'#83A06B',SIMULATION:'#E6D6A8'})[s]||'#A9A083'}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
async function startMonitoring(){hideNotice();try{const d=await api('/api/monitor/start',{method:'POST',body:JSON.stringify({})});showNotice(d.message);await refresh();}catch(e){showNotice(e.message);}}
async function stopMonitoring(){try{const d=await api('/api/monitor/stop',{method:'POST',body:JSON.stringify({})});showNotice(d.message);await refresh();}catch(e){showNotice(e.message);}}
async function runDemo(){hideNotice();try{const d=await api('/api/demo',{method:'POST',body:JSON.stringify({})});showNotice(d.message);await refresh();}catch(e){showNotice(e.message);}}
setView("overview");renderChart();refresh();refreshTimer=setInterval(refresh,2000);
</script></body></html>"""

def parse_log():
    if not LOG_PATH.exists():
        return []
    try:
        lines = LOG_PATH.read_text(encoding="utf-8", errors="replace").splitlines()[-1200:]
    except OSError:
        return []
    out = []
    for line in lines:
        m = re.match(r"^\[(.*?)\]\s+\[(CRITICAL|HIGH|MEDIUM|LOW|INFO|SIMULATION)\]\s*(.*)$", line)
        if m:
            out.append({"time": m.group(1), "severity": m.group(2), "message": m.group(3)})
        else:
            # Preserve other log entries, including simulation step messages.
            tm = re.match(r"^\[(.*?)\]\s+(.*)$", line)
            if tm:
                msg = tm.group(2)
                sev_match = re.match(r"\[(CRITICAL|HIGH|MEDIUM|LOW|INFO|SIMULATION)\]\s*(.*)", msg)
                if sev_match:
                    out.append({"time": tm.group(1), "severity": sev_match.group(1), "message": sev_match.group(2)})
                elif "[SIMULATION]" in msg:
                    out.append({"time": tm.group(1), "severity": "SIMULATION", "message": msg.replace("[SIMULATION]", "").strip()})
                else:
                    out.append({"time": tm.group(1), "severity": "INFO", "message": msg})
    return out

def severity_counts(alerts):
    counts = {k: 0 for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "SIMULATION")}
    for a in alerts:
        counts[a["severity"]] = counts.get(a["severity"], 0) + 1
    return counts

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("index"))
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        with sqlite3.connect(USER_DB) as con:
            con.row_factory = sqlite3.Row
            user = con.execute("SELECT id, username, email, password_hash FROM users WHERE email = ?", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("index"))
        error = "Email or password is incorrect. Please try again."
    return render_template_string(AUTH_PAGE, title="Welcome back", subtitle="Log in to your security workspace.", headline="Your network. In focus.", signup=False, error=error)

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if session.get("user_id"):
        return redirect(url_for("index"))
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if len(username) < 2 or len(username) > 40:
            error = "Name must be between 2 and 40 characters."
        elif len(email) > 254 or "@" not in email:
            error = "Enter a valid email address."
        elif len(password) < 8:
            error = "Use a password with at least 8 characters."
        elif password != confirm:
            error = "Passwords do not match."
        else:
            try:
                with sqlite3.connect(USER_DB) as con:
                    cur = con.execute("INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)", (username, email, generate_password_hash(password), datetime.now().isoformat(timespec="seconds")))
                    con.commit()
                    user_id = cur.lastrowid
                session.clear()
                session["user_id"] = user_id
                session["username"] = username
                return redirect(url_for("index"))
            except sqlite3.IntegrityError:
                error = "An account with that email already exists. Try logging in."
    return render_template_string(AUTH_PAGE, title="Create your account", subtitle="A few details, then you’re in.", headline="Security starts with visibility.", signup=True, error=error)

@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.get("/")
@login_required
def index():
    return render_template_string(PAGE, username=session.get("username", "User"))

@app.get("/api/status")
@login_required
def status():
    alerts = parse_log()
    with capture_lock:
        capture = dict(capture_status)
    return jsonify({
        "capture": capture,
        "stats": {
            "packets": state.packet_count,
            "arp_alerts": state.arp_alerts,
            "mitm_alerts": state.mitm_alerts,
            "port_scan_alerts": state.port_scan_alerts,
            "suspicious_alerts": state.suspicious_alerts,
        },
        "protocols": dict(getattr(state, "protocol_counts", {})),
        "alerts": alerts[-250:],
        "severity": severity_counts(alerts),
        "server_time": datetime.now().isoformat(timespec="seconds"),
    })

@app.get("/api/alerts/export.csv")
@login_required
def export_alerts_csv():
    """Download the parsed alert history as a spreadsheet-friendly CSV."""
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["timestamp", "severity", "event"])
    for alert in parse_log():
        writer.writerow([alert.get("time", ""), alert.get("severity", "INFO"), alert.get("message", "")])
    from flask import Response
    return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=netshield-alerts.csv"})

def capture_worker():
    global capture_thread
    try:
        from sniffer import start_sniffer
        start_sniffer(prompt_user=False, stop_event=capture_stop)
        with capture_lock:
            if capture_status["running"]:
                capture_status.update(running=False, mode="stopped", message="Monitoring stopped")
    except Exception as exc:
        with capture_lock:
            capture_status.update(running=False, mode="stopped", message=f"ERROR: {exc}")
    finally:
        with capture_lock:
            if capture_status["mode"] == "live":
                capture_status.update(running=False, mode="stopped", message="Monitoring stopped")

@app.post("/api/monitor/start")
@login_required
def monitor_start():
    global capture_thread
    with capture_lock:
        if capture_status["running"]:
            return jsonify({"message": "Monitoring is already running"}), 200
        capture_stop.clear()
        capture_status.update(running=True, mode="live", message="Starting live packet capture…", interface=None)
        capture_thread = threading.Thread(target=capture_worker, daemon=True)
        capture_thread.start()
    return jsonify({"message": "Live capture requested. If capture fails, run the server as Administrator/root and verify the capture driver."})

@app.post("/api/monitor/stop")
@login_required
def monitor_stop():
    capture_stop.set()
    with capture_lock:
        was_running = capture_status["running"]
        capture_status.update(running=False, mode="stopped", message="Monitoring stop requested")
    return jsonify({"message": "Monitoring stop requested" if was_running else "Monitoring is already stopped"})

@app.post("/api/demo")
@login_required
def demo():
    with capture_lock:
        if capture_status["mode"] == "demo" and capture_status["running"]:
            return jsonify({"message": "Demo simulation is already running"}), 409
        capture_status.update(running=True, mode="demo", message="Running safe synthetic demo events")
    def worker():
        try:
            import simulate_attacks
            simulate_attacks.run_simulation(on_progress=lambda msg: set_capture_message(msg))
            # Simulation runs asynchronously; allow the progress worker to finish.
            time.sleep(5)
        except Exception as exc:
            set_capture_message(f"ERROR: demo failed: {exc}")
        finally:
            with capture_lock:
                if capture_status["mode"] == "demo":
                    capture_status.update(running=False, mode="stopped", message="Demo finished")
    threading.Thread(target=worker, daemon=True).start()
    return jsonify({"message": "Synthetic attack simulation started. These are demo-generated packets, not real network attacks."})

def set_capture_message(message):
    with capture_lock:
        capture_status["message"] = str(message)

@app.get("/api/health")
def health():
    return jsonify({"ok": True, "service": "NetShield", "time": datetime.now().isoformat(timespec="seconds")})

if __name__ == "__main__":
    host = os.environ.get("NETSHIELD_HOST", "127.0.0.1")
    port = int(os.environ.get("NETSHIELD_PORT", "5000"))
    print(f"NetShield dashboard: http://{host}:{port}")
    print("For live capture, use an elevated terminal. Keep the dashboard on localhost unless authentication is configured.")
    app.run(host=host, port=port, debug=False, threaded=True)
