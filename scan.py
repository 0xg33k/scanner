#!/usr/bin/env python3
"""

  ▓▒░ DevNull Scanner CVE — multi-source real-time CVE scanner. ░▒▓
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import io
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, quote

import aiohttp
from packaging.version import Version, InvalidVersion

# ===========================================================================
#  CONFIG
# ===========================================================================

NVD_API  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API  = "https://api.osv.dev/v1/query"
KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EDB_URL  = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

NVD_API_KEY = os.environ.get("NVD_API_KEY") or "01AEE5A4-704E-40BE-9805-AADDD3764C4A"

FINDINGS_DIR = Path("findings")
SUCCESS_FILE = Path("success.txt")
DEFAULT_THREADS = 4

# ===========================================================================
#  ANSI
# ===========================================================================

class C:
    RESET="\033[0m"; DIM="\033[2m"; BOLD="\033[1m"
    RED="\033[38;5;196m"; RED_DK="\033[38;5;88m"
    ORANGE="\033[38;5;208m"; YELLOW="\033[38;5;226m"
    GREEN="\033[38;5;46m"; GREEN_D="\033[38;5;28m"
    CYAN="\033[38;5;51m"; CYAN_D="\033[38;5;37m"
    MAGENTA="\033[38;5;201m"; PURPLE="\033[38;5;135m"
    GRAY="\033[38;5;245m"; GRAY_DK="\033[38;5;238m"
    WHITE="\033[38;5;231m"

USE_COLOR = True

def p(txt, *c):
    if not USE_COLOR: return str(txt)
    return "".join(c) + str(txt) + C.RESET

def s_star():  return p("[*]", C.CYAN, C.BOLD)
def s_plus():  return p("[+]", C.GREEN, C.BOLD)
def s_bang():  return p("[!]", C.YELLOW, C.BOLD)
def s_arrow(): return p("[>]", C.MAGENTA, C.BOLD)
def s_minus(): return p("[-]", C.GRAY_DK, C.BOLD)
def s_net():   return p("[~]", C.PURPLE, C.BOLD)
def s_kev():   return p("[KEV]", C.RED, C.BOLD)
def s_poc():   return p("[PoC]", C.ORANGE, C.BOLD)

# ===========================================================================
#  BANNER
# ===========================================================================

DEVNULL_ART = r"""
   ██████╗ ███████╗██╗   ██╗███╗   ██╗██╗   ██╗██╗     ██╗
   ██╔══██╗██╔════╝██║   ██║████╗  ██║██║   ██║██║     ██║
   ██║  ██║█████╗  ██║   ██║██╔██╗ ██║██║   ██║██║     ██║
   ██║  ██║██╔══╝  ╚██╗ ██╔╝██║╚██╗██║██║   ██║██║     ██║
   ██████╔╝███████╗ ╚████╔╝ ██║ ╚████║╚██████╔╝███████╗███████╗
   ╚═════╝ ╚══════╝  ╚═══╝  ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝
                ▓▒░  S C A N N E R  ·  C V E  ░▒▓
"""

def banner():
    W = 66
    top = "╔" + "═" * (W - 2) + "╗"
    bot = "╚" + "═" * (W - 2) + "╝"
    title    = "DevNull Scanner CVE"
    subtitle = "OSV + NVD + KEV + Exploit-DB · Strict Version Gate"

    print()
    print(p(C.PURPLE, C.BOLD) + DEVNULL_ART + C.RESET)
    print(p(C.RED_DK, C.BOLD) + top + C.RESET)
    print(p(C.RED_DK, C.BOLD) + "║" + C.RESET + " " * (W - 2) +
          p(C.RED_DK, C.BOLD) + "║" + C.RESET)
    print(p(C.RED_DK, C.BOLD) + "║" + C.RESET +
          p("  " + title.center(W - 6) + "  ", C.BOLD, C.RED) +
          p(C.RED_DK, C.BOLD) + "║" + C.RESET)
    print(p(C.RED_DK, C.BOLD) + "║" + C.RESET +
          p("  " + subtitle.center(W - 6) + "  ", C.ORANGE) +
          p(C.RED_DK, C.BOLD) + "║" + C.RESET)
    print(p(C.RED_DK, C.BOLD) + "║" + C.RESET + " " * (W - 2) +
          p(C.RED_DK, C.BOLD) + "║" + C.RESET)
    print(p(C.RED_DK, C.BOLD) + bot + C.RESET)
    print(p("  made by G33K · scanning only · authorized use only", C.DIM, C.GRAY))
    print()

def sep_eq(w=60):  print(p("=" * w, C.GRAY_DK))
def sep_thin(w=60): print(p("─" * w, C.GRAY_DK))

# ===========================================================================
#  DATA
# ===========================================================================

@dataclass
class Tech:
    name: str
    vendor: str
    product: str
    version: Optional[str] = None
    cpe_base: str = ""
    osv_ecosystem: Optional[str] = None
    osv_package: Optional[str] = None
    confidence: int = 0
    signals: list[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.cpe_base:
            self.cpe_base = f"cpe:2.3:a:{self.vendor}:{self.product}"

@dataclass
class Finding:
    cve: str
    score: float
    severity: str
    verdict: str
    summary: str
    matched_range: str = ""
    url: str = ""
    target_url: str = ""
    reason: str = ""
    detected_version: str = ""
    source: str = ""
    cwe: str = ""
    vector: str = ""
    kev: bool = False
    poc: bool = False
    exploitability: str = ""
    priority: float = 0.0

@dataclass
class Report:
    url: str
    host: str = ""
    path: str = ""
    server: str = ""
    techs: list[Tech] = field(default_factory=list)
    findings: dict[str, list[Finding]] = field(default_factory=dict)
    info: dict[str, list[Finding]] = field(default_factory=dict)
    error: str = ""
    scanned_at: str = ""
    status: str = ""
    saved_paths: list[str] = field(default_factory=list)
    nvd_calls: int = 0
    osv_calls: int = 0

    def _b(self, verdict, d):
        out = []
        for tn, fs in d.items():
            for f in fs:
                if f.verdict == verdict: out.append((tn, f))
        return sorted(out, key=lambda x: x[1].priority, reverse=True)

    def criticals(self): return self._b("CRITICAL", self.findings)
    def vulns(self):     return self._b("VULNERABLE", self.findings)
    def infos(self):     return self._b("INFO", self.info)

    def counts(self):
        return (len(self.criticals()), len(self.vulns()), len(self.infos()))

    def has_real_vuln(self) -> bool:
        c, v, _ = self.counts()
        return (c + v) > 0

# ===========================================================================
#  VERSION
# ===========================================================================

def _norm(v: str) -> str:
    v = v.strip().lstrip("vV")
    v = re.sub(r"[_\-]\d{8,}$", "", v)
    v = re.sub(r"[_\-]?p(\d+)$", r".post\1", v)
    v = re.sub(r"([0-9])p([0-9])", r"\1.post\2", v)
    return v

def vparse(v):
    if not v: return None
    try: return Version(_norm(v))
    except InvalidVersion: return None

def vcmp(a, b):
    va, vb = vparse(a), vparse(b)
    if va is None or vb is None: return None
    if va < vb: return -1
    if va > vb: return 1
    return 0

# ===========================================================================
#  RATE LIMITERS
# ===========================================================================

class RateLimiter:
    def __init__(self, max_calls, period):
        self.max_calls, self.period = max_calls, period
        self._calls: list[float] = []
        self._lock = asyncio.Lock()

    async def acquire(self):
        while True:
            async with self._lock:
                now = time.monotonic()
                self._calls = [t for t in self._calls if now - t < self.period]
                if len(self._calls) < self.max_calls:
                    self._calls.append(now); return
                wait = self.period - (now - self._calls[0]) + 0.02
            await asyncio.sleep(wait)

class HostLimiter:
    def __init__(self, delay: float = 0.3):
        self.delay = delay
        self._last: dict[str, float] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    async def acquire(self, host: str):
        lock = self._locks.setdefault(host, asyncio.Lock())
        async with lock:
            now = time.monotonic()
            last = self._last.get(host, 0.0)
            wait = self.delay - (now - last)
            if wait > 0: await asyncio.sleep(wait)
            self._last[host] = time.monotonic()

# ===========================================================================
#  FINGERPRINT
# ===========================================================================

VENDOR_MAP = {
    "apache":("apache","http_server"), "httpd":("apache","http_server"),
    "nginx":("nginx","nginx"),
    "iis":("microsoft","internet_information_services"),
    "litespeed":("litespeedtech","litespeed_web_server"),
    "caddy":("caddyserver","caddy"),
    "tomcat":("apache","tomcat"), "jetty":("eclipse","jetty"),
    "gunicorn":("gunicorn","gunicorn"),
    "werkzeug":("palletsprojects","werkzeug"),
    "php":("php","php"), "asp.net":("microsoft","asp.net"),
    "express":("expressjs","express"), "node.js":("nodejs","node.js"),
    "openssl":("openssl","openssl"),
    "wordpress":("wordpress","wordpress"), "drupal":("drupal","drupal"),
    "joomla":("joomla","joomla"),
    "jquery":("jquery","jquery"), "jquery-ui":("jquery","jquery_ui"),
    "bootstrap":("getbootstrap","bootstrap"),
    "angular":("google","angular"), "angularjs":("angularjs","angular.js"),
    "react":("facebook","react"), "vue":("vuejs","vue.js"),
    "moment":("momentjs","moment"), "lodash":("lodash","lodash"),
    "django":("djangoproject","django"),
    "flask":("palletsprojects","flask"),
    "laravel":("laravel","laravel"), "rails":("rubyonrails","rails"),
    "spring":("vmware","spring_framework"),
    "struts":("apache","struts"), "log4j":("apache","log4j"),
    "openssh":("openbsd","openssh"),
    "elasticsearch":("elastic","elasticsearch"),
    "redis":("redis","redis"), "mongodb":("mongodb","mongodb"),
    "mysql":("oracle","mysql"), "mariadb":("mariadb","mariadb"),
    "postgresql":("postgresql","postgresql"), "sqlite":("sqlite","sqlite"),
    "grafana":("grafana","grafana"), "kibana":("elastic","kibana"),
    "jenkins":("jenkins","jenkins"), "gitlab":("gitlab","gitlab"),
    "nextcloud":("nextcloud","nextcloud"),
    "phpmyadmin":("phpmyadmin","phpmyadmin"),
    "roundcube":("roundcube","roundcube"),
    "magento":("magento","magento"), "prestashop":("prestashop","prestashop"),
}

OSV_MAP = {
    "jquery":       ("npm", "jquery"),
    "jquery-ui":    ("npm", "jquery-ui"),
    "bootstrap":    ("npm", "bootstrap"),
    "lodash":       ("npm", "lodash"),
    "moment":       ("npm", "moment"),
    "vue":          ("npm", "vue"),
    "react":        ("npm", "react"),
    "angular":      ("npm", "@angular/core"),
    "angularjs":    ("npm", "angular"),
    "express":      ("npm", "express"),
    "flask":        ("PyPI", "flask"),
    "django":       ("PyPI", "django"),
    "werkzeug":     ("PyPI", "werkzeug"),
    "gunicorn":     ("PyPI", "gunicorn"),
    "rails":        ("RubyGems", "rails"),
    "laravel":      ("Packagist", "laravel/framework"),
    "spring":       ("Maven", "org.springframework:spring-core"),
    "struts":       ("Maven", "org.apache.struts:struts2-core"),
    "log4j":        ("Maven", "org.apache.logging.log4j:log4j-core"),
}

SERVER_RE = re.compile(r"([A-Za-z][\w\-]+)(?:/([\w\.\-]+))?", re.I)
META_GEN_RE  = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.I)
META_GEN_RE2 = re.compile(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']', re.I)
SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
PHP_RE = re.compile(r"PHP/([\d\.]+)", re.I)

SIGNAL_WEIGHTS = {
    "server_version": 30, "server_name": 15,
    "powered_version": 25, "powered_name": 10,
    "aspnet_version": 30,
    "generator": 25, "meta": 10,
    "cookie": 15,
    "js_version": 25, "js_name": 10,
    "body": 10,
}

def _add(techs, seen, name, version, signals, evidence):
    key = name.lower()
    if key in seen:
        for t in techs:
            if t.name.lower() == key:
                if version and not t.version: t.version = version
                for s in signals:
                    if s not in t.signals:
                        t.signals.append(s)
                        t.confidence = min(100, t.confidence + SIGNAL_WEIGHTS.get(s, 5))
                return
        return
    seen.add(key)
    vendor, product = VENDOR_MAP.get(key, (key.replace(" ","_"), key.replace(" ","_")))
    osv_eco, osv_pkg = OSV_MAP.get(key, (None, None))
    conf = sum(SIGNAL_WEIGHTS.get(s, 5) for s in signals)
    techs.append(Tech(
        name=name, vendor=vendor, product=product, version=version,
        osv_ecosystem=osv_eco, osv_package=osv_pkg,
        confidence=min(100, conf), signals=list(signals),
    ))

def detect(headers, body, cookies):
    techs, seen = [], set()

    server = headers.get("Server") or headers.get("server") or ""
    if server:
        m = SERVER_RE.match(server.strip())
        if m:
            sname = m.group(1).lower(); sver = m.group(2)
            key = {"apache":"apache","nginx":"nginx","microsoft-iis":"iis","iis":"iis",
                   "litespeed":"litespeed","caddy":"caddy","gunicorn":"gunicorn",
                   "werkzeug":"werkzeug","openresty":"nginx"}.get(sname, sname)
            _add(techs, seen, key, sver,
                 ["server_version" if sver else "server_name"], f"Server: {server}")

    powered = headers.get("X-Powered-By") or headers.get("x-powered-by") or ""
    if powered:
        pu = powered.upper()
        if "PHP" in pu:
            m = PHP_RE.search(powered)
            _add(techs, seen, "php", m.group(1) if m else None,
                 ["powered_version" if m else "powered_name"], f"X-Powered-By: {powered}")
        if "ASP.NET" in pu:
            _add(techs, seen, "asp.net", None, ["powered_name"], f"X-Powered-By: {powered}")
        if "Express" in powered:
            _add(techs, seen, "express", None, ["powered_name"], f"X-Powered-By: {powered}")

    asp = headers.get("X-AspNet-Version") or headers.get("x-aspnet-version") or ""
    if asp:
        _add(techs, seen, "asp.net", asp, ["aspnet_version"], f"X-AspNet-Version: {asp}")

    gen = headers.get("X-Generator") or headers.get("x-generator") or ""
    if gen:
        gm = re.match(r"([A-Za-z][\w \-]+?)\s*([\d\.]+)?", gen)
        if gm:
            gname = gm.group(1).strip().lower().replace(" ", "")
            gver = gm.group(2)
            key = {"wordpress":"wordpress","drupal":"drupal","joomla":"joomla",
                   "magento":"magento","prestashop":"prestashop"}.get(gname, gname)
            _add(techs, seen, key, gver, ["generator"], f"X-Generator: {gen}")

    cs = set(cookies)
    if "PHPSESSID" in cs:         _add(techs, seen, "php", None, ["cookie"], "PHPSESSID cookie")
    if "JSESSIONID" in cs:        _add(techs, seen, "tomcat", None, ["cookie"], "JSESSIONID cookie")
    if "ASP.NET_SessionId" in cs: _add(techs, seen, "asp.net", None, ["cookie"], "ASP.NET_SessionId cookie")
    if "laravel_session" in cs:   _add(techs, seen, "laravel", None, ["cookie"], "laravel_session cookie")
    if "csrftoken" in cs and "sessionid" in cs:
        _add(techs, seen, "django", None, ["cookie"], "Django CSRF cookie")
    joined = " ".join(cs)
    if "wp-settings-" in joined or "wordpress_logged_in" in joined:
        _add(techs, seen, "wordpress", None, ["cookie"], "WordPress cookies")
    if any(c.startswith("SESS") for c in cs):
        _add(techs, seen, "drupal", None, ["cookie"], "Drupal SESS* cookie")

    for rx in (META_GEN_RE, META_GEN_RE2):
        m = rx.search(body)
        if m:
            content = m.group(1)
            gm = re.match(r"([A-Za-z][\w \-]+?)\s*([\d\.]+)?", content)
            if gm:
                gname = gm.group(1).strip().lower().replace(" ", "")
                gver = gm.group(2)
                key = {"wordpress":"wordpress","drupal":"drupal","joomla":"joomla",
                       "magento":"magento","prestashop":"prestashop"}.get(gname, gname)
                _add(techs, seen, key, gver, ["generator"], f"generator: {content}")
            break

    if "wp-content" in body or "wp-includes" in body:
        _add(techs, seen, "wordpress", None, ["body"], "wp-content in body")
    if "/sites/default/files" in body or "drupalSettings" in body:
        _add(techs, seen, "drupal", None, ["body"], "Drupal path in body")
    if "/components/com_" in body:
        _add(techs, seen, "joomla", None, ["body"], "/components/com_ in body")

    for src in SCRIPT_SRC_RE.findall(body):
        low = src.lower()
        for lib, rx in (
            ("jquery",     r"jquery[\.\-]?(\d+\.\d+\.\d+)"),
            ("jquery-ui",  r"jquery-ui[\.\-]?(\d+\.\d+\.\d+)"),
            ("bootstrap",  r"bootstrap[\.\-]?(\d+\.\d+\.\d+)"),
            ("angular",    r"angular[\.\-]?(\d+\.\d+\.\d+)"),
            ("angularjs",  r"angular(?:\.min)?\.js"),
            ("react",      r"react[\.\-]?(\d+\.\d+\.\d+)"),
            ("vue",        r"vue[\.\-]?(\d+\.\d+\.\d+)"),
            ("moment",     r"moment[\.\-]?(\d+\.\d+\.\d+)"),
            ("lodash",     r"lodash[\.\-]?(\d+\.\d+\.\d+)"),
        ):
            m = re.search(rx, low)
            if m:
                has_ver = bool(m.groups() and m.group(1))
                _add(techs, seen, lib, m.group(1) if has_ver else None,
                     ["js_version" if has_ver else "js_name"], f"script: {src[:60]}")

    return techs

def extract_cookies(headers):
    raw = headers.get("Set-Cookie") or headers.get("set-cookie") or ""
    if not raw: return []
    names = []
    for part in re.split(r",(?=\s*[A-Za-z0-9_\-]+=)", raw):
        name = part.split("=", 1)[0].strip()
        if name: names.append(name)
    return names

# ===========================================================================
#  STRICT RANGE
# ===========================================================================

def strict_range_match(cve_obj, vendor, product, version):
    if not version or vparse(version) is None: return None
    for cfg in cve_obj.get("configurations", []) or []:
        for node in cfg.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                if not match.get("vulnerable", False): continue
                parts = match.get("criteria", "").split(":")
                if len(parts) < 5: continue
                if parts[3].lower() not in (vendor.lower(), "*"): continue
                if parts[4].lower() not in (product.lower(), "*"): continue

                start   = match.get("versionStartIncluding")
                start_x = match.get("versionStartExcluding")
                end     = match.get("versionEndIncluding")
                end_x   = match.get("versionEndExcluding")
                has_b   = bool(start or start_x or end or end_x)

                if not has_b:
                    cpe_ver = parts[5] if len(parts) > 5 else "*"
                    if cpe_ver in ("*", "-", ""): continue
                    if vcmp(version, cpe_ver) == 0: return (f"= {cpe_ver}", "exact version")
                    continue

                ok = True
                if start:
                    c = vcmp(version, start)
                    if c is None or c < 0: ok = False
                elif start_x:
                    c = vcmp(version, start_x)
                    if c is None or c <= 0: ok = False
                if ok and end:
                    c = vcmp(version, end)
                    if c is None or c > 0: ok = False
                elif ok and end_x:
                    c = vcmp(version, end_x)
                    if c is None or c >= 0: ok = False

                if ok:
                    if start and end:       rng = f"{start} ≤ v ≤ {end}"
                    elif start_x and end_x: rng = f"{start_x} < v < {end_x}"
                    elif start and end_x:   rng = f"{start} ≤ v < {end_x}"
                    elif start_x and end:   rng = f"{start_x} < v ≤ {end}"
                    elif start:             rng = f"v ≥ {start}"
                    elif start_x:           rng = f"v > {start_x}"
                    elif end:               rng = f"v ≤ {end}"
                    elif end_x:             rng = f"v < {end_x}"
                    else:                   rng = "in range"
                    return (rng, "bounded range")
    return None

def osv_range_match(affected, version):
    if not version: return None
    vers = affected.get("versions") or []
    if version in vers: return f"= {version}"
    for r in affected.get("ranges", []) or []:
        introduced = None
        for ev in r.get("events", []) or []:
            if "introduced" in ev:
                introduced = ev["introduced"]
            elif "fixed" in ev:
                end = ev["fixed"]
                if _in_win(version, introduced, end, inc_end=False):
                    return f">= {introduced} < {end}"
                introduced = None
            elif "last_affected" in ev:
                end = ev["last_affected"]
                if _in_win(version, introduced, end, inc_end=True):
                    return f">= {introduced} ≤ {end}"
                introduced = None
        if introduced is not None and introduced != "0":
            c = vcmp(version, introduced)
            if c is not None and c >= 0:
                return f">= {introduced}"
        elif introduced == "0":
            return f"all versions (≤ {version})"
    return None

def _in_win(version, start, end, inc_end=False):
    v = vparse(version)
    if v is None: return False
    if start and start != "0":
        s = vparse(start)
        if s is not None and v < s: return False
    if end:
        e = vparse(end)
        if e is not None:
            if inc_end and v > e: return False
            if not inc_end and v >= e: return False
    return True

# ===========================================================================
#  KEV + EDB
# ===========================================================================

class KevFeed:
    def __init__(self):
        self.cves: set[str] = set()

    async def load(self, session, out_lock):
        async with out_lock:
            print(f"{s_star()} {p('Loading CISA KEV feed...', C.GRAY)}")
        try:
            async with session.get(KEV_URL, timeout=aiohttp.ClientTimeout(total=30)) as r:
                if r.status != 200:
                    async with out_lock:
                        print(f"      {s_bang()} {p(f'KEV HTTP {r.status}', C.YELLOW)}")
                    return
                data = await r.json()
                for v in data.get("vulnerabilities", []) or []:
                    cid = v.get("cveID", "").upper()
                    if cid: self.cves.add(cid)
                async with out_lock:
                    print(f"      {s_plus()} {p(f'{len(self.cves)} KEV entries', C.GREEN)}")
        except Exception as e:
            async with out_lock:
                print(f"      {s_bang()} {p(f'KEV load failed: {e}', C.YELLOW)}")

    def is_kev(self, cve): return cve.upper() in self.cves

class ExploitDbFeed:
    def __init__(self):
        self.cves: set[str] = set()

    async def load(self, session, out_lock):
        async with out_lock:
            print(f"{s_star()} {p('Loading Exploit-DB PoC index...', C.GRAY)}")
        try:
            async with session.get(EDB_URL, timeout=aiohttp.ClientTimeout(total=60)) as r:
                if r.status != 200:
                    async with out_lock:
                        print(f"      {s_bang()} {p(f'EDB HTTP {r.status}', C.YELLOW)}")
                    return
                text = await r.text()
                reader = csv.DictReader(io.StringIO(text))
                for row in reader:
                    codes = (row.get("codes") or "").upper()
                    for m in re.finditer(r"CVE-\d{4}-\d{4,}", codes):
                        self.cves.add(m.group(0))
                async with out_lock:
                    print(f"      {s_plus()} {p(f'{len(self.cves)} CVE IDs with public PoC', C.GREEN)}")
        except Exception as e:
            async with out_lock:
                print(f"      {s_bang()} {p(f'EDB load failed: {e}', C.YELLOW)}")

    def has_poc(self, cve): return cve.upper() in self.cves

# ===========================================================================
#  CVE SOURCES
# ===========================================================================

async def osv_query(session, tech: Tech):
    if not tech.osv_ecosystem or not tech.osv_package or not tech.version:
        return []
    body = {"package": {"name": tech.osv_package, "ecosystem": tech.osv_ecosystem},
            "version": tech.version}
    for attempt in range(3):
        try:
            async with session.post(OSV_API, json=body,
                                    timeout=aiohttp.ClientTimeout(total=20)) as r:
                if r.status != 200: return []
                data = await r.json()
                return data.get("vulns", []) or []
        except (aiohttp.ClientError, asyncio.TimeoutError):
            await asyncio.sleep(1 * (attempt + 1))
    return []

async def nvd_query(session, limiter, cpe_base, api_key):
    headers = {"apiKey": api_key} if api_key else {}
    params = {"virtualMatchString": cpe_base, "resultsPerPage": 500}
    for attempt in range(3):
        await limiter.acquire()
        try:
            async with session.get(NVD_API, params=params, headers=headers) as r:
                if r.status == 403:
                    await asyncio.sleep(3 * (attempt + 1)); continue
                if r.status in (400, 404): return []
                if r.status != 200: return []
                data = await r.json()
                return data.get("vulnerabilities", []) or []
        except (aiohttp.ClientError, asyncio.TimeoutError):
            await asyncio.sleep(1 * (attempt + 1))
    return []

class CveAggregator:
    def __init__(self, session, nvd_limiter, api_key):
        self.session = session
        self.nvd_limiter = nvd_limiter
        self.api_key = api_key
        self.nvd_inflight: dict[str, asyncio.Future] = {}
        self.osv_inflight: dict[str, asyncio.Future] = {}

    async def nvd_get(self, cpe):
        fut = self.nvd_inflight.get(cpe)
        if fut is not None: return await fut
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        self.nvd_inflight[cpe] = fut
        try:
            r = await nvd_query(self.session, self.nvd_limiter, cpe, self.api_key)
            if not fut.done(): fut.set_result(r)
            return r
        finally:
            self.nvd_inflight.pop(cpe, None)

    async def osv_get(self, tech: Tech):
        key = f"{tech.osv_ecosystem}:{tech.osv_package}@{tech.version}"
        fut = self.osv_inflight.get(key)
        if fut is not None: return await fut
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        self.osv_inflight[key] = fut
        try:
            r = await osv_query(self.session, tech)
            if not fut.done(): fut.set_result(r)
            return r
        finally:
            self.osv_inflight.pop(key, None)

# ===========================================================================
#  NVD helpers
# ===========================================================================

def nvd_severity(cve_obj):
    metrics = cve_obj.get("metrics", {}) or {}
    best_score, best_sev, best_vec = 0.0, "NONE", ""
    for key in ("cvssMetricV40","cvssMetricV31","cvssMetricV30","cvssMetricV2"):
        for m in metrics.get(key, []) or []:
            d = m.get("cvssData", {}) or {}
            s = float(d.get("baseScore", 0.0) or 0.0)
            sev = (d.get("baseSeverity") or m.get("baseSeverity") or "").upper()
            if not sev:
                sev = ("CRITICAL" if s>=9.0 else "HIGH" if s>=7.0
                       else "MEDIUM" if s>=4.0 else "LOW" if s>0 else "NONE")
            if s > best_score:
                best_score, best_sev = s, sev
                best_vec = d.get("vectorString","") or ""
    return best_score, best_sev, best_vec

def nvd_desc(cve_obj):
    for d in cve_obj.get("descriptions", []) or []:
        if d.get("lang") == "en": return d.get("value","")
    return ""

def nvd_cwe(cve_obj):
    for w in cve_obj.get("weaknesses", []) or []:
        for d in w.get("description", []) or []:
            val = d.get("value","")
            if val.startswith("CWE-"): return val
    return ""

def exploitability_from_vector(vec: str) -> str:
    if not vec: return "unknown"
    av = re.search(r"AV:([NALP])", vec)
    pr = re.search(r"PR:([NALH])", vec)
    ui = re.search(r"UI:([NR])", vec)
    if av and av.group(1)=="N" and pr and pr.group(1)=="N" and ui and ui.group(1)=="N":
        return "network · no-auth · no-UI"
    if av and av.group(1)=="N": return "network"
    if av and av.group(1)=="A": return "adjacent"
    if av and av.group(1)=="L": return "local"
    if av and av.group(1)=="P": return "physical"
    return "unknown"

# ===========================================================================
#  EVALUATE
# ===========================================================================

def make_finding(cve_id, score, severity, verdict, summary, rng, source,
                 target_url, detected_version, reason, kev=False, poc=False,
                 cwe="", vector=""):
    f = Finding(
        cve=cve_id, score=score, severity=severity, verdict=verdict,
        summary=summary[:400], matched_range=rng,
        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        target_url=target_url, reason=reason, detected_version=detected_version,
        source=source, cwe=cwe, vector=vector, kev=kev, poc=poc,
        exploitability=exploitability_from_vector(vector),
    )
    pr = f.score
    if f.kev: pr += 2.0
    if f.poc: pr += 1.5
    if f.exploitability == "network · no-auth · no-UI": pr += 1.0
    elif f.exploitability == "network": pr += 0.5
    f.priority = round(pr, 2)
    return f

def evaluate(tech, osv_data, nvd_data, target_url, kev, edb):
    merged: dict[str, Finding] = {}
    info: list[Finding] = []

    for v in osv_data:
        osv_id = v.get("id","")
        aliases = v.get("aliases", []) or []
        cve_ids = [a for a in aliases if a.startswith("CVE-")]
        summary = v.get("summary") or (v.get("details","")[:400]) or osv_id

        matched_range = None
        for aff in v.get("affected", []) or []:
            pkg = aff.get("package", {}) or {}
            if (pkg.get("ecosystem") == tech.osv_ecosystem and
                pkg.get("name") == tech.osv_package):
                matched_range = osv_range_match(aff, tech.version)
                if matched_range: break

        if not matched_range and tech.version:
            matched_range = f"(OSV matched version {tech.version})"

        if not cve_ids:
            info.append(make_finding(
                osv_id, 0.0, "NONE", "INFO", summary, matched_range or "",
                "osv", target_url, tech.version or "", "OSV advisory, no CVE alias",
            ))
            continue

        for cid in cve_ids:
            if cid in merged: continue
            nvd_cve = None
            for nv in nvd_data:
                if nv.get("cve",{}).get("id") == cid:
                    nvd_cve = nv.get("cve",{}); break
            if nvd_cve:
                score, sev, vec = nvd_severity(nvd_cve)
                cwe = nvd_cwe(nvd_cve)
                if not summary: summary = nvd_desc(nvd_cve)
            else:
                score, sev, vec, cwe = 0.0, "NONE", "", ""
            verdict = "CRITICAL" if sev == "CRITICAL" else "VULNERABLE"
            merged[cid] = make_finding(
                cid, score, sev or "UNKNOWN", verdict, summary,
                matched_range or "", "osv" if not nvd_cve else "osv+nvd",
                target_url, tech.version or "", "OSV range match",
                kev=kev.is_kev(cid), poc=edb.has_poc(cid), cwe=cwe, vector=vec,
            )

    for nv in nvd_data:
        cve_obj = nv.get("cve", {})
        cid = cve_obj.get("id","")
        if not cid or cid in merged: continue

        score, sev, vec = nvd_severity(cve_obj)
        cwe = nvd_cwe(cve_obj)
        summary = nvd_desc(cve_obj)

        hit = strict_range_match(cve_obj, tech.vendor, tech.product, tech.version) \
              if tech.version else None

        if hit is not None:
            rng, reason = hit
            verdict = "CRITICAL" if sev == "CRITICAL" else "VULNERABLE"
            merged[cid] = make_finding(
                cid, score, sev, verdict, summary, rng, "nvd",
                target_url, tech.version or "", reason,
                kev=kev.is_kev(cid), poc=edb.has_poc(cid), cwe=cwe, vector=vec,
            )
        else:
            why = "no version detected" if not tech.version else "outside declared range"
            info.append(make_finding(
                cid, score, sev or "NONE", "INFO", summary, "", "nvd",
                target_url, tech.version or "", why,
                kev=kev.is_kev(cid), poc=edb.has_poc(cid), cwe=cwe, vector=vec,
            ))

    flagged = list(merged.values())
    flagged.sort(key=lambda x: x.priority, reverse=True)
    info.sort(key=lambda x: x.priority, reverse=True)
    return flagged, info

# ===========================================================================
#  SAVE
# ===========================================================================

def save_report(report: Report):
    FINDINGS_DIR.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe_host = re.sub(r"[^A-Za-z0-9._-]", "_", report.host) or "target"
    base = FINDINGS_DIR / f"{safe_host}_{ts}"
    txt_path  = base.with_suffix(".txt")
    json_path = base.with_suffix(".json")
    html_path = base.with_suffix(".html")
    csv_path  = base.with_suffix(".csv")

    crits = report.criticals(); vlns = report.vulns()

    L = []
    L.append("=" * 80)
    L.append("  DevNull Scanner CVE — CONFIRMED VULNERABILITY REPORT")
    L.append("  OSV + NVD + KEV + Exploit-DB · strict version gate")
    L.append("=" * 80)
    L.append(f"  target      : {report.url}")
    L.append(f"  host        : {report.host}")
    L.append(f"  path        : {report.path}")
    L.append(f"  server      : {report.server or '(none)'}")
    L.append(f"  scanned_at  : {report.scanned_at}")
    L.append(f"  nvd_calls   : {report.nvd_calls}")
    L.append(f"  osv_calls   : {report.osv_calls}")
    L.append(f"  status      : {report.status}")
    L.append(f"  criticals   : {len(crits)}")
    L.append(f"  vulnerable  : {len(vlns)}")
    L.append("")
    L.append("  Detected stack:")
    for t in report.techs:
        L.append(f"    - {t.name:<20} {t.version or '?':<14} "
                 f"conf={t.confidence:>3}%  signals={','.join(t.signals)}")
    L.append("")

    for label, bucket in (("CRITICAL", crits), ("VULNERABLE", vlns)):
        if not bucket: continue
        L.append("-" * 80); L.append(f"  {label}"); L.append("-" * 80)
        for i, (tn, f) in enumerate(bucket, 1):
            L.append("")
            tags = []
            if f.kev: tags.append("[KEV]")
            if f.poc: tags.append("[PoC]")
            tag_s = " ".join(tags)
            L.append(f"  [{i}] {f.cve}  CVSS {f.score:.1f}  ({tn})  {tag_s}")
            L.append(f"      target       : {f.target_url}")
            L.append(f"      detected     : {f.detected_version}")
            L.append(f"      affected     : {f.matched_range}")
            L.append(f"      exploit      : {f.exploitability or 'n/a'}")
            if f.cwe: L.append(f"      cwe          : {f.cwe}")
            if f.vector: L.append(f"      vector       : {f.vector}")
            L.append(f"      source       : {f.source}")
            L.append(f"      advisory     : {f.url}")
            L.append(f"      summary      : {f.summary}")
            L.append(f"      priority     : {f.priority}")

    L.append("")
    L.append("-" * 80); L.append("  PENTEST LEAD NOTES"); L.append("-" * 80)
    for tn, f in crits + vlns:
        tags = ("KEV " if f.kev else "") + ("PoC" if f.poc else "")
        L.append(f"  · {tn} @ {f.cve}  [{tags.strip() or 'n/a'}]")
        L.append(f"      detected : {f.detected_version}")
        L.append(f"      affected : {f.matched_range}")
        L.append(f"      check    : {f.url}")
    L.append("")
    L.append("  [i] Scanned only. No exploit executed.")
    L.append("      Authorized testing only. Made by G33K.")
    L.append("")
    txt_path.write_text("\n".join(L), encoding="utf-8")

    payload = {
        "tool": "DevNull Scanner CVE", "author": "G33K",
        "notice": "OSV + NVD + KEV + Exploit-DB · strict version gate",
        "target": report.url, "host": report.host, "path": report.path,
        "server": report.server, "scanned_at": report.scanned_at,
        "status": report.status,
        "nvd_calls": report.nvd_calls, "osv_calls": report.osv_calls,
        "counts": {"critical": len(crits), "vulnerable": len(vlns)},
        "technologies": [asdict(t) for t in report.techs],
        "critical_findings":   [{"technology": tn, **asdict(f)} for tn, f in crits],
        "vulnerable_findings": [{"technology": tn, **asdict(f)} for tn, f in vlns],
    }
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["target","technology","detected","cve","cvss","severity",
                    "verdict","affected_range","exploitability","kev","poc",
                    "cwe","source","advisory","priority"])
        for tn, f in crits + vlns:
            w.writerow([report.url, tn, f.detected_version, f.cve,
                        f"{f.score:.1f}", f.severity, f.verdict, f.matched_range,
                        f.exploitability, f.kev, f.poc, f.cwe, f.source,
                        f.url, f.priority])

    html_path.write_text(_render_html(report, crits, vlns), encoding="utf-8")

    append_success_log(report, txt_path, json_path)
    return [str(txt_path), str(json_path), str(html_path), str(csv_path)]

def _render_html(report, crits, vlns):
    def row(i, tn, f):
        tags = ""
        if f.kev: tags += '<span class="kev">KEV</span>'
        if f.poc: tags += '<span class="poc">PoC</span>'
        cls = "crit" if f.verdict == "CRITICAL" else "vuln"
        return f"""<tr class="{cls}">
  <td>{i}</td><td>{tn}</td><td><code>{f.cve}</code></td>
  <td>{f.score:.1f}</td><td>{f.detected_version}</td>
  <td>{f.matched_range}</td><td>{f.exploitability or '-'}</td>
  <td>{tags or '-'}</td><td><a href="{f.url}">NVD</a></td>
</tr>"""
    stack = "".join(
        f"<li><b>{t.name}</b> {t.version or '?'} "
        f"<span class='conf'>{t.confidence}%</span> "
        f"<small>({', '.join(t.signals)})</small></li>"
        for t in report.techs
    )
    crit_rows = "".join(row(i, tn, f) for i, (tn, f) in enumerate(crits, 1))
    vuln_rows = "".join(row(i, tn, f) for i, (tn, f) in enumerate(vlns, 1))
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>DevNull CVE — {report.host}</title>
<style>
 body{{font-family:ui-monospace,Consolas,monospace;background:#0a0a0a;color:#e0e0e0;margin:2em}}
 h1{{color:#ff3b3b}} h2{{color:#ffb000;border-bottom:1px solid #333;padding-bottom:.3em}}
 table{{border-collapse:collapse;width:100%;margin:1em 0}}
 th,td{{border:1px solid #262626;padding:.4em .6em;font-size:13px;text-align:left;vertical-align:top}}
 th{{background:#141414;color:#fff}}
 tr.crit td{{background:#2a0808}} tr.vuln td{{background:#2a1f08}}
 .kev{{background:#c00;color:#fff;padding:1px 6px;border-radius:3px;font-size:11px;margin-right:4px}}
 .poc{{background:#e07000;color:#000;padding:1px 6px;border-radius:3px;font-size:11px}}
 a{{color:#4ac7ff}} code{{color:#ffb000}}
 .conf{{background:#1a3a1a;color:#7ef07e;padding:1px 5px;border-radius:3px;font-size:11px}}
 ul{{list-style:none;padding:0}} li{{padding:.2em 0}}
 .meta{{color:#888;font-size:12px}}
</style></head><body>
<h1>DevNull Scanner CVE</h1>
<p class="meta">target <b>{report.url}</b> · host {report.host} · scanned {report.scanned_at}</p>
<p class="meta">critical {len(crits)} · vulnerable {len(vlns)} · server {report.server or '-'}</p>
<h2>Detected Stack</h2><ul>{stack}</ul>
<h2>CRITICAL ({len(crits)})</h2>
<table>
<tr><th>#</th><th>tech</th><th>CVE</th><th>CVSS</th><th>detected</th>
<th>affected</th><th>exploit</th><th>flags</th><th>ref</th></tr>
{crit_rows or '<tr><td colspan="9">none</td></tr>'}
</table>
<h2>VULNERABLE ({len(vlns)})</h2>
<table>
<tr><th>#</th><th>tech</th><th>CVE</th><th>CVSS</th><th>detected</th>
<th>affected</th><th>exploit</th><th>flags</th><th>ref</th></tr>
{vuln_rows or '<tr><td colspan="9">none</td></tr>'}
</table>
<p class="meta">DevNull Scanner CVE · made by G33K · scanning only · authorized use only</p>
</body></html>"""

def append_success_log(report, txt_path, json_path):
    c, v, _ = report.counts()
    header_needed = not SUCCESS_FILE.is_file()
    with SUCCESS_FILE.open("a", encoding="utf-8") as fh:
        if header_needed:
            fh.write("=" * 80 + "\n")
            fh.write("  DevNull Scanner CVE :: SUCCESS LOG — confirmed vulns\n")
            fh.write("=" * 80 + "\n")
            fh.write(f"  {'TIMESTAMP':<20} {'C':>3} {'V':>3}  {'URL':<48}\n")
            fh.write("-" * 80 + "\n")
        url_short = report.url if len(report.url) <= 48 else report.url[:45] + "..."
        fh.write(f"  {report.scanned_at:<20} {c:>3} {v:>3}  {url_short}\n")
        for tn, f in report.criticals():
            tag = ("KEV " if f.kev else "") + ("PoC" if f.poc else "")
            fh.write(f"      [C] {f.cve}  CVSS {f.score:>4.1f}  {tn}  "
                     f"detected={f.detected_version}  {f.matched_range}"
                     f"{'  [' + tag.strip() + ']' if tag.strip() else ''}\n")
        for tn, f in report.vulns()[:20]:
            tag = ("KEV " if f.kev else "") + ("PoC" if f.poc else "")
            fh.write(f"      [V] {f.cve}  CVSS {f.score:>4.1f}  {tn}  "
                     f"detected={f.detected_version}  {f.matched_range}"
                     f"{'  [' + tag.strip() + ']' if tag.strip() else ''}\n")
        fh.write(f"      detail: {txt_path}  |  {json_path}\n\n")

# ===========================================================================
#  WEBHOOK
# ===========================================================================

async def notify_webhook(session, url, report, out_lock):
    crits = report.criticals()
    if not crits: return
    lines = [f"DevNull CVE :: {report.host} :: {len(crits)} CRITICAL"]
    for tn, f in crits[:5]:
        tag = ("[KEV] " if f.kev else "") + ("[PoC] " if f.poc else "")
        lines.append(f"  {tag}{f.cve}  CVSS {f.score:.1f}  {tn}  "
                     f"detected={f.detected_version}  affected={f.matched_range}")
    text = "\n".join(lines)
    payload = {"text": text, "content": text}
    try:
        async with session.post(url, json=payload,
                                timeout=aiohttp.ClientTimeout(total=10)) as r:
            async with out_lock:
                if r.status < 300:
                    print(f"      {s_plus()} {p(f'webhook sent ({r.status})', C.GREEN_D)}")
                else:
                    print(f"      {s_bang()} {p(f'webhook {r.status}', C.YELLOW)}")
    except Exception as e:
        async with out_lock:
            print(f"      {s_bang()} {p(f'webhook failed: {e}', C.YELLOW)}")

# ===========================================================================
#  DIFF
# ===========================================================================

def load_previous_findings(host: str) -> set[str]:
    if not FINDINGS_DIR.is_dir(): return set()
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", host)
    matches = sorted(FINDINGS_DIR.glob(f"{safe}_*.json"), reverse=True)
    if not matches: return set()
    try:
        data = json.loads(matches[0].read_text())
        out = set()
        for k in ("critical_findings", "vulnerable_findings"):
            for f in data.get(k, []) or []:
                out.add(f.get("cve",""))
        return out
    except Exception:
        return set()

# ===========================================================================
#  SCOPE
# ===========================================================================

def load_scope(path):
    try:
        data = json.loads(Path(path).read_text())
        return [d.lower() for d in data.get("authorized_domains", [])]
    except Exception as e:
        print(f"  [!] scope load failed: {e}")
        return None

def in_scope(url, scope):
    if not scope: return True
    host = (urlparse(url).hostname or "").lower()
    if not host: return False
    for entry in scope:
        if entry == host: return True
        if entry.startswith("*.") and host.endswith(entry[1:]): return True
        if host.endswith("." + entry): return True
    return False

# ===========================================================================
#  SCAN
# ===========================================================================

async def fetch(session, url, timeout, headers, host_limiter):
    host = urlparse(url).hostname or ""
    await host_limiter.acquire(host)
    try:
        async with session.get(url, timeout=timeout, headers=headers,
                               allow_redirects=True) as r:
            body = await r.text(errors="replace")
            return dict(r.headers), body, str(r.url)
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return {}, "", url


async def scan_one(session, agg, kev, edb, url, timeout, req_headers,
                   out_lock, host_limiter, webhook_url=None, diff_mode=False):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    h, body, final = await fetch(session, url, timeout, req_headers, host_limiter)

    parsed = urlparse(final)
    report = Report(url=final, scanned_at=ts,
                    host=parsed.hostname or "", path=parsed.path or "/")

    async with out_lock:
        print()
        sep_eq(60)
        print(f"TARGET: {p(final, C.CYAN)}")
        sep_eq(60)

        if not h:
            print(f"  {s_bang()} {p('Could not reach host', C.RED)}")
            report.error = "unreachable"; report.status = "UNREACHABLE"
            return report

        print(f"  {s_star()} {p('Fingerprinting tech stack...', C.GRAY)}")
        report.server = h.get("Server") or h.get("server") or ""
        report.techs = detect(h, body, extract_cookies(h))

        if report.server:
            print(f"      {s_plus()} Server: {p(report.server, C.WHITE)}")

        if not report.techs:
            print(f"  {s_bang()} {p('No recognizable technology detected', C.YELLOW)}")
            report.status = "NO-TECH"; return report

        for t in report.techs:
            conf = t.confidence
            conf_col = C.GREEN if conf >= 70 else C.YELLOW if conf >= 40 else C.GRAY
            ver = t.version or "?"
            print(f"      {s_plus()} Detected: "
                  f"{p(t.name, C.WHITE)} {p(str(ver), C.GREEN if t.version else C.YELLOW)} "
                  f"{p(f'conf={conf}%', conf_col)}")

        print(f"  {s_star()} {p(f'Querying NVD + OSV for {len(report.techs)} product(s)...', C.GRAY)}")

    prev_cves = load_previous_findings(report.host) if diff_mode else set()
    new_cves: set[str] = set()

    for i, t in enumerate(report.techs, 1):
        async with out_lock:
            print(f"      {p('Progress:', C.GRAY_DK)} "
                  f"{p(f'{i}/{len(report.techs)}', C.CYAN)} {p(t.name, C.GRAY_DK)}")

        osv_data, nvd_data = [], []
        if t.osv_ecosystem and t.osv_package and t.version:
            report.osv_calls += 1
            osv_data = await agg.osv_get(t)
        if t.cpe_base:
            report.nvd_calls += 1
            nvd_data = await agg.nvd_get(t.cpe_base)

        flagged, info = evaluate(t, osv_data, nvd_data, final, kev, edb)
        report.findings[t.name] = flagged
        report.info[t.name] = info

        async with out_lock:
            if flagged:
                for f in flagged[:3]:
                    tags = ""
                    if f.kev: tags += s_kev() + " "
                    if f.poc: tags += s_poc() + " "
                    print(f"          {p('▶', C.RED, C.BOLD)} {tags}"
                          f"{p(f.cve, C.BOLD, C.RED)} "
                          f"{p(f'(CVSS {f.score:.1f})', C.ORANGE)} "
                          f"{p('on ' + t.name, C.WHITE)}")
                if len(flagged) > 3:
                    print(f"          {p(f'... +{len(flagged)-3} more', C.GRAY_DK)}")
                for cid in [f.cve for f in flagged]:
                    if cid not in prev_cves:
                        new_cves.add(cid)

    c, v, _ = report.counts()
    if c:    report.status = "SUCCESS-CRITICAL"
    elif v:  report.status = "SUCCESS-VULN"
    elif any(not t.version for t in report.techs):
        report.status = "VERSION-UNKNOWN"
    else:
        report.status = "CLEAN"

    if report.has_real_vuln():
        report.saved_paths = save_report(report)

    async with out_lock:
        crits = report.criticals(); vlns = report.vulns()

        if crits:
            print(f"  {s_bang()} {p('CRITICAL FINDINGS:', C.BOLD, C.RED)}")
            for tn, f in crits:
                tags = ""
                if f.kev: tags += s_kev() + " "
                if f.poc: tags += s_poc() + " "
                print(f"      {p('▶', C.RED, C.BOLD)} {tags}"
                      f"{p(f.cve, C.BOLD, C.RED)} "
                      f"{p(f'(CVSS {f.score:.1f})', C.ORANGE)} "
                      f"{p('on ' + tn, C.WHITE)}")
                print(f"        {p('detected :', C.GRAY_DK)} "
                      f"{p(f.detected_version, C.GREEN, C.BOLD)}")
                print(f"        {p('affected :', C.GRAY_DK)} "
                      f"{p(f.matched_range, C.YELLOW, C.BOLD)}")
                print(f"        {p('info     :', C.GRAY_DK)} {p(f.url, C.CYAN_D)}")

        if vlns:
            print(f"  {s_star()} {p('Vulnerable findings:', C.YELLOW, C.BOLD)}")
            for tn, f in vlns:
                tags = ""
                if f.kev: tags += s_kev() + " "
                if f.poc: tags += s_poc() + " "
                print(f"      {p('·', C.YELLOW)} {tags}"
                      f"{p(f.cve, C.YELLOW)} "
                      f"{p(f'(CVSS {f.score:.1f})', C.GRAY)} "
                      f"{p('on ' + tn, C.WHITE)}")
                print(f"        {p('detected :', C.GRAY_DK)} "
                      f"{p(f.detected_version, C.GREEN, C.BOLD)}")
                print(f"        {p('affected :', C.GRAY_DK)} "
                      f"{p(f.matched_range, C.YELLOW, C.BOLD)}")
                print(f"        {p('info     :', C.GRAY_DK)} {p(f.url, C.CYAN_D)}")

        if not crits and not vlns:
            print(f"  {s_plus()} {p('No vulnerabilities matched.', C.GREEN)}")

        print(f"  {s_star()} {p(f'Scanned {len(report.techs)}/{len(report.techs)} products', C.GRAY)}")

        if diff_mode and new_cves:
            print(f"  {s_star()} {p('NEW since last scan:', C.CYAN, C.BOLD)}")
            for cid in sorted(new_cves):
                print(f"      {p('+', C.GREEN, C.BOLD)} {p(cid, C.CYAN)}")

        if report.saved_paths:
            for path in report.saved_paths:
                print(f"      {s_plus()} {p('Saved: ' + path, C.GREEN_D)}")
            print(f"      {s_plus()} {p('Appended: ' + str(SUCCESS_FILE), C.GREEN_D)}")

    if webhook_url and report.criticals():
        await notify_webhook(session, webhook_url, report, out_lock)

    return report

# ===========================================================================
#  ORCHESTRATOR
# ===========================================================================

async def scan_all(targets, api_key, timeout, concurrency,
                   webhook_url=None, diff_mode=False, scope=None):
    req_headers = {
        "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/122.0 Safari/537.36"),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
    }
    connector = aiohttp.TCPConnector(limit=0, ttl_dns_cache=300, ssl=False)
    client_timeout = aiohttp.ClientTimeout(total=timeout, connect=min(4.0, timeout))

    nvd_limiter = RateLimiter(50 if api_key else 5, 30.0)
    host_limiter = HostLimiter(delay=0.3)
    out_lock = asyncio.Lock()

    norm = []
    for t in targets:
        t = t.strip()
        if not t or t.startswith("#"): continue
        if not urlparse(t).scheme: t = "https://" + t
        if scope is not None and not in_scope(t, scope):
            print(f"{s_bang()} {p('out of scope — skipped:', C.YELLOW)} {t}")
            continue
        norm.append(t)

    total = len(norm)
    reports: list[Report] = []
    sem = asyncio.Semaphore(max(1, concurrency))

    print(f"{s_star()} {p('Targets:', C.WHITE, C.BOLD)} {p(str(total), C.CYAN)}  "
          f"{p('|', C.GRAY_DK)}  {p('Threads:', C.WHITE, C.BOLD)} {p(str(concurrency), C.CYAN)}")
    if scope is not None:
        print(f"{s_star()} {p(f'Scope: {len(scope)} domain(s) enforced', C.GRAY_DK)}")
    print()

    async with aiohttp.ClientSession(timeout=client_timeout, connector=connector) as session:
        kev = KevFeed(); edb = ExploitDbFeed()
        await asyncio.gather(kev.load(session, out_lock), edb.load(session, out_lock))
        print()

        agg = CveAggregator(session, nvd_limiter, api_key)

        async def _one(u):
            async with sem:
                rep = await scan_one(session, agg, kev, edb, u, timeout,
                                     req_headers, out_lock, host_limiter,
                                     webhook_url=webhook_url, diff_mode=diff_mode)
                reports.append(rep)

        await asyncio.gather(*(_one(u) for u in norm))

    order = {u: i for i, u in enumerate(norm)}
    reports.sort(key=lambda r: order.get(r.url, 10**9))
    return reports

# ===========================================================================
#  EXEC SUMMARY
# ===========================================================================

def exec_summary(reports, elapsed):
    print()
    sep_eq(60)
    total_nvd = sum(r.nvd_calls for r in reports)
    total_osv = sum(r.osv_calls for r in reports)
    print(f"  {p('SCAN COMPLETE', C.BOLD, C.GREEN)}  "
          f"{p(f'({elapsed:.1f}s)', C.GRAY_DK)}  "
          f"{p(f'· {total_nvd} NVD · {total_osv} OSV live calls', C.GRAY_DK)}")
    sep_eq(60)

    all_f = []
    for r in reports:
        for tn, f in r.criticals() + r.vulns():
            all_f.append((r, tn, f))
    all_f.sort(key=lambda x: x[2].priority, reverse=True)

    print(f"  {p('TOP 5 URGENT FINDINGS', C.BOLD, C.MAGENTA)}")
    sep_thin(60)
    if not all_f:
        print(f"  {s_plus()} {p('no confirmed vulnerabilities across all targets', C.GREEN)}")
    for i, (r, tn, f) in enumerate(all_f[:5], 1):
        tags = ""
        if f.kev: tags += s_kev() + " "
        if f.poc: tags += s_poc() + " "
        pr_col = C.RED if f.priority >= 9 else C.ORANGE if f.priority >= 7 else C.YELLOW
        print(f"  {p(f'{i}.', C.GRAY_DK)} {tags}"
              f"{p(f.cve, C.BOLD, C.RED)}  "
              f"{p(f'CVSS {f.score:.1f}', C.ORANGE)}  "
              f"{p(f'prio {f.priority}', pr_col)}  "
              f"{p(tn, C.WHITE)}  {p(r.host, C.CYAN_D)}")
        print(f"      {p('affected :', C.GRAY_DK)} {p(f.matched_range, C.YELLOW)}")

    print()
    sep_thin(60)
    print(f"  {p('PER-TARGET ROLL-UP', C.BOLD, C.WHITE)}")
    sep_thin(60)
    ranked = sorted(reports, key=lambda r: (r.counts()[0], r.counts()[1]), reverse=True)
    for i, r in enumerate(ranked, 1):
        c, v, _ = r.counts()
        kev_n = sum(1 for _, f in r.criticals() + r.vulns() if f.kev)
        poc_n = sum(1 for _, f in r.criticals() + r.vulns() if f.poc)
        url_short = r.url if len(r.url) <= 38 else r.url[:35] + "..."
        if r.error: marker = p("[!]", C.YELLOW); tint = C.GRAY
        elif c: marker = p("[C]", C.BOLD, C.RED); tint = C.RED
        elif v: marker = p("[V]", C.YELLOW); tint = C.YELLOW
        elif r.status == "VERSION-UNKNOWN": marker = p("[?]", C.CYAN); tint = C.CYAN
        else: marker = p("[+]", C.GREEN); tint = C.GREEN
        flags = ""
        if kev_n: flags += p(f" KEV:{kev_n}", C.RED, C.BOLD)
        if poc_n: flags += p(f" PoC:{poc_n}", C.ORANGE, C.BOLD)
        print(f"  {marker} {p(f'{i:>2}.', C.GRAY_DK)} {p(url_short, tint)} "
              f"{p(f'C:{c} V:{v}', C.GRAY_DK)}{flags}")

    tc = sum(r.counts()[0] for r in reports)
    tv = sum(r.counts()[1] for r in reports)
    tk = sum(1 for r in reports for _, f in r.criticals()+r.vulns() if f.kev)
    tp = sum(1 for r in reports for _, f in r.criticals()+r.vulns() if f.poc)
    sep_thin(60)
    print(f"  {p('TOTAL', C.BOLD, C.WHITE)}  {p(f'{len(reports)} target(s)', C.GRAY)}  "
          f"{p('|', C.GRAY_DK)}  {p(f'CRIT: {tc}', C.RED)}  "
          f"{p(f'VULN: {tv}', C.YELLOW)}  "
          f"{p(f'KEV: {tk}', C.RED, C.BOLD)}  "
          f"{p(f'PoC: {tp}', C.ORANGE, C.BOLD)}")

    saved = [r for r in reports if r.saved_paths]
    if saved:
        print()
        print(f"  {p('SAVED REPORTS:', C.BOLD, C.GREEN)}")
        for r in saved:
            print(f"      {s_plus()} {p(r.url, C.WHITE)}")
            for path in r.saved_paths:
                print(f"          {p('→', C.GREEN)} {p(path, C.GREEN_D)}")
        print(f"      {s_plus()} {p('master log: ' + str(SUCCESS_FILE), C.GREEN_D)}")

    sep_eq(60)
    print(f"  {p('DevNull Scanner CVE · made by G33K · scanning only', C.DIM, C.GRAY)}")
    sep_eq(60)

# ===========================================================================
#  FILTERS
# ===========================================================================

def apply_filters(reports, only_kev=False, only_poc=False,
                  min_cvss=None, cwes=None, exploitable=False):
    cwes = [c.upper() for c in (cwes or [])]
    def keep(f):
        if only_kev and not f.kev: return False
        if only_poc and not f.poc: return False
        if min_cvss is not None and f.score < min_cvss: return False
        if cwes and (f.cwe or "").upper() not in cwes: return False
        if exploitable and f.exploitability != "network · no-auth · no-UI": return False
        return True
    for r in reports:
        for tn in list(r.findings.keys()):
            r.findings[tn] = [f for f in r.findings[tn] if keep(f)]

# ===========================================================================
#  MENU
# ===========================================================================

def prompt_url():
    while True:
        try:
            u = input(p("\n  [>] Enter URL (e.g. https://example.com): ",
                        C.MAGENTA, C.BOLD)).strip()
        except (EOFError, KeyboardInterrupt):
            print(); sys.exit(0)
        if u: return u
        print(p("  [!] URL cannot be empty.", C.RED))

def prompt_file():
    while True:
        try:
            fp = input(p("\n  [>] Enter filename (e.g. example.txt): ",
                         C.MAGENTA, C.BOLD)).strip().strip('"').strip("'")
        except (EOFError, KeyboardInterrupt):
            print(); sys.exit(0)
        if not fp:
            print(p("  [!] Filename cannot be empty.", C.RED)); continue
        path = Path(fp).expanduser()
        if not path.is_file():
            print(p(f"  [!] File not found: {path}", C.RED)); continue
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        targets = [ln.strip() for ln in lines
                   if ln.strip() and not ln.strip().startswith("#")]
        if not targets:
            print(p("  [!] File contains no targets.", C.RED)); continue
        return targets

def menu():
    banner()
    print(f"  {p('SELECT MODE', C.BOLD, C.MAGENTA)}")
    print()
    print(f"    {p('[1]', C.BOLD, C.GREEN)}  {p('Single site', C.WHITE)}")
    print(f"    {p('[2]', C.BOLD, C.GREEN)}  {p('Bulk list from file', C.WHITE)}")
    print(f"    {p('[q]', C.BOLD, C.RED)}  {p('Quit', C.WHITE)}")
    print()
    while True:
        try:
            choice = input(p("  root@DevNull:~# ", C.PURPLE, C.BOLD)).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print(); sys.exit(0)
        if choice in ("q", "quit", "exit"): sys.exit(0)
        if choice in ("1", "2"): return choice
        print(p("  [!] Pick 1, 2, or q.", C.RED))

# ===========================================================================
#  MAIN
# ===========================================================================

def parse_args():
    ap = argparse.ArgumentParser(description="DevNull Scanner CVE.")
    ap.add_argument("--url", default=None)
    ap.add_argument("--file", default=None)
    ap.add_argument("--scope", default=None)
    ap.add_argument("--webhook", default=None)
    ap.add_argument("--api-key", default=None)
    ap.add_argument("--timeout", type=float, default=None)
    ap.add_argument("--concurrency", type=int, default=None)
    ap.add_argument("--diff", action="store_true")
    ap.add_argument("--only-kev", action="store_true")
    ap.add_argument("--only-poc", action="store_true")
    ap.add_argument("--min-cvss", type=float, default=None)
    ap.add_argument("--cwe", default=None)
    ap.add_argument("--exploitable", action="store_true")
    ap.add_argument("--no-color", action="store_true")
    return ap.parse_args()


def main():
    if os.name == "nt":
        os.system("")
    global USE_COLOR
    args = parse_args()
    if args.no_color: USE_COLOR = False

    if args.file:
        path = Path(args.file).expanduser()
        if not path.is_file():
            print(f"[!] file not found: {path}", file=sys.stderr); sys.exit(1)
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        targets = [ln.strip() for ln in lines
                   if ln.strip() and not ln.strip().startswith("#")]
        bulk = True
    elif args.url:
        targets = [args.url]; bulk = False
    else:
        choice = menu()
        if choice == "1":
            targets = [prompt_url()]; bulk = False
        else:
            targets = prompt_file(); bulk = True
            print(f"  {s_plus()} {p(f'Loaded {len(targets)} target(s)', C.GREEN)}")

    scope = None
    if args.scope:
        scope = load_scope(args.scope)
        if scope is None:
            print("[!] scope file required but failed to load. Aborting.", file=sys.stderr)
            sys.exit(1)

    cwes = [c.strip() for c in (args.cwe or "").split(",") if c.strip()]

    api_key = args.api_key or NVD_API_KEY
    concurrency = args.concurrency if args.concurrency else (1 if not bulk else DEFAULT_THREADS)
    timeout = args.timeout if args.timeout else (15.0 if not bulk else 8.0)

    t0 = time.time()
    try:
        reports = asyncio.run(scan_all(
            targets=targets, api_key=api_key, timeout=timeout,
            concurrency=concurrency, webhook_url=args.webhook,
            diff_mode=args.diff, scope=scope,
        ))
    except KeyboardInterrupt:
        print(); print(f"  {s_bang()} {p('interrupted', C.YELLOW)}")
        sys.exit(130)

    if any([args.only_kev, args.only_poc, args.min_cvss, cwes, args.exploitable]):
        apply_filters(reports, only_kev=args.only_kev, only_poc=args.only_poc,
                      min_cvss=args.min_cvss, cwes=cwes, exploitable=args.exploitable)

    elapsed = time.time() - t0
    if bulk:
        exec_summary(reports, elapsed)
    else:
        print()
        sep_eq(60)
        print(f"  {p('DONE', C.BOLD, C.GREEN)}  "
              f"{p(f'({elapsed:.1f}s)', C.GRAY_DK)}  "
              f"{p('· DevNull Scanner CVE · made by G33K', C.DIM, C.GRAY)}")
        sep_eq(60)


if __name__ == "__main__":
    main()