#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DScanner v4.1 — WAF Detector + Parameter Finder + Payload Recommender
Auto-collab dengan external tools (waybackurls, gau, paramspider, ffuf) jika tersedia.
Mode interaktif + CLI support.
"""

import sys
import re
import time
import random
import urllib.parse
import subprocess
import json
import argparse
import os
from typing import Dict, List, Tuple, Optional

# ===== Color =====
try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = '\033[91m'; GREEN = '\033[92m'; YELLOW = '\033[93m'
        BLUE = '\033[94m'; MAGENTA = '\033[95m'; CYAN = '\033[96m'
        WHITE = '\033[97m'; RESET = '\033[0m'; LIGHTBLACK_EX = '\033[90m'
    class Back: RED = '\033[101m'; GREEN = '\033[102m'; YELLOW = '\033[103m'; RESET = '\033[0m'
    class Style:
        BRIGHT = '\033[1m'; DIM = '\033[2m'; NORMAL = '\033[22m'; RESET_ALL = '\033[0m'

# ===== Dependencies =====
try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    print("[!] Install: pip install requests beautifulsoup4")
    sys.exit(1)

# ============================================================
# CONFIG
# ============================================================
CONFIG = {
    "timeout": 10,
    "fuzz_timeout": 3,
    "user_agents": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    ]
}

def get_random_ua():
    return random.choice(CONFIG["user_agents"])

# ============================================================
# EXTERNAL TOOLS INTEGRATION (AUTO DETECT)
# ============================================================
class ExternalTools:
    @staticmethod
    def is_installed(tool: str) -> bool:
        """Cek apakah tool terinstall di system."""
        try:
            # coba 'which' (Linux/macOS) atau 'where' (Windows)
            cmd = "where" if os.name == 'nt' else "which"
            subprocess.run([cmd, tool], capture_output=True, check=True)
            return True
        except:
            return False

    @staticmethod
    def run_tool(tool: str, url: str) -> List[str]:
        """Jalankan external tool dan kembalikan daftar parameter yang ditemukan."""
        params = []
        try:
            if tool == "waybackurls":
                cmd = f"echo {url} | waybackurls 2>/dev/null"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                if result.stdout:
                    for line in result.stdout.splitlines():
                        if '?' in line:
                            qs = line.split('?')[1]
                            for p in urllib.parse.parse_qs(qs).keys():
                                if p not in params:
                                    params.append(p)
            elif tool == "gau":
                cmd = f"gau {url} 2>/dev/null"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                if result.stdout:
                    for line in result.stdout.splitlines():
                        if '?' in line:
                            qs = line.split('?')[1]
                            for p in urllib.parse.parse_qs(qs).keys():
                                if p not in params:
                                    params.append(p)
            elif tool == "paramspider":
                cmd = f"paramspider -d {url} -s 2>/dev/null"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
                domain = url.replace('https://', '').replace('http://', '').replace('/', '_')
                filepath = f"output/{domain}.txt"
                if os.path.exists(filepath):
                    with open(filepath, 'r') as f:
                        for line in f:
                            if '?' in line:
                                qs = line.split('?')[1]
                                for p in urllib.parse.parse_qs(qs).keys():
                                    if p not in params:
                                        params.append(p)
            elif tool == "ffuf":
                wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"
                # fallback ke wordlist bawaan jika tidak ada
                if not os.path.exists(wordlist):
                    wordlist = "/usr/share/wordlists/dirb/common.txt"
                if os.path.exists(wordlist):
                    cmd = f"ffuf -u {url}?FUZZ=test -w {wordlist} -c -t 10 -s 2>/dev/null"
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                    if result.stdout:
                        for line in result.stdout.splitlines():
                            if '|' in line and 'FUZZ' not in line:
                                parts = line.split('|')
                                if len(parts) >= 2:
                                    p = parts[1].strip()
                                    if p and p not in params:
                                        params.append(p)
        except Exception:
            pass
        return params

    @staticmethod
    def get_available_tools() -> List[str]:
        """Kembalikan daftar tools yang terinstall."""
        tools = ['waybackurls', 'gau', 'paramspider', 'ffuf']
        return [t for t in tools if ExternalTools.is_installed(t)]

# ============================================================
# WAF DETECTOR
# ============================================================
class WAFDetector:
    SIGS = {
        'cloudflare': ['cf-ray', 'cf-cache-status', '__cfduid', 'server: cloudflare'],
        'aws_waf': ['x-amzn-requestid', 'aws-waf', 'server: awselb'],
        'modsecurity': ['mod_security', 'modsecurity', 'x-mod-security'],
        'imperva': ['x-iinfo', 'incapsula'],
        'sucuri': ['x-sucuri-id', 'x-sucuri-cache'],
        'akamai': ['x-akamai-transformed'],
        'f5': ['x-aspnet-version', 'f5-fullproxy'],
        'wordfence': ['wordfence', 'wfvt_'],
        'fortinet': ['fortigate', 'fortiweb'],
        'azure': ['x-azure-ref', 'x-azure'],
        'alibaba': ['ali-cdn', 'x-cdn'],
        'barracuda': ['barracuda', 'cuda'],
    }

    @staticmethod
    def detect(url):
        detected = []
        status = 0
        try:
            sess = requests.Session()
            sess.headers.setdefault('User-Agent', get_random_ua())
            resp = sess.get(url, timeout=CONFIG["timeout"], allow_redirects=False)
            status = resp.status_code
            h = str(resp.headers).lower()
            body = resp.text.lower()

            for waf, keys in WAFDetector.SIGS.items():
                for k in keys:
                    if k in h:
                        if waf not in detected:
                            detected.append(waf)
                        break

            if not detected:
                body_sigs = {
                    'cloudflare': ['cloudflare', 'error 1020'],
                    'imperva': ['incapsula', 'imperva'],
                    'sucuri': ['sucuri', 'cloudproxy'],
                    'f5': ['f5', 'big-ip'],
                    'alibaba': ['ali-cdn', 'aliyun'],
                    'akamai': ['akamai', 'ghost'],
                }
                for waf, keys in body_sigs.items():
                    for k in keys:
                        if k in body:
                            detected.append(waf)
                            break

            if not detected and status in [403, 406, 429]:
                detected.append("unknown-waf (blocked)")

            if not detected:
                test_payload = "<script>alert(1)</script>"
                parsed = urllib.parse.urlparse(url)
                qd = urllib.parse.parse_qs(parsed.query)
                qd['test'] = [test_payload]
                new_q = urllib.parse.urlencode(qd, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_q))
                try:
                    test_resp = sess.get(test_url, timeout=CONFIG["fuzz_timeout"], allow_redirects=False)
                    if test_resp.status_code != resp.status_code or abs(len(test_resp.text) - len(resp.text)) > 100:
                        detected.append("possible-waf (behavior change)")
                except:
                    pass
        except Exception:
            pass
        return detected, status

# ============================================================
# PARAMETER SCANNER (INTERNAL + EXTERNAL AUTO)
# ============================================================
class ParamScanner:
    @staticmethod
    def scan(url):
        results = {}
        sess = requests.Session()
        sess.headers.setdefault('User-Agent', get_random_ua())

        # 1. URL
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        for p, vals in qs.items():
            results[p] = {'value': vals[0] if vals else '(empty)', 'source': 'URL'}

        # 2. HTML
        try:
            resp = sess.get(url, timeout=CONFIG["timeout"], allow_redirects=False)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'html.parser')
                for tag in soup.find_all(['input', 'select', 'textarea', 'button']):
                    name = tag.get('name')
                    if name and name.strip():
                        val = tag.get('value') or tag.get('placeholder') or '(no value)'
                        if name not in results:
                            results[name.strip()] = {'value': val, 'source': 'HTML form'}
                for form in soup.find_all('form'):
                    action = form.get('action')
                    if action and '?' in action:
                        qs = action.split('?')[1]
                        for p, vals in urllib.parse.parse_qs(qs).items():
                            if p not in results:
                                results[p] = {'value': vals[0] if vals else '(empty)', 'source': 'HTML form action'}
        except:
            pass

        # 3. JS
        try:
            resp = sess.get(url, timeout=CONFIG["timeout"], allow_redirects=False)
            if resp.status_code == 200:
                text = resp.text
                patterns = [
                    (r'fetch\s*\([^,]+,\s*\{[^}]*body\s*:\s*JSON\.stringify\(\s*\{([^}]+)\}\s*\)', 'fetch'),
                    (r'data\s*:\s*\{([^}]+)\}', 'ajax'),
                    (r'axios\.[a-z]+\([^,]+,\s*\{([^}]+)\}', 'axios'),
                    (r'["\']([^"\']*\?[^"\']+)["\']', 'url'),
                    (r'formData\.append\s*\(\s*["\']([^"\']+)["\']', 'formdata'),
                ]
                for pattern, src in patterns:
                    matches = re.findall(pattern, text, re.IGNORECASE | re.DOTALL)
                    for m in matches:
                        if isinstance(m, str):
                            if '?' in m:
                                qs = m.split('?')[1]
                                for p, vals in urllib.parse.parse_qs(qs).items():
                                    if p not in results:
                                        results[p] = {'value': vals[0] if vals else '(empty)', 'source': f'JS ({src})'}
                        else:
                            keys = re.findall(r'["\']?(\w+)["\']?\s*:', m)
                            for k in keys:
                                if k and k not in results:
                                    results[k] = {'value': '(from JS)', 'source': f'JS ({src})'}
        except:
            pass

        # 4. External tools (AUTO COLLAB — detect dan jalankan jika ada)
        available_tools = ExternalTools.get_available_tools()
        if available_tools:
            for tool in available_tools:
                try:
                    ext_params = ExternalTools.run_tool(tool, url)
                    for p in ext_params:
                        if p not in results:
                            results[p] = {'value': f'(from {tool})', 'source': f'External ({tool})'}
                except:
                    pass

        # 5. Fuzzing fallback (jika masih kosong)
        if not results:
            common = ['q', 'id', 'search', 'page', 'sort', 'filter', 'user', 'type', 'mode', 'view', 'action', 'format', 'lang']
            try:
                baseline = sess.get(url, timeout=CONFIG["fuzz_timeout"], allow_redirects=False)
                base_len = len(baseline.text)
                base_status = baseline.status_code
                for p in common:
                    test_url = f"{url}{'&' if '?' in url else '?'}{p}=test"
                    try:
                        resp = sess.get(test_url, timeout=CONFIG["fuzz_timeout"], allow_redirects=False)
                        if abs(len(resp.text) - base_len) > 30 or resp.status_code != base_status:
                            results[p] = {'value': 'test (fuzzing)', 'source': 'Fuzzing'}
                        time.sleep(0.05)
                    except:
                        continue
            except:
                pass

        # Clean amp;
        cleaned = {}
        for k, v in results.items():
            clean = k.replace('amp;', '')
            if clean in cleaned and v['source'] != 'Fuzzing':
                continue
            cleaned[clean] = v
        return cleaned

# ============================================================
# RECOMMENDER
# ============================================================
class Recommender:
    @staticmethod
    def suggest(param: str) -> List[str]:
        p = param.lower()
        types = []
        if any(k in p for k in ['id', 'page', 'user', 'username', 'email']):
            types.append('SQLi'); types.append('IDOR')
        if any(k in p for k in ['q', 'search', 'cari', 'query', 'keyword']):
            types.append('XSS'); types.append('SQLi')
        if any(k in p for k in ['file', 'path', 'dir', 'document', 'filename']):
            types.append('LFI'); types.append('Path Traversal')
        if any(k in p for k in ['url', 'redirect', 'next', 'return', 'callback']):
            types.append('SSRF'); types.append('Open Redirect')
        if any(k in p for k in ['cmd', 'command', 'exec', 'ip', 'host']):
            types.append('Command Injection')
        if any(k in p for k in ['role', 'admin', 'permission', 'is_admin', 'authenticated']):
            types.append('Mass Assignment'); types.append('Privilege Escalation')
        if any(k in p for k in ['xml', 'data', 'document', 'payload']):
            types.append('XXE')
        if any(k in p for k in ['jndi', 'ldap', 'rmi']):
            types.append('Log4j')
        if not types:
            types.append('SQLi'); types.append('XSS')
        return sorted(types)

# ============================================================
# DSCANNER ENGINE
# ============================================================
class DScanner:
    def __init__(self, url, output_json=False):
        self.url = url
        self.output_json = output_json
        self.waf = []
        self.params = {}
        self.status = 0
        self.external_used = []

    def scan(self):
        print(f"\n  {Fore.CYAN}╔══════════════════════════════════════════════════════════╗{Fore.RESET}")
        print(f"  {Fore.CYAN}║  {Fore.WHITE}🔍 SCANNING TARGET{Fore.CYAN}                                      ║{Fore.RESET}")
        print(f"  {Fore.CYAN}╚══════════════════════════════════════════════════════════╝{Fore.RESET}")
        print(f"  {Fore.LIGHTBLACK_EX}URL: {self.url}{Fore.RESET}\n")

        # WAF
        print(f"  {Fore.CYAN}┌── WAF DETECTION ───────────────────────────────────────────┐{Fore.RESET}")
        sys.stdout.write("  │ Scanning WAF")
        sys.stdout.flush()
        time.sleep(0.3)
        self.waf, self.status = WAFDetector.detect(self.url)
        print("\r  │ Scanning WAF... Done!        ")
        if self.waf:
            print(f"  │ {Fore.GREEN}✔ WAF detected: {Fore.WHITE}{', '.join(self.waf)}{Fore.RESET}")
        else:
            print(f"  │ {Fore.YELLOW}─ WAF not detected{Fore.RESET}")
        print(f"  │ {Fore.LIGHTBLACK_EX}HTTP Status: {self.status}{Fore.RESET}")
        print(f"  {Fore.CYAN}└──────────────────────────────────────────────────────────────┘{Fore.RESET}\n")

        # External tools info
        available = ExternalTools.get_available_tools()
        if available:
            print(f"  {Fore.CYAN}┌── EXTERNAL TOOLS (AUTO-DETECTED) ──────────────────────┐{Fore.RESET}")
            print(f"  │ {Fore.GREEN}✔ Found: {', '.join(available)}{Fore.RESET}")
            print(f"  │ {Fore.LIGHTBLACK_EX}→ Will be used for parameter discovery{Fore.RESET}")
            print(f"  {Fore.CYAN}└──────────────────────────────────────────────────────────────┘{Fore.RESET}\n")

        # Parameters
        print(f"  {Fore.CYAN}┌── PARAMETER DISCOVERY ──────────────────────────────────────┐{Fore.RESET}")
        sys.stdout.write("  │ Scanning parameters")
        sys.stdout.flush()
        time.sleep(0.3)
        self.params = ParamScanner.scan(self.url)
        print("\r  │ Scanning parameters... Done! ")
        if self.params:
            # Hitung sumber parameter
            sources = {}
            for info in self.params.values():
                src = info.get('source', 'unknown')
                sources[src] = sources.get(src, 0) + 1
            source_str = ", ".join([f"{k}: {v}" for k, v in sources.items()])
            print(f"  │ {Fore.GREEN}✔ Found {len(self.params)} parameter(s) ({source_str}){Fore.RESET}")
            for idx, (p, info) in enumerate(self.params.items(), 1):
                val = info.get('value', '')
                src = info.get('source', '')
                display = val[:40] + '...' if len(str(val)) > 40 else val
                progress = f"[{Fore.CYAN}{idx:02d}/{len(self.params):02d}{Fore.RESET}]"
                print(f"  │ {Fore.MAGENTA}MUTATE{Fore.RESET}] {Fore.YELLOW}Bypass{Fore.RESET} {Fore.CYAN}{p}{Fore.RESET} {progress} {Fore.GREEN}[PASSED]{Fore.RESET}")
                print(f"  │   {Fore.LIGHTBLACK_EX}→ {p} = \"{display}\" ({src}){Fore.RESET}")
        else:
            print(f"  │ {Fore.YELLOW}─ No parameters found{Fore.RESET}")
        print(f"  {Fore.CYAN}└──────────────────────────────────────────────────────────────┘{Fore.RESET}\n")

        # Recommendations
        print(f"  {Fore.CYAN}┌── PAYLOAD RECOMMENDATION ──────────────────────────────────┐{Fore.RESET}")
        if not self.params:
            print(f"  │ {Fore.YELLOW}─ No parameters to recommend{Fore.RESET}")
        else:
            for idx, (p, info) in enumerate(self.params.items(), 1):
                types = Recommender.suggest(p)
                progress = f"[{Fore.CYAN}{idx:02d}/{len(self.params):02d}{Fore.RESET}]"
                type_colors = {
                    'SQLi': Fore.GREEN, 'XSS': Fore.RED, 'LFI': Fore.YELLOW,
                    'Path Traversal': Fore.MAGENTA, 'SSRF': Fore.CYAN,
                    'Open Redirect': Fore.BLUE, 'Command Injection': Fore.RED,
                    'Mass Assignment': Fore.YELLOW, 'Privilege Escalation': Fore.MAGENTA,
                    'XXE': Fore.GREEN, 'Log4j': Fore.RED, 'IDOR': Fore.CYAN,
                }
                colored = [f"{type_colors.get(t, Fore.WHITE)}{t}{Fore.RESET}" for t in types]
                print(f"  │ {Fore.MAGENTA}MUTATE{Fore.RESET}] {Fore.YELLOW}Bypass{Fore.RESET} {Fore.CYAN}{p}{Fore.RESET} {progress} {Fore.GREEN}[PASSED]{Fore.RESET}")
                print(f"  │   {Fore.LIGHTBLACK_EX}→ Suitable for: {Fore.GREEN}[{Fore.RESET}{', '.join(colored)}{Fore.GREEN}]{Fore.RESET}")
        print(f"  {Fore.CYAN}└──────────────────────────────────────────────────────────────┘{Fore.RESET}\n")

        # Summary
        print(f"  {Fore.CYAN}┌── SUMMARY ───────────────────────────────────────────────────┐{Fore.RESET}")
        print(f"  │ {Fore.LIGHTBLACK_EX}URL{Fore.RESET}          : {self.url}")
        print(f"  │ {Fore.LIGHTBLACK_EX}Status{Fore.RESET}       : {self.status}")
        print(f"  │ {Fore.LIGHTBLACK_EX}WAF{Fore.RESET}          : {', '.join(self.waf) if self.waf else 'None'}")
        print(f"  │ {Fore.LIGHTBLACK_EX}Parameters{Fore.RESET}   : {len(self.params)}")
        if available:
            print(f"  │ {Fore.LIGHTBLACK_EX}External Tools{Fore.RESET}: {', '.join(available)}")
        print(f"  {Fore.CYAN}└──────────────────────────────────────────────────────────────┘{Fore.RESET}")

        if self.output_json:
            self._output_json()

        return self

    def _output_json(self):
        data = {
            "url": self.url,
            "status": self.status,
            "waf": self.waf,
            "parameters": self.params,
            "external_tools_used": ExternalTools.get_available_tools()
        }
        print("\n" + json.dumps(data, indent=2))

# ============================================================
# MAIN — CLI + Interactive
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="DScanner V1.0 — Auto-collab WAF Detector + Parameter Finder + Payload Recommender",
        epilog="Example: python dscanner.py -u https://example.com\n       python dscanner.py --help"
    )
    parser.add_argument("-u", "--url", help="Target URL (optional, will prompt if not provided)")
    parser.add_argument("--json", action="store_true", help="Output result in JSON format")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--waf-only", action="store_true", help="Only detect WAF (skip parameter discovery)")
    parser.add_argument("--params-only", action="store_true", help="Only discover parameters (skip WAF detection)")
    args = parser.parse_args()

    # Disable color if requested
    if args.no_color:
        global Fore, Back, Style
        Fore.RED = Fore.GREEN = Fore.YELLOW = Fore.BLUE = Fore.MAGENTA = Fore.CYAN = Fore.WHITE = Fore.LIGHTBLACK_EX = Fore.RESET = ''
        Back.RED = Back.GREEN = Back.YELLOW = Back.BLUE = Back.MAGENTA = Back.CYAN = Back.WHITE = Back.RESET = ''
        Style.BRIGHT = Style.DIM = Style.NORMAL = Style.RESET_ALL = ''

    # Banner
    if not args.json:
        print(f"""
{Fore.CYAN}  ╔══════════════════════════════════════════════════════════════╗
  ║  {Fore.RED}██████╗ {Fore.BLUE}███████╗{Fore.BLUE} ██████╗{Fore.BLUE} █████╗ {Fore.BLUE}███╗   ██╗{Fore.CYAN}███╗   ██╗███████╗██████╗ {Fore.CYAN}
  ║  {Fore.RED}██╔══██╗{Fore.BLUE}██╔════╝{Fore.BLUE}██╔════╝{Fore.BLUE}██╔══██╗{Fore.BLUE}████╗  ██║{Fore.CYAN}████╗  ██║██╔════╝██╔══██╗{Fore.CYAN}
  ║  {Fore.RED}██║  ██║{Fore.BLUE}███████╗{Fore.BLUE}██║     {Fore.BLUE}███████║{Fore.BLUE}██╔██╗ ██║{Fore.CYAN}██╔██╗ ██║█████╗  ██████╔╝{Fore.CYAN}
  ║  {Fore.RED}██║  ██║{Fore.BLUE}╚════██║{Fore.BLUE}██║     {Fore.BLUE}██╔══██║{Fore.BLUE}██║╚██╗██║{Fore.CYAN}██║╚██╗██║██╔══╝  ██╔══██╗{Fore.CYAN}
  ║  {Fore.RED}██████╔╝{Fore.BLUE}███████║{Fore.BLUE}╚██████╗{Fore.BLUE}██║  ██║{Fore.BLUE}██║ ╚████║{Fore.CYAN}██║ ╚████║███████╗██║  ██║{Fore.CYAN}
  ║  {Fore.RED}╚═════╝ {Fore.BLUE}╚══════╝{Fore.BLUE} ╚═════╝{Fore.BLUE}╚═╝  ╚═╝{Fore.BLUE}╚═╝  ╚═══╝{Fore.CYAN}╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝{Fore.CYAN}
  ║  {Fore.WHITE}🔍 WAF Detector + Parameter Finder + Payload Recommender{Fore.CYAN}
  ║  {Fore.YELLOW}📡 v1.0 — Auto Collab + CLI — by Dka{Fore.CYAN}                 
  ║  {Fore.LIGHTBLACK_EX}⚡ Auto-detects waybackurls, gau, paramspider, ffuf if installed{Fore.CYAN}
  ╚══════════════════════════════════════════════════════════════╝{Fore.RESET}
""")

    # Get URL from args or interactive
    url = args.url
    if not url:
        url = input(f"\n  {Fore.YELLOW}[?] Target URL:{Fore.RESET} ").strip()
        if not url:
            print(f"  {Fore.RED}[!] URL required.{Fore.RESET}")
            sys.exit(1)

    # Jika waf-only atau params-only, kita bisa shortcut
    if args.waf_only:
        waf, status = WAFDetector.detect(url)
        print(f"\n  {Fore.CYAN}WAF DETECTION (only){Fore.RESET}")
        print(f"  URL: {url}")
        print(f"  Status: {status}")
        print(f"  WAF: {', '.join(waf) if waf else 'None'}")
        return

    if args.params_only:
        params = ParamScanner.scan(url)
        print(f"\n  {Fore.CYAN}PARAMETER DISCOVERY (only){Fore.RESET}")
        print(f"  URL: {url}")
        print(f"  Parameters found: {len(params)}")
        for p, info in params.items():
            print(f"    {p} = {info.get('value', '')} ({info.get('source', 'unknown')})")
        return

    # Full scan
    scanner = DScanner(url, output_json=args.json)
    scanner.scan()

    if not args.json:
        print(f"\n  {Fore.GREEN}✅ Done.{Fore.RESET}")
        print(f"  {Fore.LIGHTBLACK_EX}──────────────────────────────────────────────────────────────────{Fore.RESET}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n  {Fore.YELLOW}[!] Interrupted.{Fore.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n  {Fore.RED}[!] Error: {e}{Fore.RESET}")
        sys.exit(1)