#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ParamWizard - Outil avancé d'extraction de paramètres d'URL
--------------------------------------------------------
Un outil puissant pour extraire, analyser et manipuler les paramètres d'URL
dans les applications web, avec support du multi-threading et de la détection avancée.
"""

import argparse
import requests
import sys
import os
import re
import json
import time
import random
import hashlib
import re
import json
import time
import random
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse, parse_qsl
from collections import defaultdict, deque, OrderedDict, namedtuple
from typing import List, Dict, Set, Tuple, Optional, Any, Union, Generator
from dataclasses import dataclass, field
from enum import Enum, auto
import dns.resolver
import tldextract

# Types personnalisés
class SecurityIssueLevel(Enum):
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()

@dataclass
class SecurityIssue:
    type: str
    level: SecurityIssueLevel
    url: str
    parameter: str = ""
    description: str = ""
    payload: str = ""
    confidence: float = 0.0
    references: List[str] = field(default_factory=list)

@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    parameters: Dict[str, List[str]] = field(default_factory=dict)
    forms: List[Dict] = field(default_factory=list)
    security_issues: List[SecurityIssue] = field(default_factory=list)
    response_code: int = 0
    response_size: int = 0
    content_type: str = ""
    title: str = ""
    technologies: List[str] = field(default_factory=list)

class HTTPMethod(Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    TRACE = "TRACE"

# Gestion des couleurs
class Colors:
    """Codes de couleurs ANSI pour la sortie console"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Configuration globale
VERSION = "2.0.0"
AUTHOR = "Chico Hacker3108"
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
]

class ParamWizard:
    """Classe principale de l'outil ParamWizard"""
    
    # Modèles de vulnérabilités courants
    VULN_PATTERNS = {
        'xss': [
            (r'<script>alert\(1\)</script>', SecurityIssueLevel.HIGH),
            (r'"onmouseover="alert\(1")', SecurityIssueLevel.MEDIUM),
            (r'javascript:alert\(1")', SecurityIssueLevel.HIGH)
        ],
        'sqli': [
            (r'\'\s+OR\s+\d+=\d+--', SecurityIssueLevel.CRITICAL),
            (r'\'\s+OR\s+\d+=\d+;?--', SecurityIssueLevel.CRITICAL),
            (r'\'\s+OR\s+\d+=\d+;?/*', SecurityIssueLevel.CRITICAL)
        ],
        'lfi': [
            (r'(\.\./)+etc/passwd', SecurityIssueLevel.HIGH),
            (r'(\.\./)+windows/win\.ini', SecurityIssueLevel.HIGH)
        ],
        'rce': [
            (r';\s*(?:ls|dir|whoami|id|pwd|ifconfig|ipconfig)\s*;?', SecurityIssueLevel.CRITICAL),
            (r'\|\s*(?:ls|dir|whoami|id|pwd|ifconfig|ipconfig)\s*;?', SecurityIssueLevel.CRITICAL),
            (r'`.*`', SecurityIssueLevel.HIGH)
        ]
    }

    # En-têtes de sécurité courants à vérifier
    SECURITY_HEADERS = [
        'Content-Security-Policy',
        'X-Content-Type-Options',
        'X-Frame-Options',
        'X-XSS-Protection',
        'Strict-Transport-Security',
        'Referrer-Policy',
        'Permissions-Policy'
    ]
    
    def __init__(self, target: str, output_file: str = None, threads: int = 10, 
                 timeout: int = 30, user_agent: str = None, cookies: str = None, 
                 headers: dict = None, proxy: str = None, verify_ssl: bool = False, 
                 check_vulns: bool = True, check_headers: bool = True, 
                 check_apis: bool = True, custom_headers: dict = None):
        """
        Initialise l'outil ParamWizard
        
        Args:
            target: URL cible à analyser
            output_file: Fichier de sortie pour sauvegarder les résultats
            threads: Nombre de threads à utiliser
            timeout: Délai d'expiration des requêtes en secondes
            user_agent: User-Agent personnalisé
            cookies: Cookies à utiliser pour les requêtes
            headers: En-têtes HTTP personnalisés
            proxy: Proxy à utiliser (format: http://host:port)
            verify_ssl: Vérifier les certificats SSL
        """
        self.target = self.normalize_url(target)
        self.output_file = output_file
        self.threads = threads
        self.timeout = timeout
        self.user_agent = user_agent or random.choice(USER_AGENTS)
        self.cookies = self.parse_cookies(cookies) if cookies else {}
        self.headers = headers or {}
        self.proxy = {'http': proxy, 'https': proxy} if proxy else None
        self.verify_ssl = verify_ssl
        self.visited_urls = set()
        self.parameters = defaultdict(set)
        self.endpoints = []
        self.security_issues = []
        self.check_vulns = check_vulns
        self.check_headers = check_headers
        self.check_apis = check_apis
        self.custom_headers = custom_headers or {}
        self.session = self.create_session()
        self.technologies = set()
        self.vulnerability_scans = {
            'xss': False,
            'sqli': False,
            'lfi': False,
            'rce': False,
            'idor': False,
            'ssrf': False
        }
    
    @staticmethod
    def print_banner() -> None:
        """Affiche la bannière d'introduction"""
        banner = f"""
{Colors.GREEN + Colors.BOLD}
  _____                       __        ___      .___  __      __  .__                
  \_   \_ __ __ _ _ __ ___   \ \      / (_) ___|   \ \ \    / /__| |_ __   ___ _ __ 
   / /\/ '__/ _` | '_ ` _ \   \ \ /\ / /| |/ __| |) \ \ \/\/ / _ \ | '_ \ / _ \ '__|
/\/ /_ | | | (_| | | | | | |   \ V  V / | | (__|  __/ \_/\_/  __/ | | | |  __/ |   
\____/ |_|  \__,_|_| |_| |_|    \_/\_/  |_|\___|_|    \_/\_/ \___|_|_| |_|\___|_|   
                                                                                    
{Colors.ENDC}
    {Colors.CYAN}Version: {VERSION}{Colors.ENDC} | {Colors.YELLOW}Created by: {AUTHOR}{Colors.ENDC}
    {Colors.BLUE}Advanced URL Parameter Extractor & Analyzer{Colors.ENDC}
    {Colors.UNDERLINE}https://github.com/yourusername/paramwizard{Colors.ENDC}
"""
        print(banner)
    
    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalise l'URL en ajoutant le schéma si nécessaire"""
        if not url.startswith(('http://', 'https://')):
            return 'http://' + url
        return url
    
    # ============================================
    # Méthodes de détection de vulnérabilités
    # ============================================
    
    def check_security_headers(self, url: str, response_headers: dict) -> List[SecurityIssue]:
        """Vérifie les en-têtes de sécurité manquants ou mal configurés"""
        issues = []
        
        for header in self.SECURITY_HEADERS:
            if header not in response_headers:
                issues.append(SecurityIssue(
                    type="Security Header Missing",
                    level=SecurityIssueLevel.MEDIUM,
                    url=url,
                    description=f"En-tête de sécurité manquant: {header}",
                    references=[
                        "https://owasp.org/www-project-secure-headers/"
                    ]
                ))
        
        # Vérifications spécifiques
        if 'X-Content-Type-Options' in response_headers and \
           'nosniff' not in response_headers['X-Content-Type-Options'].lower():
            issues.append(SecurityIssue(
                type="Insecure X-Content-Type-Options",
                level=SecurityIssueLevel.MEDIUM,
                url=url,
                description="X-Content-Type-Options ne contient pas 'nosniff'",
                references=[
                    "https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/X-Content-Type-Options"
                ]
            ))
            
        return issues
    
    def scan_for_vulnerabilities(self, url: str, param: str, value: str) -> List[SecurityIssue]:
        """Recherche des vulnérabilités dans les paramètres"""
        issues = []
        
        # Vérification XSS
        for pattern, level in self.VULN_PATTERNS['xss']:
            if re.search(pattern, value, re.IGNORECASE):
                issues.append(SecurityIssue(
                    type="Cross-Site Scripting (XSS)",
                    level=level,
                    url=url,
                    parameter=param,
                    payload=value,
                    description=f"Possible vulnérabilité XSS détectée dans le paramètre: {param}",
                    confidence=0.8,
                    references=[
                        "https://owasp.org/www-community/attacks/xss/",
                        "https://portswigger.net/web-security/cross-site-scripting"
                    ]
                ))
        
        # Vérification SQL Injection
        for pattern, level in self.VULN_PATTERNS['sqli']:
            if re.search(pattern, value, re.IGNORECASE):
                issues.append(SecurityIssue(
                    type="SQL Injection",
                    level=level,
                    url=url,
                    parameter=param,
                    payload=value,
                    description=f"Possible injection SQL détectée dans le paramètre: {param}",
                    confidence=0.85,
                    references=[
                        "https://owasp.org/www-community/attacks/SQL_Injection",
                        "https://portswigger.net/web-security/sql-injection"
                    ]
                ))
        
        # Vérification LFI/RFI
        for pattern, level in self.VULN_PATTERNS['lfi']:
            if re.search(pattern, value, re.IGNORECASE):
                issues.append(SecurityIssue(
                    type="Local/Remote File Inclusion",
                    level=level,
                    url=url,
                    parameter=param,
                    payload=value,
                    description=f"Possible inclusion de fichier détectée dans le paramètre: {param}",
                    confidence=0.9,
                    references=[
                        "https://owasp.org/www-community/attacks/Path_Traversal"
                    ]
                ))
        
        # Vérification RCE
        for pattern, level in self.VULN_PATTERNS['rce']:
            if re.search(pattern, value, re.IGNORECASE):
                issues.append(SecurityIssue(
                    type="Remote Code Execution",
                    level=level,
                    url=url,
                    parameter=param,
                    payload=value,
                    description=f"Possible tentative d'exécution de commande dans le paramètre: {param}",
                    confidence=0.95,
                    references=[
                        "https://owasp.org/www-community/attacks/Code_Injection"
                    ]
                ))
        
        return issues
    
    def check_for_idor(self, url: str, params: dict) -> List[SecurityIssue]:
        """Détecte les IDOR (Insecure Direct Object References)"""
        issues = []
        sensitive_params = ['id', 'user', 'account', 'order', 'invoice', 'document', 'file']
        
        for param in params:
            if any(sensitive in param.lower() for sensitive in sensitive_params):
                # Vérifie si la valeur ressemble à un ID
                if any(str(num) in params[param] for num in range(10)):
                    issues.append(SecurityIssue(
                        type="Insecure Direct Object Reference (IDOR)",
                        level=SecurityIssueLevel.HIGH,
                        url=url,
                        parameter=param,
                        description=f"Paramètre potentiellement sensible détecté: {param}",
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References"
                        ]
                    ))
        
        return issues
    
    def analyze_forms(self, url: str, html_content: str) -> List[Dict]:
        """Analyse les formulaires pour les vulnérabilités potentielles"""
        from bs4 import BeautifulSoup
        
        forms = []
        soup = BeautifulSoup(html_content, 'html.parser')
        
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'inputs': []
            }
            
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'type': input_tag.get('type', 'text'),
                    'name': input_tag.get('name', ''),
                    'value': input_tag.get('value', '')
                }
                
                # Détection de champs sensibles
                sensitive_fields = ['password', 'pass', 'pwd', 'creditcard', 'cc', 'cvv', 'ssn']
                if any(field in input_data['name'].lower() for field in sensitive_fields):
                    input_data['sensitive'] = True
                
                form_data['inputs'].append(input_data)
            
            forms.append(form_data)
        
        return forms
    
    def detect_technologies(self, response: requests.Response) -> List[str]:
        """Détecte les technologies utilisées par le site"""
        techs = set()
        headers = response.headers
        
        # Détection via les en-têtes
        if 'server' in headers:
            techs.add(headers['server'])
        
        if 'x-powered-by' in headers:
            techs.add(headers['x-powered-by'])
        
        # Détection via les cookies
        for cookie in response.cookies:
            if cookie.name in ('PHPSESSID', 'ASP.NET_SessionId', 'JSESSIONID'):
                techs.add(cookie.name.split('_')[0])
        
        # Détection via le contenu
        content = response.text.lower()
        if 'jquery' in content:
            techs.add('jQuery')
        if 'react' in content:
            techs.add('React')
        if 'vue' in content:
            techs.add('Vue.js')
        if 'angular' in content:
            techs.add('Angular')
        
        return list(techs)
    
    def create_session(self) -> requests.Session:
        """Crée et configure une session HTTP"""
        session = requests.Session()
        default_headers = {
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            **self.headers,
            **self.custom_headers
        }
        
        session.headers.update(default_headers)
        
        if self.cookies:
            session.cookies.update(self.cookies)
            
        if self.proxy:
            session.proxies.update(self.proxy)
            
        session.verify = self.verify_ssl
        
        return session
    
    def send_request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Envoie une requête HTTP avec gestion des erreurs"""
        try:
            response = self.session.request(method, url, timeout=self.timeout, **kwargs)
            return response
        except requests.exceptions.RequestException as e:
            print(f"{Colors.RED}✗ Erreur lors de la requête vers {url}: {str(e)}{Colors.ENDC}")
            return None
    
    def analyze_response(self, response: requests.Response) -> Dict[str, Any]:
        """Analyse une réponse HTTP pour en extraire des informations utiles"""
        result = {
            'status_code': response.status_code,
            'url': response.url,
            'content_type': response.headers.get('content-type', ''),
            'content_length': len(response.content),
            'headers': dict(response.headers),
            'cookies': [dict(cookie) for cookie in response.cookies],
            'redirect_chain': response.history,
            'elapsed': response.elapsed.total_seconds(),
            'encoding': response.encoding,
            'is_html': 'text/html' in response.headers.get('content-type', '').lower(),
            'is_json': 'application/json' in response.headers.get('content-type', '').lower(),
            'is_xml': 'application/xml' in response.headers.get('content-type', '').lower() or \
                     'text/xml' in response.headers.get('content-type', '').lower(),
            'security_issues': []
        }
        
        # Détection des technologies
        detected_techs = self.detect_technologies(response)
        if detected_techs:
            result['technologies'] = detected_techs
            self.technologies.update(detected_techs)
        
        # Vérification des en-têtes de sécurité
        if self.check_headers:
            security_issues = self.check_security_headers(response.url, response.headers)
            if security_issues:
                result['security_issues'].extend(security_issues)
                self.security_issues.extend(security_issues)
        
        # Analyse du contenu HTML pour les formulaires
        if result['is_html'] and self.check_vulns:
            forms = self.analyze_forms(response.url, response.text)
            if forms:
                result['forms'] = forms
                
                # Vérification des formulaires pour les vulnérabilités
                for form in forms:
                    if form.get('action'):
                        form_url = urljoin(response.url, form['action'])
                        form_method = form.get('method', 'GET').upper()
                        
                        # Vérification IDOR pour les paramètres du formulaire
                        form_params = {}
                        for field in form.get('inputs', []):
                            if field.get('name'):
                                form_params[field['name']] = field.get('value', '')
                        
                        if form_params:
                            idor_issues = self.check_for_idor(form_url, form_params)
                            if idor_issues:
                                result['security_issues'].extend(idor_issues)
                                self.security_issues.extend(idor_issues)
        
        # Détection des API et endpoints
        if self.check_apis:
            api_issues = self.detect_api_endpoints(response)
            if api_issues:
                result['api_endpoints'] = api_issues
        
        return result
    
    def detect_api_endpoints(self, response: requests.Response) -> List[Dict]:
        """Détecte les endpoints d'API dans la réponse"""
        api_endpoints = []
        
        # Détection basée sur les URLs
        api_patterns = [
            r'/api/',
            r'\.json$',
            r'/\.php\?.*=api',
            r'/v\d+/',
            r'/graphql',
            r'/rest/',
            r'/soap/',
            r'/wsdl',
            r'/xmlrpc',
            r'/jsonrpc',
            r'/rpc',
            r'/endpoint',
            r'/service',
            r'/ws/'
        ]
        
        # Vérification des liens dans la réponse
        from bs4 import BeautifulSoup
        import json
        
        # Détection dans le contenu HTML
        if 'text/html' in response.headers.get('content-type', ''):
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Recherche des balises script, link, a, etc.
            for tag in soup.find_all(['script', 'link', 'a', 'form', 'img', 'iframe']):
                url = None
                if tag.name == 'script' and tag.get('src'):
                    url = tag['src']
                elif tag.name == 'link' and tag.get('href'):
                    url = tag['href']
                elif tag.name == 'a' and tag.get('href'):
                    url = tag['href']
                elif tag.name == 'form' and tag.get('action'):
                    url = tag['action']
                elif tag.name in ['img', 'iframe'] and tag.get('src'):
                    url = tag['src']
                
                if url and any(re.search(pattern, url, re.IGNORECASE) for pattern in api_patterns):
                    api_endpoints.append({
                        'url': urljoin(response.url, url),
                        'source': 'html',
                        'tag': tag.name,
                        'attributes': dict(tag.attrs)
                    })
        
        # Détection dans le contenu JSON
        elif 'application/json' in response.headers.get('content-type', ''):
            try:
                data = response.json()
                if isinstance(data, dict):
                    # Recherche récursive d'URLs dans le JSON
                    def find_urls(obj, path=''):
                        urls = []
                        if isinstance(obj, dict):
                            for k, v in obj.items():
                                new_path = f"{path}.{k}" if path else k
                                urls.extend(find_urls(v, new_path))
                        elif isinstance(obj, list):
                            for i, v in enumerate(obj):
                                new_path = f"{path}[{i}]"
                                urls.extend(find_urls(v, new_path))
                        elif isinstance(obj, str) and re.match(r'^https?://', obj):
                            urls.append({
                                'url': obj,
                                'source': 'json',
                                'path': path
                            })
                        return urls
                    
                    urls_in_json = find_urls(data)
                    api_endpoints.extend([
                        url for url in urls_in_json 
                        if any(re.search(pattern, url['url'], re.IGNORECASE) for pattern in api_patterns)
                    ])
            except json.JSONDecodeError:
                pass
        
        return api_endpoints
    
    def parse_cookies(self, cookie_string: str) -> dict:
        """Parse une chaîne de cookies au format name=value"""
        cookies = {}
        for cookie in cookie_string.split(';'):
            if '=' in cookie:
                name, value = cookie.strip().split('=', 1)
                cookies[name] = value
        return cookies
    
    def get_page(self, url: str) -> Optional[requests.Response]:
        """Récupère le contenu d'une page web"""
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                proxies=self.proxy,
                verify=self.verify_ssl,
                allow_redirects=True
            )
            return response
        except requests.RequestException as e:
            print(f"{Colors.RED}[!] Erreur lors de la récupération de {url}: {e}{Colors.ENDC}")
            return None
    
    def extract_links(self, base_url: str, html_content: str) -> Set[str]:
        """Extrait les liens d'une page HTML"""
        from bs4 import BeautifulSoup
        
        soup = BeautifulSoup(html_content, 'html.parser')
        links = set()
        
        for tag in soup.find_all(['a', 'link', 'script', 'img', 'form']):
            url = None
            if tag.name == 'a' and tag.get('href'):
                url = tag['href']
            elif tag.name == 'link' and tag.get('href'):
                url = tag['href']
            elif tag.name == 'script' and tag.get('src'):
                url = tag['src']
            elif tag.name == 'img' and tag.get('src'):
                url = tag['src']
            elif tag.name == 'form' and tag.get('action'):
                url = tag['action']
            
            if url:
                # Nettoyage et normalisation de l'URL
                url = url.split('#')[0].split('?')[0].rstrip('/')
                if url.startswith(('http://', 'https://')):
                    links.add(url)
                elif url.startswith('//'):
                    links.add(f"https:{url}" if 'https:' in base_url else f"http:{url}")
                elif url.startswith('/'):
                    parsed = urlparse(base_url)
                    links.add(f"{parsed.scheme}://{parsed.netloc}{url}")
                else:
                    links.add(f"{base_url.rstrip('/')}/{url}")
        
        return links
    
    def extract_parameters(self, url: str) -> None:
        """Extrait les paramètres d'une URL"""
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            for param in params.keys():
                self.parameters[param].add(url)
    
    def crawl(self, max_depth: int = 3) -> None:
        """Parcourt récursivement le site web"""
        queue = deque([(self.target, 0)])
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            while queue:
                current_url, depth = queue.popleft()
                
                if depth > max_depth or current_url in self.visited_urls:
                    continue
                    
                self.visited_urls.add(current_url)
                print(f"{Colors.CYAN}[*] Analyse de: {current_url}{Colors.ENDC}")
                
                response = self.get_page(current_url)
                if not response or not response.ok:
                    continue
                
                # Extraction des paramètres de l'URL actuelle
                self.extract_parameters(current_url)
                
                # Extraction des liens et soumission des tâches
                if 'text/html' in response.headers.get('Content-Type', ''):
                    links = self.extract_links(current_url, response.text)
                    for link in links:
                        if link not in self.visited_urls and self.target in link:
                            queue.append((link, depth + 1))
    
    def save_results(self) -> None:
        """Sauvegarde les résultats dans un fichier"""
        if not self.output_file:
            return
            
        results = {
            'target': self.target,
            'parameters': {k: list(v) for k, v in self.parameters.items()},
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'version': VERSION
        }
        
        try:
            with open(self.output_file, 'w') as f:
                if self.output_file.endswith('.json'):
                    json.dump(results, f, indent=2)
                else:
                    f.write(f"ParamWizard Scan Results\n")
                    f.write(f"======================\n\n")
                    f.write(f"Target: {self.target}\n")
                    f.write(f"Date: {results['timestamp']}\n")
                    f.write(f"Parameters found: {len(self.parameters)}\n\n")
                    
                    for param, urls in self.parameters.items():
                        f.write(f"\nParameter: {param}\n")
                        f.write("-" * (len(param) + 11) + "\n")
                        for url in urls:
                            f.write(f"- {url}\n")
            
            print(f"{Colors.GREEN}[+] Résultats sauvegardés dans {self.output_file}{Colors.ENDC}")
        except IOError as e:
            print(f"{Colors.RED}[!] Erreur lors de la sauvegarde des résultats: {e}{Colors.ENDC}")
    
    def generate_report(self, format: str = 'text') -> Union[dict, str]:
        """Génère un rapport d'analyse dans le format spécifié"""
        report = {
            'metadata': {
                'tool': 'ParamWizard',
                'version': VERSION,
                'author': AUTHOR,
                'date': time.strftime('%Y-%m-%d %H:%M:%S'),
                'target': self.target,
                'duration_seconds': time.time() - getattr(self, 'start_time', 0),
                'pages_analyzed': len(self.visited_urls),
                'unique_parameters': len(self.parameters),
                'technologies_detected': list(self.technologies),
                'security_issues_found': len(self.security_issues)
            },
            'parameters': {param: list(urls) for param, urls in self.parameters.items()},
            'endpoints': self.endpoints,
            'security_issues': [
                {
                    'type': issue.type,
                    'level': issue.level.name,
                    'url': issue.url,
                    'parameter': issue.parameter,
                    'description': issue.description,
                    'payload': issue.payload,
                    'confidence': issue.confidence,
                    'references': issue.references
                }
                for issue in self.security_issues
            ]
        }
        
        if format.lower() == 'json':
            return json.dumps(report, indent=2, ensure_ascii=False)
        elif format.lower() == 'html':
            return self._generate_html_report(report)
        else:
            return self._generate_text_report(report)
    
    def _generate_html_report(self, report: dict) -> str:
        """Génère un rapport HTML"""
        from jinja2 import Environment, FileSystemLoader, select_autoescape
        import os
        
        # Création d'un environnement Jinja2
        env = Environment(
            loader=FileSystemLoader(os.path.dirname(os.path.abspath(__file__))),
            autoescape=select_autoescape(['html', 'xml'])
        )
        
        # Chargement du template HTML
        template = env.get_template('report_template.html')
        
        # Rendu du template avec les données
        return template.render(
            report=report,
            colors={
                'CRITICAL': '#ff0000',
                'HIGH': '#ff4500',
                'MEDIUM': '#ffa500',
                'LOW': '#ffff00'
            }
        )
    
    def _generate_text_report(self, report: dict) -> str:
        """Génère un rapport texte formaté"""
        output = []
        meta = report['metadata']
        
        # En-tête
        output.append(f"=" * 80)
        output.append(f"ParamWizard - Rapport d'analyse")
        output.append(f"=" * 80)
        output.append(f"Cible: {meta['target']}")
        output.append(f"Date: {meta['date']}")
        output.append(f"Durée: {meta['duration_seconds']:.2f} secondes")
        output.append(f"Pages analysées: {meta['pages_analyzed']}")
        output.append(f"Paramètres uniques trouvés: {meta['unique_parameters']}")
        output.append(f"Technologies détectées: {', '.join(meta['technologies_detected']) or 'Aucune'}")
        output.append(f"Problèmes de sécurité trouvés: {meta['security_issues_found']}")
        
        # Détails des problèmes de sécurité
        if report['security_issues']:
            output.append("\n" + "-" * 40)
            output.append("PROBLÈMES DE SÉCURITÉ")
            output.append("-" * 40)
            
            for i, issue in enumerate(report['security_issues'], 1):
                output.append(f"\n{i}. [{issue['level']}] {issue['type']}")
                output.append(f"   URL: {issue['url']}")
                if issue['parameter']:
                    output.append(f"   Paramètre: {issue['parameter']}")
                if issue['payload']:
                    output.append(f"   Charge utile: {issue['payload']}")
                output.append(f"   Description: {issue['description']}")
                output.append(f"   Confiance: {issue['confidence']*100:.1f}%")
                
                if issue['references']:
                    output.append("   Références:")
                    for ref in issue['references']:
                        output.append(f"     - {ref}")
        
        # Détails des paramètres
        if report['parameters']:
            output.append("\n" + "-" * 40)
            output.append("PARAMÈTRES TROUVÉS")
            output.append("-" * 40)
            
            for param, urls in sorted(report['parameters'].items()):
                output.append(f"\n{Colors.YELLOW}{param}{Colors.ENDC} (trouvé dans {len(urls)} URL{'s' if len(urls) > 1 else ''}):")
                for url in sorted(urls)[:3]:
                    output.append(f"  - {url}")
                if len(urls) > 3:
                    output.append(f"  - ... et {len(urls) - 3} autres")
        
        # Détails des endpoints
        if report['endpoints']:
            output.append("\n" + "-" * 40)
            output.append(f"ENDPOINTS D'API DÉTECTÉS ({len(report['endpoints'])})")
            output.append("-" * 40)
            
            for i, endpoint in enumerate(report['endpoints'], 1):
                output.append(f"\n{i}. {endpoint['url']}")
                output.append(f"   Source: {endpoint.get('source', 'inconnue')}")
                if 'tag' in endpoint:
                    output.append(f"   Balise: {endpoint['tag']}")
        
        return "\n".join(output)
    
    def print_summary(self) -> None:
        """Affiche un résumé de l'analyse"""
        print(self.generate_report('text'))
    
    def save_report(self, filename: str = None, format: str = None) -> bool:
        """Sauvegarde le rapport dans un fichier"""
        if not filename and not self.output_file:
            return False
        
        filename = filename or self.output_file
        
        # Détection du format à partir de l'extension si non spécifié
        if not format:
            if filename.lower().endswith('.json'):
                format = 'json'
            elif filename.lower().endswith('.html'):
                format = 'html'
            else:
                format = 'text'
        
        try:
            report = self.generate_report(format)
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(report)
            
            print(f"{Colors.GREEN}[+] Rapport sauvegardé dans {filename}{Colors.ENDC}")
            return True
        except Exception as e:
            print(f"{Colors.RED}[!] Erreur lors de la sauvegarde du rapport: {e}{Colors.ENDC}")
            return False


def parse_arguments():
    """Parse les arguments en ligne de commande"""
    parser = argparse.ArgumentParser(
        description=f"ParamWizard {VERSION} - Outil avancé d'extraction de paramètres d'URL",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python paramwizard.py https://example.com -o rapport.html
  python paramwizard.py https://example.com -t 20 -d 5 --proxy http://localhost:8080
  python paramwizard.py https://example.com --cookies "session=abc123; token=xyz789"

Pour plus d'informations, consultez la documentation complète sur GitHub.
        """
    )
    
    # Arguments principaux
    parser.add_argument('target', help="URL cible à analyser (ex: https://example.com)")
    
    # Options de sortie
    output_group = parser.add_argument_group('Options de sortie')
    output_group.add_argument('-o', '--output', 
                            help="Fichier de sortie pour sauvegarder les résultats (supporte .json, .html, .txt)")
    output_group.add_argument('--format', choices=['text', 'json', 'html'], 
                            help="Format de sortie (par défaut: déduit de l'extension du fichier ou 'text')")
    output_group.add_argument('--no-color', action='store_true', 
                            help="Désactive les couleurs dans la sortie console")
    
    # Options d'analyse
    scan_group = parser.add_argument_group('Options d\'analyse')
    scan_group.add_argument('-t', '--threads', type=int, default=10, 
                          help="Nombre de threads à utiliser (défaut: 10)")
    scan_group.add_argument('-d', '--depth', type=int, default=3,
                          help="Profondeur maximale de l'analyse (défaut: 3)")
    scan_group.add_argument('--timeout', type=int, default=30,
                          help="Délai d'expiration des requêtes en secondes (défaut: 30)")
    
    # Options de sécurité
    security_group = parser.add_argument_group('Options de sécurité')
    security_group.add_argument('--no-vuln-scan', action='store_false', dest='check_vulns',
                              help="Désactive la détection des vulnérabilités")
    security_group.add_argument('--no-header-check', action='store_false', dest='check_headers',
                              help="Désactive la vérification des en-têtes de sécurité")
    security_group.add_argument('--no-api-detect', action='store_false', dest='check_apis',
                              help="Désactive la détection des API")
    security_group.add_argument('--cookies', 
                              help="Cookies à utiliser (format: name1=value1; name2=value2)")
    security_group.add_argument('--user-agent', 
                              help="User-Agent personnalisé (défaut: navigateur moderne)")
    security_group.add_argument('--proxy', 
                              help="Proxy à utiliser (format: http://host:port ou socks5://host:port)")
    security_group.add_argument('--no-ssl-verify', action='store_false', dest='verify_ssl',
                              help="Ne pas vérifier les certificats SSL")
    
    # Options avancées
    advanced_group = parser.add_argument_group('Options avancées')
    advanced_group.add_argument('--header', action='append', dest='headers',
                              help="Ajouter un en-tête personnalisé (ex: 'X-API-Key: 12345')")
    advanced_group.add_argument('--delay', type=float, default=0,
                              help="Délai en secondes entre les requêtes (pour éviter les limitations de débit)")
    advanced_group.add_argument('--retries', type=int, default=3,
                              help="Nombre de tentatives en cas d'échec (défaut: 3)")
    
    # Informations et débogage
    info_group = parser.add_argument_group('Informations et débogage')
    info_group.add_argument('-v', '--verbose', action='count', default=0,
                          help="Augmente la verbosité (peut être utilisé plusieurs fois)")
    info_group.add_argument('--version', action='version',
                          version=f'ParamWizard {VERSION} par {AUTHOR}')
    
    return parser.parse_args()


def main():
    """Fonction principale"""
    try:
        # Affichage de la bannière
def is_within_domain(url, domain):
    return urlparse(url).netloc.endswith(domain)

def get_links(url, domain, timeout):
    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        links = set()
        for a_tag in soup.find_all('a', href=True):
            href = a_tag.get('href')
            full_url = urljoin(url, href)
            if is_within_domain(full_url, domain):
                links.add(full_url)
        return links
    except requests.RequestException as e:
        print(Fore.RED + f"×͜× Error with {url}: {e}")
        return set()

def extract_parameters(url):
    params = []
    parsed_url = urlparse(url)
    if parsed_url.query:
        params.append(url)
    return params

def crawl_url(url, domain, timeout, verbose):
    if verbose:
        print(Fore.RED + f"➤ [Target] {url}")
    links = get_links(url, domain, timeout)
    params = extract_parameters(url)
    return links, params

def main():
    parser = argparse.ArgumentParser(description="ParamWizard - Extract URLs with Parameters")
    parser.add_argument('-u', '--url', required=True, help="Base URL to start crawling")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose logging")
    parser.add_argument('-t', '--threads', type=int, default=3, help="Number of threads to use for crawling (default: 3)")
    parser.add_argument('--time-sec', type=int, default=30, help="Timeout in seconds for HTTP requests (default: 30)")
    args = parser.parse_args()

    print_banner()

    base_url = ensure_scheme(args.url)
    domain = urlparse(base_url).netloc
    urls_to_process = deque([base_url])
    urls_with_params = set()
    processed_urls = 0

    seen_urls = set() 

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        while urls_to_process or futures:
            while urls_to_process:
                url = urls_to_process.popleft()
                if url not in seen_urls:
                    seen_urls.add(url)
                    future = executor.submit(crawl_url, url, domain, args.time_sec, args.verbose)
                    futures.append(future)

            for future in as_completed(futures):
                links, params = future.result()
                for link in links:
                    if link not in seen_urls:
                        urls_to_process.append(link)
                urls_with_params.update(params)
                processed_urls += 1

                # Write URLs with parameters to file incrementally
                with open('paramwizard.txt', 'a') as f:
                    for param in params:
                        f.write(param + '\n')

                # Log target URLs and errors on separate lines
                if args.verbose:
                    print(Fore.RED + f"➤ [Target] {url}")

            futures = [f for f in futures if not f.done()]

    # Final output
    print(f"\n[+] Number of URLs processed: {processed_urls}")
    print(f"[+] Number of URLs with parameters extracted: {len(urls_with_params)}")
    print(f"[+] Results written to paramwizard.txt")

if __name__ == "__main__":
    main()
