#!/usr/bin/env python3


import requests
import urllib.parse
import re
import time
import random
import subprocess
from colorama import Fore, Style
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import hashlib

class OWASPScanner:
    def __init__(self, target, timeout=8):
        self.target = target
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })
        self.vulnerabilities = []
        self.cve_results = {}
        
        self.sql_payloads = [
            "'", "\"", "';", "')", "'))",
            "' OR 1=1--", "' OR '1'='1",
            "admin'--", "admin' #",
            "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "1' AND 1=1", "1' AND 1=2"
        ]
        
        self.xss_payloads = [
            "v0marker<", "v0marker\"", "v0marker'",
            "<script>confirm(1)</script>",
            "<img src=x onerror=confirm(1)>",
            "javascript:confirm(1)"
        ]
        
        self.ssrf_payloads = [
            "http://127.0.0.1:80", "http://localhost:22",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd", "file:///etc/hosts"
        ]
        
        # Default credentials for auth testing
        self.default_creds = [
            ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
            ("admin", "admin123"), ("root", "root"), ("admin", ""),
            ("administrator", "administrator"), ("user", "user"),
            ("test", "test"), ("guest", "guest")
        ]

    def is_web_service(self, port):
        """Check if the service on given port is HTTP/HTTPS"""
        web_ports = [80, 443, 8080, 8443, 8000, 3000, 5000, 9000, 8888, 9090]
        return port in web_ports

    def build_target_url(self, port, path=""):
        """Build target URL based on port and path"""
        protocol = "https" if port == 443 or port == 8443 else "http"
        if port in [80, 443]:
            return f"{protocol}://{self.target}{path}"
        else:
            return f"{protocol}://{self.target}:{port}{path}"

    def test_sql_injection(self, base_url):
        """Refactored for stealth, early-stop, and no CLI noise"""
        vulnerabilities = []
        test_params = ['id', 'user', 'search', 'q', 'page', 'cat', 'username', 'login']
        
        sql_errors = [
            r"mysql_fetch_array", r"MySQL server version", r"PostgreSQL.*ERROR",
            r"Microsoft.*ODBC.*SQL Server", r"Oracle error", r"syntax error"
        ]
        
        for param in test_params:
            detected_count = 0
            for payload in self.sql_payloads:
                try:
                    test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                    start_time = time.time()
                    response = self.session.get(test_url, timeout=self.timeout)
                    response_time = time.time() - start_time
                    
                    is_vuln = False
                    # Indicator: SQL error
                    for pattern in sql_errors:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            is_vuln = True
                            break
                    
                    # Indicator: Time-based
                    if not is_vuln and ('SLEEP' in payload or 'WAITFOR' in payload):
                        if response_time > 4:
                            is_vuln = True
                            
                    if is_vuln:
                        detected_count += 1
                        if detected_count >= 2:
                            vulnerabilities.append({
                                'type': 'SQL Injection',
                                'severity': 'HIGH',
                                'parameter': param,
                                'confidence': 'High',
                                'remediation': 'Use parameterized queries and input validation.'
                            })
                            break # Move to next parameter
                except:
                    continue
        return vulnerabilities

    def test_xss(self, base_url):
        """Refactored for reflection detection and early-stop"""
        vulnerabilities = []
        test_params = ['q', 'search', 'name', 'comment', 'message', 'input', 'data']
        
        for param in test_params:
            detected_count = 0
            for payload in self.xss_payloads:
                try:
                    test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                    response = self.session.get(test_url, timeout=self.timeout)
                    if payload in response.text:
                        detected_count += 1
                        if detected_count >= 2:
                            vulnerabilities.append({
                                'type': 'Reflected Input (Potential XSS)',
                                'severity': 'MEDIUM',
                                'parameter': param,
                                'confidence': 'Medium',
                                'remediation': 'Implement input validation and output encoding.'
                            })
                            break
                except:
                    continue
        return vulnerabilities

    def test_ssrf(self, base_url):
        """Refactored for behavior-based detection ONLY"""
        vulnerabilities = []
        ssrf_params = ['url', 'link', 'src', 'source', 'target', 'redirect', 'proxy']
        
        for param in ssrf_params:
            detected_count = 0
            for payload in self.ssrf_payloads:
                try:
                    test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                    start_time = time.time()
                    try:
                        response = self.session.get(test_url, timeout=2) # Shorter timeout for SSRF check
                        duration = time.time() - start_time
                    except requests.exceptions.Timeout:
                        duration = 2
                    
                    # Indicator: Significant delay or timeout
                    if duration >= 2:
                        detected_count += 1
                        if detected_count >= 2:
                            vulnerabilities.append({
                                'type': 'Server-Side Request Forgery (SSRF)',
                                'severity': 'HIGH',
                                'parameter': param,
                                'confidence': 'Medium',
                                'remediation': 'Validate and whitelist URLs. Use network segmentation.'
                            })
                            break
                except:
                    continue
            if vulnerabilities: break # Group SSRF into ONE finding maximum
        return vulnerabilities

    def test_security_misconfig(self, base_url):
        """WORKING security misconfiguration test"""
        print(f"{Fore.BLUE}[*] Testing Security Misconfigurations on {base_url}...{Style.RESET_ALL}")
        vulnerabilities = []
        
        try:
            # Test dangerous HTTP methods
            dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'OPTIONS']
            for method in dangerous_methods:
                try:
                    response = self.session.request(method, base_url, timeout=self.timeout)
                    if response.status_code not in [405, 501, 404]:
                        severity = 'HIGH' if method in ['PUT', 'DELETE'] else 'MEDIUM'
                        vuln = {
                            'type': 'Security Misconfiguration',
                            'severity': severity,
                            'url': base_url,
                            'parameter': 'HTTP Method',
                            'payload': method,
                            'evidence': f'{method} method allowed (Status: {response.status_code})',
                            'remediation': f'Disable {method} method if not required.'
                        }
                        vulnerabilities.append(vuln)
                        print(f"{Fore.YELLOW}[!] Dangerous method allowed: {method}{Style.RESET_ALL}")
                except:
                    pass
            
            # Test security headers
            response = self.session.get(base_url, timeout=self.timeout)
            missing_headers = []
            
            security_headers = {
                'X-Frame-Options': 'MEDIUM',
                'Content-Security-Policy': 'HIGH',
                'X-Content-Type-Options': 'LOW',
                'Strict-Transport-Security': 'MEDIUM'
            }
            
            for header, severity in security_headers.items():
                if header not in response.headers:
                    missing_headers.append(header)
                    vuln = {
                        'type': 'Security Misconfiguration',
                        'severity': severity,
                        'url': base_url,
                        'parameter': 'HTTP Headers',
                        'payload': header,
                        'evidence': f'{header} header missing',
                        'remediation': f'Add {header} security header.'
                    }
                    vulnerabilities.append(vuln)
            
            if missing_headers:
                print(f"{Fore.YELLOW}[!] Missing security headers: {', '.join(missing_headers)}{Style.RESET_ALL}")
            
            # Test sensitive paths
            sensitive_paths = [
                '/.env', '/.git/', '/admin/', '/backup/', '/config/',
                '/phpinfo.php', '/server-info', '/.htaccess'
            ]
            
            for path in sensitive_paths:
                try:
                    test_response = self.session.get(base_url + path, timeout=self.timeout)
                    if test_response.status_code == 200:
                        vuln = {
                            'type': 'Sensitive File Exposure',
                            'severity': 'MEDIUM',
                            'url': base_url + path,
                            'parameter': 'File Access',
                            'payload': path,
                            'evidence': f'Sensitive file accessible: {path}',
                            'remediation': f'Restrict access to {path}.'
                        }
                        vulnerabilities.append(vuln)
                        print(f"{Fore.YELLOW}[!] Sensitive file exposed: {path}{Style.RESET_ALL}")
                except:
                    pass
        
        except Exception as e:
            pass
        
        return vulnerabilities

    def test_weak_authentication(self, base_url):
        """WORKING authentication test"""
        print(f"{Fore.BLUE}[*] Testing Weak Authentication on {base_url}...{Style.RESET_ALL}")
        vulnerabilities = []
        
        # Login paths to test
        login_paths = ['/login', '/admin', '/administrator', '/admin/login', '/login.php']
        
        for path in login_paths:
            try:
                login_url = base_url + path
                response = self.session.get(login_url, timeout=self.timeout)
                
                if response.status_code == 200 and any(keyword in response.text.lower() 
                                                     for keyword in ['login', 'password', 'username']):
                    
                    # Test default credentials
                    for username, password in self.default_creds[:5]:  # Test top 5
                        try:
                            login_data = {
                                'username': username, 'password': password,
                                'user': username, 'pass': password
                            }
                            
                            login_response = self.session.post(login_url, data=login_data, timeout=self.timeout)
                            
                            # Check for successful login indicators
                            success_indicators = ['dashboard', 'welcome', 'logout', 'admin panel']
                            if any(indicator in login_response.text.lower() for indicator in success_indicators):
                                vuln = {
                                    'type': 'Weak Authentication',
                                    'severity': 'HIGH',
                                    'url': login_url,
                                    'parameter': 'Credentials',
                                    'payload': f'{username}:{password}',
                                    'evidence': f'Default credentials work: {username}/{password}',
                                    'remediation': 'Change default credentials and implement strong password policy.'
                                }
                                vulnerabilities.append(vuln)
                                print(f"{Fore.RED}[!] Weak credentials: {username}:{password}{Style.RESET_ALL}")
                                return vulnerabilities  # Found one, that's enough
                            
                            time.sleep(0.5)  # Rate limiting
                            
                        except:
                            continue
            except:
                continue
        
        return vulnerabilities

    def run_owasp_scan(self, port):
        """WORKING OWASP scan - simplified but effective"""
        if not self.is_web_service(port):
            return []
        
        base_url = self.build_target_url(port)
        print(f"{Fore.CYAN}[*] Starting OWASP scan on {base_url}{Style.RESET_ALL}")
        
        # Quick connectivity test
        try:
            response = self.session.get(base_url, timeout=self.timeout)
            print(f"{Fore.GREEN}[+] Target responding: {response.status_code}{Style.RESET_ALL}")
        except requests.RequestException as e:
            print(f"{Fore.RED}[!] Cannot connect to {base_url}: {str(e)}{Style.RESET_ALL}")
            return []
        
        all_vulnerabilities = []
        
        # Run all OWASP tests
        test_functions = [
            ('SQL Injection', self.test_sql_injection),
            ('Cross-Site Scripting', self.test_xss),
            ('SSRF', self.test_ssrf),
            ('Security Misconfiguration', self.test_security_misconfig),
            ('Weak Authentication', self.test_weak_authentication)
        ]
        
        for test_name, test_func in test_functions:
            try:
                print(f"{Fore.BLUE}[*] Running {test_name} test...{Style.RESET_ALL}")
                vulnerabilities = test_func(base_url)
                all_vulnerabilities.extend(vulnerabilities)
                print(f"{Fore.GREEN}[+] {test_name} completed: {len(vulnerabilities)} vulnerabilities found{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[!] Error in {test_name}: {str(e)}{Style.RESET_ALL}")
        
        print(f"{Fore.CYAN}[*] OWASP scan completed: {len(all_vulnerabilities)} total vulnerabilities{Style.RESET_ALL}")
        return all_vulnerabilities

def get_exploit_info(cve_id):
    """WORKING exploit information with proper display"""
    exploits = []
    
    print(f"{Fore.BLUE}[*] Searching exploits for {cve_id}...{Style.RESET_ALL}")
    
    try:
        # Method 1: Try searchsploit with JSON
        result = subprocess.run(['searchsploit', '--cve', cve_id, '--json'], 
                              capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0 and result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                if 'RESULTS_EXPLOIT' in data and data['RESULTS_EXPLOIT']:
                    for exploit in data['RESULTS_EXPLOIT'][:5]:
                        exploit_info = {
                            'name': exploit.get('Title', 'Unknown'),
                            'path': exploit.get('Path', ''),
                            'type': exploit.get('Type', 'Unknown'),
                            'platform': exploit.get('Platform', 'Unknown'),
                            'date': exploit.get('Date', 'Unknown')
                        }
                        exploits.append(exploit_info)
                        print(f"{Fore.GREEN}  [+] {exploit_info['name'][:60]}...{Style.RESET_ALL}")
            except json.JSONDecodeError:
                pass
        
        # Method 2: Fallback to text output
        if not exploits:
            result = subprocess.run(['searchsploit', '--cve', cve_id], 
                                  capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().split('\n')
                
                for line in lines:
                    if '|' in line and not line.startswith('-') and 'Exploit Title' not in line:
                        parts = line.split('|')
                        if len(parts) >= 2:
                            exploit_name = parts[0].strip()
                            exploit_path = parts[1].strip()
                            if exploit_name and exploit_path and len(exploit_name) > 10:
                                exploit_info = {
                                    'name': exploit_name,
                                    'path': exploit_path,
                                    'type': 'Unknown',
                                    'platform': 'Multiple',
                                    'date': 'Unknown'
                                }
                                exploits.append(exploit_info)
                                print(f"{Fore.GREEN}  [+] {exploit_name[:60]}...{Style.RESET_ALL}")
                                
                                if len(exploits) >= 5:
                                    break
        
        # Method 3: Manual database for common CVEs
        if not exploits:
            manual_exploits = get_manual_exploits(cve_id)
            if manual_exploits:
                exploits.extend(manual_exploits)
                for exploit in manual_exploits:
                    print(f"{Fore.GREEN}  [+] {exploit['name'][:60]}... [Manual DB]{Style.RESET_ALL}")
        
        if exploits:
            print(f"{Fore.GREEN}[+] Found {len(exploits)} exploits for {cve_id}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] No exploits found for {cve_id}{Style.RESET_ALL}")
            
    except FileNotFoundError:
        print(f"{Fore.RED}[!] searchsploit not found. Install: sudo apt install exploitdb{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error searching exploits: {str(e)}{Style.RESET_ALL}")
    
    return exploits

def get_manual_exploits(cve_id):
    """Manual exploit database for common CVEs"""
    manual_db = {
        'CVE-2021-44228': [
            {
                'name': 'Apache Log4j2 Remote Code Execution (Log4Shell)',
                'path': 'java/remote/50592.py',
                'type': 'Remote Code Execution',
                'platform': 'Java',
                'date': '2021-12-10'
            }
        ],
        'CVE-2017-0144': [
            {
                'name': 'Microsoft Windows SMB Remote Code Execution (EternalBlue)',
                'path': 'windows/remote/42315.py',
                'type': 'Remote Code Execution',
                'platform': 'Windows',
                'date': '2017-03-14'
            }
        ],
        'CVE-2014-6271': [
            {
                'name': 'GNU Bash Remote Code Execution (Shellshock)',
                'path': 'linux/remote/34900.py',
                'type': 'Remote Code Execution',
                'platform': 'Linux',
                'date': '2014-09-24'
            }
        ]
    }
    
    return manual_db.get(cve_id, [])

def search_additional_exploits(service_name, version):
    """WORKING service exploit search"""
    exploits = []
    
    if not service_name or len(service_name) < 3:
        return exploits
    
    print(f"{Fore.BLUE}[*] Searching service exploits for {service_name} {version}...{Style.RESET_ALL}")
    
    try:
        search_term = f"{service_name}"
        if version:
            search_term += f" {version}"
        
        result = subprocess.run(['searchsploit', search_term, '--exclude=dos'], 
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0 and result.stdout.strip():
            lines = result.stdout.strip().split('\n')
            
            for line in lines[:3]:  # Top 3 results
                if '|' in line and not line.startswith('-') and 'Exploit Title' not in line:
                    parts = line.split('|')
                    if len(parts) >= 2:
                        exploit_name = parts[0].strip()
                        exploit_path = parts[1].strip()
                        if (exploit_name and exploit_path and 
                            len(exploit_name) > 10 and 
                            service_name.lower() in exploit_name.lower()):
                            
                            exploit_info = {
                                'name': exploit_name,
                                'path': exploit_path,
                                'type': 'Service-specific',
                                'platform': 'Multiple'
                            }
                            exploits.append(exploit_info)
                            print(f"{Fore.GREEN}  [+] {exploit_name[:50]}...{Style.RESET_ALL}")
        
        if exploits:
            print(f"{Fore.GREEN}[+] Found {len(exploits)} service exploits{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Service exploit search error: {str(e)}{Style.RESET_ALL}")
    
    return exploits
