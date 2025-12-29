#!/usr/bin/env python3
import sys
import os
import socket
import argparse
import nmap
import json
import requests
import time
import datetime
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore, Style
from tabulate import tabulate
from tqdm import tqdm
import html

# Import our OWASP scanner module
from owasp_scanner import OWASPScanner, get_exploit_info, search_additional_exploits

# Initialize colorama for cross-platform colored terminal output
init()

class VulnerabilityScanner:
    def __init__(self, target, ports=None, threads=10, timeout=2, enable_owasp=False):
        self.target = target
        self.ports = ports or "1-1000"
        self.threads = threads
        self.timeout = timeout
        self.enable_owasp = enable_owasp
        self.nm = nmap.PortScanner()
        self.open_ports = []
        self.service_info = {}
        self.vulnerabilities = {}
        self.web_vulnerabilities = []
        self.service_exploits = {}  # Store service-specific exploits
        self.scan_start_time = None
        self.scan_end_time = None
        
        # Initialize OWASP scanner if enabled
        if self.enable_owasp:
            self.owasp_scanner = OWASPScanner(target, timeout=timeout)
        
    def resolve_host(self):
        """Resolve hostname to IP address"""
        try:
            print(f"{Fore.BLUE}[*] Resolving hostname {self.target}...{Style.RESET_ALL}")
            ip = socket.gethostbyname(self.target)
            print(f"{Fore.GREEN}[+] Hostname resolved to {ip}{Style.RESET_ALL}")
            return ip
        except socket.gaierror:
            print(f"{Fore.RED}[!] Could not resolve hostname {self.target}{Style.RESET_ALL}")
            return self.target
    
    def is_port_open(self, port):
        """Check if a port is open using socket"""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        result = s.connect_ex((self.target, port))
        s.close()
        return result == 0
    
    def quick_scan(self):
        """Perform a quick scan to find open ports"""
        print(f"{Fore.BLUE}[*] Starting quick port scan on {self.target}...{Style.RESET_ALL}")
        
        # Parse port range
        if "-" in self.ports:
            start_port, end_port = map(int, self.ports.split("-"))
            port_list = range(start_port, end_port + 1)
        else:
            port_list = [int(p) for p in self.ports.split(",")]
        
        # Use ThreadPoolExecutor with tqdm progress bar for parallel scanning
        with tqdm(total=len(port_list), desc="Scanning ports", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]") as pbar:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                results = []
                for port in port_list:
                    future = executor.submit(self.is_port_open, port)
                    results.append((port, future))
                
                for port, future in results:
                    is_open = future.result()
                    if is_open:
                        self.open_ports.append(port)
                    pbar.update(1)
        
        if self.open_ports:
            print(f"{Fore.GREEN}[+] Found {len(self.open_ports)} open ports: {', '.join(map(str, self.open_ports))}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] No open ports found{Style.RESET_ALL}")
    
    def detailed_scan(self):
        """Perform detailed scan on open ports to get service information"""
        if not self.open_ports:
            return
        
        print(f"{Fore.BLUE}[*] Starting detailed service scan on open ports...{Style.RESET_ALL}")
        
        ports_str = ",".join(map(str, self.open_ports))
        
        try:
            print(f"{Fore.BLUE}[*] Running Nmap service detection...{Style.RESET_ALL}")
            with tqdm(total=len(self.open_ports), desc="Identifying services", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]") as pbar:
                self.nm.scan(self.target, ports=ports_str, arguments="-sV")
                pbar.update(len(self.open_ports))
            
            # Process service information and search for exploits
            for port in self.open_ports:
                port = str(port)
                if self.target in self.nm.all_hosts() and 'tcp' in self.nm[self.target] and int(port) in self.nm[self.target]['tcp']:
                    service_info = self.nm[self.target]['tcp'][int(port)]
                    self.service_info[port] = {
                        'name': service_info['name'],
                        'product': service_info.get('product', ''),
                        'version': service_info.get('version', ''),
                        'extrainfo': service_info.get('extrainfo', '')
                    }
                    
                    # Search for service-specific exploits
                    if self.service_info[port]['product']:
                        service_exploits = search_additional_exploits(
                            self.service_info[port]['product'], 
                            self.service_info[port]['version']
                        )
                        
                        if service_exploits:
                            self.service_exploits[port] = service_exploits
                            print(f"{Fore.GREEN}[+] Found {len(service_exploits)} service exploits for {self.service_info[port]['product']} on port {port}{Style.RESET_ALL}")
                    
                    print(f"{Fore.GREEN}[+] Port {port}: {self.service_info[port]['name']} - {self.service_info[port]['product']} {self.service_info[port]['version']}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error during detailed scan: {str(e)}{Style.RESET_ALL}")
    
    def check_vulnerabilities(self):
        """Check for vulnerabilities in detected services"""
        if not self.service_info:
            return
        
        print(f"{Fore.BLUE}[*] Checking for CVE vulnerabilities...{Style.RESET_ALL}")
        
        with tqdm(total=len(self.service_info), desc="Checking CVEs", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]") as pbar:
            for port, service in self.service_info.items():
                product = service['product']
                version = service['version']
                
                if not product:
                    pbar.update(1)
                    continue
                    
                # Query the NVD API for vulnerabilities
                cve_vulns = self.query_nvd(product, version)
                
                # FIXED: Add exploit information to each CVE
                for vuln in cve_vulns:
                    print(f"{Fore.BLUE}[*] Searching exploits for {vuln['cve_id']}...{Style.RESET_ALL}")
                    vuln['exploits'] = get_exploit_info(vuln['cve_id'])
                    
                    # FIXED: Show exploit count immediately
                    if vuln['exploits']:
                        print(f"{Fore.GREEN}[+] Found {len(vuln['exploits'])} exploits for {vuln['cve_id']}:{Style.RESET_ALL}")
                        for i, exploit in enumerate(vuln['exploits'][:3], 1):
                            print(f"{Fore.GREEN}    {i}. {exploit['name'][:50]}...{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.YELLOW}[!] No exploits found for {vuln['cve_id']}{Style.RESET_ALL}")
                
                self.vulnerabilities[port] = cve_vulns
                
                if self.vulnerabilities[port]:
                    print(f"{Fore.GREEN}[+] Found {len(self.vulnerabilities[port])} CVEs for {product} {version} on port {port}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}[!] No known CVEs found for {product} {version} on port {port}{Style.RESET_ALL}")
                
                pbar.update(1)
    
    def run_owasp_scan(self):
        """Run OWASP Top 10 vulnerability scan on web services"""
        if not self.enable_owasp:
            return
        
        print(f"{Fore.CYAN}[*] Starting OWASP Top 10 vulnerability scan...{Style.RESET_ALL}")
        
        # Find web services
        web_ports = []
        for port in self.open_ports:
            if self.owasp_scanner.is_web_service(port):
                web_ports.append(port)
        
        if not web_ports:
            print(f"{Fore.YELLOW}[!] No web services detected for OWASP scanning{Style.RESET_ALL}")
            return
        
        print(f"{Fore.BLUE}[*] Found {len(web_ports)} web services: {', '.join(map(str, web_ports))}{Style.RESET_ALL}")
        
        # Run OWASP scan on each web service
        for port in web_ports:
            vulnerabilities = self.owasp_scanner.run_owasp_scan(port)
            if vulnerabilities:
                self.web_vulnerabilities.extend(vulnerabilities)
                print(f"{Fore.GREEN}[+] Found {len(vulnerabilities)} web vulnerabilities on port {port}{Style.RESET_ALL}")
                
                # FIXED: Show OWASP vulnerabilities immediately
                for vuln in vulnerabilities:
                    print(f"{Fore.RED}  [!] {vuln['type']}: {vuln['parameter']} -> {vuln['payload'][:30]}...{Style.RESET_ALL}")
    
    def query_nvd(self, product, version):
        """Query the NVD database for vulnerabilities"""
        vulnerabilities = []
        
        try:
            search_term = f"{product}"
            if version:
                search_term += f" {version}"
                
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={search_term}&resultsPerPage=10"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                if 'vulnerabilities' in data:
                    for vuln in data['vulnerabilities']:
                        cve_item = vuln['cve']
                        cve_id = cve_item['id']
                        description = cve_item['descriptions'][0]['value'] if cve_item['descriptions'] else "No description available"
                        
                        # Get CVSS score if available
                        cvss_score = "N/A"
                        severity = "N/A"
                        
                        if 'metrics' in cve_item:
                            metrics = cve_item['metrics']
                            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                                cvss_score = cvss_data.get('baseScore', 'N/A')
                                severity = cvss_data.get('baseSeverity', 'N/A')
                            elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                                cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                                cvss_score = cvss_data.get('baseScore', 'N/A')
                        
                        remediation = self.get_cve_remediation(description)
                        
                        vulnerabilities.append({
                            'cve_id': cve_id,
                            'description': description,
                            'cvss_score': cvss_score,
                            'severity': severity,
                            'remediation': remediation,
                            'exploits': []  # Will be populated later
                        })
        except Exception as e:
            print(f"{Fore.RED}[!] Error querying NVD: {str(e)}{Style.RESET_ALL}")
        
        return vulnerabilities
    
    def get_cve_remediation(self, description):
        """Get remediation suggestion based on CVE description"""
        description_lower = description.lower()
        
        if 'buffer overflow' in description_lower:
            return "Update to latest version. Implement proper input validation and bounds checking."
        elif 'sql injection' in description_lower:
            return "Use parameterized queries. Validate and sanitize all user inputs."
        elif 'cross-site scripting' in description_lower or 'xss' in description_lower:
            return "Implement proper input validation and output encoding. Use Content Security Policy."
        elif 'authentication' in description_lower:
            return "Implement strong authentication mechanisms. Use multi-factor authentication."
        elif 'privilege escalation' in description_lower:
            return "Apply principle of least privilege. Update to patched version."
        elif 'denial of service' in description_lower or 'dos' in description_lower:
            return "Implement rate limiting and input validation. Update to latest version."
        elif 'remote code execution' in description_lower or 'rce' in description_lower:
            return "CRITICAL: Update immediately. Restrict network access if possible."
        else:
            return "Update to the latest patched version. Follow vendor security advisories."
    
    def run_scan(self):
        """Run the full vulnerability scan"""
        self.scan_start_time = datetime.datetime.now()
        
        # Resolve hostname to IP if needed
        if not self.is_ip_address(self.target):
            self.target = self.resolve_host()
        
        # Run quick scan to find open ports
        self.quick_scan()
        
        # If open ports found, run detailed scan
        if self.open_ports:
            self.detailed_scan()
            self.check_vulnerabilities()
            
            # Run OWASP scan if enabled
            if self.enable_owasp:
                self.run_owasp_scan()
        
        self.scan_end_time = datetime.datetime.now()
        
        # Generate report
        self.generate_report()
    
    def is_ip_address(self, address):
        """Check if the given address is an IP address"""
        try:
            socket.inet_aton(address)
            return True
        except socket.error:
            return False
    
    def generate_report(self):
        """Generate a report of the scan results"""
        self.print_console_report()
    
    def print_console_report(self):
        """FIXED: Print a formatted report to the console with proper exploit display"""
        scan_duration = (self.scan_end_time - self.scan_start_time).total_seconds()
        
        print("\n" + "=" * 80)
        print(f"{Fore.CYAN}🚨 RED ALERT CLI - VULNERABILITY SCAN REPORT{Style.RESET_ALL}")
        print("=" * 80)
        
        # Print scan information
        print(f"\n{Fore.CYAN}SCAN INFORMATION:{Style.RESET_ALL}")
        scan_info = [
            ["Target", self.target],
            ["Scan Start Time", self.scan_start_time.strftime("%Y-%m-%d %H:%M:%S")],
            ["Scan End Time", self.scan_end_time.strftime("%Y-%m-%d %H:%M:%S")],
            ["Duration", f"{scan_duration:.2f} seconds"],
            ["Ports Scanned", self.ports],
            ["Open Ports Found", len(self.open_ports)],
            ["OWASP Scan", "Enabled" if self.enable_owasp else "Disabled"]
        ]
        print(tabulate(scan_info, tablefmt="pretty"))
        
        if not self.open_ports:
            print(f"\n{Fore.YELLOW}No open ports found.{Style.RESET_ALL}")
            return
        
        # Print open ports and services
        print(f"\n{Fore.CYAN}OPEN PORTS AND SERVICES:{Style.RESET_ALL}")
        
        port_data = []
        for port in self.open_ports:
            port_str = str(port)
            if port_str in self.service_info:
                service = self.service_info[port_str]
                port_data.append([
                    port,
                    service['name'],
                    service['product'],
                    service['version'],
                    service['extrainfo']
                ])
            else:
                port_data.append([port, "Unknown", "", "", ""])
        
        print(tabulate(port_data, headers=["Port", "Service", "Product", "Version", "Extra Info"], tablefmt="pretty"))
        
        # FIXED: Print CVE vulnerabilities with exploits
        print(f"\n{Fore.CYAN}CVE VULNERABILITIES:{Style.RESET_ALL}")
        
        cve_found = False
        for port in self.open_ports:
            port_str = str(port)
            if port_str in self.vulnerabilities and self.vulnerabilities[port_str]:
                cve_found = True
                service = self.service_info.get(port_str, {'name': 'Unknown', 'product': '', 'version': ''})
                print(f"\n{Fore.YELLOW}Port {port} - {service['name']} - {service['product']} {service['version']}{Style.RESET_ALL}")
                
                for vuln in self.vulnerabilities[port_str]:
                    severity_color = Fore.GREEN
                    if vuln['severity'] == 'HIGH':
                        severity_color = Fore.RED
                    elif vuln['severity'] == 'MEDIUM':
                        severity_color = Fore.YELLOW
                    
                    print(f"  {Fore.RED}CVE: {vuln['cve_id']}{Style.RESET_ALL}")
                    print(f"  {severity_color}Severity: {vuln['severity']} (CVSS: {vuln['cvss_score']}){Style.RESET_ALL}")
                    print(f"  Description: {vuln['description'][:100]}...")
                    print(f"  {Fore.BLUE}Remediation: {vuln['remediation']}{Style.RESET_ALL}")
                    
                    # FIXED: Show exploits properly
                    if vuln['exploits']:
                        print(f"  {Fore.MAGENTA}🔥 Available Exploits ({len(vuln['exploits'])}):{Style.RESET_ALL}")
                        for i, exploit in enumerate(vuln['exploits'][:5], 1):
                            print(f"    {Fore.GREEN}{i}. {exploit['name']}{Style.RESET_ALL}")
                            print(f"       {Fore.CYAN}Path: {exploit['path']}{Style.RESET_ALL}")
                            if exploit.get('type') != 'Unknown':
                                print(f"       {Fore.CYAN}Type: {exploit['type']}{Style.RESET_ALL}")
                        if len(vuln['exploits']) > 5:
                            print(f"    {Fore.YELLOW}... and {len(vuln['exploits']) - 5} more exploits{Style.RESET_ALL}")
                    else:
                        print(f"  {Fore.CYAN}ℹ️  No public exploits found{Style.RESET_ALL}")
                    print()
        
        # FIXED: Print service-specific exploits
        if hasattr(self, 'service_exploits') and self.service_exploits:
            print(f"\n{Fore.CYAN}SERVICE-SPECIFIC EXPLOITS:{Style.RESET_ALL}")
            for port, exploits in self.service_exploits.items():
                service = self.service_info.get(port, {'product': 'Unknown'})
                print(f"\n{Fore.YELLOW}Port {port} - {service['product']}:{Style.RESET_ALL}")
                for i, exploit in enumerate(exploits, 1):
                    print(f"  {Fore.GREEN}{i}. {exploit['name']}{Style.RESET_ALL}")
                    print(f"     {Fore.CYAN}Path: {exploit['path']}{Style.RESET_ALL}")
        
        if not cve_found:
            print(f"{Fore.GREEN}No CVE vulnerabilities found for any service.{Style.RESET_ALL}")
        
        # FIXED: Print OWASP vulnerabilities properly
        if self.enable_owasp and self.web_vulnerabilities:
            print(f"\n{Fore.CYAN}OWASP TOP 10 VULNERABILITIES:{Style.RESET_ALL}")
            
            for vuln in self.web_vulnerabilities:
                severity_color = Fore.GREEN
                if vuln['severity'] == 'HIGH':
                    severity_color = Fore.RED
                elif vuln['severity'] == 'MEDIUM':
                    severity_color = Fore.YELLOW
                
                print(f"\n{severity_color}[{vuln['severity']}] {vuln['type']}{Style.RESET_ALL}")
                print(f"  {Fore.CYAN}URL: {vuln['url']}{Style.RESET_ALL}")
                print(f"  {Fore.CYAN}Parameter: {vuln['parameter']}{Style.RESET_ALL}")
                print(f"  {Fore.CYAN}Payload: {vuln['payload']}{Style.RESET_ALL}")
                print(f"  {Fore.CYAN}Evidence: {vuln['evidence']}{Style.RESET_ALL}")
                print(f"  {Fore.BLUE}Remediation: {vuln['remediation']}{Style.RESET_ALL}")
        elif self.enable_owasp:
            print(f"\n{Fore.GREEN}No OWASP vulnerabilities found.{Style.RESET_ALL}")
    
    def save_report(self, output_file, format_type):
        """Save the scan report to a file in the specified format"""
        # Validate format type
        valid_formats = ['txt', 'json', 'html']
        if format_type.lower() not in valid_formats:
            print(f"{Fore.RED}[!] Unsupported report format: {format_type}. Using txt format instead.{Style.RESET_ALL}")
            format_type = 'txt'
        
        # Create directory if it doesn't exist
        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
                print(f"{Fore.BLUE}[*] Created directory: {output_dir}{Style.RESET_ALL}")
            except OSError as e:
                print(f"{Fore.RED}[!] Error creating directory {output_dir}: {str(e)}{Style.RESET_ALL}")
                print(f"{Fore.RED}[!] Report will be saved in the current directory{Style.RESET_ALL}")
                output_file = os.path.basename(output_file)
        
        # Check if file already exists
        if os.path.exists(output_file):
            print(f"{Fore.YELLOW}[!] Warning: File {output_file} already exists and will be overwritten{Style.RESET_ALL}")
        
        # Save report in the specified format
        print(f"{Fore.BLUE}[*] Saving report in {format_type.upper()} format to {output_file}...{Style.RESET_ALL}")
        
        try:
            if format_type.lower() == 'txt':
                self.save_txt_report(output_file)
            elif format_type.lower() == 'json':
                self.save_json_report(output_file)
            elif format_type.lower() == 'html':
                self.save_html_report(output_file)
            
            # Verify file was created
            if os.path.exists(output_file):
                file_size = os.path.getsize(output_file)
                print(f"{Fore.GREEN}[+] Report successfully saved to {output_file} ({file_size} bytes){Style.RESET_ALL}")
                print(f"{Fore.GREEN}[+] You can access the report at: {os.path.abspath(output_file)}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] Error: Report file was not created{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving report: {str(e)}{Style.RESET_ALL}")
    
    def save_txt_report(self, output_file):
        """FIXED: Save the scan report in plain text format with exploits"""
        try:
            with open(output_file, 'w') as f:
                scan_duration = (self.scan_end_time - self.scan_start_time).total_seconds()
                
                f.write("=" * 80 + "\n")
                f.write("🚨 RED ALERT CLI - VULNERABILITY SCAN REPORT\n")
                f.write("=" * 80 + "\n\n")
                
                # Scan information
                f.write("SCAN INFORMATION:\n")
                scan_info = [
                    ["Target", self.target],
                    ["Scan Start Time", self.scan_start_time.strftime("%Y-%m-%d %H:%M:%S")],
                    ["Scan End Time", self.scan_end_time.strftime("%Y-%m-%d %H:%M:%S")],
                    ["Duration", f"{scan_duration:.2f} seconds"],
                    ["Ports Scanned", self.ports],
                    ["Open Ports Found", len(self.open_ports)],
                    ["OWASP Scan", "Enabled" if self.enable_owasp else "Disabled"]
                ]
                f.write(tabulate(scan_info, tablefmt="pretty") + "\n")
                
                if not self.open_ports:
                    f.write("\nNo open ports found.\n")
                    return
                
                # Open ports and services
                f.write("\nOPEN PORTS AND SERVICES:\n")
                port_data = []
                for port in self.open_ports:
                    port_str = str(port)
                    if port_str in self.service_info:
                        service = self.service_info[port_str]
                        port_data.append([
                            port,
                            service['name'],
                            service['product'],
                            service['version'],
                            service['extrainfo']
                        ])
                    else:
                        port_data.append([port, "Unknown", "", "", ""])
                
                f.write(tabulate(port_data, headers=["Port", "Service", "Product", "Version", "Extra Info"], tablefmt="pretty") + "\n")
                
                # FIXED: CVE vulnerabilities with exploits
                f.write("\nCVE VULNERABILITIES:\n")
                cve_found = False
                for port in self.open_ports:
                    port_str = str(port)
                    if port_str in self.vulnerabilities and self.vulnerabilities[port_str]:
                        cve_found = True
                        service = self.service_info.get(port_str, {'name': 'Unknown', 'product': '', 'version': ''})
                        f.write(f"\nPort {port} - {service['name']} - {service['product']} {service['version']}\n")
                        
                        for vuln in self.vulnerabilities[port_str]:
                            f.write(f"  CVE: {vuln['cve_id']}\n")
                            f.write(f"  Severity: {vuln['severity']} (CVSS: {vuln['cvss_score']})\n")
                            f.write(f"  Description: {vuln['description']}\n")
                            f.write(f"  Remediation: {vuln['remediation']}\n")
                            
                            # FIXED: Include exploits in text report
                            if vuln['exploits']:
                                f.write(f"  Available Exploits ({len(vuln['exploits'])}):\n")
                                for i, exploit in enumerate(vuln['exploits'], 1):
                                    f.write(f"    {i}. {exploit['name']}\n")
                                    f.write(f"       Path: {exploit['path']}\n")
                                    if exploit.get('type') != 'Unknown':
                                        f.write(f"       Type: {exploit['type']}\n")
                            else:
                                f.write("  No public exploits found\n")
                            f.write("\n")
                
                if not cve_found:
                    f.write("No CVE vulnerabilities found for any service.\n")
                
                # FIXED: OWASP vulnerabilities
                if self.enable_owasp and self.web_vulnerabilities:
                    f.write("\nOWASP TOP 10 VULNERABILITIES:\n")
                    for vuln in self.web_vulnerabilities:
                        f.write(f"\n[{vuln['severity']}] {vuln['type']}\n")
                        f.write(f"  URL: {vuln['url']}\n")
                        f.write(f"  Parameter: {vuln['parameter']}\n")
                        f.write(f"  Payload: {vuln['payload']}\n")
                        f.write(f"  Evidence: {vuln['evidence']}\n")
                        f.write(f"  Remediation: {vuln['remediation']}\n")
                elif self.enable_owasp:
                    f.write("\nNo OWASP vulnerabilities found.\n")
                    
        except Exception as e:
            raise Exception(f"Error saving TXT report: {str(e)}")
    
    def save_json_report(self, output_file):
        """FIXED: Save the scan report in JSON format with exploits"""
        try:
            report = {
                "scan_info": {
                    "target": self.target,
                    "start_time": self.scan_start_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "end_time": self.scan_end_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "duration": (self.scan_end_time - self.scan_start_time).total_seconds(),
                    "ports_scanned": self.ports,
                    "open_ports_count": len(self.open_ports),
                    "owasp_enabled": self.enable_owasp
                },
                "open_ports": self.open_ports,
                "services": self.service_info,
                "cve_vulnerabilities": self.vulnerabilities,
                "service_exploits": getattr(self, 'service_exploits', {}),  # FIXED: Include service exploits
                "web_vulnerabilities": self.web_vulnerabilities
            }
            
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=4)
        except Exception as e:
            raise Exception(f"Error saving JSON report: {str(e)}")
    
    def save_html_report(self, output_file):
        """FIXED: Save the scan report in HTML format with exploits"""
        try:
            scan_duration = (self.scan_end_time - self.scan_start_time).total_seconds()
            
            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RED ALERT CLI - Vulnerability Scan Report - {self.target}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }}
        h1, h2, h3 {{
            color: #2c3e50;
        }}
        h1 {{
            text-align: center;
            padding-bottom: 10px;
            border-bottom: 3px solid #e74c3c;
            color: #e74c3c;
        }}
        .section {{
            margin: 25px 0;
            padding: 20px;
            background-color: #f9f9f9;
            border-radius: 8px;
            border-left: 4px solid #3498db;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #34495e;
            color: white;
        }}
        tr:nth-child(even) {{
            background-color: #f8f9fa;
        }}
        .severity-high {{
            color: #e74c3c;
            font-weight: bold;
        }}
        .severity-medium {{
            color: #f39c12;
            font-weight: bold;
        }}
        .severity-low {{
            color: #27ae60;
            font-weight: bold;
        }}
        .cve-id {{
            color: #e74c3c;
            font-weight: bold;
        }}
        .vuln-card {{
            background-color: white;
            border-radius: 8px;
            padding: 15px;
            margin: 10px 0;
            border-left: 4px solid #e74c3c;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .owasp-card {{
            border-left-color: #f39c12;
        }}
        .exploit-list {{
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            font-size: 0.9em;
            color: #7f8c8d;
            border-top: 1px solid #ecf0f1;
            padding-top: 20px;
        }}
        .logo {{
            color: #e74c3c;
            font-weight: bold;
            font-size: 1.2em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1><span class="logo">🚨 RED ALERT CLI</span><br>Vulnerability Scan Report</h1>
        
        <div class="section">
            <h2>📊 Scan Information</h2>
            <table>
                <tr>
                    <th>Property</th>
                    <th>Value</th>
                </tr>
                <tr>
                    <td>Target</td>
                    <td>{html.escape(self.target)}</td>
                </tr>
                <tr>
                    <td>Scan Start Time</td>
                    <td>{self.scan_start_time.strftime("%Y-%m-%d %H:%M:%S")}</td>
                </tr>
                <tr>
                    <td>Scan End Time</td>
                    <td>{self.scan_end_time.strftime("%Y-%m-%d %H:%M:%S")}</td>
                </tr>
                <tr>
                    <td>Duration</td>
                    <td>{scan_duration:.2f} seconds</td>
                </tr>
                <tr>
                    <td>Ports Scanned</td>
                    <td>{html.escape(self.ports)}</td>
                </tr>
                <tr>
                    <td>Open Ports Found</td>
                    <td>{len(self.open_ports)}</td>
                </tr>
                <tr>
                    <td>OWASP Scan</td>
                    <td>{"Enabled" if self.enable_owasp else "Disabled"}</td>
                </tr>
            </table>
        </div>
"""
            
            if not self.open_ports:
                html_content += """
        <div class="section">
            <h2>🔍 Open Ports and Services</h2>
            <p>No open ports found.</p>
        </div>
"""
            else:
                html_content += """
        <div class="section">
            <h2>🔍 Open Ports and Services</h2>
            <table>
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Product</th>
                    <th>Version</th>
                    <th>Extra Info</th>
                </tr>
"""
                
                for port in self.open_ports:
                    port_str = str(port)
                    if port_str in self.service_info:
                        service = self.service_info[port_str]
                        html_content += f"""
                <tr>
                    <td>{port}</td>
                    <td>{html.escape(service['name'])}</td>
                    <td>{html.escape(service['product'])}</td>
                    <td>{html.escape(service['version'])}</td>
                    <td>{html.escape(service['extrainfo'])}</td>
                </tr>
"""
                    else:
                        html_content += f"""
                <tr>
                    <td>{port}</td>
                    <td>Unknown</td>
                    <td></td>
                    <td></td>
                    <td></td>
                </tr>
"""
                
                html_content += """
            </table>
        </div>
"""
                
                # CVE vulnerabilities section with exploits
                html_content += """
        <div class="section">
            <h2>🛡️ CVE Vulnerabilities</h2>
"""
                
                cve_found = False
                for port in self.open_ports:
                    port_str = str(port)
                    if port_str in self.vulnerabilities and self.vulnerabilities[port_str]:
                        cve_found = True
                        service = self.service_info.get(port_str, {'name': 'Unknown', 'product': '', 'version': ''})
                        
                        html_content += f"""
            <h3>Port {port} - {html.escape(service['name'])} - {html.escape(service['product'])} {html.escape(service['version'])}</h3>
"""
                        
                        for vuln in self.vulnerabilities[port_str]:
                            severity_class = "severity-low"
                            if vuln['severity'] == 'HIGH':
                                severity_class = "severity-high"
                            elif vuln['severity'] == 'MEDIUM':
                                severity_class = "severity-medium"
                            
                            html_content += f"""
            <div class="vuln-card">
                <h4 class="cve-id">{html.escape(vuln['cve_id'])}</h4>
                <p><strong class="{severity_class}">Severity: {html.escape(vuln['severity'])} (CVSS: {html.escape(str(vuln['cvss_score']))})</strong></p>
                <p><strong>Description:</strong> {html.escape(vuln['description'])}</p>
                <p><strong>Remediation:</strong> {html.escape(vuln['remediation'])}</p>
"""
                            
                            # FIXED: Include exploits in HTML report
                            if vuln['exploits']:
                                html_content += f"""
                <div class="exploit-list">
                    <p><strong>🔥 Available Exploits ({len(vuln['exploits'])}):</strong></p>
                    <ul>
"""
                                for exploit in vuln['exploits']:
                                    html_content += f"""
                        <li>
                            <strong>{html.escape(exploit['name'])}</strong><br>
                            <small>Path: {html.escape(exploit['path'])}</small><br>
                            <small>Type: {html.escape(exploit.get('type', 'Unknown'))}</small>
                        </li>
"""
                                html_content += """
                    </ul>
                </div>
"""
                            else:
                                html_content += """
                <p><em>No public exploits found</em></p>
"""
                            
                            html_content += """
            </div>
"""
                
                if not cve_found:
                    html_content += """
            <p>✅ No CVE vulnerabilities found for any service.</p>
"""
                
                html_content += """
        </div>
"""
                
                # OWASP vulnerabilities section
                if self.enable_owasp:
                    html_content += """
        <div class="section">
            <h2>🌐 OWASP Top 10 Vulnerabilities</h2>
"""
                    
                    if self.web_vulnerabilities:
                        for vuln in self.web_vulnerabilities:
                            severity_class = "severity-low"
                            if vuln['severity'] == 'HIGH':
                                severity_class = "severity-high"
                            elif vuln['severity'] == 'MEDIUM':
                                severity_class = "severity-medium"
                            
                            html_content += f"""
            <div class="vuln-card owasp-card">
                <h4 class="{severity_class}">[{html.escape(vuln['severity'])}] {html.escape(vuln['type'])}</h4>
                <p><strong>URL:</strong> {html.escape(vuln['url'])}</p>
                <p><strong>Parameter:</strong> {html.escape(vuln['parameter'])}</p>
                <p><strong>Payload:</strong> <code>{html.escape(vuln['payload'])}</code></p>
                <p><strong>Evidence:</strong> {html.escape(vuln['evidence'])}</p>
                <p><strong>Remediation:</strong> {html.escape(vuln['remediation'])}</p>
            </div>
"""
                    else:
                        html_content += """
            <p>✅ No OWASP vulnerabilities found.</p>
"""
                    
                    html_content += """
        </div>
"""
            
            # Footer
            html_content += f"""
        <div class="footer">
            <p class="logo">🚨 RED ALERT CLI</p>
            <p>Comprehensive Vulnerability Scanner for Cybersecurity Professionals</p>
            <p>Report generated on {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
    </div>
</body>
</html>
"""
            
            with open(output_file, 'w') as f:
                f.write(html_content)
        except Exception as e:
            raise Exception(f"Error saving HTML report: {str(e)}")


def print_banner():
    """Print an ASCII art banner for the tool"""
    banner = f"""
{Fore.RED}
==================================================
 ____  _____ ____     _    _     _____ ____  _____ 
|  _ \| ____|  _ \   / \  | |   | ____|  _ \|_   _|
| |_) |  _| | | | | / _ \ | |   |  _| | |_) | | |  
|  _ <| |___| |_| |/ ___ \| |___| |___|  _ <  | |  
|_| \_\_____|____//_/   \_\_____|_____||_| \_\|_|  
==================================================                   
                                                            
{Style.RESET_ALL}
"""
    print(banner)
    print(f"{Fore.YELLOW}🚨 Enhanced Vulnerability Scanner for Cybersecurity Professionals{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}🇮🇳 Made for Ethical Hackers & Bug Bounty Hunters{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Version 2.0.0 : OWASP Detection + Exploit Listing{Style.RESET_ALL}")
    print("=" * 80)

def main():
    parser = argparse.ArgumentParser(description='RED ALERT CLI - Enhanced Vulnerability Scanner')
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', default='1-1000', help='Port range to scan (e.g., 1-1000 or 22,80,443)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads for scanning')
    parser.add_argument('-T', '--timeout', type=float, default=1.0, help='Timeout for port scanning in seconds')
    parser.add_argument('-o', '--output', help='Output file to save the report')
    parser.add_argument('-f', '--format', choices=['txt', 'json', 'html'], default='txt', 
                        help='Report format (txt, json, or html)')
    parser.add_argument('--owasp', action='store_true', help='Enable OWASP Top 10 vulnerability scanning for web services')
    
    args = parser.parse_args()
    
    print_banner()
    
    scanner = VulnerabilityScanner(
        target=args.target,
        ports=args.ports,
        threads=args.threads,
        timeout=args.timeout,
        enable_owasp=args.owasp
    )
    
    scanner.run_scan()
    
    # Save report if output file is specified
    if args.output:
        scanner.save_report(args.output, args.format)
    else:
        print(f"\n{Fore.YELLOW}[!] No output file specified. Report not saved.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Use -o/--output option to save the report.{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Example: python3 RED_ALERT_CLI.py {args.target} --owasp -o report.html -f html{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
