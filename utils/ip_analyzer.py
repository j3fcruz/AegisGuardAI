# utils/ip_analyzer.py
import ipaddress
import socket
import requests
from datetime import datetime
import streamlit as st
import re
import json
import geoip2.database
import geoip2.errors
from typing import Dict, List, Optional, Tuple
import concurrent.futures
import subprocess
import platform

class IPAnalyzer:
    """IP address analysis and geolocation utility"""
    
    def __init__(self):
        """Initialize IP analyzer"""
        self.private_ranges = [
            ipaddress.IPv4Network('10.0.0.0/8'),
            ipaddress.IPv4Network('172.16.0.0/12'),
            ipaddress.IPv4Network('192.168.0.0/16'),
            ipaddress.IPv4Network('127.0.0.0/8'),
            ipaddress.IPv4Network('169.254.0.0/16'),
            ipaddress.IPv4Network('224.0.0.0/4'),
            ipaddress.IPv4Network('240.0.0.0/4')
        ]
        
        self.known_bad_ranges = [
            # Example known bad ranges - in production, maintain updated threat intelligence
            '185.220.100.0/22',  # Tor exit nodes range example
            '198.96.155.0/24',   # Example malicious hosting range
        ]
        
        # Free geolocation services (limited but functional)
        self.geolocation_apis = [
            'http://ip-api.com/json/',
            'https://ipapi.co/',
            'https://ipinfo.io/'
        ]
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CyberSecure-Dashboard/1.0'
        })
    
    def analyze_ip(self, ip_address: str) -> Dict:
        """Comprehensive IP address analysis"""
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            
            analysis = {
                'ip_address': ip_address,
                'timestamp': datetime.now().isoformat(),
                'ip_version': ip_obj.version,
                'is_private': ip_obj.is_private,
                'is_loopback': ip_obj.is_loopback,
                'is_multicast': ip_obj.is_multicast,
                'is_reserved': ip_obj.is_reserved,
                'is_global': ip_obj.is_global if hasattr(ip_obj, 'is_global') else not ip_obj.is_private,
                'classification': self._classify_ip(ip_obj),
                'risk_score': 0,
                'risk_factors': []
            }
            
            # Skip detailed analysis for private/local IPs
            if ip_obj.is_private or ip_obj.is_loopback:
                analysis['geolocation'] = {'country': 'Private/Local', 'city': 'N/A'}
                analysis['reverse_dns'] = self._get_reverse_dns(ip_address)
                return analysis
            
            # Geolocation lookup
            analysis['geolocation'] = self._get_geolocation(ip_address)
            
            # Reverse DNS lookup
            analysis['reverse_dns'] = self._get_reverse_dns(ip_address)
            
            # Check against known bad ranges
            analysis['bad_range_check'] = self._check_bad_ranges(ip_address)
            
            # Port scanning detection
            analysis['open_ports'] = self._scan_common_ports(ip_address)
            
            # Calculate risk score
            analysis['risk_score'] = self._calculate_ip_risk_score(analysis)
            
            return analysis
            
        except ipaddress.AddressValueError:
            return {
                'error': f'Invalid IP address: {ip_address}',
                'ip_address': ip_address,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'error': f'IP analysis failed: {str(e)}',
                'ip_address': ip_address,
                'timestamp': datetime.now().isoformat()
            }
    
    def _classify_ip(self, ip_obj) -> str:
        """Classify IP address type"""
        if ip_obj.is_loopback:
            return 'Loopback'
        elif ip_obj.is_private:
            return 'Private'
        elif ip_obj.is_multicast:
            return 'Multicast'
        elif ip_obj.is_reserved:
            return 'Reserved'
        elif ip_obj.is_link_local:
            return 'Link-local'
        else:
            return 'Public'
    
    def _get_geolocation(self, ip_address: str) -> Dict:
        """Get IP geolocation using free services"""
        try:
            # Try ip-api.com first (free, no key required)
            url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
            
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country', 'Unknown'),
                        'country_code': data.get('countryCode', ''),
                        'region': data.get('regionName', ''),
                        'city': data.get('city', ''),
                        'zip_code': data.get('zip', ''),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'timezone': data.get('timezone', ''),
                        'isp': data.get('isp', ''),
                        'organization': data.get('org', ''),
                        'as_number': data.get('as', ''),
                        'source': 'ip-api.com'
                    }
            
            # Fallback to simplified data
            return {
                'country': 'Unknown',
                'city': 'Unknown',
                'source': 'fallback',
                'error': 'Geolocation lookup failed'
            }
            
        except Exception as e:
            return {
                'country': 'Unknown',
                'city': 'Unknown',
                'error': f'Geolocation error: {str(e)}'
            }
    
    def _get_reverse_dns(self, ip_address: str) -> Dict:
        """Perform reverse DNS lookup"""
        try:
            hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(ip_address)
            return {
                'hostname': hostname,
                'aliases': aliaslist,
                'success': True
            }
        except socket.herror:
            return {
                'hostname': None,
                'success': False,
                'error': 'No reverse DNS record found'
            }
        except Exception as e:
            return {
                'hostname': None,
                'success': False,
                'error': str(e)
            }
    
    def _check_bad_ranges(self, ip_address: str) -> Dict:
        """Check IP against known bad ranges"""
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            
            for bad_range in self.known_bad_ranges:
                network = ipaddress.ip_network(bad_range, strict=False)
                if ip_obj in network:
                    return {
                        'is_in_bad_range': True,
                        'bad_range': bad_range,
                        'risk_level': 'HIGH'
                    }
            
            return {
                'is_in_bad_range': False,
                'risk_level': 'LOW'
            }
            
        except Exception as e:
            return {
                'error': f'Bad range check failed: {str(e)}',
                'is_in_bad_range': False
            }
    
    def _scan_common_ports(self, ip_address: str, timeout: int = 2) -> Dict:
        """Scan common ports on IP address"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 6379, 27017]
        suspicious_ports = [1337, 31337, 12345, 54321, 6666, 6667]
        
        open_ports = []
        suspicious_open = []
        
        try:
            def check_port(port):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(timeout)
                        result = sock.connect_ex((ip_address, port))
                        return port if result == 0 else None
                except:
                    return None
            
            # Use threading for faster scanning
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                future_to_port = {executor.submit(check_port, port): port for port in common_ports + suspicious_ports}
                
                for future in concurrent.futures.as_completed(future_to_port, timeout=10):
                    port = future_to_port[future]
                    try:
                        result = future.result()
                        if result is not None:
                            open_ports.append(result)
                            if result in suspicious_ports:
                                suspicious_open.append(result)
                    except:
                        continue
            
            return {
                'open_ports': sorted(open_ports),
                'suspicious_open_ports': sorted(suspicious_open),
                'total_open': len(open_ports),
                'has_suspicious_ports': len(suspicious_open) > 0,
                'common_services': self._identify_services(open_ports)
            }
            
        except Exception as e:
            return {
                'error': f'Port scan failed: {str(e)}',
                'open_ports': [],
                'suspicious_open_ports': [],
                'total_open': 0
            }
    
    def _identify_services(self, ports: List[int]) -> List[str]:
        """Identify services based on open ports"""
        service_map = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 6379: 'Redis', 27017: 'MongoDB'
        }
        
        return [service_map.get(port, f'Unknown-{port}') for port in ports if port in service_map]
    
    def _calculate_ip_risk_score(self, analysis: Dict) -> int:
        """Calculate risk score for IP address"""
        risk_score = 0
        risk_factors = []
        
        # Check if IP is in known bad ranges
        bad_range_check = analysis.get('bad_range_check', {})
        if bad_range_check.get('is_in_bad_range'):
            risk_score += 50
            risk_factors.append('IP in known malicious range')
        
        # Check for suspicious open ports
        open_ports_info = analysis.get('open_ports', {})
        if open_ports_info.get('has_suspicious_ports'):
            risk_score += 30
            risk_factors.append(f"Suspicious ports open: {open_ports_info.get('suspicious_open_ports', [])}")
        
        # Check number of open ports
        total_open = open_ports_info.get('total_open', 0)
        if total_open > 10:
            risk_score += 20
            risk_factors.append(f'Many open ports ({total_open})')
        elif total_open > 5:
            risk_score += 10
            risk_factors.append(f'Multiple open ports ({total_open})')
        
        # Check geolocation
        geo = analysis.get('geolocation', {})
        country = geo.get('country', '').upper()
        high_risk_countries = ['UNKNOWN', 'NORTH KOREA', 'IRAN', 'RUSSIA', 'CHINA']  # Example list
        if country in high_risk_countries:
            risk_score += 15
            risk_factors.append(f'High-risk country: {country}')
        
        # Check reverse DNS
        reverse_dns = analysis.get('reverse_dns', {})
        if not reverse_dns.get('success'):
            risk_score += 5
            risk_factors.append('No reverse DNS record')
        else:
            hostname = reverse_dns.get('hostname', '').lower()
            suspicious_keywords = ['bot', 'proxy', 'vpn', 'tor', 'anonymous', 'malware', 'spam']
            if any(keyword in hostname for keyword in suspicious_keywords):
                risk_score += 25
                risk_factors.append(f'Suspicious hostname: {hostname}')
        
        analysis['risk_factors'] = risk_factors
        return min(risk_score, 100)  # Cap at 100
    
    def batch_analyze_ips(self, ip_list: List[str]) -> Dict:
        """Analyze multiple IP addresses in batch"""
        results = {
            'timestamp': datetime.now().isoformat(),
            'total_ips': len(ip_list),
            'results': [],
            'summary': {
                'successful': 0,
                'failed': 0,
                'high_risk': 0,
                'medium_risk': 0,
                'low_risk': 0,
                'private_ips': 0,
                'public_ips': 0
            }
        }
        
        def analyze_single_ip(ip):
            return self.analyze_ip(ip)
        
        # Use threading for batch analysis
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_ip = {executor.submit(analyze_single_ip, ip): ip for ip in ip_list}
            
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    result = future.result(timeout=30)
                    results['results'].append(result)
                    
                    # Update summary
                    if 'error' not in result:
                        results['summary']['successful'] += 1
                        
                        risk_score = result.get('risk_score', 0)
                        if risk_score >= 70:
                            results['summary']['high_risk'] += 1
                        elif risk_score >= 40:
                            results['summary']['medium_risk'] += 1
                        else:
                            results['summary']['low_risk'] += 1
                        
                        if result.get('is_private'):
                            results['summary']['private_ips'] += 1
                        else:
                            results['summary']['public_ips'] += 1
                    else:
                        results['summary']['failed'] += 1
                        
                except Exception as e:
                    results['results'].append({
                        'ip_address': ip,
                        'error': str(e),
                        'timestamp': datetime.now().isoformat()
                    })
                    results['summary']['failed'] += 1
        
        return results
    
    def get_local_network_info(self) -> Dict:
        """Get local network interface information"""
        try:
            import psutil
            
            network_info = {
                'interfaces': [],
                'connections': [],
                'timestamp': datetime.now().isoformat()
            }
            
            # Get network interfaces
            for interface, addrs in psutil.net_if_addrs().items():
                interface_info = {
                    'interface': interface,
                    'addresses': []
                }
                
                for addr in addrs:
                    if addr.family == socket.AF_INET:  # IPv4
                        interface_info['addresses'].append({
                            'type': 'IPv4',
                            'address': addr.address,
                            'netmask': addr.netmask,
                            'broadcast': addr.broadcast
                        })
                    elif addr.family == socket.AF_INET6:  # IPv6
                        interface_info['addresses'].append({
                            'type': 'IPv6',
                            'address': addr.address,
                            'netmask': addr.netmask
                        })
                
                network_info['interfaces'].append(interface_info)
            
            # Get active connections
            connections = psutil.net_connections(kind='inet')
            for conn in connections[:20]:  # Limit to first 20 connections
                if conn.raddr:  # Only include connections with remote address
                    network_info['connections'].append({
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}",
                        'status': conn.status,
                        'family': 'IPv4' if conn.family == socket.AF_INET else 'IPv6',
                        'type': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
                    })
            
            return network_info
            
        except ImportError:
            return {'error': 'psutil library not available'}
        except Exception as e:
            return {'error': f'Failed to get network info: {str(e)}'}
    
    def trace_route(self, target_ip: str, max_hops: int = 15) -> Dict:
        """Perform traceroute to target IP"""
        try:
            system = platform.system().lower()
            
            if system == "windows":
                cmd = ["tracert", "-h", str(max_hops), target_ip]
            else:
                cmd = ["traceroute", "-m", str(max_hops), target_ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            return {
                'target': target_ip,
                'timestamp': datetime.now().isoformat(),
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr if result.returncode != 0 else None,
                'hops': self._parse_traceroute_output(result.stdout, system)
            }
            
        except subprocess.TimeoutExpired:
            return {
                'target': target_ip,
                'error': 'Traceroute timed out',
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'target': target_ip,
                'error': f'Traceroute failed: {str(e)}',
                'timestamp': datetime.now().isoformat()
            }
    
    def _parse_traceroute_output(self, output: str, system: str) -> List[Dict]:
        """Parse traceroute output into structured data"""
        hops = []
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Basic parsing - can be enhanced for different OS formats
            if system == "windows":
                # Windows tracert format
                match = re.match(r'\s*(\d+)\s+(<?\d+\s*ms|\*)\s+(<?\d+\s*ms|\*)\s+(<?\d+\s*ms|\*)\s+(.+)', line)
                if match:
                    hop_num = int(match.group(1))
                    target = match.group(5).strip()
                    hops.append({
                        'hop': hop_num,
                        'target': target,
                        'times': [match.group(2), match.group(3), match.group(4)]
                    })
            else:
                # Unix traceroute format
                match = re.match(r'\s*(\d+)\s+(.+)', line)
                if match:
                    hop_num = int(match.group(1))
                    rest = match.group(2).strip()
                    hops.append({
                        'hop': hop_num,
                        'data': rest
                    })
        
        return hops
