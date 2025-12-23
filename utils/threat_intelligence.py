# utils/threat_intelligence.py
import requests
import hashlib
import time
import json
from datetime import datetime, timedelta
import streamlit as st
import os
from typing import Dict, List, Optional
import base64

class ThreatIntelligence:
    """Threat intelligence integration for IP, domain, and file hash lookups"""

    def __init__(self, cache_file="ti_cache.json", cache_ttl_hours=24):
        """Initialize threat intelligence client"""
        self.virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CyberSecure-Dashboard/1.0'
        })
        self.cache_file = cache_file
        self.cache_ttl = timedelta(hours=cache_ttl_hours)
        self.cache = self._load_cache()
        # Timestamps of recent requests for rate limiting
        self.request_timestamps: List[float] = []

    def _load_cache(self):
        """Load cache from file"""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
            except (IOError, json.JSONDecodeError) as e:
                st.warning(f"Could not load cache file: {e}")
                return {}
        return {}

    def _save_cache(self):
        """Save cache to file"""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f)
        except IOError as e:
            st.warning(f"Could not save cache file: {e}")

    def _check_rate_limit(self, service='virustotal'):
        """
        Enforce rate limits using a rolling window based on timestamps.
        This is a more robust method than a simple counter.
        """
        # Settings for VirusTotal Public API v3
        MAX_REQUESTS = 4
        PERIOD_SECONDS = 60.0

        now = time.time()

        # Remove timestamps older than the period
        self.request_timestamps = [t for t in self.request_timestamps if now - t < PERIOD_SECONDS]

        # If we have hit the maximum requests, we must wait
        if len(self.request_timestamps) >= MAX_REQUESTS:
            # The oldest request is the first one in the list
            oldest_request_time = self.request_timestamps[0]
            
            # Calculate the time to wait until the oldest request expires from the window
            time_to_wait = (oldest_request_time + PERIOD_SECONDS) - now
            
            if time_to_wait > 0:
                st.info(f"Rate limit reached for {service}. Waiting {time_to_wait:.1f} seconds...")
                time.sleep(time_to_wait)
        
        # Log the new request time
        self.request_timestamps.append(time.time())


    def _is_cache_valid(self, cache_entry):
        """Check if cache entry is still valid"""
        if not cache_entry:
            return False

        cache_time = datetime.fromisoformat(cache_entry.get('timestamp', ''))
        return datetime.now() - cache_time < self.cache_ttl

    def _cache_result(self, key, data):
        """Cache API result"""
        self.cache[key] = {
            'timestamp': datetime.now().isoformat(),
            'data': data
        }
        self._save_cache()

    def lookup_file_hash(self, file_hash: str, hash_type: str = 'sha256') -> Dict:
        """Lookup file hash in VirusTotal"""
        try:
            # Check cache first
            cache_key = f"file_{hash_type}_{file_hash}"
            if cache_key in self.cache and self._is_cache_valid(self.cache[cache_key]):
                cached_result = self.cache[cache_key]['data']
                cached_result['source'] = 'cache'
                return cached_result

            if not self.virustotal_api_key:
                return {
                    'error': 'VirusTotal API key not configured',
                    'hash': file_hash,
                    'hash_type': hash_type,
                    'source': 'error'
                }

            self._check_rate_limit('virustotal')

            # VirusTotal API v3
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {
                'x-apikey': self.virustotal_api_key
            }

            response = self.session.get(url, headers=headers, timeout=30)

            if response.status_code == 200:
                data = response.json()
                result = self._parse_virustotal_file_response(data, file_hash, hash_type)
                self._cache_result(cache_key, result)
                return result
            elif response.status_code == 404:
                result = {
                    'hash': file_hash,
                    'hash_type': hash_type,
                    'found': False,
                    'message': 'File hash not found in VirusTotal database',
                    'source': 'virustotal',
                    'timestamp': datetime.now().isoformat()
                }
                self._cache_result(cache_key, result)
                return result
            else:
                return {
                    'error': f'VirusTotal API error: {response.status_code}',
                    'hash': file_hash,
                    'hash_type': hash_type,
                    'source': 'error'
                }

        except requests.exceptions.RequestException as e:
            return {
                'error': f'Network error: {str(e)}',
                'hash': file_hash,
                'hash_type': hash_type,
                'source': 'error'
            }
        except Exception as e:
            return {
                'error': f'Unexpected error: {str(e)}',
                'hash': file_hash,
                'hash_type': hash_type,
                'source': 'error'
            }

    def _parse_virustotal_file_response(self, data: Dict, file_hash: str, hash_type: str) -> Dict:
        """Parse VirusTotal file response"""
        try:
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})

            result = {
                'hash': file_hash,
                'hash_type': hash_type,
                'found': True,
                'source': 'virustotal',
                'timestamp': datetime.now().isoformat(),
                'scan_date': attributes.get('last_analysis_date'),
                'detection_stats': {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'undetected': stats.get('undetected', 0),
                    'harmless': stats.get('harmless', 0),
                    'timeout': stats.get('timeout', 0),
                    'confirmed_timeout': stats.get('confirmed-timeout', 0),
                    'failure': stats.get('failure', 0),
                    'type_unsupported': stats.get('type-unsupported', 0)
                },
                'total_engines': sum(stats.values()),
                'detection_ratio': f"{stats.get('malicious', 0) + stats.get('suspicious', 0)}/{sum(stats.values())}",
                'file_info': {
                    'size': attributes.get('size'),
                    'type_description': attributes.get('type_description'),
                    'magic': attributes.get('magic'),
                    'md5': attributes.get('md5'),
                    'sha1': attributes.get('sha1'),
                    'sha256': attributes.get('sha256'),
                    'ssdeep': attributes.get('ssdeep'),
                    'vhash': attributes.get('vhash')
                },
                'names': attributes.get('names', []),
                'reputation': self._calculate_reputation_score(stats)
            }

            # Add detailed scan results
            scan_results = attributes.get('last_analysis_results', {})
            result['scan_results'] = {}

            for engine, details in scan_results.items():
                result['scan_results'][engine] = {
                    'category': details.get('category'),
                    'result': details.get('result'),
                    'version': details.get('version'),
                    'update': details.get('update')
                }

            return result

        except Exception as e:
            return {
                'error': f'Error parsing VirusTotal response: {str(e)}',
                'hash': file_hash,
                'hash_type': hash_type,
                'source': 'error'
            }

    def lookup_ip_address(self, ip_address: str) -> Dict:
        """Lookup IP address reputation"""
        try:
            # Check cache first
            cache_key = f"ip_{ip_address}"
            if cache_key in self.cache and self._is_cache_valid(self.cache[cache_key]):
                cached_result = self.cache[cache_key]['data']
                cached_result['source'] = 'cache'
                return cached_result

            if not self.virustotal_api_key:
                return {
                    'error': 'VirusTotal API key not configured',
                    'ip': ip_address,
                    'source': 'error'
                }

            self._check_rate_limit('virustotal')

            # VirusTotal API v3
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
            headers = {
                'x-apikey': self.virustotal_api_key
            }

            response = self.session.get(url, headers=headers, timeout=30)

            if response.status_code == 200:
                data = response.json()
                result = self._parse_virustotal_ip_response(data, ip_address)
                self._cache_result(cache_key, result)
                return result
            elif response.status_code == 404:
                result = {
                    'ip': ip_address,
                    'found': False,
                    'message': 'IP address not found in VirusTotal database',
                    'source': 'virustotal',
                    'timestamp': datetime.now().isoformat()
                }
                self._cache_result(cache_key, result)
                return result
            else:
                return {
                    'error': f'VirusTotal API error: {response.status_code}',
                    'ip': ip_address,
                    'source': 'error'
                }

        except requests.exceptions.RequestException as e:
            return {
                'error': f'Network error: {str(e)}',
                'ip': ip_address,
                'source': 'error'
            }
        except Exception as e:
            return {
                'error': f'Unexpected error: {str(e)}',
                'ip': ip_address,
                'source': 'error'
            }

    def _parse_virustotal_ip_response(self, data: Dict, ip_address: str) -> Dict:
        """Parse VirusTotal IP response"""
        try:
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})

            result = {
                'ip': ip_address,
                'found': True,
                'source': 'virustotal',
                'timestamp': datetime.now().isoformat(),
                'country': attributes.get('country'),
                'asn': attributes.get('asn'),
                'as_owner': attributes.get('as_owner'),
                'network': attributes.get('network'),
                'detection_stats': {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'undetected': stats.get('undetected', 0),
                    'harmless': stats.get('harmless', 0),
                    'timeout': stats.get('timeout', 0)
                },
                'total_engines': sum(stats.values()),
                'detection_ratio': f"{stats.get('malicious', 0) + stats.get('suspicious', 0)}/{sum(stats.values())}",
                'reputation': self._calculate_reputation_score(stats),
                'regional_internet_registry': attributes.get('regional_internet_registry'),
                'whois': attributes.get('whois'),
                'whois_date': attributes.get('whois_date')
            }

            # Add detected URLs if available
            if 'last_https_certificate' in attributes:
                cert = attributes['last_https_certificate']
                result['certificate_info'] = {
                    'issuer': cert.get('issuer'),
                    'subject': cert.get('subject'),
                    'validity': {
                        'not_before': cert.get('validity', {}).get('not_before'),
                        'not_after': cert.get('validity', {}).get('not_after')
                    }
                }

            return result

        except Exception as e:
            return {
                'error': f'Error parsing VirusTotal IP response: {str(e)}',
                'ip': ip_address,
                'source': 'error'
            }

    def lookup_domain(self, domain: str) -> Dict:
        """Lookup domain reputation"""
        try:
            # Check cache first
            cache_key = f"domain_{domain}"
            if cache_key in self.cache and self._is_cache_valid(self.cache[cache_key]):
                cached_result = self.cache[cache_key]['data']
                cached_result['source'] = 'cache'
                return cached_result

            if not self.virustotal_api_key:
                return {
                    'error': 'VirusTotal API key not configured',
                    'domain': domain,
                    'source': 'error'
                }

            self._check_rate_limit('virustotal')

            # VirusTotal API v3
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            headers = {
                'x-apikey': self.virustotal_api_key
            }

            response = self.session.get(url, headers=headers, timeout=30)

            if response.status_code == 200:
                data = response.json()
                result = self._parse_virustotal_domain_response(data, domain)
                self._cache_result(cache_key, result)
                return result
            elif response.status_code == 404:
                result = {
                    'domain': domain,
                    'found': False,
                    'message': 'Domain not found in VirusTotal database',
                    'source': 'virustotal',
                    'timestamp': datetime.now().isoformat()
                }
                self._cache_result(cache_key, result)
                return result
            else:
                return {
                    'error': f'VirusTotal API error: {response.status_code}',
                    'domain': domain,
                    'source': 'error'
                }

        except requests.exceptions.RequestException as e:
            return {
                'error': f'Network error: {str(e)}',
                'domain': domain,
                'source': 'error'
            }
        except Exception as e:
            return {
                'error': f'Unexpected error: {str(e)}',
                'domain': domain,
                'source': 'error'
            }

    def _parse_virustotal_domain_response(self, data: Dict, domain: str) -> Dict:
        """Parse VirusTotal domain response"""
        try:
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})

            result = {
                'domain': domain,
                'found': True,
                'source': 'virustotal',
                'timestamp': datetime.now().isoformat(),
                'categories': attributes.get('categories', {}),
                'creation_date': attributes.get('creation_date'),
                'last_update_date': attributes.get('last_update_date'),
                'registrar': attributes.get('registrar'),
                'detection_stats': {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'undetected': stats.get('undetected', 0),
                    'harmless': stats.get('harmless', 0),
                    'timeout': stats.get('timeout', 0)
                },
                'total_engines': sum(stats.values()),
                'detection_ratio': f"{stats.get('malicious', 0) + stats.get('suspicious', 0)}/{sum(stats.values())}",
                'reputation': self._calculate_reputation_score(stats),
                'whois': attributes.get('whois'),
                'whois_date': attributes.get('whois_date')
            }

            # Add DNS resolution info
            if 'last_dns_records' in attributes:
                result['dns_records'] = attributes['last_dns_records']

            return result

        except Exception as e:
            return {
                'error': f'Error parsing VirusTotal domain response: {str(e)}',
                'domain': domain,
                'source': 'error'
            }

    def _calculate_reputation_score(self, stats: Dict) -> Dict:
        """Calculate reputation score based on detection stats"""
        total = sum(stats.values())
        if total == 0:
            return {'score': 0, 'level': 'UNKNOWN'}

        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        harmful = malicious + suspicious

        # Calculate percentage of engines that detected as harmful
        harmful_percentage = (harmful / total) * 100

        if harmful_percentage >= 10:
            level = 'MALICIOUS'
            score = 100
        elif harmful_percentage >= 5:
            level = 'SUSPICIOUS'
            score = 75
        elif harmful_percentage >= 1:
            level = 'QUESTIONABLE'
            score = 50
        else:
            level = 'CLEAN'
            score = 0

        return {
            'score': score,
            'level': level,
            'harmful_detections': harmful,
            'total_scanned': total,
            'harmful_percentage': harmful_percentage
        }

    def batch_lookup(self, indicators: List[Dict]) -> Dict:
        """Perform batch lookup of multiple indicators"""
        results = {
            'timestamp': datetime.now().isoformat(),
            'total_indicators': len(indicators),
            'results': [],
            'summary': {
                'successful': 0,
                'failed': 0,
                'cached': 0,
                'malicious': 0,
                'suspicious': 0,
                'clean': 0
            }
        }

        for indicator in indicators:
            indicator_type = indicator.get('type')
            value = indicator.get('value')

            if indicator_type == 'hash' and value:
                result = self.lookup_file_hash(value, indicator.get('hash_type', 'sha256'))
            elif indicator_type == 'ip' and value:
                result = self.lookup_ip_address(value)
            elif indicator_type == 'domain' and value:
                result = self.lookup_domain(value)
            else:
                result = {'error': f'Unsupported indicator type: {indicator_type}'}

            # Update summary
            if 'error' not in result:
                results['summary']['successful'] += 1
                if result.get('source') == 'cache':
                    results['summary']['cached'] += 1

                reputation = result.get('reputation', {})
                level = reputation.get('level', 'UNKNOWN')
                if level == 'MALICIOUS':
                    results['summary']['malicious'] += 1
                elif level in ['SUSPICIOUS', 'QUESTIONABLE']:
                    results['summary']['suspicious'] += 1
                elif level == 'CLEAN':
                    results['summary']['clean'] += 1
            else:
                results['summary']['failed'] += 1

            results['results'].append({
                'indicator': indicator,
                'result': result
            })

        return results

    def get_api_status(self) -> Dict:
        """Get API status and quota information"""
        status = {
            'timestamp': datetime.now().isoformat(),
            'apis': {}
        }

        # VirusTotal status
        if self.virustotal_api_key:
            status['apis']['virustotal'] = {
                'configured': True,
                'rate_limit': {
                    'requests_this_minute': len(self.request_timestamps)
                },
                'cache_size': len(
                    [k for k in self.cache.keys() if not k.startswith('ip_') and not k.startswith('domain_')])
            }
        else:
            status['apis']['virustotal'] = {
                'configured': False,
                'message': 'API key not configured'
            }

        # Cache statistics
        status['cache_stats'] = {
            'total_entries': len(self.cache),
            'valid_entries': len([k for k, v in self.cache.items() if self._is_cache_valid(v)])
        }

        return status
