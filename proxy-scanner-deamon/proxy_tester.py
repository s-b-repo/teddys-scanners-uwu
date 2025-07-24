#!/usr/bin/env python3
"""
Advanced Proxy Tester with WHOIS/ORG Detection
Tests proxies against multiple sites and checks for government/LEA registrations
"""

import asyncio
import aiohttp
import json
import logging
import sys
import os
from datetime import datetime
from typing import List, Tuple, Dict, Optional
from urllib.parse import urlparse
import re
import socket
import subprocess
import ipaddress

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('proxy_tester.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('ProxyTester')

class ProxyTester:
    def __init__(self, config_file: str = 'proxy_tester_config.json'):
        self.config_file = config_file
        self.load_config()
        
        # Test sites - must return identifiable content
        self.test_sites = [
            "http://httpbin.org/ip",
            "http://httpbin.org/user-agent",
            "https://api.ipify.org?format=json",
            "https://httpbin.org/headers"
        ]
        
        # Quality validation patterns
        self.quality_patterns = {
            'httpbin.org/ip': r'"origin"\s*:\s*"[^"]*"',
            'httpbin.org/user-agent': r'"user-agent"\s*:\s*"[^"]*"',
            'api.ipify.org': r'\{"ip":"[^"]+"\}',
            'httpbin.org/headers': r'"Headers"\s*:\s*\{'
        }
        
        # Suspicious organizations/government entities (case insensitive)
        self.suspicious_orgs = [
            'government', 'federal', 'department', 'agency', 'police', 'sheriff',
            'intelligence', 'defense', 'military', 'army', 'navy', 'air force',
            'cia', 'fbi', 'nsa', 'dhs', 'dea', 'atf', 'sec', 'fda', 'fcc',
            'irs', 'uspto', 'fema', 'nasa', 'doe', 'dos', 'dod', 'doc', 'hud',
            'va', 'ssa', 'epa', 'nhtsa', 'faa', 'tsa', 'cbp', 'ice', 'uscis',
            'bureau', 'administration', 'commission', 'authority', 'force',
            'law enforcement', 'court', 'justice', 'federal reserve', 'treasury',
            'state department', 'white house', 'pentagon', 'capitol', 'congress',
            'senate', 'house of representatives', 'supreme court', 'federal court'
        ]
        
    def load_config(self):
        """Load configuration from JSON file or create default"""
        default_config = {
            "timeout": 10,
            "concurrent_tests": 50,
            "min_success_sites": 2,
            "check_org": True,
            "output_file": "working_proxies.txt",
            "failed_file": "failed_proxies.txt",
            "suspicious_file": "suspicious_proxies.txt"
        }
        
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                    self.config = {**default_config, **loaded_config}
            else:
                self.config = default_config
                with open(self.config_file, 'w') as f:
                    json.dump(self.config, f, indent=2)
        except Exception as e:
            logger.error(f"Error loading config: {e}. Using defaults.")
            self.config = default_config
    
    def load_proxies(self, input_file: str) -> List[str]:
        """Load proxies from file"""
        proxies = []
        try:
            with open(input_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Extract proxy from various formats
                        proxy = self.extract_proxy(line)
                        if proxy:
                            proxies.append(proxy)
        except FileNotFoundError:
            logger.error(f"Input file {input_file} not found")
        except Exception as e:
            logger.error(f"Error reading proxies: {e}")
            
        logger.info(f"Loaded {len(proxies)} proxies from {input_file}")
        return proxies
    
    def extract_proxy(self, line: str) -> str:
        """Extract proxy IP:PORT from various line formats"""
        # Handle formats like: "IP:PORT | TYPE | TIMESTAMP" or just "IP:PORT"
        if '|' in line:
            parts = line.split('|')
            proxy_part = parts[0].strip()
        else:
            proxy_part = line.strip()
            
        # Validate IP:PORT format
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}$', proxy_part):
            return proxy_part
        return None
    
    def save_proxy_result(self, proxy: str, result_type: str, details: str = ""):
        """Save proxy test result to appropriate file"""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Determine output file based on result type
            if result_type == "WORKING":
                output_file = self.config['output_file']
            elif result_type == "SUSPICIOUS":
                output_file = self.config['suspicious_file']
            else:  # FAILED
                output_file = self.config['failed_file']
            
            result_line = f"{proxy} | {timestamp} | {result_type} | {details}\n"
            
            with open(output_file, 'a') as f:
                f.write(result_line)
                
        except Exception as e:
            logger.error(f"Error saving proxy {proxy}: {e}")
    
    def get_ip_from_proxy(self, proxy: str) -> Optional[str]:
        """Extract IP from proxy string"""
        try:
            ip = proxy.split(':')[0]
            # Validate IP
            ipaddress.ip_address(ip)
            return ip
        except:
            return None
    
    def check_whois_org(self, ip: str) -> Tuple[bool, str]:
        """Check WHOIS info for suspicious organizations"""
        if not self.config.get('check_org', True):
            return False, ""
        
        try:
            # Use whois command
            result = subprocess.run(
                ['whois', ip],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                whois_data = result.stdout.lower()
                
                # Check for suspicious organizations
                found_orgs = []
                for org in self.suspicious_orgs:
                    if org in whois_data:
                        found_orgs.append(org)
                
                if found_orgs:
                    return True, f"Suspicious org(s): {', '.join(found_orgs)}"
                
                # Check for common government/LEA indicators
                gov_indicators = ['gov', 'mil', 'federal', 'government']
                for indicator in gov_indicators:
                    if indicator in whois_data:
                        found_orgs.append(indicator)
                
                if found_orgs:
                    return True, f"Government/LEA indicator(s): {', '.join(found_orgs)}"
                    
            return False, ""
            
        except subprocess.TimeoutExpired:
            return False, "WHOIS timeout"
        except FileNotFoundError:
            logger.warning("whois command not found. Install whois package for organization checking.")
            return False, "whois not available"
        except Exception as e:
            return False, f"WHOIS error: {str(e)[:50]}"
    
    async def test_single_site(self, session: aiohttp.ClientSession, proxy: str, site: str) -> Tuple[bool, str, int]:
        """Test proxy against a single site"""
        try:
            proxy_url = f"http://{proxy}"
            
            async with session.get(
                site,
                proxy=proxy_url,
                timeout=aiohttp.ClientTimeout(total=self.config['timeout'])
            ) as response:
                status = response.status
                content = await response.text()
                
                # Check if response is valid
                if status == 200:
                    # Validate content quality
                    site_key = urlparse(site).netloc
                    pattern = self.quality_patterns.get(site_key, '')
                    
                    if pattern and re.search(pattern, content, re.IGNORECASE):
                        return True, content[:200], status  # Return first 200 chars
                    elif not pattern:  # No specific pattern, just check if content exists
                        if len(content.strip()) > 10:
                            return True, content[:200], status
                    
                return False, f"Status: {status}", status
                
        except asyncio.TimeoutError:
            return False, "TIMEOUT", 0
        except Exception as e:
            return False, str(e)[:100], 0
    
    async def test_proxy(self, proxy: str) -> Tuple[str, str]:
        """Test proxy against all sites and check organization"""
        try:
            # First check organization/WHOIS
            ip = self.get_ip_from_proxy(proxy)
            if ip:
                is_suspicious, org_details = self.check_whois_org(ip)
                if is_suspicious:
                    return "SUSPICIOUS", f"ORGANIZATION ALERT: {org_details}"
            
            # Test proxy functionality
            timeout = aiohttp.ClientTimeout(total=self.config['timeout'])
            connector = aiohttp.TCPConnector(
                limit=0,
                limit_per_host=1,
                use_dns_cache=False,
                ttl_dns_cache=300,
                keepalive_timeout=0,
                force_close=True
            )
            
            async with aiohttp.ClientSession(
                timeout=timeout,
                connector=connector
            ) as session:
                # Test all sites concurrently
                tasks = [
                    self.test_single_site(session, proxy, site)
                    for site in self.test_sites
                ]
                
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Process results
                success_count = 0
                failed_sites = []
                success_sites = []
                
                for i, result in enumerate(results):
                    site = self.test_sites[i]
                    site_name = urlparse(site).netloc
                    
                    if isinstance(result, tuple) and len(result) == 3:
                        success, content, status = result
                        if success:
                            success_count += 1
                            success_sites.append(site_name)
                        else:
                            failed_sites.append(f"{site_name}({status})")
                    else:
                        failed_sites.append(f"{site_name}(ERROR)")
                
                # Determine if proxy is working
                is_working = success_count >= self.config['min_success_sites']
                
                # Create detailed result
                if is_working:
                    details = f"Passed {success_count}/{len(self.test_sites)} sites: {', '.join(success_sites)}"
                    return "WORKING", details
                else:
                    details = f"Failed sites: {', '.join(failed_sites) if failed_sites else 'All sites failed'}"
                    return "FAILED", details
                
        except Exception as e:
            return "FAILED", f"Proxy test error: {str(e)[:100]}"
    
    async def test_proxies_batch(self, proxies: List[str]) -> Dict[str, Tuple[str, str]]:
        """Test a batch of proxies"""
        semaphore = asyncio.Semaphore(self.config['concurrent_tests'])
        
        async def limited_test(proxy):
            async with semaphore:
                return await self.test_proxy(proxy)
        
        # Create tasks
        tasks = [limited_test(proxy) for proxy in proxies]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        proxy_results = {}
        for i, result in enumerate(results):
            proxy = proxies[i]
            if isinstance(result, tuple) and len(result) == 2:
                status, details = result
                proxy_results[proxy] = (status, details)
            else:
                proxy_results[proxy] = ("FAILED", f"Test error: {str(result)[:100]}")
                
        return proxy_results
    
    async def run_test(self, input_file: str = 'found_proxies.txt'):
        """Run proxy testing"""
        logger.info("Starting advanced proxy testing...")
        logger.info(f"Testing against sites: {', '.join([urlparse(s).netloc for s in self.test_sites])}")
        logger.info(f"WHOIS organization checking: {'ENABLED' if self.config.get('check_org', True) else 'DISABLED'}")
        
        # Load proxies
        proxies = self.load_proxies(input_file)
        if not proxies:
            logger.error("No proxies to test")
            return
        
        # Test in batches
        batch_size = self.config['concurrent_tests'] * 2
        working_count = 0
        failed_count = 0
        suspicious_count = 0
        
        for i in range(0, len(proxies), batch_size):
            batch = proxies[i:i + batch_size]
            logger.info(f"Testing batch {i//batch_size + 1}: {len(batch)} proxies")
            
            # Test batch
            results = await self.test_proxies_batch(batch)
            
            # Process results
            for proxy, (status, details) in results.items():
                self.save_proxy_result(proxy, status, details)
                
                if status == "WORKING":
                    working_count += 1
                    logger.info(f"✓ WORKING: {proxy} - {details}")
                elif status == "SUSPICIOUS":
                    suspicious_count += 1
                    logger.warning(f"⚠ SUSPICIOUS: {proxy} - {details}")
                else:  # FAILED
                    failed_count += 1
                    logger.debug(f"✗ FAILED: {proxy} - {details}")
            
            # Progress update
            tested_so_far = i + len(batch)
            logger.info(f"Progress: {tested_so_far}/{len(proxies)} proxies tested. "
                       f"Working: {working_count}, Failed: {failed_count}, Suspicious: {suspicious_count}")
        
        # Final summary
        logger.info("=" * 60)
        logger.info("ADVANCED PROXY TESTING COMPLETE")
        logger.info(f"Total tested: {len(proxies)}")
        logger.info(f"Working proxies: {working_count}")
        logger.info(f"Failed proxies: {failed_count}")
        logger.info(f"Suspicious proxies (ORG ALERT): {suspicious_count}")
        logger.info(f"Success rate: {working_count/len(proxies)*100:.1f}%")
        logger.info(f"Working proxies saved to: {self.config['output_file']}")
        logger.info(f"Failed proxies saved to: {self.config['failed_file']}")
        logger.info(f"Suspicious proxies saved to: {self.config['suspicious_file']}")
        logger.info("=" * 60)

async def main():
    """Main entry point"""
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
    else:
        input_file = 'found_proxies.txt'
    
    tester = ProxyTester()
    
    try:
        await tester.run_test(input_file)
    except KeyboardInterrupt:
        logger.info("Testing interrupted by user")
    except Exception as e:
        logger.error(f"Error during testing: {e}")

if __name__ == "__main__":
    asyncio.run(main())