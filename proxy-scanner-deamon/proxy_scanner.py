import asyncio
import ipaddress
import json
import logging
import os
import signal
import sys
import random
from datetime import datetime
from typing import Optional, List
import aiohttp
from aiohttp import ClientTimeout

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('proxy_scanner.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('ProxyScanner')

class IPGenerator:
    """Random IP generator that excludes private/reserved ranges"""
    
    def __init__(self):
        # Private and reserved IP ranges to exclude
        self.excluded_ranges = [
            ipaddress.IPv4Network('0.0.0.0/8'),        # Current network
            ipaddress.IPv4Network('10.0.0.0/8'),       # Private network
            ipaddress.IPv4Network('100.64.0.0/10'),    # Shared Address Space
            ipaddress.IPv4Network('127.0.0.0/8'),      # Loopback
            ipaddress.IPv4Network('169.254.0.0/16'),   # Link-local
            ipaddress.IPv4Network('172.16.0.0/12'),    # Private network
            ipaddress.IPv4Network('192.0.0.0/24'),     # IETF Protocol Assignments
            ipaddress.IPv4Network('192.0.2.0/24'),     # TEST-NET-1
            ipaddress.IPv4Network('192.88.99.0/24'),   # 6to4 Relay Anycast
            ipaddress.IPv4Network('192.168.0.0/16'),   # Private network
            ipaddress.IPv4Network('198.18.0.0/15'),    # Network Interconnect Benchmark
            ipaddress.IPv4Network('198.51.100.0/24'),  # TEST-NET-2
            ipaddress.IPv4Network('203.0.113.0/24'),   # TEST-NET-3
            ipaddress.IPv4Network('224.0.0.0/4'),      # Multicast
            ipaddress.IPv4Network('240.0.0.0/4'),      # Reserved
            ipaddress.IPv4Network('255.255.255.255/32') # Limited Broadcast
        ]
    
    def is_excluded(self, ip_int: int) -> bool:
        """Check if IP is in excluded ranges"""
        try:
            ip_addr = ipaddress.IPv4Address(ip_int)
            
            # Check against excluded ranges
            for network in self.excluded_ranges:
                if ip_addr in network:
                    return True
            return False
        except:
            return True  # Invalid IP, exclude it
    
    def generate_random_public_ip(self) -> Optional[int]:
        """Generate a random public IP address"""
        max_attempts = 1000
        attempts = 0
        
        while attempts < max_attempts:
            # Generate random IP in the valid IPv4 range (1.0.0.0 to 223.255.255.254)
            # Avoiding 0.x.x.x, 224-255.x.x.x ranges which are problematic
            ip_int = random.randint(16777216, 3758096383)  # 1.0.0.0 to 223.255.255.255
            
            if not self.is_excluded(ip_int):
                return ip_int
            attempts += 1
            
        return None

class ProxyScanner:
    def __init__(self, config_file: str = 'scanner_config.json'):
        self.config_file = config_file
        self.load_config()
        
        # Components
        self.ip_generator = IPGenerator()
        
        # Scanner state
        self.running = False
        self.scanned_count = 0
        self.found_proxies = []
        self.session = None
        
        # Progress tracking
        self.progress_file = 'scan_progress.json'
        self.results_file = 'found_proxies.txt'  # <-- FOUND PROXIES SAVED HERE
        
        # Load previous progress
        self.load_progress()
        
    def load_config(self):
        """Load configuration from JSON file or create default"""
        default_config = {
            "scan_ports": [80, 443, 8080, 3128, 1080, 9050, 9051, 8000, 8888, 3129],
            "timeout": 5,
            "concurrent_ips": 1000,
            "batch_size": 5000,
            "scan_delay": 0,
            "connection_limit": 5000,
            "test_url": "http://httpbin.org/ip"
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
            logger.error(f"Error loading config file: {e}. Using default configuration.")
            self.config = default_config
    
    def load_progress(self):
        """Load scan progress from file"""
        if os.path.exists(self.progress_file):
            try:
                with open(self.progress_file, 'r') as f:
                    data = json.load(f)
                    self.scanned_count = data.get('scanned_count', 0)
                    logger.info(f"Loaded progress: {self.scanned_count} IPs scanned")
            except Exception as e:
                logger.error(f"Failed to load progress: {e}")
    
    def save_progress(self):
        """Save scan progress to file"""
        try:
            data = {
                'scanned_count': self.scanned_count,
                'timestamp': datetime.now().isoformat()
            }
            with open(self.progress_file, 'w') as f:
                json.dump(data, f)
        except Exception as e:
            logger.error(f"Failed to save progress: {e}")
    
    def save_proxy(self, proxy: str, proxy_type: str = "unknown"):
        """Append found proxy to results file with timestamp and type"""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            proxy_info = f"{proxy} | {proxy_type} | {timestamp}\n"
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.results_file) if os.path.dirname(self.results_file) else '.', exist_ok=True)
            
            # Append to file (never overwrite)
            with open(self.results_file, 'a') as f:  # <-- APPEND MODE
                f.write(proxy_info)
                
            self.found_proxies.append(proxy)
            logger.info(f"Found working proxy: {proxy} ({proxy_type})")
        except Exception as e:
            logger.error(f"Failed to save proxy {proxy}: {e}")
    
    async def test_http_proxy(self, ip: str, port: int) -> bool:
        """Test if IP:port is a working HTTP proxy"""
        try:
            timeout = ClientTimeout(total=self.config['timeout'], connect=2)
            
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
                async with session.get(
                    self.config['test_url'],
                    proxy=f'http://{ip}:{port}',
                    timeout=timeout
                ) as response:
                    if response.status == 200:
                        content = await response.text()
                        # Verify the proxy actually forwarded the request
                        if 'origin' in content.lower() or ip in content:
                            return True
        except Exception as e:
            logger.debug(f"HTTP proxy test failed for {ip}:{port} - {str(e)[:100]}")
        return False
    
    async def test_socks_proxy(self, ip: str, port: int) -> bool:
        """Test if IP:port is a working SOCKS proxy (basic connectivity)"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=2
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception as e:
            logger.debug(f"SOCKS proxy test failed for {ip}:{port} - {str(e)[:100]}")
        return False
    
    async def test_proxy(self, ip: str, port: int) -> Optional[tuple]:
        """Test if IP:port is a working proxy and return (proxy_string, type)"""
        if not self.running:
            return None
            
        # Test HTTP proxy first
        if await self.test_http_proxy(ip, port):
            return (f"{ip}:{port}", "HTTP")
            
        # Test SOCKS proxy
        if await self.test_socks_proxy(ip, port):
            return (f"{ip}:{port}", "SOCKS")
            
        return None
    
    async def scan_ip(self, ip: str) -> List[tuple]:
        """Scan a single IP for open proxy ports - MULTIPLE PORTS PER IP"""
        found_proxies = []
        
        # Test ALL configured ports for this IP concurrently
        tasks = []
        for port in self.config['scan_ports']:
            task = asyncio.create_task(self.test_proxy(ip, port))
            tasks.append(task)
        
        # Wait for all port tests to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for result in results:
            if isinstance(result, tuple) and result is not None:
                found_proxies.append(result)
                
        return found_proxies
    
    async def scan_batch(self, ips: List[str]):
        """Scan a batch of IPs with maximum concurrency"""
        if not self.running:
            return
            
        semaphore = asyncio.Semaphore(self.config['concurrent_ips'])
        
        async def limited_scan(ip):
            async with semaphore:
                if not self.running:
                    return []
                proxies = await self.scan_ip(ip)
                return proxies
        
        # Create all tasks - each IP tests ALL ports
        tasks = [asyncio.create_task(limited_scan(ip)) for ip in ips]
        
        # Execute with high concurrency
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process found proxies
        for result in results:
            if isinstance(result, list):
                for proxy_info in result:
                    if isinstance(proxy_info, tuple) and len(proxy_info) == 2:
                        proxy_string, proxy_type = proxy_info
                        self.save_proxy(proxy_string, proxy_type)
    
    def generate_random_ips(self, count: int) -> List[str]:
        """Generate random public IPs"""
        ips = []
        generated = 0
        attempts = 0
        max_attempts = count * 100  # Prevent infinite loops
        
        while generated < count and attempts < max_attempts:
            ip_int = self.ip_generator.generate_random_public_ip()
            if ip_int is not None:
                ips.append(str(ipaddress.IPv4Address(ip_int)))
                generated += 1
            attempts += 1
            
        return ips
    
    async def run_scan(self):
        """Main scanning loop - optimized for speed with random IPs"""
        logger.info("Starting high-speed random proxy scan...")
        logger.info(f"Found proxies will be saved to: {self.results_file}")  # <-- LOCATION INFO
        
        batches_scanned = 0
        
        while self.running:
            try:
                # Generate random IPs for this batch
                ips_to_scan = self.generate_random_ips(self.config['batch_size'])
                
                if not ips_to_scan:
                    logger.warning("Failed to generate random IPs. Retrying...")
                    await asyncio.sleep(1)
                    continue
                
                logger.info(f"Scanning random batch {batches_scanned + 1} with {len(ips_to_scan)} IPs")
                logger.info(f"Each IP will be tested on {len(self.config['scan_ports'])} ports")
                
                # Scan the batch
                await self.scan_batch(ips_to_scan)
                
                # Update progress
                self.scanned_count += len(ips_to_scan)
                batches_scanned += 1
                self.save_progress()
                
                # Log progress periodically
                if batches_scanned % 5 == 0:
                    logger.info(f"Scanned {self.scanned_count:,} IPs in {batches_scanned} batches | Found {len(self.found_proxies)} proxies")
                
            except Exception as e:
                logger.error(f"Error in scan loop: {e}")
                await asyncio.sleep(0.1)
    
    async def start(self):
        """Start the scanner daemon with optimized settings"""
        self.running = True
        
        # Setup signal handlers for graceful shutdown
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, lambda: asyncio.create_task(self.stop()))
        
        logger.info("High-speed random proxy scanner started")
        await self.run_scan()
    
    async def stop(self):
        """Stop the scanner gracefully"""
        logger.info("Stopping proxy scanner...")
        self.running = False
        
        self.save_progress()
        logger.info(f"Proxy scanner stopped. Total proxies found: {len(self.found_proxies)}")

async def main():
    """Main entry point"""
    scanner = ProxyScanner()
    
    try:
        await scanner.start()
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    finally:
        await scanner.stop()

if __name__ == "__main__":
    # Run multiple instances if specified
    if len(sys.argv) > 1:
        instance_id = sys.argv[1]
        logger = logging.getLogger(f'ProxyScanner-{instance_id}')
    
    asyncio.run(main())
