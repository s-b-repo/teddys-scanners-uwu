import asyncio
import aiohttp
import ipaddress
import os
import sys
import time

OUTPUT_FILE = "working_proxies.txt"
PROGRESS_FILE = "scan_progress.magic"
STATUS_FILE = "scan_status.txt"

COMMON_PORTS = [
    80, 81, 1080, 3128, 8000, 8080, 8081, 8888, 9000, 9999, 10000, 10800,
    3127, 3129, 3130, 4444, 5000, 6666, 7000, 8082, 8083, 8084, 8090, 8443
]
CONCURRENT_IPS = 50
TEST_SITES = ["http://example.com", "http://cheese.com"]

def is_public_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.version == 4 and ip_obj.is_global
    except ValueError:
        return False

def save_progress(progress: int):
    with open(PROGRESS_FILE, "w") as f:
        f.write(str(progress))

def load_progress() -> int:
    if os.path.exists(PROGRESS_FILE):
        with open(PROGRESS_FILE, "r") as f:
            return int(f.read().strip())
    return 0

def save_proxy(proxy: str, already_saved: set):
    if proxy in already_saved:
        return
    with open(OUTPUT_FILE, "a") as f:
        f.write(proxy + "\n")
    already_saved.add(proxy)

def load_saved_proxies() -> set:
    if os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, "r") as f:
            return set(line.strip() for line in f if line.strip())
    return set()

def save_status(ip_idx, ips_scanned, working_proxies):
    with open(STATUS_FILE, "w") as f:
        f.write(f"Current IP index: {ip_idx}\nIPs scanned: {ips_scanned}\nWorking proxies: {working_proxies}\nTime: {time.ctime()}")

async def test_proxy(ip, port, session):
    proxy_url = f"http://{ip}:{port}"
    for site in TEST_SITES:
        try:
            async with session.get(site, proxy=proxy_url, timeout=8) as resp:
                text = await resp.text()
                # Filter out proxies with "nginx" or "apache" in the response
                if resp.status != 200:
                    return False
                if "nginx" in text.lower() or "apache" in text.lower():
                    return False
        except Exception:
            return False
    return True

async def check_ip(ip, session, already_saved, stats):
    found = False
    for port in COMMON_PORTS:
        ok = await test_proxy(ip, port, session)
        stats['proxies_tested'] += 1
        if ok:
            found = True
            save_proxy(f"{ip}:{port}", already_saved)
            stats['working'] += 1
    stats['ips_scanned'] += 1

async def scanner(start_ip_idx, already_saved, stats):
    ip_idx = start_ip_idx
    total_ips = 2**32
    timeout = aiohttp.ClientTimeout(total=10)
    stats['start_time'] = time.time()
    async with aiohttp.ClientSession(timeout=timeout) as session:
        while ip_idx < total_ips:
            batch = []
            for _ in range(CONCURRENT_IPS):
                if ip_idx >= total_ips:
                    break
                ip = str(ipaddress.IPv4Address(ip_idx))
                if is_public_ip(ip):
                    batch.append(ip)
                ip_idx += 1
            if not batch:
                continue
            await asyncio.gather(*(check_ip(ip, session, already_saved, stats) for ip in batch))
            save_progress(ip_idx)
            if stats['ips_scanned'] % 100 == 0:
                save_status(ip_idx, stats['ips_scanned'], stats['working'])
    save_status(ip_idx, stats['ips_scanned'], stats['working'])

def print_status():
    if os.path.exists(STATUS_FILE):
        with open(STATUS_FILE, "r") as f:
            print(f.read())
    else:
        print("No status file found yet.")

def main():
    if '--status' in sys.argv:
        print_status()
        return

    already_saved = load_saved_proxies()
    start_ip_idx = load_progress()
    stats = {'ips_scanned': 0, 'proxies_tested': 0, 'working': len(already_saved), 'start_time': 0}
    print(f"[*] Resuming from IP index: {start_ip_idx} (Run with --status to see progress)")
    try:
        asyncio.run(scanner(start_ip_idx, already_saved, stats))
    except KeyboardInterrupt:
        print("\n[!] Interrupted, saving progress and status...")
        save_progress(start_ip_idx)
        save_status(start_ip_idx, stats['ips_scanned'], stats['working'])
        print("[!] Exiting.")

if __name__ == "__main__":
    main()
