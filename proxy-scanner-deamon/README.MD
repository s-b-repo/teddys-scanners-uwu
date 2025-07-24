
````
# 🌎 Async Internet-Scale Proxy Scanner

This project is a fully asynchronous, resumable, internet-scale proxy scanner in Python.  
It scans all public IPv4 addresses and all common proxy ports for open HTTP proxies.  
The tool supports background execution, automatic resume, and efficient deduplication.  
Proxies are only considered **working** if they:
- **Do not serve content containing “nginx” or “apache”**
- **Allow access to both http://example.com and http://cheese.com**

## 🚀 Features

- **Scans the entire IPv4 internet** (skipping all reserved/private/non-public IPs)
- **Fully async** and highly concurrent (tunable)
- **Tests all common proxy ports**
- **Automatic progress save and resume**
- **Automatic deduplication of found proxies**
- **Appends every working proxy as soon as it’s found**
- **Runs cleanly in the background** (use `nohup` or `screen`)
- **Does not print scan info by default** (status with `--status` flag)
- **Status/progress saved to file for easy monitoring**
- **Filters out proxies serving “nginx” or “apache”**

---

## ⚡️ Usage
# Start 8 instances
./proxy_manager.sh start 8

# Check status
./proxy_manager.sh status

# Scale to 12 instances
./proxy_manager.sh scale 12

# View logs from instance 3
./proxy_manager.sh logs 3 200

# Stop all instances
./proxy_manager.sh stop

# Restart with 4 instances
./proxy_manager.sh restart 4

### 1. Install dependencies

```
pip install aiohttp
````

### 2. Run the scanner in the background

```
nohup python3 scanner.py &
```

Or use [screen](https://www.gnu.org/software/screen/) or [tmux](https://github.com/tmux/tmux) if preferred.

### 3. Check status at any time

```
python3 scanner.py --status
```

### 4. Output files

* **`working_proxies.txt`**: List of discovered working proxies (`IP:PORT` per line)
* **`scan_progress.magic`**: Progress file (auto-resume support)
* **`scan_status.txt`**: Status information (scanned count, working found, etc)

---

## 🛠 How It Works

* **Scans** every public IPv4 (skips reserved ranges automatically)
* **Tests** each with all common proxy ports
* **Uses** aiohttp for async/concurrent requests


## 🔒 Ethical Use

This tool is designed **strictly for educational and legal research**.
Do **not** use it for any unauthorized activity or against networks without explicit permission.
The author is **not responsible** for misuse or any legal consequences.

---

## 🙏 Credits

* Python & aiohttp
* [ipaddress](https://docs.python.org/3/library/ipaddress.html) for address filtering

---

**Pull requests and issues are welcome!**

```

---

```
