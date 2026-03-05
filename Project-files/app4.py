import sqlite3, secrets, subprocess, threading, time, os, base64, io, json, csv
from datetime import datetime, timedelta
from flask import Flask, request, redirect, render_template_string, session, jsonify, Response
from io import StringIO
import qrcode
try:
    import psutil
except ImportError:
    psutil = None

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

DB = "/opt/captive-portal/portal.db"
PORTAL_HOST = "192.168.50.1"
DNSMASQ_LEASES = "/var/lib/misc/dnsmasq.leases"

# ─────────────────────── IPTABLES CACHE ───────────────────────
# Cache iptables checks with 10-second TTL to avoid slow subprocess calls on every request
_iptables_cache = {}
_iptables_cache_lock = threading.Lock()
IPTABLES_CACHE_TTL = 10  # seconds

def _get_cached_iptables_allowed(ip):
    """Check iptables status with caching (safe version that doesn't hang)"""
    with _iptables_cache_lock:
        if ip in _iptables_cache:
            result, timestamp = _iptables_cache[ip]
            if time.time() - timestamp < IPTABLES_CACHE_TTL:
                return result
    
    # Cache miss or stale, do the actual check
    # Try sudo but abort quickly if it hangs (password prompt)
    is_allowed = False
    try:
        # Use timeout and env to prevent interactive prompts
        result = subprocess.run(
            ["sudo", "-n", "iptables", "-C", "FORWARD", "-s", ip, "-j", "ACCEPT"],
            capture_output=True, timeout=0.5, text=True, env={**os.environ, "SUDO_ASKPASS": "/bin/false"}
        )
        is_allowed = result.returncode == 0
    except (subprocess.TimeoutExpired, OSError, Exception):
        # If sudo fails or times out, assume not allowed (safe default for portal bypass)
        # On a fresh/unconfigured system, just reject the check
        pass
    
    # Update cache
    with _iptables_cache_lock:
        _iptables_cache[ip] = (is_allowed, time.time())
    
    return is_allowed

ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "")
if not ADMIN_SECRET:
    raise RuntimeError("ADMIN_SECRET environment variable is not set. Refusing to start.")

# ─────────────────────── VALIDATION & SECURITY ───────────────────────

def is_valid_ipv4(ip):
    """Validate IPv4 address to prevent injection attacks"""
    import re
    return bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip)) and all(0 <= int(x) <= 255 for x in ip.split('.'))

def is_valid_hostname_or_ip(host):
    """Validate hostname or IP for commands like ping, traceroute"""
    import re
    return bool(re.match(r'^[a-zA-Z0-9.\-]+$', host)) and len(host) <= 253

# ─────────────────────── PERFORMANCE OPTIMIZATION ───────────────────────

@app.after_request
def optimize_response(response):
    """Add caching headers for performance. Real-time polling endpoints are never cached."""
    # These endpoints are polled every few seconds — must never be served stale
    REALTIME_ENDPOINTS = {
        '/admin/api/health', '/admin/api/stats', '/admin/api/sessions',
        '/admin/api/lobby/count', '/admin/api/lobby/list',
        '/admin/api/activity', '/admin/api/system/health',
    }
    if request.path in REALTIME_ENDPOINTS:
        response.cache_control.no_cache = True
        response.cache_control.no_store = True
        response.cache_control.must_revalidate = True
    elif request.path.startswith('/admin/api/'):
        # Other API responses (analytics, audit logs, top-devices) can cache briefly
        response.cache_control.max_age = 15
        response.cache_control.private = True
    # Don't cache HTML pages
    elif request.path.startswith('/admin/') or request.path.startswith('/portal'):
        response.cache_control.no_cache = True
        response.cache_control.no_store = True
    return response

# ─────────────────────── DATABASE ───────────────────────

def get_db():
    db = sqlite3.connect(DB, check_same_thread=False, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    return db

def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS codes (
            id INTEGER PRIMARY KEY,
            code TEXT UNIQUE NOT NULL,
            duration_minutes INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            used_by TEXT,
            used_at TEXT,
            expires_at TEXT,
            absolute_expiry TEXT,
            paused_at TEXT,
            remaining_seconds INTEGER,
            active INTEGER DEFAULT 1,
            speed_mbps INTEGER DEFAULT 5,
            temporary INTEGER DEFAULT 0,
            expires_temporary_at TEXT
        );
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY,
            mac TEXT UNIQUE NOT NULL,
            name TEXT,
            ip TEXT,
            first_seen TEXT,
            last_seen TEXT,
            whitelisted INTEGER DEFAULT 0,
            connected INTEGER DEFAULT 0,
            blocked INTEGER DEFAULT 0,
            daily_quota_mb INTEGER,
            hourly_quota_mb INTEGER
        );
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );
        CREATE TABLE IF NOT EXISTS lobby_requests (
            id INTEGER PRIMARY KEY,
            ip TEXT NOT NULL,
            mac TEXT,
            device_name TEXT,
            plan_name TEXT,
            plan_minutes INTEGER,
            plan_speed INTEGER,
            plan_label TEXT,
            requested_at TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            granted_code TEXT,
            granted_at TEXT,
            note TEXT
        );
        CREATE TABLE IF NOT EXISTS session_logs (
            id INTEGER PRIMARY KEY,
            code_id INTEGER,
            device_mac TEXT,
            device_ip TEXT,
            bytes_up INTEGER DEFAULT 0,
            bytes_down INTEGER DEFAULT 0,
            timestamp TEXT NOT NULL,
            FOREIGN KEY(code_id) REFERENCES codes(id)
        );
        CREATE TABLE IF NOT EXISTS admin_logs (
            id INTEGER PRIMARY KEY,
            admin_user TEXT,
            action TEXT NOT NULL,
            target TEXT,
            details TEXT,
            timestamp TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS device_groups (
            id INTEGER PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            color TEXT DEFAULT '#3b82f6',
            speed_limit_mbps INTEGER,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS device_tags (
            id INTEGER PRIMARY KEY,
            device_mac TEXT NOT NULL,
            group_id INTEGER,
            FOREIGN KEY(group_id) REFERENCES device_groups(id),
            FOREIGN KEY(device_mac) REFERENCES devices(mac)
        );
        CREATE TABLE IF NOT EXISTS bandwidth_profiles (
            id INTEGER PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            speed_mbps INTEGER NOT NULL,
            daily_limit_gb REAL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS activity_history (
            id INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            active_sessions INTEGER,
            bytes_up INTEGER DEFAULT 0,
            bytes_down INTEGER DEFAULT 0
        );
    """)
    # Create indices for performance
    try:
        db.execute("CREATE INDEX IF NOT EXISTS idx_codes_used_by ON codes(used_by)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_codes_expires ON codes(expires_at)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_session_logs_code ON session_logs(code_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_admin_logs_timestamp ON admin_logs(timestamp DESC)")
    except Exception:
        pass
    
    migrations = [
        "ALTER TABLE codes ADD COLUMN speed_mbps INTEGER DEFAULT 5",
        "ALTER TABLE codes ADD COLUMN absolute_expiry TEXT",
        "ALTER TABLE codes ADD COLUMN paused_at TEXT",
        "ALTER TABLE codes ADD COLUMN remaining_seconds INTEGER",
        "ALTER TABLE codes ADD COLUMN temporary INTEGER DEFAULT 0",
        "ALTER TABLE codes ADD COLUMN expires_temporary_at TEXT",
        "ALTER TABLE devices ADD COLUMN name TEXT",
        "ALTER TABLE devices ADD COLUMN blocked INTEGER DEFAULT 0",
        "ALTER TABLE devices ADD COLUMN daily_quota_mb INTEGER",
        "ALTER TABLE devices ADD COLUMN hourly_quota_mb INTEGER",
    ]
    for m in migrations:
        try:
            db.execute(m)
        except sqlite3.OperationalError:
            pass
    defaults = {
        "allow_pause": "1",
        "portal_title": "WiFi Access",
        "portal_subtitle": "Scan QR or enter access code to connect",
        "max_pause_seconds": "0",
        "absolute_expiry_hours": "0",
        "show_rates": "1",
        "data_rates": '[{"name":"30 Minutes","minutes":30,"speed":5,"label":"\u20b110"},{"name":"1 Hour","minutes":60,"speed":10,"label":"\u20b120"},{"name":"3 Hours","minutes":180,"speed":10,"label":"\u20b150"},{"name":"24 Hours","minutes":1440,"speed":20,"label":"\u20b1100"}]',
        "enable_audit_logs": "1",
        "enable_session_logs": "1",
        "qr_logo_url": "",
        "rate_limit_enable": "0",
        "default_daily_quota_mb": "0",
        "default_hourly_quota_mb": "0",
    }
    for k, v in defaults.items():
        db.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v))
    db.commit()
    db.close()

# ─────────────────────── SETTINGS CACHE ───────────────────────
_settings_cache = {}
_settings_cache_lock = threading.Lock()
SETTINGS_CACHE_TTL = 30  # seconds

def get_setting(key, default=""):
    """Get setting with in-memory caching to reduce DB queries"""
    with _settings_cache_lock:
        if key in _settings_cache:
            value, timestamp = _settings_cache[key]
            if time.time() - timestamp < SETTINGS_CACHE_TTL:
                return value
    
    db = get_db()
    row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    db.close()
    value = row["value"] if row else default
    
    with _settings_cache_lock:
        _settings_cache[key] = (value, time.time())
    
    return value

def set_setting(key, value):
    """Set setting and invalidate cache"""
    db = get_db()
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    db.commit()
    db.close()
    
    # Invalidate cache for this key
    with _settings_cache_lock:
        _settings_cache.pop(key, None)

# ─────────────────────── FIREWALL & SPEED LIMITER ───────────────────────

def set_speed_limit(ip, speed_mbps):
    if not ip or not is_valid_ipv4(ip): return
    octet = ip.split('.')[-1]
    classid = f"1:{octet}"
    try:
        subprocess.run(["sudo", "tc", "class", "add", "dev", "eth0", "parent", "1:", "classid", classid,
                        "htb", "rate", f"{speed_mbps}mbit"], check=False, timeout=5)
        subprocess.run(["sudo", "tc", "filter", "add", "dev", "eth0", "protocol", "ip", "parent", "1:",
                        "prio", "1", "u32", "match", "ip", "dst", ip, "flowid", classid], check=False, timeout=5)
    except (subprocess.TimeoutExpired, Exception):
        pass

def remove_speed_limit(ip):
    if not ip or not is_valid_ipv4(ip): return
    octet = ip.split('.')[-1]
    classid = f"1:{octet}"
    try:
        subprocess.run(["sudo", "tc", "filter", "del", "dev", "eth0", "protocol", "ip", "parent", "1:",
                        "prio", "1", "u32", "match", "ip", "dst", ip], check=False, timeout=5)
        subprocess.run(["sudo", "tc", "class", "del", "dev", "eth0", "classid", classid], check=False, timeout=5)
    except (subprocess.TimeoutExpired, Exception):
        pass

def add_iptables_allow(ip, speed=5):
    if not ip or not is_valid_ipv4(ip): return
    try:
        subprocess.run(["sudo", "iptables", "-I", "FORWARD", "1", "-s", ip, "-j", "ACCEPT"], check=False, timeout=5)
        subprocess.run(["sudo", "iptables", "-t", "nat", "-I", "CAPTIVE_PORTAL", "1", "-s", ip, "-j", "RETURN"], check=False, timeout=5)
        set_speed_limit(ip, speed)
    except (subprocess.TimeoutExpired, Exception):
        pass

def remove_iptables_allow(ip):
    if not ip or not is_valid_ipv4(ip): return
    try:
        subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-s", ip, "-j", "ACCEPT"], check=False, timeout=5)
        subprocess.run(["sudo", "iptables", "-t", "nat", "-D", "CAPTIVE_PORTAL", "-s", ip, "-j", "RETURN"], check=False, timeout=5)
        remove_speed_limit(ip)
    except (subprocess.TimeoutExpired, Exception):
        pass

def is_iptables_allowed(ip):
    return _get_cached_iptables_allowed(ip)

def get_mac_for_ip(ip):
    if not is_valid_ipv4(ip):
        return "unknown"
    try:
        result = subprocess.run(["arp", "-n", ip], capture_output=True, text=True, timeout=3)
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == ip:
                return parts[2]
    except (subprocess.TimeoutExpired, Exception):
        pass
    return "unknown"

def get_dnsmasq_leases():
    """Parse /var/lib/misc/dnsmasq.leases → {mac: hostname, ip: hostname}"""
    leases = {}  # keyed by both mac and ip for flexible lookup
    try:
        with open(DNSMASQ_LEASES, "r") as f:
            for line in f:
                parts = line.strip().split()
                # format: expiry mac ip hostname client-id
                if len(parts) >= 4:
                    mac = parts[1].lower()
                    ip  = parts[2]
                    hostname = parts[3] if parts[3] != "*" else None
                    if hostname:
                        leases[mac] = hostname
                        leases[ip]  = hostname
    except Exception:
        pass
    return leases

def sync_device_names_from_leases():
    """Update device names in DB from dnsmasq leases (only if name is not manually set)."""
    leases = get_dnsmasq_leases()
    if not leases:
        return
    db = get_db()
    devices = db.execute("SELECT mac, ip, name FROM devices").fetchall()
    for d in devices:
        mac = (d["mac"] or "").lower()
        ip  = d["ip"] or ""
        # Only auto-fill if name is blank — don't overwrite manual edits
        if not d["name"]:
            name = leases.get(mac) or leases.get(ip)
            if name:
                db.execute("UPDATE devices SET name=? WHERE mac=?", (name, d["mac"]))
    db.commit()
    db.close()

def generate_qr_base64(code):
    url = f"http://{PORTAL_HOST}:8080/portal?code={code}"
    qr = qrcode.QRCode(version=1, box_size=5, border=2)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode("utf-8")

# ─────────────────────── LOGGING & AUDIT ───────────────────────

def log_admin_action(action, target="", details=""):
    """Log admin action to audit trail (feature #7)"""
    if get_setting("enable_audit_logs", "1") != "1":
        return
    db = get_db()
    try:
        db.execute(
            "INSERT INTO admin_logs (admin_user, action, target, details, timestamp) VALUES (?,?,?,?,?)",
            ("admin", action, target, details, datetime.utcnow().isoformat()))
        db.commit()
    except Exception:
        pass
    finally:
        db.close()

def log_session_activity(code_id, mac, ip, bytes_up=0, bytes_down=0):
    """Log session bandwidth usage (feature #2)"""
    if get_setting("enable_session_logs", "1") != "1":
        return
    db = get_db()
    try:
        db.execute(
            "INSERT INTO session_logs (code_id, device_mac, device_ip, bytes_up, bytes_down, timestamp) VALUES (?,?,?,?,?,?)",
            (code_id, mac, ip, bytes_up, bytes_down, datetime.utcnow().isoformat()))
        db.commit()
    except Exception:
        pass
    finally:
        db.close()

def is_device_blocked(mac):
    """Check if device is banned (feature #1)"""
    db = get_db()
    row = db.execute("SELECT blocked FROM devices WHERE mac=?", (mac,)).fetchone()
    db.close()
    return bool(row and row["blocked"])

def is_device_blocked_by_ip(ip):
    """Check if device IP is blocked"""
    db = get_db()
    row = db.execute("SELECT blocked FROM devices WHERE ip=?", (ip,)).fetchone()
    db.close()
    return bool(row and row["blocked"])

def check_rate_limit(mac_or_ip):
    """Check if device hit daily/hourly quota (feature #5)"""
    if get_setting("rate_limit_enable", "0") != "1":
        return True
    db = get_db()
    # Get device limits
    device = db.execute("SELECT * FROM devices WHERE mac=? OR ip=?", (mac_or_ip, mac_or_ip)).fetchone()
    if not device:
        db.close()
        return True
    
    daily_quota = device["daily_quota_mb"] or int(get_setting("default_daily_quota_mb", "0"))
    hourly_quota = device["hourly_quota_mb"] or int(get_setting("default_hourly_quota_mb", "0"))
    
    now = datetime.utcnow()
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    hour_ago = now - timedelta(hours=1)
    
    # Check daily
    if daily_quota > 0:
        daily_used = db.execute(
            "SELECT SUM(bytes_up + bytes_down) as total FROM session_logs WHERE device_mac=? AND timestamp >= ?",
            (mac_or_ip, today.isoformat())).fetchone()
        if daily_used and (daily_used["total"] or 0) / 1e6 >= daily_quota:
            db.close()
            return False
    
    # Check hourly
    if hourly_quota > 0:
        hourly_used = db.execute(
            "SELECT SUM(bytes_up + bytes_down) as total FROM session_logs WHERE device_mac=? AND timestamp >= ?",
            (mac_or_ip, hour_ago.isoformat())).fetchone()
        if hourly_used and (hourly_used["total"] or 0) / 1e6 >= hourly_quota:
            db.close()
            return False
    
    db.close()
    return True

# ─────────────────────── SYSTEM HEALTH ───────────────────────

import re as _re
_prev_net = {}   # {iface: (bytes_rx, bytes_tx, timestamp)}

def _read_proc_net_dev():
    """Return {iface: (bytes_rx, bytes_tx)} from /proc/net/dev"""
    stats = {}
    try:
        with open("/proc/net/dev") as f:
            for line in f:
                line = line.strip()
                if ":" not in line:
                    continue
                iface, rest = line.split(":", 1)
                iface = iface.strip()
                nums = rest.split()
                if len(nums) >= 9:
                    stats[iface] = (int(nums[0]), int(nums[8]))  # rx_bytes, tx_bytes
    except Exception:
        pass
    return stats

def get_net_speed(iface="eth0"):
    """Return (rx_mbps, tx_mbps, total_rx_mb, total_tx_mb) for iface."""
    global _prev_net
    now = time.time()
    cur = _read_proc_net_dev()
    rx_mbps = tx_mbps = 0.0
    total_rx_mb = total_tx_mb = 0
    if iface in cur:
        rx_b, tx_b = cur[iface]
        total_rx_mb = round(rx_b / 1024 / 1024, 1)
        total_tx_mb = round(tx_b / 1024 / 1024, 1)
        if iface in _prev_net:
            prev_rx, prev_tx, prev_ts = _prev_net[iface]
            dt = now - prev_ts
            if dt > 0:
                rx_mbps = round((rx_b - prev_rx) * 8 / 1e6 / dt, 2)
                tx_mbps = round((tx_b - prev_tx) * 8 / 1e6 / dt, 2)
                rx_mbps = max(0.0, rx_mbps)
                tx_mbps = max(0.0, tx_mbps)
        _prev_net[iface] = (rx_b, tx_b, now)
    return rx_mbps, tx_mbps, total_rx_mb, total_tx_mb

def _detect_wan_iface():
    """Find the default route interface (WAN)."""
    try:
        r = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=3)
        m = _re.search(r"dev\s+(\S+)", r.stdout)
        if m:
            return m.group(1)
    except (subprocess.TimeoutExpired, Exception):
        pass
    return "eth0"

def get_system_health():
    import re
    health = {}

    # CPU usage
    try:
        import psutil
        health["cpu_percent"] = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        health["ram_percent"] = round(mem.percent, 1)
        health["ram_used_mb"] = round(mem.used / 1024 / 1024)
        health["ram_total_mb"] = round(mem.total / 1024 / 1024)
    except ImportError:
        try:
            with open("/proc/stat") as f:
                line = f.readline()
            vals = list(map(int, line.split()[1:]))
            idle = vals[3]
            total = sum(vals)
            health["cpu_percent"] = round((1 - idle / total) * 100, 1) if total else -1
        except Exception:
            health["cpu_percent"] = -1
        try:
            with open("/proc/meminfo") as f:
                lines = {l.split(":")[0]: int(l.split()[1]) for l in f if ":" in l}
            total = lines.get("MemTotal", 0)
            free  = lines.get("MemAvailable", lines.get("MemFree", 0))
            used  = total - free
            health["ram_percent"] = round(used / total * 100, 1) if total else 0
            health["ram_used_mb"] = round(used / 1024)
            health["ram_total_mb"] = round(total / 1024)
        except Exception:
            health["ram_percent"] = -1
            health["ram_used_mb"] = 0
            health["ram_total_mb"] = 0

    # CPU temperature
    try:
        import psutil
        temps = psutil.sensors_temperatures()
        for key in ("coretemp", "cpu_thermal", "cpu-thermal", "k10temp"):
            if key in temps and temps[key]:
                health["cpu_temp"] = round(temps[key][0].current, 1)
                break
        else:
            health["cpu_temp"] = None
    except Exception:
        health["cpu_temp"] = None
    if health.get("cpu_temp") is None:
        # Try all thermal zones and pick the highest reading
        best = None
        try:
            import glob
            for tz in sorted(glob.glob("/sys/class/thermal/thermal_zone*/temp")):
                try:
                    v = round(int(open(tz).read().strip()) / 1000, 1)
                    if best is None or v > best:
                        best = v
                except Exception:
                    pass
        except Exception:
            pass
        health["cpu_temp"] = best

    # eth0 / LAN interface
    try:
        result = subprocess.run(["ip", "link", "show", "eth0"], capture_output=True, text=True, timeout=3)
        health["eth0_up"] = "UP" in result.stdout
        result2 = subprocess.run(["ip", "-4", "addr", "show", "eth0"], capture_output=True, text=True, timeout=3)
        m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', result2.stdout)
        health["eth0_ip"] = m.group(1) if m else "N/A"
    except (subprocess.TimeoutExpired, Exception):
        health["eth0_up"] = False
        health["eth0_ip"] = "N/A"

    # WAN interface speed and data usage
    wan = _detect_wan_iface()
    health["wan_iface"] = wan
    rx_s, tx_s, rx_mb, tx_mb = get_net_speed(wan)
    health["wan_rx_mbps"]  = rx_s
    health["wan_tx_mbps"]  = tx_s
    health["wan_rx_mb"]    = rx_mb
    health["wan_tx_mb"]    = tx_mb
    health["wan_total_gb"] = round((rx_mb + tx_mb) / 1024, 3)

    # Also grab LAN (eth0) stats if different from WAN
    if wan != "eth0":
        _, _, lan_rx, lan_tx = get_net_speed("eth0")
        health["lan_rx_mb"] = lan_rx
        health["lan_tx_mb"] = lan_tx
    else:
        health["lan_rx_mb"] = rx_mb
        health["lan_tx_mb"] = tx_mb

    # Upstream / internet connectivity
    try:
        result = subprocess.run(["ping", "-c", "1", "-W", "2", "8.8.8.8"],
                                capture_output=True, text=True, timeout=5)
        health["upstream_ok"] = result.returncode == 0
        m = re.search(r'time=(\d+\.?\d*)', result.stdout)
        health["upstream_latency"] = float(m.group(1)) if m else None
    except Exception:
        health["upstream_ok"] = False
        health["upstream_latency"] = None

    # Portal self-check
    try:
        result = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "--max-time", "2", "http://127.0.0.1:8080/portal"],
            capture_output=True, text=True, timeout=5)
        health["portal_ok"] = result.stdout.strip() in ("200", "302")
    except Exception:
        health["portal_ok"] = False

    # Load average
    try:
        with open("/proc/loadavg") as f:
            parts = f.read().split()
            health["load_1"]  = parts[0]
            health["load_5"]  = parts[1]
            health["load_15"] = parts[2]
    except Exception:
        health["load_1"] = health["load_5"] = health["load_15"] = "N/A"

    # Uptime in seconds (for JS live counter)
    try:
        with open("/proc/uptime") as f:
            secs = float(f.read().split()[0])
        health["uptime_secs"] = int(secs)
        h, r = divmod(int(secs), 3600)
        m2, s2 = divmod(r, 60)
        health["uptime"] = f"{h}h {m2}m {s2}s"
    except Exception:
        health["uptime_secs"] = 0
        health["uptime"] = "N/A"

    return health


def run_diagnostics():
    """Run a set of network/service diagnostic checks and return results list."""
    import re
    checks = []

    def check(name, fn):
        try:
            ok, detail = fn()
            checks.append({"name": name, "ok": ok, "detail": detail})
        except Exception as e:
            checks.append({"name": name, "ok": False, "detail": str(e)})

    # 1. Ping Google DNS
    def ping_google():
        r = subprocess.run(["ping", "-c", "3", "-W", "2", "8.8.8.8"],
                           capture_output=True, text=True, timeout=10)
        m = re.search(r'(\d+)% packet loss', r.stdout)
        loss = m.group(1) if m else "?"
        m2 = re.search(r'rtt min/avg/max[^=]+=\s*([\d.]+)/([\d.]+)/([\d.]+)', r.stdout)
        if m2:
            return r.returncode == 0, f"Loss {loss}% — avg {m2.group(2)}ms / min {m2.group(1)}ms / max {m2.group(3)}ms"
        return r.returncode == 0, f"Loss {loss}%" if r.returncode != 0 else "3 packets OK"
    check("Ping 8.8.8.8 (Google DNS)", ping_google)

    # 2. Ping Cloudflare DNS
    def ping_cf():
        r = subprocess.run(["ping", "-c", "3", "-W", "2", "1.1.1.1"],
                           capture_output=True, text=True, timeout=10)
        m = re.search(r'rtt min/avg/max[^=]+=\s*([\d.]+)/([\d.]+)/([\d.]+)', r.stdout)
        loss_m = re.search(r'(\d+)% packet loss', r.stdout)
        loss = loss_m.group(1) if loss_m else "?"
        detail = (f"Loss {loss}% — avg {m.group(2)}ms" if m else f"Loss {loss}%")
        return r.returncode == 0, detail
    check("Ping 1.1.1.1 (Cloudflare DNS)", ping_cf)

    # 3. DNS resolution
    def dns_resolve():
        r = subprocess.run(["nslookup", "google.com", "8.8.8.8"],
                           capture_output=True, text=True, timeout=8)
        m = re.search(r'Address:\s*([\d.]+)', r.stdout)
        ip = m.group(1) if m else None
        return r.returncode == 0, f"Resolved to {ip}" if ip else r.stderr[:80]
    check("DNS Resolution (google.com via 8.8.8.8)", dns_resolve)

    # 4. HTTP connectivity
    def http_check():
        r = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{time_total}",
             "--max-time", "5", "http://example.com"],
            capture_output=True, text=True, timeout=10)
        parts = r.stdout.strip().split()
        code = parts[0] if parts else "?"
        ms   = round(float(parts[1]) * 1000) if len(parts) > 1 else "?"
        return r.returncode == 0 and code in ("200","301","302"), f"HTTP {code} in {ms}ms"
    check("HTTP Connectivity (example.com)", http_check)

    # 5. HTTPS connectivity
    def https_check():
        r = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{time_total}",
             "--max-time", "5", "https://example.com"],
            capture_output=True, text=True, timeout=10)
        parts = r.stdout.strip().split()
        code = parts[0] if parts else "?"
        ms   = round(float(parts[1]) * 1000) if len(parts) > 1 else "?"
        return r.returncode == 0 and code in ("200","301","302"), f"HTTPS {code} in {ms}ms"
    check("HTTPS / TLS Connectivity (example.com)", https_check)

    # 6. Portal self-check
    def portal_self():
        r = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{time_total}",
             "--max-time", "3", "http://127.0.0.1:8080/portal"],
            capture_output=True, text=True, timeout=6)
        parts = r.stdout.strip().split()
        code = parts[0] if parts else "?"
        ms   = round(float(parts[1]) * 1000) if len(parts) > 1 else "?"
        return code in ("200","302"), f"HTTP {code} in {ms}ms"
    check("Captive Portal (port 8080)", portal_self)

    # 7. eth0 carrier
    def eth0_carrier():
        try:
            carrier = open("/sys/class/net/eth0/carrier").read().strip()
            speed_f = "/sys/class/net/eth0/speed"
            speed = open(speed_f).read().strip() + " Mbps" if os.path.exists(speed_f) else "unknown speed"
            return carrier == "1", f"Carrier up — {speed}"
        except Exception as e:
            return False, str(e)
    check("eth0 Carrier / Link", eth0_carrier)

    # 8. iptables FORWARD default policy
    def ipt_forward():
        r = subprocess.run(["sudo", "iptables", "-L", "FORWARD", "--line-numbers", "-n"],
                           capture_output=True, text=True, timeout=5)
        has_drop = "DROP" in r.stdout or "REJECT" in r.stdout
        lines = [l for l in r.stdout.splitlines() if l.strip()]
        return True, f"{len(lines)-2} rules — {'default DROP/REJECT found' if has_drop else 'no default drop'}"
    check("iptables FORWARD chain", ipt_forward)

    # 9. dnsmasq running
    def dnsmasq_running():
        r = subprocess.run(["pgrep", "-x", "dnsmasq"], capture_output=True, text=True, timeout=3)
        pid = r.stdout.strip()
        return bool(pid), f"PID {pid}" if pid else "not running"
    check("dnsmasq service", dnsmasq_running)

    # 10. Traceroute first hop
    def traceroute_hop():
        r = subprocess.run(["traceroute", "-m", "3", "-w", "1", "-n", "8.8.8.8"],
                           capture_output=True, text=True, timeout=12)
        hops = [l for l in r.stdout.splitlines() if l.strip() and not l.startswith("traceroute")]
        detail = " → ".join(h.split()[1] for h in hops[:3] if len(h.split()) > 1)
        return bool(hops), detail or "no hops"
    check("Traceroute (first 3 hops to 8.8.8.8)", traceroute_hop)

    return checks

def _warmup_net_stats():
    """Prime _prev_net so the first health API call returns a real speed, not 0."""
    wan = _detect_wan_iface()
    get_net_speed(wan)
    if wan != "eth0":
        get_net_speed("eth0")

# ─────────────────────── EXPIRY CHECKER ───────────────────────

def expiry_checker():
    while True:
        time.sleep(30)
        db = get_db()
        now = datetime.utcnow()
        now_iso = now.isoformat()

        # Check session expiry (only non-paused)
        expired = db.execute(
            "SELECT used_by FROM codes WHERE active=1 AND expires_at IS NOT NULL "
            "AND expires_at < ? AND paused_at IS NULL",
            (now_iso,)).fetchall()
        for row in expired:
            if row["used_by"]:
                remove_iptables_allow(row["used_by"])
                db.execute("UPDATE codes SET active=0 WHERE used_by=?", (row["used_by"],))

        # Check absolute expiry (hard cutoff even if paused)
        abs_expired = db.execute(
            "SELECT used_by FROM codes WHERE active=1 AND absolute_expiry IS NOT NULL "
            "AND absolute_expiry < ?", (now_iso,)).fetchall()
        for row in abs_expired:
            if row["used_by"]:
                remove_iptables_allow(row["used_by"])
                db.execute("UPDATE codes SET active=0 WHERE used_by=?", (row["used_by"],))

        # Check temporary code expiry (Feature #6 - auto-revoke after 30 min)
        temp_expired = db.execute(
            "SELECT code FROM codes WHERE active=1 AND temporary=1 AND expires_temporary_at IS NOT NULL "
            "AND expires_temporary_at < ?", (now_iso,)).fetchall()
        for row in temp_expired:
            db.execute("UPDATE codes SET active=0 WHERE code=?", (row["code"],))

        db.commit()
        db.close()
        # Sync device names from dnsmasq leases every cycle
        try:
            sync_device_names_from_leases()
        except Exception:
            pass

PORTAL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ portal_title }}</title>
<style>
  /* No external font imports - use system fonts for captive portal compatibility */
  * { margin:0; padding:0; box-sizing:border-box; }
  :root {
    --bg: #080c14; --surface: rgba(255,255,255,0.04);
    --border: rgba(255,255,255,0.08); --accent: #00d4ff;
    --accent2: #7b61ff; --text: #e8eaf0; --muted: rgba(255,255,255,0.35);
  }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif; background: var(--bg); min-height: 100vh;
         display: flex; align-items: center; justify-content: center;
         padding: 20px; overflow-x: hidden; }
  .bg-orb { position: fixed; border-radius: 50%; filter: blur(80px); pointer-events: none; z-index: 0; }
  .orb1 { width:400px; height:400px; background:rgba(0,212,255,0.08); top:-100px; right:-100px; }
  .orb2 { width:300px; height:300px; background:rgba(123,97,255,0.07); bottom:-80px; left:-80px; }
  .card { position:relative; z-index:1; background:var(--surface); backdrop-filter:blur(30px);
          border:1px solid var(--border); border-radius:24px; padding:40px 36px;
          width:100%; max-width:480px;
          box-shadow:0 40px 80px rgba(0,0,0,0.6),inset 0 1px 0 rgba(255,255,255,0.06); }
  .logo-row { display:flex; align-items:center; gap:12px; margin-bottom:24px; }
  .wifi-badge { width:46px; height:46px; background:linear-gradient(135deg,var(--accent),var(--accent2));
                border-radius:12px; display:flex; align-items:center; justify-content:center;
                font-size:22px; box-shadow:0 8px 24px rgba(0,212,255,0.3);
                animation:float 3s ease-in-out infinite; }
  @keyframes float { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-4px)} }
  h1 { color:var(--text); font-size:1.4rem; font-weight:800; }
  .subtitle { color:var(--muted); font-size:0.82rem; margin-top:2px; }
  /* Tabs */
  .tabs { display:flex; gap:3px; background:rgba(255,255,255,0.04); border-radius:10px;
          padding:3px; margin-bottom:22px; }
  .tab-btn { flex:1; padding:8px 4px; border:none; background:transparent; color:var(--muted);
             border-radius:7px; cursor:pointer; font-family:inherit; font-size:0.72rem;
             font-weight:700; transition:all 0.2s; letter-spacing:0.3px; }
  .tab-btn.active { background:var(--accent); color:#000; box-shadow:0 4px 12px rgba(0,212,255,0.4); }
  .tab-pane { display:none; }
  .tab-pane.active { display:block; }
  /* Form */
  .form-group { margin-bottom:18px; }
  label { display:block; color:var(--muted); font-size:0.7rem; margin-bottom:8px;
          font-weight:700; letter-spacing:1.5px; text-transform:uppercase; }
  input[type="text"] { width:100%; padding:14px 18px; background:rgba(255,255,255,0.05);
    border:1px solid var(--border); border-radius:12px; color:var(--text);
    font-family:monospace; font-size:1.15rem; letter-spacing:4px;
    text-align:center; text-transform:uppercase; transition:all 0.25s; outline:none; }
  input[type="text"]::placeholder { letter-spacing:2px; color:rgba(255,255,255,0.2); }
  input[type="text"]:focus { border-color:var(--accent); background:rgba(0,212,255,0.05);
    box-shadow:0 0 0 3px rgba(0,212,255,0.12); }
  .btn { width:100%; padding:14px; background:linear-gradient(135deg,var(--accent),var(--accent2));
         border:none; border-radius:12px; color:#fff; font-family:inherit;
         font-size:0.95rem; font-weight:700; cursor:pointer; transition:all 0.25s;
         box-shadow:0 8px 24px rgba(0,212,255,0.25); margin-top:4px; }
  .btn:hover { transform:translateY(-2px); box-shadow:0 12px 32px rgba(0,212,255,0.4); }
  .error { background:rgba(255,80,80,0.1); border:1px solid rgba(255,80,80,0.3); color:#ff9090;
           border-radius:10px; padding:12px 16px; margin-bottom:18px; font-size:0.88rem; }
  /* Rate cards */
  .rates-grid { display:grid; grid-template-columns:1fr 1fr; gap:10px; margin-bottom:18px; }
  .rate-card { background:rgba(255,255,255,0.04); border:1px solid var(--border); border-radius:12px;
               padding:14px 12px; cursor:pointer; transition:all 0.2s; text-align:center; }
  .rate-card:hover, .rate-card.selected { border-color:var(--accent); background:rgba(0,212,255,0.08);
    box-shadow:0 0 0 2px rgba(0,212,255,0.18); }
  .rate-card .r-label { font-size:1.1rem; font-weight:800; color:var(--accent); }
  .rate-card .r-name { font-size:0.78rem; color:var(--text); margin-top:3px; font-weight:600; }
  .rate-card .r-speed { font-size:0.7rem; color:var(--muted); margin-top:2px; }
  /* QR scanner */
  #qr-video-wrap { position:relative; border-radius:14px; overflow:hidden; background:#000;
                   margin-bottom:16px; aspect-ratio:1; }
  #qr-video { width:100%; height:100%; object-fit:cover; display:block; }
  .scan-overlay { position:absolute; inset:0; display:flex; align-items:center; justify-content:center; pointer-events:none; }
  .scan-frame { width:55%; height:55%; border:2px solid var(--accent); border-radius:12px;
                box-shadow:0 0 0 2000px rgba(0,0,0,0.5); animation:scanPulse 2s ease-in-out infinite; }
  @keyframes scanPulse { 0%,100%{border-color:var(--accent)} 50%{border-color:var(--accent2)} }
  .scan-line { position:absolute; left:22.5%; right:22.5%; height:2px;
               background:linear-gradient(90deg,transparent,var(--accent),transparent);
               animation:scanLine 2s ease-in-out infinite; top:22.5%; }
  @keyframes scanLine { 0%{top:22.5%} 100%{top:77.5%} }
  .scan-status { text-align:center; color:var(--muted); font-size:0.82rem; margin-bottom:10px; min-height:20px; }
  .scan-status.ok { color:#4ade80; } .scan-status.err { color:#f87171; }
  #start-scan-btn { width:100%; padding:11px; background:rgba(0,212,255,0.1);
    border:1px solid rgba(0,212,255,0.3); border-radius:10px; color:var(--accent);
    font-family:'Syne',sans-serif; font-size:0.88rem; font-weight:600; cursor:pointer;
    transition:all 0.2s; margin-bottom:10px; }
  #start-scan-btn:hover { background:rgba(0,212,255,0.18); }
  /* History */
  .hist-item { background:rgba(255,255,255,0.04); border:1px solid var(--border); border-radius:10px;
               padding:12px 14px; margin-bottom:8px; display:flex; align-items:center; gap:12px; }
  .hist-code { font-family:monospace; font-size:0.95rem; color:var(--accent); letter-spacing:2px; flex:1; }
  .hist-badge { font-size:0.7rem; font-weight:700; padding:2px 8px; border-radius:20px; }
  .hist-badge.active { background:rgba(74,222,128,0.15); color:#4ade80; border:1px solid rgba(74,222,128,0.3); }
  .hist-badge.used { background:rgba(100,116,139,0.15); color:#94a3b8; border:1px solid rgba(100,116,139,0.2); }
  .hist-meta { font-size:0.72rem; color:var(--muted); margin-top:2px; }
  /* Lobby request */
  .lobby-form { background:rgba(123,97,255,0.08); border:1px solid rgba(123,97,255,0.25); border-radius:14px; padding:18px; }
  .lobby-form h3 { color:var(--text); font-size:0.88rem; font-weight:700; margin-bottom:12px; }
  .lobby-confirm { background:rgba(74,222,128,0.1); border:1px solid rgba(74,222,128,0.3);
                   border-radius:10px; padding:12px 14px; color:#4ade80; font-size:0.85rem; margin-bottom:12px; }
  .lobby-btn { width:100%; padding:12px; background:linear-gradient(135deg,var(--accent2),#9b59b6);
               border:none; border-radius:10px; color:#fff; font-family:'Syne',sans-serif;
               font-size:0.88rem; font-weight:700; cursor:pointer; transition:all 0.2s; margin-top:8px; }
  .lobby-btn:hover { filter:brightness(1.1); }
  .footer { margin-top:20px; text-align:center; }
  .footer a { color:var(--accent); text-decoration:none; font-size:0.78rem; opacity:0.7; transition:opacity 0.2s; }
  .footer a:hover { opacity:1; }
</style>
</head>
<body>
<div class="bg-orb orb1"></div>
<div class="bg-orb orb2"></div>
<div class="card">
  <div class="logo-row">
    <div class="wifi-badge">📶</div>
    <div>
      <h1>{{ portal_title }}</h1>
      <div class="subtitle">{{ portal_subtitle }}</div>
    </div>
  </div>

  {% if error %}<div class="error">⚠️ {{ error }}</div>{% endif %}

  <div class="tabs">
    <button class="tab-btn active"   onclick="showTab('type',this)">⌨️ Enter Code</button>
    <button class="tab-btn"         onclick="showTab('scan',this)">📷 Scan QR</button>
    <button class="tab-btn"         onclick="showTab('request',this)">📋 Request</button>
    <button class="tab-btn"         onclick="showTab('history',this)">🕓 History</button>
  </div>

  <!-- TAB: Enter Code -->
  <div id="tab-type" class="tab-pane active">
    {% if show_rates and data_rates %}
    <div style="font-size:0.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:10px;">Available Plans</div>
    <div class="rates-grid">
      {% for plan in data_rates %}
      <div class="rate-card" onclick="selectPlan(this,'{{ plan.name }}','{{ plan.label }}')">
        <div class="r-label">{{ plan.label }}</div>
        <div class="r-name">{{ plan.name }}</div>
        <div class="r-speed">{{ plan.speed }} Mbps</div>
      </div>
      {% endfor %}
    </div>
    {% endif %}
    <form method="POST" action="/portal/login">
      <div class="form-group">
        <label>Access Code</label>
        <input type="text" name="code" placeholder="XXXX-XXXX" maxlength="10"
               autocomplete="off" autofocus required value="{{ prefill_code }}" id="code-input">
      </div>
      <button type="submit" class="btn">🔓 Connect to Internet</button>
    </form>
  </div>

  <!-- TAB: Scan QR -->
  <div id="tab-scan" class="tab-pane">
    <div id="qr-video-wrap" style="display:none;">
      <video id="qr-video" playsinline autoplay muted></video>
      <div class="scan-overlay"><div class="scan-frame"></div><div class="scan-line"></div></div>
    </div>
    <div class="scan-status" id="scan-status">Press the button below to start your camera</div>
    <button id="start-scan-btn" onclick="startScanner()">📷 Start Camera Scanner</button>
    <form method="POST" action="/portal/login" id="scan-form">
      <input type="hidden" name="code" id="scanned-code">
    </form>
  </div>

  <!-- TAB: Request Access -->
  <div id="tab-request" class="tab-pane">
    {% if lobby_sent %}
    <div class="lobby-confirm">✅ Request sent! The admin will grant you access shortly. Check back on this tab.</div>
    {% endif %}
    {% if lobby_granted %}
    <div class="lobby-confirm" style="background:rgba(0,212,255,0.1);border-color:rgba(0,212,255,0.3);color:var(--accent);">
      🎉 Your access has been granted!<br>
      <span style="font-family:monospace;font-size:1.1rem;letter-spacing:3px;margin-top:6px;display:block;">{{ lobby_granted }}</span>
      <button onclick="document.getElementById('code-input').value='{{ lobby_granted }}';showTab('type',document.querySelector('.tab-btn'))"
              style="margin-top:8px;background:var(--accent);border:none;border-radius:8px;padding:6px 16px;color:#000;font-weight:700;cursor:pointer;font-size:0.82rem;">Use This Code →</button>
    </div>
    {% endif %}
    <div class="lobby-form">
      <h3>📋 Request Internet Access</h3>
      <p style="color:var(--muted);font-size:0.78rem;margin-bottom:14px;">Select a plan and submit a request. The admin will approve and provide your code.</p>
      {% if show_rates and data_rates %}
      <div style="font-size:0.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:10px;">Choose Plan</div>
      <div class="rates-grid" style="margin-bottom:14px;">
        {% for plan in data_rates %}
        <div class="rate-card" onclick="selectLobbyPlan(this,'{{ plan.name }}','{{ plan.minutes }}','{{ plan.speed }}','{{ plan.label }}')">
          <div class="r-label">{{ plan.label }}</div>
          <div class="r-name">{{ plan.name }}</div>
          <div class="r-speed">{{ plan.speed }} Mbps</div>
        </div>
        {% endfor %}
      </div>
      {% endif %}
      <form method="POST" action="/portal/lobby/request">
        <input type="hidden" name="plan_name" id="lobby-plan-name" value="">
        <input type="hidden" name="plan_minutes" id="lobby-plan-min" value="">
        <input type="hidden" name="plan_speed" id="lobby-plan-speed" value="">
        <input type="hidden" name="plan_label" id="lobby-plan-label" value="">
        <button type="submit" class="lobby-btn" id="lobby-submit">📤 Send Request to Admin</button>
      </form>
    </div>
  </div>

  <!-- TAB: History -->
  <div id="tab-history" class="tab-pane">
    <div style="font-size:0.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:12px;">Your Previous Sessions</div>
    {% if history %}
      {% for h in history %}
      <div class="hist-item">
        <div style="flex:1;">
          <div class="hist-code">{{ h.code }}</div>
          <div class="hist-meta">{{ h.duration_minutes }} min · {{ h.speed_mbps }} Mbps
            {% if h.used_at %} · {{ h.used_at[:16].replace('T',' ') }}{% endif %}
          </div>
        </div>
        {% if h.active and h.expires_at %}
          <span class="hist-badge active">ACTIVE</span>
        {% elif h.active and not h.expires_at %}
          <span class="hist-badge active">UNUSED</span>
        {% else %}
          <span class="hist-badge used">USED</span>
        {% endif %}
      </div>
      {% endfor %}
    {% else %}
      <div style="color:var(--muted);font-size:0.85rem;text-align:center;padding:20px 0;">No previous sessions found for this device.</div>
    {% endif %}
  </div>

  <div class="footer">
    <a href="/status">⏱ Check remaining time →</a>
  </div>
</div>

<!-- QR popup overlay (fixed center) -->
<div id="qr-popup" style="display:none;position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,0.8);
     align-items:center;justify-content:center;cursor:pointer;" onclick="this.style.display='none'">
  <div style="background:#fff;border-radius:16px;padding:20px;box-shadow:0 40px 80px rgba(0,0,0,0.8);">
    <img id="qr-popup-img" src="" style="display:block;width:260px;height:260px;">
    <div id="qr-popup-code" style="text-align:center;font-family:monospace;
         font-size:1.1rem;letter-spacing:3px;color:#000;margin-top:10px;font-weight:700;"></div>
  </div>
</div>

<!-- Load jsQR with fallback for captive portal networks -->
<script>
  // Try to load jsQR, but don't block if network is restricted
  (function() {
    var script = document.createElement('script');
    script.src = 'https://cdnjs.cloudflare.com/ajax/libs/jsQR/1.4.0/jsQR.min.js';
    script.async = true;
    script.onerror = function() { 
      console.warn('jsQR failed to load - QR scanning will be disabled');
      document.getElementById('start-scan-btn').style.display = 'none';
      document.querySelector('[onclick="showTab(\'scan\',this)"]').style.display = 'none';
    };
    document.head.appendChild(script);
  })();
</script>
<script>
function showTab(name, el) {
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  el.classList.add('active');
  if (name !== 'scan') stopScanner();
}

function selectPlan(el, name, label) {
  document.querySelectorAll('.rates-grid .rate-card').forEach(c => c.classList.remove('selected'));
  el.classList.add('selected');
}

function selectLobbyPlan(el, name, minutes, speed, label) {
  el.closest('.rates-grid').querySelectorAll('.rate-card').forEach(c => c.classList.remove('selected'));
  el.classList.add('selected');
  document.getElementById('lobby-plan-name').value  = name;
  document.getElementById('lobby-plan-min').value   = minutes;
  document.getElementById('lobby-plan-speed').value = speed;
  document.getElementById('lobby-plan-label').value = label;
  document.getElementById('lobby-submit').textContent = '📤 Request: ' + label + ' — ' + name;
}

let videoStream = null, scanInterval = null;
function startScanner() {
  const video = document.getElementById('qr-video');
  const wrap = document.getElementById('qr-video-wrap');
  const status = document.getElementById('scan-status');
  const btn = document.getElementById('start-scan-btn');
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    status.textContent = '❌ Camera not supported.'; status.className = 'scan-status err'; return;
  }
  status.textContent = 'Requesting camera…';
  navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } })
    .then(stream => {
      videoStream = stream; video.srcObject = stream;
      wrap.style.display = 'block';
      btn.textContent = '🛑 Stop Camera'; btn.onclick = stopScanner;
      status.textContent = 'Scanning for QR code…'; status.className = 'scan-status';
      scanInterval = setInterval(scanFrame, 200);
    })
    .catch(err => { status.textContent = '❌ ' + err.message; status.className = 'scan-status err'; });
}
function stopScanner() {
  if (videoStream) { videoStream.getTracks().forEach(t => t.stop()); videoStream = null; }
  if (scanInterval) { clearInterval(scanInterval); scanInterval = null; }
  const wrap = document.getElementById('qr-video-wrap');
  const btn = document.getElementById('start-scan-btn');
  if (wrap) wrap.style.display = 'none';
  if (btn) { btn.textContent = '📷 Start Camera Scanner'; btn.onclick = startScanner; }
}
function scanFrame() {
  const video = document.getElementById('qr-video');
  if (!video || video.readyState !== video.HAVE_ENOUGH_DATA) return;
  const canvas = document.createElement('canvas');
  canvas.width = video.videoWidth; canvas.height = video.videoHeight;
  const ctx = canvas.getContext('2d');
  ctx.drawImage(video, 0, 0);
  const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const code = jsQR(imageData.data, imageData.width, imageData.height);
  if (code) {
    let extracted = code.data;
    try { const u = new URL(code.data); extracted = u.searchParams.get('code') || code.data; } catch(e) {}
    const status = document.getElementById('scan-status');
    status.textContent = '✅ Found: ' + extracted; status.className = 'scan-status ok';
    stopScanner();
    document.getElementById('scanned-code').value = extracted;
    setTimeout(() => document.getElementById('scan-form').submit(), 600);
  }
}

// Pre-select lobby plan if only one exists
window.addEventListener('DOMContentLoaded', () => {
  const lobbyCards = document.querySelectorAll('#tab-request .rate-card');
  if (lobbyCards.length === 1) lobbyCards[0].click();
});
</script>
</body>
</html>"""


# ─────────────────────── STATUS HTML ───────────────────────

# ─────────────────────── STATUS HTML ───────────────────────

STATUS_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Session Status</title>
<style>
  /* No external fonts - system fonts for captive portal compatibility */
  * { margin:0; padding:0; box-sizing:border-box; }
  :root { --accent: #00d4ff; --bg: #080c14; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg);
    min-height: 100vh;
    display: flex; align-items: center; justify-content: center;
    padding: 20px;
  }
  .bg-orb { position:fixed; border-radius:50%; filter:blur(80px); pointer-events:none; z-index:0; }
  .orb1 { width:400px; height:400px; background:rgba(0,212,255,0.07); top:-100px; right:-100px; }
  .orb2 { width:300px; height:300px; background:rgba(123,97,255,0.06); bottom:-80px; left:-80px; }
  .card {
    position: relative; z-index:1;
    background: rgba(255,255,255,0.04);
    backdrop-filter: blur(30px);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 24px;
    padding: 44px 40px;
    max-width: 440px; width: 100%;
    text-align: center;
    box-shadow: 0 40px 80px rgba(0,0,0,0.6);
  }
  h1 { color: #e8eaf0; font-size: 1.6rem; font-weight: 800; margin-bottom: 6px; }
  .sub { color: rgba(255,255,255,0.4); font-size: 0.9rem; margin-bottom: 30px; }
  .countdown-wrap {
    background: rgba(0,212,255,0.06);
    border: 1px solid rgba(0,212,255,0.2);
    border-radius: 16px;
    padding: 24px;
    margin-bottom: 20px;
  }
  .countdown-label { color: rgba(255,255,255,0.4); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1.5px; margin-bottom: 10px; }
  .countdown {
    font-family: monospace;
    font-size: 2.8rem;
    font-weight: 600;
    color: var(--accent);
    letter-spacing: 4px;
    line-height: 1;
  }
  .countdown.paused { color: #fbbf24; }
  .countdown.low { color: #f87171; animation: blink 1s ease-in-out infinite; }
  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.5} }
  .info-row {
    display: flex; gap: 12px; margin-bottom: 16px;
  }
  .info-box {
    flex: 1;
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(255,255,255,0.07);
    border-radius: 12px;
    padding: 14px;
  }
  .info-box .lbl { color: rgba(255,255,255,0.35); font-size: 0.72rem; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px; }
  .info-box .val { color: #e8eaf0; font-size: 1rem; font-weight: 700; }
  .pause-btn {
    width: 100%;
    padding: 13px;
    border: 1px solid rgba(251,191,36,0.4);
    background: rgba(251,191,36,0.08);
    border-radius: 12px;
    color: #fbbf24;
    font-family: inherit;
    font-size: 0.9rem;
    font-weight: 700;
    cursor: pointer;
    transition: all 0.2s;
    margin-bottom: 10px;
  }
  .pause-btn:hover { background: rgba(251,191,36,0.15); }
  .resume-btn {
    width: 100%;
    padding: 13px;
    border: none;
    background: linear-gradient(135deg, #4ade80, #22c55e);
    border-radius: 12px;
    color: #000;
    font-family: inherit;
    font-size: 0.9rem;
    font-weight: 700;
    cursor: pointer;
    transition: all 0.2s;
    margin-bottom: 10px;
    box-shadow: 0 4px 16px rgba(74,222,128,0.3);
  }
  .resume-btn:hover { transform: translateY(-1px); box-shadow: 0 8px 24px rgba(74,222,128,0.4); }
  .browse-btn {
    display: inline-block; width: 100%; padding: 13px;
    background: linear-gradient(135deg, var(--accent), #7b61ff);
    border-radius: 12px; color: #fff; text-decoration: none;
    font-weight: 700; font-size: 0.95rem;
    transition: transform 0.2s;
    box-shadow: 0 8px 24px rgba(0,212,255,0.25);
  }
  .browse-btn:hover { transform: translateY(-2px); }
  .paused-badge {
    display: inline-block;
    background: rgba(251,191,36,0.15);
    border: 1px solid rgba(251,191,36,0.35);
    color: #fbbf24;
    border-radius: 20px;
    padding: 4px 14px;
    font-size: 0.78rem;
    font-weight: 700;
    letter-spacing: 1px;
    margin-bottom: 16px;
    text-transform: uppercase;
  }
</style>
</head>
<body>
<div class="bg-orb orb1"></div>
<div class="bg-orb orb2"></div>
<div class="card">
  <h1>⏱ Session Status</h1>
  {% if expires %}
  <p class="sub">Your session is {% if paused %}paused{% else %}active{% endif %}.</p>
  {% if paused %}<div class="paused-badge">⏸ PAUSED</div>{% endif %}

  <div class="countdown-wrap">
    <div class="countdown-label">Time Remaining</div>
    <div class="countdown{% if paused %} paused{% endif %}" id="countdown">{{ remaining_display }}</div>
  </div>

  <div class="info-row">
    <div class="info-box">
      <div class="lbl">Speed</div>
      <div class="val">{{ speed }} Mbps</div>
    </div>
    <div class="info-box">
      <div class="lbl">Expires</div>
      <div class="val" style="font-size:0.82rem;">{{ expires[:16].replace('T',' ') }}</div>
    </div>
  </div>

  {% if allow_pause %}
    {% if paused %}
    <form method="POST" action="/portal/resume">
      <button type="submit" class="resume-btn">▶ Resume Session</button>
    </form>
    {% else %}
    <form method="POST" action="/portal/pause">
      <button type="submit" class="pause-btn">⏸ Pause Session</button>
    </form>
    {% endif %}
  {% endif %}

  <a href="http://www.google.com" class="browse-btn">🌐 Browse Internet</a>

  {% else %}
  <p class="sub" style="color:#f87171;">No active session found for your device.</p>
  <a href="/portal" class="browse-btn">↩ Back to Portal</a>
  {% endif %}
</div>
{% if expires and not paused %}
<script>
  const expiresAt = new Date("{{ expires }}Z");
  function tick() {
    const now = new Date();
    let diff = Math.max(0, Math.floor((expiresAt - now) / 1000));
    const h = Math.floor(diff / 3600);
    diff %= 3600;
    const m = Math.floor(diff / 60);
    const s = diff % 60;
    const el = document.getElementById('countdown');
    if (!el) return;
    el.textContent = String(h).padStart(2,'0') + ':' + String(m).padStart(2,'0') + ':' + String(s).padStart(2,'0');
    if (diff < 300) el.classList.add('low'); else el.classList.remove('low');
    if (diff === 0) { location.href = '/portal'; return; }
    setTimeout(tick, 1000);
  }
  tick();
</script>
{% endif %}
</body>
</html>"""

# ─────────────────────── ADMIN HTML ───────────────────────

ADMIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin — Captive Portal</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<style>
  /* No external fonts - system fonts for captive portal compatibility */
  * { margin:0; padding:0; box-sizing:border-box; }
  :root {
    --bg: #0a0e1a;
    --panel: #111827;
    --panel2: #1a2235;
    --border: #1f2d45;
    --accent: #3b82f6;
    --accent2: #10b981;
    --warn: #f59e0b;
    --danger: #ef4444;
    --text: #e2e8f0;
    --muted: #64748b;
    --mono: monospace;
    --sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  }
  body { font-family: var(--sans); background: var(--bg); color: var(--text); min-height: 100vh; }

  /* LAYOUT & SIDEBAR */
  .layout { display: block; min-height: 100vh; }
  .sidebar-overlay {
    display: none; position: fixed; inset: 0; z-index: 149;
    background: rgba(0,0,0,0.55); backdrop-filter: blur(2px);
  }
  .sidebar-overlay.active { display: block; }
  .sidebar {
    width: 220px;
    background: var(--panel);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    padding: 24px 0;
    position: fixed;
    top: 0; left: 0;
    height: 100vh;
    z-index: 150;
    overflow-y: auto;
    overflow-x: hidden;
    transition: transform 0.26s cubic-bezier(.4,0,.2,1), width 0.26s cubic-bezier(.4,0,.2,1);
  }
  .sidebar-logo {
    padding: 0 20px 24px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 16px;
  }
  .sidebar-logo h1 { font-size: 0.95rem; color: var(--accent); font-weight: 700; }
  .sidebar-logo .v { font-size: 0.7rem; color: var(--muted); margin-top: 2px; font-family: var(--mono); }
  .live-dot {
    display: inline-block; width: 7px; height: 7px;
    background: var(--accent2); border-radius: 50%;
    margin-right: 6px;
    animation: livePulse 1.5s ease-in-out infinite;
  }
  @keyframes livePulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:0.5;transform:scale(0.8)} }
  .nav-item {
    display: flex; align-items: center; gap: 10px;
    padding: 11px 20px;
    cursor: pointer;
    color: var(--muted);
    font-size: 0.88rem;
    font-weight: 500;
    border-left: 3px solid transparent;
    transition: all 0.2s;
    user-select: none;
  }
  .nav-item:hover { color: var(--text); background: rgba(255,255,255,0.03); }
  .nav-item.active { color: var(--accent); border-left-color: var(--accent); background: rgba(59,130,246,0.07); }
  .nav-item .icon { font-size: 1rem; width: 20px; text-align: center; }
  .sidebar-footer { margin-top: auto; padding: 16px 20px; border-top: 1px solid var(--border); }
  .sidebar-footer a { color: var(--muted); font-size: 0.8rem; text-decoration: none; display: block; margin-bottom: 8px; }
  .sidebar-footer a:hover { color: var(--danger); }
  .device-toggle { display: flex; gap: 4px; margin-bottom: 12px; }
  .device-btn { flex: 1; padding: 6px 8px; font-size: 0.7rem; border: 1px solid var(--border); background: transparent; color: var(--muted); border-radius: 4px; cursor: pointer; transition: all 0.2s; font-family: var(--mono); }
  .device-btn:hover { color: var(--text); border-color: var(--accent); }
  .device-btn.active { background: var(--accent); color: #fff; border-color: var(--accent); font-weight: 600; }

  /* TOPBAR (mobile only) */
  .topbar {
    display: none; position: fixed; top: 0; left: 0; right: 0; z-index: 100;
    height: 54px; background: var(--panel); border-bottom: 1px solid var(--border);
    align-items: center; padding: 0 14px; gap: 12px;
  }
  .topbar-hamburger {
    background: transparent; border: 1px solid var(--border);
    color: var(--text); font-size: 1.1rem; cursor: pointer;
    padding: 6px 10px; border-radius: 7px; line-height: 1;
    transition: background 0.15s;
  }
  .topbar-hamburger:hover { background: rgba(255,255,255,0.06); }
  .topbar-title { font-size: 0.95rem; font-weight: 700; color: var(--accent); }
  .topbar-live { display: flex; align-items: center; gap: 5px; margin-left: auto; font-size: 0.7rem; color: var(--muted); font-family: var(--mono); }

  /* MAIN */
  .main { padding: 30px; margin-left: 220px; min-width: 0; }
  .page { display: none; }
  .page.active { display: block; }
  .page-title { font-size: 1.3rem; font-weight: 700; margin-bottom: 6px; }
  .page-sub { color: var(--muted); font-size: 0.85rem; margin-bottom: 28px; }

  /* TOAST */
  .toast {
    background: rgba(16,185,129,0.15);
    border: 1px solid rgba(16,185,129,0.4);
    color: #6ee7b7;
    border-radius: 10px;
    padding: 12px 16px;
    margin-bottom: 24px;
    font-size: 0.88rem;
    font-weight: 500;
  }

  /* STAT CARDS */
  .stat-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 16px; margin-bottom: 28px; }
  .stat-card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 20px;
  }
  .stat-card .s-label { color: var(--muted); font-size: 0.72rem; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px; }
  .stat-card .s-val { font-size: 2rem; font-weight: 700; font-family: var(--mono); }
  .stat-card .s-sub { color: var(--muted); font-size: 0.75rem; margin-top: 4px; }
  .c-blue { color: var(--accent); }
  .c-green { color: var(--accent2); }
  .c-warn { color: var(--warn); }
  .c-red { color: var(--danger); }

  /* HEALTH GRID */
  .health-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 16px; margin-bottom: 28px; }
  .health-card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 20px;
  }
  .health-card h3 { font-size: 0.78rem; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); margin-bottom: 14px; }
  .health-status {
    display: flex; align-items: center; gap: 10px;
    font-size: 0.95rem; font-weight: 600;
  }
  .dot-ok { width:10px;height:10px;border-radius:50%;background:var(--accent2);flex-shrink:0; }
  .dot-err { width:10px;height:10px;border-radius:50%;background:var(--danger);flex-shrink:0; }
  .dot-warn { width:10px;height:10px;border-radius:50%;background:var(--warn);flex-shrink:0; }
  .progress-bar { background: var(--border); border-radius: 999px; height: 6px; margin-top: 10px; }
  .progress-fill { height: 6px; border-radius: 999px; transition: width 0.5s; }
  .fill-green { background: var(--accent2); }
  .fill-warn { background: var(--warn); }
  .fill-red { background: var(--danger); }
  .fill-blue { background: var(--accent); }
  .metric-val { font-family: var(--mono); font-size: 1.6rem; font-weight: 600; margin: 8px 0 4px; }
  .metric-sub { color: var(--muted); font-size: 0.78rem; }

  /* TABLES */
  .table-wrap { background: var(--panel); border: 1px solid var(--border); border-radius: 14px; overflow: auto; margin-bottom: 24px; }
  table { width: 100%; border-collapse: collapse; }
  thead th {
    background: var(--panel2);
    color: var(--muted);
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
    text-align: left;
    font-family: var(--mono);
    white-space: nowrap;
  }
  tbody td { padding: 11px 16px; border-bottom: 1px solid rgba(255,255,255,0.03); font-size: 0.86rem; vertical-align: middle; }
  tbody tr:last-child td { border-bottom: none; }
  tbody tr:hover td { background: rgba(255,255,255,0.02); }
  .mono { font-family: var(--mono); letter-spacing: 1px; color: var(--accent); }
  .badge {
    display: inline-block; padding: 2px 10px;
    border-radius: 20px; font-size: 0.72rem; font-weight: 600;
  }
  .badge-green { background: rgba(16,185,129,0.15); color: #6ee7b7; border: 1px solid rgba(16,185,129,0.25); }
  .badge-blue  { background: rgba(59,130,246,0.15); color: #93c5fd; border: 1px solid rgba(59,130,246,0.25); }
  .badge-gray  { background: rgba(100,116,139,0.15); color: #94a3b8; border: 1px solid rgba(100,116,139,0.25); }
  .badge-warn  { background: rgba(245,158,11,0.15); color: #fcd34d; border: 1px solid rgba(245,158,11,0.25); }
  .badge-red   { background: rgba(239,68,68,0.15); color: #fca5a5; border: 1px solid rgba(239,68,68,0.25); }
  .live-session { color: var(--accent2); font-family: var(--mono); }

  /* BUTTONS */
  .btn-sm {
    padding: 4px 12px; border: none; border-radius: 6px;
    font-family: var(--sans); font-size: 0.78rem; font-weight: 600;
    cursor: pointer; transition: all 0.15s;
  }
  .btn-danger { background: rgba(239,68,68,0.15); color: #fca5a5; border: 1px solid rgba(239,68,68,0.25); }
  .btn-danger:hover { background: rgba(239,68,68,0.3); }
  .btn-primary { background: rgba(59,130,246,0.15); color: #93c5fd; border: 1px solid rgba(59,130,246,0.25); }
  .btn-primary:hover { background: rgba(59,130,246,0.3); }
  .btn-success { background: rgba(16,185,129,0.15); color: #6ee7b7; border: 1px solid rgba(16,185,129,0.25); }
  .btn-success:hover { background: rgba(16,185,129,0.3); }

  /* GEN CARD */
  .gen-card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 24px;
    margin-bottom: 24px;
  }
  .gen-card h2 { font-size: 0.85rem; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); margin-bottom: 20px; }
  .time-btns { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }
  .time-btn {
    padding: 8px 18px;
    background: var(--panel2);
    border: 1px solid var(--border);
    border-radius: 8px;
    color: var(--muted);
    cursor: pointer;
    font-size: 0.85rem;
    font-family: var(--sans);
    transition: all 0.18s;
  }
  .time-btn:hover { border-color: var(--accent); color: var(--text); }
  .time-btn.active { background: rgba(59,130,246,0.15); border-color: var(--accent); color: var(--accent); font-weight: 600; }
  .form-row { display: flex; gap: 12px; align-items: flex-end; flex-wrap: wrap; margin-bottom: 16px; }
  .form-field { display: flex; flex-direction: column; gap: 6px; }
  .form-field label { color: var(--muted); font-size: 0.72rem; text-transform: uppercase; letter-spacing: 1px; }
  .form-field input {
    padding: 9px 12px;
    background: var(--panel2);
    border: 1px solid var(--border);
    border-radius: 8px;
    color: var(--text);
    font-family: var(--mono);
    font-size: 0.88rem;
    outline: none;
    width: 100%; max-width: 110px;
  }
  .form-field input:focus { border-color: var(--accent); }
  .gen-btn {
    padding: 10px 22px;
    background: var(--accent2);
    border: none;
    border-radius: 8px;
    color: #000;
    font-family: var(--sans);
    font-size: 0.88rem;
    font-weight: 700;
    cursor: pointer;
    transition: all 0.2s;
  }
  .gen-btn:hover { filter: brightness(1.1); }

  /* VOUCHER PRINT */
  .voucher-grid { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 20px; }
  .voucher-chip {
    background: var(--panel2);
    border: 1px solid var(--accent2);
    border-radius: 10px;
    padding: 12px 18px;
    display: flex; flex-direction: column; align-items: center; gap: 6px;
  }
  .voucher-chip .v-code { font-family: var(--mono); font-size: 1.1rem; color: var(--accent2); letter-spacing: 3px; }
  .voucher-chip .v-meta { font-size: 0.72rem; color: var(--muted); }
  .voucher-chip img { width: 80px; height: 80px; cursor: pointer; border-radius: 6px; }
  .voucher-chip img:hover { transform: scale(3); position: relative; z-index: 50; box-shadow: 0 20px 60px rgba(0,0,0,0.8); }

  /* SETTINGS */
  .settings-section { background: var(--panel); border: 1px solid var(--border); border-radius: 14px; padding: 24px; margin-bottom: 20px; }
  .settings-section h2 { font-size: 0.85rem; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); margin-bottom: 20px; }
  .setting-row { display: flex; align-items: center; justify-content: space-between; padding: 14px 0; border-bottom: 1px solid rgba(255,255,255,0.04); }
  .setting-row:last-child { border-bottom: none; }
  .setting-info h3 { font-size: 0.9rem; font-weight: 600; }
  .setting-info p { font-size: 0.78rem; color: var(--muted); margin-top: 3px; }
  .toggle { position: relative; display: inline-block; width: 44px; height: 24px; }
  .toggle input { opacity: 0; width: 0; height: 0; }
  .slider {
    position: absolute; cursor: pointer; inset: 0;
    background: var(--border); border-radius: 999px;
    transition: 0.25s;
  }
  .slider:before {
    content: ''; position: absolute;
    height: 18px; width: 18px;
    left: 3px; bottom: 3px;
    background: #fff; border-radius: 50%;
    transition: 0.25s;
  }
  input:checked + .slider { background: var(--accent2); }
  input:checked + .slider:before { transform: translateX(20px); }
  .setting-input {
    padding: 7px 12px;
    background: var(--panel2);
    border: 1px solid var(--border);
    border-radius: 8px;
    color: var(--text);
    font-family: var(--mono);
    font-size: 0.88rem;
    outline: none;
    width: 100%; max-width: 120px;
    text-align: right;
  }
  .setting-input:focus { border-color: var(--accent); }
  .save-btn {
    padding: 10px 28px;
    background: var(--accent);
    border: none; border-radius: 8px;
    color: #fff; font-family: var(--sans);
    font-size: 0.88rem; font-weight: 700;
    cursor: pointer; transition: filter 0.2s;
    margin-top: 16px;
  }
  .save-btn:hover { filter: brightness(1.15); }

  /* DEVICE NAME EDIT */
  .name-edit { display: flex; align-items: center; gap: 6px; }
  .name-input {
    padding: 4px 8px;
    background: var(--panel2);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--text);
    font-size: 0.84rem;
    width: 130px;
    outline: none;
  }
  .name-input:focus { border-color: var(--accent); }
  .name-save-btn { padding: 4px 10px; background: var(--accent); border: none; border-radius: 6px; color: #fff; font-size: 0.75rem; cursor: pointer; font-weight: 600; }

  /* COUNTDOWN IN TABLE */
  .session-cd { font-family: var(--mono); font-size: 0.9rem; color: var(--accent2); }
  .session-cd.paused { color: var(--warn); }
  .session-cd.low { color: var(--danger); }

  /* CHARTS & GRAPHS */
  .chart-container { background: var(--panel); border: 1px solid var(--border); border-radius: 14px; padding: 20px; margin-bottom: 20px; position: relative; height: 300px; }
  .chart-title { font-size: 0.9rem; font-weight: 600; color: var(--text); margin-bottom: 12px; text-transform: uppercase; letter-spacing: 1px; }
  .chart-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px; margin-bottom: 20px; }
  .mini-chart { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 14px; }
  
  /* DEVICE GROUPS */
  .group-tag { display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 600; margin: 2px; }
  .group-selector { display: flex; flex-wrap: wrap; gap: 6px; margin: 8px 0; }
  .group-btn { padding: 6px 12px; border: 1px solid var(--border); background: transparent; border-radius: 8px; cursor: pointer; font-size: 0.8rem; transition: all 0.2s; }
  .group-btn:hover { border-color: var(--accent); color: var(--accent); }
  .group-btn.active { background: var(--accent); color: #fff; border-color: var(--accent); }
  
  /* BANDWIDTH CONTROLS */
  .speed-control { display: flex; gap: 8px; align-items: flex-end; flex-wrap: wrap; }
  .speed-input { padding: 7px 10px; background: var(--panel2); border: 1px solid var(--border); border-radius: 6px; color: var(--text); font-size: 0.8rem; width: 100px; }
  .speed-unit { color: var(--muted); font-size: 0.75rem; margin-left: -4px; }
  
  /* SYSTEM HEALTH */
  .health-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
  .health-item { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 14px; }
  .health-label { color: var(--muted); font-size: 0.7rem; text-transform: uppercase; margin-bottom: 8px; }
  .health-value { font-size: 1.8rem; font-weight: 700; font-family: var(--mono); color: var(--accent); }
  .health-bar { background: var(--border); height: 4px; border-radius: 2px; margin: 6px 0; overflow: hidden; }
  .health-fill { height: 100%; background: linear-gradient(90deg, var(--accent2), var(--warn)); transition: width 0.3s; }
  
  /* EXPORT BUTTON */
  .export-btn { padding: 8px 16px; background: var(--accent2); color: #000; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; font-size: 0.85rem; transition: all 0.2s; }
  .export-btn:hover { filter: brightness(1.1); }

  @media print {
    body * { visibility: hidden; }
    .print-area, .print-area * { visibility: visible; }
    .print-area { position: absolute; left: 0; top: 0; width: 100%; display: flex; flex-wrap: wrap; gap: 15px; }
    .voucher-slip { border: 2px dashed #000; padding: 15px; width: 220px; text-align: center; background: #fff; color: #000; page-break-inside: avoid; }
    .voucher-slip img { width: 140px; height: 140px; }
    .voucher-slip h2 { font-size: 1.4rem; letter-spacing: 3px; margin: 8px 0; }
  }

  /* ── Tablet: icon-only sidebar ── */
  @media (min-width: 768px) and (max-width: 1099px) {
    .sidebar { width: 64px; }
    .sidebar-logo { padding: 0 0 16px; text-align: center; }
    .sidebar-logo h1 { display: none; }
    .sidebar-logo .v { display: none; }
    .nav-item { padding: 12px 0; justify-content: center; gap: 0; }
    .nav-item span:not(.icon) { display: none; }
    .nav-item .badge { display: none; }
    .sidebar-footer { padding: 12px 8px; }
    .sidebar-footer a { display: none; }
    .device-toggle { display: none; }
    .main { margin-left: 64px; padding: 24px; }
    .stat-grid { grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); }
    .health-grid { grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); }
  }

  /* ── Mobile: drawer sidebar ── */
  @media (max-width: 767px) {
    .sidebar { transform: translateX(-100%); width: 240px; }
    .sidebar.open { transform: translateX(0); box-shadow: 6px 0 32px rgba(0,0,0,0.5); }
    .topbar { display: flex; }
    .main { margin-left: 0; padding: 70px 14px 18px; }
    .page-title { font-size: 1.1rem; }
    .page-sub { font-size: 0.8rem; margin-bottom: 18px; }
    .stat-grid { grid-template-columns: repeat(2, 1fr); gap: 10px; margin-bottom: 18px; }
    .stat-card { padding: 14px; }
    .stat-card .s-val { font-size: 1.5rem; }
    .health-grid { grid-template-columns: 1fr; gap: 10px; }
    .health-card { padding: 14px; }
    .table-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; border-radius: 10px; }
    table { min-width: 580px; }
    thead th { font-size: 0.68rem; padding: 9px 10px; }
    tbody td { padding: 8px 10px; font-size: 0.82rem; }
    .gen-card { padding: 16px; margin-bottom: 16px; }
    .gen-btn { width: 100%; }
    .form-row { flex-direction: column; }
    .form-field input { max-width: 100%; }
    .settings-section { padding: 16px; }
    .setting-row { flex-direction: column; align-items: flex-start; }
    .setting-info { margin-bottom: 8px; }
    .setting-input { width: 100%; max-width: none; margin-top: 4px; }
    .save-btn { width: 100%; }
    .time-btns { gap: 5px; }
    .time-btn { padding: 6px 14px; font-size: 0.8rem; }
    .badge { font-size: 0.68rem; padding: 2px 7px; }
    .toast { font-size: 0.84rem; }
    .chart-grid { grid-template-columns: 1fr; }
    .chart-container { height: 220px; }
    .voucher-grid { gap: 8px; }
    .voucher-chip { padding: 10px 14px; }
    .voucher-chip img { width: 68px; height: 68px; }
    .device-toggle { display: none; }
  }

  /* ── Small phone ── */
  @media (max-width: 479px) {
    .main { padding: 66px 10px 14px; }
    .stat-grid { gap: 8px; }
    .stat-card { padding: 10px; }
    .stat-card .s-label { font-size: 0.62rem; }
    .stat-card .s-val { font-size: 1.2rem; }
    thead th { font-size: 0.6rem; padding: 7px 8px; }
    tbody td { padding: 6px 8px; font-size: 0.76rem; }
    .btn-sm { font-size: 0.72rem; padding: 4px 9px; }
    .page-title { font-size: 1rem; }
  }

  /* ── Touch targets ── */
  @media (hover: none) and (pointer: coarse) {
    .btn-sm, .gen-btn, .save-btn { min-height: 42px; }
    .nav-item { min-height: 48px; }
    .topbar-hamburger { min-height: 40px; min-width: 40px; }
    button:active { opacity: 0.8; }
  }

  html { scroll-behavior: smooth; }
</style>
</head>
<body>
<div class="layout">
<!-- MOBILE SIDEBAR OVERLAY -->
<div class="sidebar-overlay" id="sidebar-overlay" onclick="closeSidebar()"></div>
<!-- MOBILE TOP BAR -->
<div class="topbar" id="topbar">
  <button class="topbar-hamburger" onclick="toggleSidebar()" aria-label="Menu">&#9776;</button>
  <span class="topbar-title">🛡️ Portal Admin</span>
  <div class="topbar-live"><span class="live-dot"></span>LIVE</div>
</div>
<!-- SIDEBAR -->
<nav class="sidebar" id="sidebar">
  <div class="sidebar-logo">
    <h1>🛡️ Portal Admin</h1>
    <div class="v"><span class="live-dot"></span>LIVE</div>
  </div>
  <div class="nav-item active" onclick="showPage('dashboard',this)">
    <span class="icon">📊</span> Dashboard
  </div>
  <div class="nav-item" onclick="showPage('sessions',this)">
    <span class="icon">📡</span> Sessions
    {% if active_count > 0 %}<span class="badge badge-green" style="margin-left:auto">{{ active_count }}</span>{% endif %}
  </div>
  <div class="nav-item" onclick="showPage('charts',this)">
    <span class="icon">📊</span> Charts
  </div>
  <div class="nav-item" onclick="showPage('lobby',this)">
    <span class="icon">🚪</span> Lobby
    {% if lobby_pending > 0 %}<span class="badge badge-warn" style="margin-left:auto">{{ lobby_pending }}</span>{% endif %}
  </div>
  <div class="nav-item" onclick="showPage('devices',this)">
    <span class="icon">💻</span> Devices
  </div>
  <div class="nav-item" onclick="showPage('vouchers',this)">
    <span class="icon">🎟️</span> Vouchers
  </div>
  <div class="nav-item" onclick="showPage('diagnostics',this)">
    <span class="icon">🔬</span> Diagnostics
  </div>
  <div class="nav-item" onclick="showPage('settings',this)">
    <span class="icon">⚙️</span> Settings
  </div>
  <div class="nav-item" onclick="showPage('analytics',this)">
    <span class="icon">📊</span> Analytics
  </div>
  <div class="nav-item" onclick="showPage('audit',this)">
    <span class="icon">📋</span> Audit Log
  </div>
  <div class="sidebar-footer">
    <a href="/admin/logout">← Logout</a>
  </div>
</nav>

<!-- MAIN CONTENT -->
<main class="main">
{% if message %}<div class="toast">✅ {{ message }}</div>{% endif %}

<!-- ═══════════════ DASHBOARD ═══════════════ -->
<div class="page active" id="page-dashboard">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;">
    <div class="page-title">System Dashboard</div>
    <div style="display:flex;align-items:center;gap:10px;">
      <span id="dash-refresh-dot" style="display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--accent2);animation:livePulse 1.5s ease-in-out infinite;"></span>
      <span style="color:var(--muted);font-size:0.78rem;" id="dash-last-updated">Live</span>
    </div>
  </div>
  <div class="page-sub">Auto-refreshes every 3 seconds</div>

  <!-- Top stat row -->
  <div class="stat-grid">
    <div class="stat-card">
      <div class="s-label">Active Sessions</div>
      <div class="s-val c-blue" id="d-active-count">{{ active_count }}</div>
      <div class="s-sub">connected now</div>
    </div>
    <div class="stat-card">
      <div class="s-label">Total Mins Sold</div>
      <div style="display:flex;align-items:baseline;gap:8px;">
        <div class="s-val c-green" id="d-total-mins">{{ total_mins }}</div>
        <form method="POST" action="/admin/reset_stats" onsubmit="return confirm('Reset minutes sold counter to 0?')">
          <button type="submit" class="btn-sm btn-danger" style="font-size:0.68rem;padding:2px 8px;">↺ Reset</button>
        </form>
      </div>
      <div class="s-sub">all time</div>
    </div>
    <div class="stat-card">
      <div class="s-label">Known Devices</div>
      <div class="s-val" id="d-device-count">{{ device_count }}</div>
      <div class="s-sub">unique MACs</div>
    </div>
    <div class="stat-card">
      <div class="s-label">System Uptime</div>
      <div class="s-val c-warn" style="font-size:1.1rem;font-family:var(--mono);" id="d-uptime">{{ health.uptime }}</div>
      <div class="s-sub" id="d-uptime-sub">since last boot</div>
    </div>
  </div>

  <!-- Network speed row -->
  <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:16px;margin-bottom:28px;">
    <div class="health-card" style="border-color:rgba(59,130,246,0.3);">
      <h3>⬇️ Download Speed</h3>
      <div class="metric-val c-blue" id="d-rx-speed">—</div>
      <div class="metric-sub" id="d-rx-mb">Mbps ↓</div>
      <div class="progress-bar" style="margin-top:8px;">
        <div class="progress-fill fill-blue" id="d-rx-bar" style="width:0%;transition:width 0.8s;"></div>
      </div>
    </div>
    <div class="health-card" style="border-color:rgba(16,185,129,0.3);">
      <h3>⬆️ Upload Speed</h3>
      <div class="metric-val c-green" id="d-tx-speed">—</div>
      <div class="metric-sub" id="d-tx-mb">Mbps ↑</div>
      <div class="progress-bar" style="margin-top:8px;">
        <div class="progress-fill fill-green" id="d-tx-bar" style="width:0%;transition:width 0.8s;"></div>
      </div>
    </div>
    <div class="health-card">
      <h3>📊 Total Data (session)</h3>
      <div class="metric-val" id="d-total-data" style="font-size:1.5rem;">—</div>
      <div class="metric-sub" id="d-data-sub">GB transferred</div>
      <div style="display:flex;gap:8px;margin-top:10px;font-size:0.75rem;font-family:var(--mono);">
        <span style="color:#93c5fd;">↓ <span id="d-rx-total">—</span> MB</span>
        <span style="color:#6ee7b7;">↑ <span id="d-tx-total">—</span> MB</span>
      </div>
    </div>
    <div class="health-card">
      <h3>🌐 WAN Ping</h3>
      <div class="metric-val" id="d-ping" style="font-size:1.5rem;">—</div>
      <div class="metric-sub" id="d-ping-sub">ms to 8.8.8.8</div>
      <div class="progress-bar" style="margin-top:8px;">
        <div class="progress-fill" id="d-ping-bar" style="width:0%;transition:width 0.8s;background:var(--accent2);"></div>
      </div>
    </div>
  </div>

  <!-- Health grid -->
  <div class="health-grid">
    <!-- Internet -->
    <div class="health-card">
      <h3>🌐 Internet Upstream</h3>
      <div class="health-status">
        <div id="d-upstream-dot" class="{{ 'dot-ok' if health.upstream_ok else 'dot-err' }}"></div>
        <span id="d-upstream-txt">{{ 'Connected' if health.upstream_ok else 'No Connection' }}</span>
      </div>
      <div class="metric-sub" style="margin-top:8px;" id="d-upstream-sub">
        {% if health.upstream_latency %}Ping {{ health.upstream_latency }}ms{% endif %}
      </div>
    </div>

    <!-- Portal -->
    <div class="health-card">
      <h3>📶 Captive Portal</h3>
      <div class="health-status">
        <div id="d-portal-dot" class="{{ 'dot-ok' if health.portal_ok else 'dot-err' }}"></div>
        <span id="d-portal-txt">{{ 'Responding' if health.portal_ok else 'Not Responding' }}</span>
      </div>
      <div class="metric-sub" style="margin-top:8px;">Port 8080 self-check</div>
    </div>

    <!-- eth0 -->
    <div class="health-card">
      <h3>🔌 eth0 Interface</h3>
      <div class="health-status">
        <div id="d-eth0-dot" class="{{ 'dot-ok' if health.eth0_up else 'dot-err' }}"></div>
        <span id="d-eth0-txt">{{ 'UP' if health.eth0_up else 'DOWN' }}</span>
      </div>
      <div class="metric-sub" style="margin-top:8px;" id="d-eth0-ip">IP: {{ health.eth0_ip }}</div>
    </div>

    <!-- CPU -->
    <div class="health-card">
      <h3>🖥️ CPU Utilisation</h3>
      <div class="metric-val" id="d-cpu-val" style="font-size:1.8rem;">
        {{ health.cpu_percent if health.cpu_percent >= 0 else '—' }}{% if health.cpu_percent >= 0 %}%{% endif %}
      </div>
      <div class="progress-bar">
        <div class="progress-fill fill-green" id="d-cpu-bar"
             style="width:{{ health.cpu_percent if health.cpu_percent >= 0 else 0 }}%;transition:width 0.8s;"></div>
      </div>
      <div class="metric-sub" style="margin-top:6px;" id="d-load">
        Load: {{ health.load_1 }} / {{ health.load_5 }} / {{ health.load_15 }}
      </div>
    </div>

    <!-- CPU Temp -->
    <div class="health-card">
      <h3>🌡️ CPU Temperature</h3>
      <div class="metric-val" id="d-temp-val" style="font-size:1.8rem;">
        {% if health.cpu_temp is not none %}{{ health.cpu_temp }}°C{% else %}—{% endif %}
      </div>
      <div class="progress-bar">
        <div class="progress-fill fill-green" id="d-temp-bar"
             style="width:{% if health.cpu_temp %}{{ [health.cpu_temp, 100] | min }}{% else %}0{% endif %}%;transition:width 0.8s;"></div>
      </div>
      <div class="metric-sub" style="margin-top:6px;" id="d-temp-sub">
        {% if health.cpu_temp %}{{ 'Throttling risk' if health.cpu_temp > 80 else ('Warm' if health.cpu_temp > 65 else 'Normal') }}{% else %}Sensor unavailable{% endif %}
      </div>
    </div>

    <!-- RAM -->
    <div class="health-card">
      <h3>💾 Memory (RAM)</h3>
      <div class="metric-val" id="d-ram-val" style="font-size:1.8rem;">
        {{ health.ram_percent if health.ram_percent >= 0 else '—' }}{% if health.ram_percent >= 0 %}%{% endif %}
      </div>
      <div class="progress-bar">
        <div class="progress-fill fill-green" id="d-ram-bar"
             style="width:{{ health.ram_percent if health.ram_percent >= 0 else 0 }}%;transition:width 0.8s;"></div>
      </div>
      <div class="metric-sub" style="margin-top:6px;" id="d-ram-sub">
        {{ health.ram_used_mb }}MB / {{ health.ram_total_mb }}MB
      </div>
    </div>
  </div>
</div>

<!-- ═══════════════ LOBBY ═══════════════ -->
<div class="page" id="page-lobby">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;">
    <div class="page-title">Lobby — Pending Requests</div>
    <span id="lobby-refresh-dot" style="display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--warn);animation:livePulse 1.5s ease-in-out infinite;"></span>
  </div>
  <div class="page-sub">Devices waiting on the portal — grant them access with a single click</div>

  {% if lobby_requests %}
  <div class="table-wrap">
    <table>
      <thead>
        <tr><th>Device</th><th>IP</th><th>Plan Requested</th><th>Speed</th><th>Price</th><th>Requested At</th><th>Status</th><th>Grant</th></tr>
      </thead>
      <tbody>
        {% for r in lobby_requests %}
        <tr id="lobby-row-{{ r.id }}">
          <td>
            <div style="font-weight:600;">{{ r.device_name or '—' }}</div>
            <div style="font-family:var(--mono);font-size:0.72rem;color:var(--muted);">{{ r.mac or r.ip }}</div>
          </td>
          <td style="font-family:var(--mono);font-size:0.84rem;">{{ r.ip }}</td>
          <td><span style="font-weight:600;">{{ r.plan_name or 'Custom' }}</span></td>
          <td><span class="badge badge-blue">{{ r.plan_speed or '—' }} Mbps</span></td>
          <td style="font-weight:700;color:var(--accent2);">{{ r.plan_label or '—' }}</td>
          <td style="font-size:0.8rem;color:var(--muted);">{{ r.requested_at[:16].replace('T',' ') }}</td>
          <td>
            {% if r.status == 'pending' %}<span class="badge badge-warn">Pending</span>
            {% elif r.status == 'granted' %}<span class="badge badge-green">Granted</span>
            {% else %}<span class="badge badge-gray">{{ r.status }}</span>{% endif %}
          </td>
          <td style="display:flex;gap:5px;flex-wrap:wrap;">
            {% if r.status == 'pending' %}
            <form method="POST" action="/admin/lobby/grant/{{ r.id }}" style="display:inline">
              <input type="hidden" name="minutes" value="{{ r.plan_minutes or 60 }}">
              <input type="hidden" name="speed" value="{{ r.plan_speed or 5 }}">
              <button class="btn-sm btn-success" style="font-size:0.82rem;padding:6px 14px;">
                ✅ Grant {{ r.plan_name or '' }}
              </button>
            </form>
            <form method="POST" action="/admin/lobby/dismiss/{{ r.id }}" style="display:inline">
              <button class="btn-sm btn-danger">✕</button>
            </form>
            {% elif r.status == 'granted' %}
            <span style="font-family:var(--mono);font-size:0.82rem;color:var(--accent2);">{{ r.granted_code }}</span>
            {% endif %}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% else %}
  <div style="color:var(--muted);padding:50px;text-align:center;background:var(--panel);border:1px solid var(--border);border-radius:14px;">
    <div style="font-size:2rem;margin-bottom:10px;">🚪</div>
    No pending requests. Devices on the portal can use the Request tab to ask for access.
  </div>
  {% endif %}
</div>

<!-- ═══════════════ CHARTS & ANALYTICS ═══════════════ -->
<div class="page" id="page-charts">
  <div class="page-title">📊 Charts & Analytics</div>
  <div class="page-sub">Real-time activity, bandwidth usage, and system health monitoring</div>

  <!-- System Health Widget -->
  <div style="margin-bottom: 28px;">
    <div class="chart-title">System Health</div>
    <div class="health-grid">
      <div class="health-item">
        <div class="health-label">CPU Usage</div>
        <div class="health-value" id="health-cpu-value">0%</div>
        <div class="health-bar"><div class="health-fill" id="health-cpu-bar" style="width:0%"></div></div>
      </div>
      <div class="health-item">
        <div class="health-label">Memory</div>
        <div class="health-value" id="health-mem-value">0%</div>
        <div class="health-bar"><div class="health-fill" id="health-mem-bar" style="width:0%"></div></div>
      </div>
      <div class="health-item">
        <div class="health-label">Disk Space</div>
        <div class="health-value" id="health-disk-value">0%</div>
        <div class="health-bar"><div class="health-fill" id="health-disk-bar" style="width:0%"></div></div>
      </div>
      <div class="health-item">
        <div class="health-label">Uptime</div>
        <div class="health-value" id="health-uptime-value">0h</div>
      </div>
    </div>
  </div>

  <!-- Activity Graph -->
  <div style="margin-bottom: 28px;">
    <div class="chart-title">Real-time Activity (24h)</div>
    <div class="chart-container">
      <canvas id="activityChart"></canvas>
    </div>
  </div>

  <!-- Top Devices Chart -->
  <div style="margin-bottom: 28px;">
    <div class="chart-title">Top Devices by Bandwidth</div>
    <div class="chart-container" style="height:350px;">
      <canvas id="topDevicesChart"></canvas>
    </div>
  </div>

  <!-- Device Groups Management -->
  <div style="margin-bottom: 28px;">
    <div class="chart-title">Device Groups & Labels</div>
    <div style="margin-bottom: 16px;">
      <div style="display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px;">
        <input type="text" id="group-name" placeholder="Group name" class="speed-input" style="width:150px;">
        <input type="color" id="group-color" value="#3498db" style="width:50px; height:34px; border:1px solid var(--border); border-radius:6px; cursor:pointer;">
        <input type="number" id="group-speed" placeholder="Speed Mbps" class="speed-input" style="width:120px;" min="0">
        <button onclick="createDeviceGroup()" class="export-btn">Create Group</button>
      </div>
      <div id="device-groups-list" class="group-selector"></div>
    </div>
  </div>

  <!-- Session Export -->
  <div style="margin-bottom: 28px;">
    <div class="chart-title">Data Export</div>
    <button onclick="exportSessions()" class="export-btn">Export Sessions (CSV)</button>
    <p style="color: var(--muted); font-size: 0.8rem; margin-top: 8px;">Download session logs and device activity in CSV format</p>
  </div>
</div>

<!-- ═══════════════ SESSIONS ═══════════════ -->
<div class="page" id="page-sessions">
  <div class="page-title">Active Sessions</div>
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:28px;">
    <div class="page-sub" style="margin-bottom:0;">Live connected users with real-time countdown</div>
    <form method="POST" action="/admin/sync/leases" style="display:inline">
      <button class="btn-sm btn-primary" title="Re-read dnsmasq leases and update device names">🔄 Sync Device Names</button>
    </form>
  </div>

  {% if active_sessions %}
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>IP Address</th>
          <th>Device</th>
          <th>Code</th>
          <th>Speed</th>
          <th>Time Remaining</th>
          <th>Expires At</th>
          <th>Status</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {% for s in active_sessions %}
        <tr>
          <td><span class="live-dot"></span> {{ s.ip or s.used_by }}</td>
          <td>
            {% if s.device_name %}
              <span style="font-weight:600;">{{ s.device_name }}</span><br>
              <span style="color:var(--muted);font-size:0.74rem;font-family:var(--mono);">{{ s.mac or '—' }}</span>
            {% else %}
              <span style="font-family:var(--mono);font-size:0.82rem;">{{ s.mac or '—' }}</span>
            {% endif %}
          </td>
          <td class="mono">{{ s.code }}</td>
          <td><span class="badge badge-blue">{{ s.speed_mbps }} Mbps</span></td>
          <td>
            <span class="session-cd {% if s.paused_at %}paused{% endif %}"
                  data-expires="{{ s.expires_at or '' }}"
                  data-paused="{{ '1' if s.paused_at else '0' }}"
                  data-remaining="{{ s.remaining_seconds or '' }}">
              {% if s.paused_at %}⏸ PAUSED{% elif not s.expires_at %}∞ Unlimited{% else %}...{% endif %}
            </span>
          </td>
          <td style="font-size:0.82rem;">
            {% if s.expires_at %}{{ s.expires_at[:16].replace('T',' ') }}{% else %}—{% endif %}
          </td>
          <td>
            {% if s.paused_at %}<span class="badge badge-warn">Paused</span>{% else %}<span class="badge badge-green">Active</span>{% endif %}
          </td>
          <td style="display:flex;gap:5px;flex-wrap:wrap;">
            <button class="btn-sm btn-primary"
                    onclick="openEditModal(
                      '{{ s.used_by }}',
                      '{{ s.device_name or (s.mac or s.used_by) }}',
                      {{ s.speed_mbps }},
                      '{{ s.expires_at or '' }}',
                      {{ s.remaining_seconds or 0 }},
                      {{ 1 if s.paused_at else 0 }}
                    )">✏️ Edit</button>
            <form method="POST" action="/admin/kick/{{ s.used_by }}" style="display:inline">
              <button class="btn-sm btn-danger">⏏ Kick</button>
            </form>
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% else %}
  <div style="color:var(--muted);padding:40px;text-align:center;background:var(--panel);border:1px solid var(--border);border-radius:14px;">
    No active sessions right now.
  </div>
  {% endif %}
</div>

<!-- ════ SESSION EDIT MODAL ════ -->
<div id="edit-modal-overlay" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.75);z-index:1000;align-items:center;justify-content:center;">
  <div style="background:#111827;border:1px solid #1f2d45;border-radius:18px;padding:36px 32px;width:480px;max-width:95vw;box-shadow:0 40px 80px rgba(0,0,0,0.7);">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:24px;">
      <div>
        <div style="font-size:1.1rem;font-weight:700;color:var(--text);">✏️ Edit Session</div>
        <div id="modal-device-label" style="font-size:0.82rem;color:var(--muted);margin-top:3px;"></div>
      </div>
      <button onclick="closeEditModal()"
              style="background:rgba(255,255,255,0.06);border:1px solid var(--border);color:var(--muted);
                     border-radius:8px;padding:6px 12px;cursor:pointer;font-size:0.9rem;">✕</button>
    </div>

    <form id="edit-session-form" method="POST" action="">
      <!-- Speed -->
      <div style="margin-bottom:18px;">
        <label style="display:block;color:var(--muted);font-size:0.72rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;">
          Speed Limit (Mbps)
        </label>
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px;" id="speed-presets">
          <button type="button" class="time-btn" onclick="setModalSpeed(1,this)">1</button>
          <button type="button" class="time-btn" onclick="setModalSpeed(2,this)">2</button>
          <button type="button" class="time-btn" onclick="setModalSpeed(5,this)">5</button>
          <button type="button" class="time-btn" onclick="setModalSpeed(10,this)">10</button>
          <button type="button" class="time-btn" onclick="setModalSpeed(20,this)">20</button>
          <button type="button" class="time-btn" onclick="setModalSpeed(50,this)">50</button>
          <button type="button" class="time-btn" onclick="setModalSpeed(100,this)">100</button>
        </div>
        <input type="number" name="speed_mbps" id="modal-speed"
               min="1" max="1000"
               style="padding:9px 12px;background:#1a2235;border:1px solid #1f2d45;border-radius:8px;
                      color:var(--text);font-family:var(--mono);font-size:0.9rem;width:120px;outline:none;">
        <span style="color:var(--muted);font-size:0.82rem;margin-left:6px;">Mbps</span>
      </div>

      <!-- Add / Remove Time -->
      <div style="margin-bottom:18px;">
        <label style="display:block;color:var(--muted);font-size:0.72rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;">
          Adjust Time Remaining
        </label>
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px;">
          <button type="button" class="time-btn" onclick="adjustTime(-60,this)">−1h</button>
          <button type="button" class="time-btn" onclick="adjustTime(-30,this)">−30m</button>
          <button type="button" class="time-btn" onclick="adjustTime(-10,this)">−10m</button>
          <button type="button" class="time-btn" onclick="adjustTime(10,this)">+10m</button>
          <button type="button" class="time-btn" onclick="adjustTime(30,this)">+30m</button>
          <button type="button" class="time-btn" onclick="adjustTime(60,this)">+1h</button>
          <button type="button" class="time-btn" onclick="adjustTime(1440,this)">+24h</button>
        </div>
        <div style="display:flex;align-items:center;gap:8px;">
          <input type="number" name="add_minutes" id="modal-add-min"
                 placeholder="± minutes" min="-9999" max="9999"
                 style="padding:9px 12px;background:#1a2235;border:1px solid #1f2d45;border-radius:8px;
                        color:var(--text);font-family:var(--mono);font-size:0.9rem;width:130px;outline:none;">
          <span style="color:var(--muted);font-size:0.82rem;">minutes (negative to reduce)</span>
        </div>
      </div>

      <!-- Hard set expiry -->
      <div style="margin-bottom:18px;">
        <label style="display:block;color:var(--muted);font-size:0.72rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;">
          Set Absolute Expiry (optional override)
        </label>
        <input type="datetime-local" name="set_expiry" id="modal-expiry"
               style="padding:9px 12px;background:#1a2235;border:1px solid #1f2d45;border-radius:8px;
                      color:var(--text);font-family:var(--mono);font-size:0.88rem;outline:none;width:100%;">
        <div style="color:var(--muted);font-size:0.74rem;margin-top:4px;">Leave blank to use adjusted time above. Device timezone: UTC.</div>
      </div>

      <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:8px;">
        <button type="button" onclick="closeEditModal()"
                style="padding:10px 20px;background:rgba(255,255,255,0.05);border:1px solid var(--border);
                       border-radius:8px;color:var(--muted);cursor:pointer;font-family:var(--sans);font-size:0.88rem;">
          Cancel
        </button>
        <button type="submit"
                style="padding:10px 24px;background:var(--accent);border:none;border-radius:8px;
                       color:#fff;font-family:var(--sans);font-size:0.88rem;font-weight:700;cursor:pointer;">
          💾 Apply Changes
        </button>
      </div>
    </form>
  </div>
</div>

<!-- ═══════════════ DEVICES ═══════════════ -->
<div class="page" id="page-devices">
  <div class="page-title">Known Devices</div>
  <div class="page-sub">All devices that have connected — click name to edit | 🚫 = Blocked (Feature #1) | 📊 = Rate Limit (Feature #5)</div>

  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Device Name</th>
          <th>MAC Address</th>
          <th>IP</th>
          <th>First Seen</th>
          <th>Last Seen</th>
          <th>Status</th>
          <th>Rate Limit</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {% for d in devices %}
        <tr {% if d.blocked %}style="opacity:0.5;background:rgba(239,68,68,0.05);"{% endif %}>
          <td>
            {% if d.blocked %}<span style="color:#ef4444;font-weight:700;margin-right:4px;">🚫</span>{% endif %}
            <div class="name-edit">
              <input class="name-input" id="name-{{ d.mac }}"
                     value="{{ d.name or '' }}"
                     placeholder="Unnamed device"
                     onkeydown="if(event.key==='Enter') saveName('{{ d.mac }}')">
              <button class="name-save-btn" onclick="saveName('{{ d.mac }}')">✓</button>
            </div>
          </td>
          <td style="font-family:var(--mono);font-size:0.82rem;color:var(--muted);">{{ d.mac }}</td>
          <td>{{ d.ip or '—' }}</td>
          <td style="font-size:0.8rem;color:var(--muted);">{{ d.first_seen[:16].replace('T',' ') if d.first_seen else '—' }}</td>
          <td style="font-size:0.8rem;color:var(--muted);">{{ d.last_seen[:16].replace('T',' ') if d.last_seen else '—' }}</td>
          <td>
            {% if d.connected %}<span class="badge badge-green">● Online</span>
            {% else %}<span class="badge badge-gray">○ Offline</span>{% endif %}
            {% if d.whitelisted %}<span class="badge badge-blue" style="margin-left:4px">WL</span>{% endif %}
          </td>
          <td style="font-size:0.75rem;">
            {% if d.daily_quota_mb %}📊 {{ d.daily_quota_mb }}MB/day{% else %}-{% endif %}
          </td>
          <td style="display:flex;gap:4px;flex-wrap:wrap;">
            {% if not d.blocked %}
            <form method="POST" action="/admin/device/block/{{ d.mac }}" style="display:inline">
              <button class="btn-sm btn-danger" title="Block this device">🚫 Block</button>
            </form>
            {% else %}
            <form method="POST" action="/admin/device/unblock/{{ d.mac }}" style="display:inline">
              <button class="btn-sm btn-success" title="Unblock device">✓ Unblock</button>
            </form>
            {% endif %}
            <button class="btn-sm btn-primary" onclick="openRateLimitModal('{{ d.mac }}', {{ d.daily_quota_mb or 0 }}, {{ d.hourly_quota_mb or 0 }})">📊 Limits</button>
            {% if not d.whitelisted %}
            <form method="POST" action="/admin/whitelist/{{ d.mac }}" style="display:inline">
              <button class="btn-sm btn-primary">WL</button>
            </form>
            {% else %}
            <form method="POST" action="/admin/unwhitelist/{{ d.mac }}" style="display:inline">
              <button class="btn-sm btn-danger">Remove WL</button>
            </form>
            {% endif %}
            {% if d.ip %}
            <form method="POST" action="/admin/kick/{{ d.ip }}" style="display:inline">
              <button class="btn-sm btn-danger">Kick</button>
            </form>
            {% endif %}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</div>

<!-- Rate Limit Modal (Feature #5) -->
<div id="ratelimit-modal-overlay" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.75);z-index:1000;align-items:center;justify-content:center;">
  <div style="background:#111827;border:1px solid #1f2d45;border-radius:18px;padding:36px 32px;width:400px;max-width:95vw;box-shadow:0 40px 80px rgba(0,0,0,0.7);">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:24px;">
      <div>
        <div style="font-size:1.1rem;font-weight:700;color:var(--text);">📊 Rate Limiting</div>
        <div id="rl-device-label" style="font-size:0.82rem;color:var(--muted);margin-top:3px;"></div>
      </div>
      <button onclick="closeRateLimitModal()" style="background:rgba(255,255,255,0.06);border:1px solid var(--border);color:var(--muted);border-radius:8px;padding:6px 12px;cursor:pointer;font-size:0.9rem;">✕</button>
    </div>
    <form method="POST" id="rl-form">
      <div style="margin-bottom:18px;">
        <label style="display:block;color:var(--muted);font-size:0.72rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;">Daily Quota (MB)</label>
        <input type="number" name="daily_quota_mb" id="rl-daily" min="0" style="padding:9px 12px;background:#1a2235;border:1px solid #1f2d45;border-radius:8px;color:var(--text);font-size:0.9rem;width:100%;outline:none;">
        <div style="color:var(--muted);font-size:0.74rem;margin-top:4px;">0 = unlimited</div>
      </div>
      <div style="margin-bottom:18px;">
        <label style="display:block;color:var(--muted);font-size:0.72rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;">Hourly Quota (MB)</label>
        <input type="number" name="hourly_quota_mb" id="rl-hourly" min="0" style="padding:9px 12px;background:#1a2235;border:1px solid #1f2d45;border-radius:8px;color:var(--text);font-size:0.9rem;width:100%;outline:none;">
        <div style="color:var(--muted);font-size:0.74rem;margin-top:4px;">0 = unlimited</div>
      </div>
      <div style="display:flex;gap:10px;justify-content:flex-end;">
        <button type="button" onclick="closeRateLimitModal()" style="padding:10px 20px;background:rgba(255,255,255,0.05);border:1px solid var(--border);border-radius:8px;color:var(--muted);cursor:pointer;font-family:var(--sans);font-size:0.88rem;">Cancel</button>
        <button type="submit" style="padding:10px 24px;background:var(--accent);border:none;border-radius:8px;color:#fff;font-family:var(--sans);font-size:0.88rem;font-weight:700;cursor:pointer;">💾 Save</button>
      </div>
    </form>
  </div>
</div>

<!-- ═══════════════ VOUCHERS ═══════════════ -->
<div class="page" id="page-vouchers">
  <div class="page-title">Voucher Management</div>
  <div class="page-sub">Generate, print, and manage access vouchers | 🎁 = Temporary Guest Code (Feature #6) | 📤 = Export (Feature #8)</div>

  <div class="gen-card">
    <h2>Generate Regular Vouchers</h2>
    <form method="POST" action="/admin/generate">
      <input type="hidden" name="minutes" id="minutesInput" value="60">
      <div class="time-btns">
        <button type="button" class="time-btn" onclick="setTime(1,this)">1 min</button>
        <button type="button" class="time-btn" onclick="setTime(5,this)">5 min</button>
        <button type="button" class="time-btn" onclick="setTime(10,this)">10 min</button>
        <button type="button" class="time-btn" onclick="setTime(30,this)">30 min</button>
        <button type="button" class="time-btn active" onclick="setTime(60,this)">1 hour</button>
        <button type="button" class="time-btn" onclick="setTime(1440,this)">24 hours</button>
      </div>
      <div class="form-row">
        <div class="form-field">
          <label>Custom (min)</label>
          <input type="number" id="customMin" placeholder="e.g. 90" min="1" max="9999"
                 oninput="setCustom(this.value)">
        </div>
        <div class="form-field">
          <label>Speed (Mbps)</label>
          <input type="number" name="speed" value="5" min="1" max="1000">
        </div>
        <div class="form-field">
          <label>Hard Expiry (hrs)</label>
          <input type="number" name="absolute_expiry_hours" value="0" min="0" max="720"
                 title="Hours until voucher becomes invalid regardless of pause. 0 = none.">
        </div>
        <div class="form-field">
          <label>Quantity</label>
          <input type="number" name="qty" value="1" min="1" max="50">
        </div>
        <div class="form-field" style="justify-content:flex-end">
          <button type="submit" class="gen-btn">Generate</button>
        </div>
        <div class="form-field" style="justify-content:flex-end">
          <button type="button" onclick="window.print()"
                  style="background:rgba(59,130,246,0.2);border:1px solid rgba(59,130,246,0.4);color:#93c5fd;"
                  class="gen-btn">🖨️ Print</button>
        </div>
        <div class="form-field" style="justify-content:flex-end">
          <a href="/admin/export/vouchers"
                  style="background:rgba(16,185,129,0.2);border:1px solid rgba(16,185,129,0.4);color:#6ee7b7;text-decoration:none;display:inline-block;"
                  class="gen-btn">📤 Export CSV</a>
        </div>
      </div>
    </form>

    {% if new_vouchers %}
    <div style="border-top:1px solid var(--border);padding-top:20px;margin-top:4px;">
      <div style="font-size:0.78rem;color:var(--muted);margin-bottom:12px;">GENERATED CODES</div>
      <div class="voucher-grid print-area">
        {% for v in new_vouchers %}
        <div class="voucher-chip voucher-slip">
          <img src="data:image/png;base64,{{ v.qr }}" alt="QR">
          <div class="v-code">{{ v.code }}</div>
          <div class="v-meta">{{ v.minutes }} min | {{ v.speed }} Mbps{% if v.abs_expiry_h %} | ⏰ {{ v.abs_expiry_h }}h hard limit{% endif %}</div>
        </div>
        {% endfor %}
      </div>
    </div>
    {% endif %}
  </div>

  <!-- Temporary Guest Codes (Feature #6) -->
  <div class="gen-card" style="margin-top:28px;">
    <h2>🎁 Generate Temporary Guest Codes (30 min auto-revoke)</h2>
    <form method="POST" action="/admin/generate_temporary">
      <div style="display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap;margin-bottom:16px;">
        <div class="form-field">
          <label>Speed (Mbps)</label>
          <input type="number" name="speed" value="3" min="1" max="1000">
        </div>
        <div class="form-field">
          <label>Quantity</label>
          <input type="number" name="qty" value="1" min="1" max="10">
        </div>
        <div class="form-field" style="justify-content:flex-end">
          <button type="submit" class="gen-btn">🎁 Generate Temp Codes</button>
        </div>
      </div>
    </form>
  </div>

  <!-- Bulk Import (Feature #8) -->
  <div class="gen-card" style="margin-top:28px;">
    <h2>📥 Bulk Import Vouchers from CSV</h2>
    <form method="POST" action="/admin/import/vouchers" enctype="multipart/form-data">
      <div style="display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap;margin-bottom:16px;">
        <div class="form-field" style="flex:1;min-width:200px;">
          <label>CSV File (Code, Duration, Speed columns)</label>
          <input type="file" name="file" accept=".csv" required style="padding:9px 12px;background:#1a2235;border:1px solid #1f2d45;border-radius:8px;color:var(--text);font-size:0.88rem;cursor:pointer;">
        </div>
        <div class="form-field" style="justify-content:flex-end">
          <button type="submit" class="gen-btn">📥 Import</button>
        </div>
      </div>
    </form>
  </div>

  <div style="font-size:0.78rem;color:var(--muted);letter-spacing:1px;text-transform:uppercase;margin-bottom:12px;margin-top:28px;">Recent Vouchers (last 100)</div>
  <div class="table-wrap">
    <table>
      <thead>
        <tr><th>QR</th><th>Code</th><th>Duration</th><th>Speed</th><th>Type</th><th>Status</th><th>Used By</th><th>Used At</th><th>Action</th></tr>
      </thead>
      <tbody>
        {% for v in vouchers %}
        <tr>
          <td><img src="data:image/png;base64,{{ v.qr }}" style="width:36px;height:36px;border-radius:4px;cursor:zoom-in;"
                   onclick="showQrPopup(this.src,'{{ v.code }}')" title="Click to enlarge"></td>
          <td class="mono">{{ v.code }}</td>
          <td>{{ v.duration_minutes }} min</td>
          <td><span class="badge badge-blue">{{ v.speed_mbps }} Mbps</span></td>
          <td>
            {% if v.temporary %}<span class="badge badge-warn">🎁 Temp</span>{% else %}<span class="badge badge-gray">Regular</span>{% endif %}
          </td>
          <td>
            {% if v.used_by %}
              {% if v.paused_at %}<span class="badge badge-warn">Paused</span>
              {% elif v.active %}<span class="badge badge-green">Active</span>
              {% else %}<span class="badge badge-gray">Expired</span>{% endif %}
            {% elif not v.active %}<span class="badge badge-red">Revoked</span>
            {% else %}<span class="badge badge-gray">Available</span>{% endif %}
          </td>
          <td style="font-size:0.82rem;">{{ v.used_by or '—' }}</td>
          <td style="font-size:0.8rem;color:var(--muted);">{{ v.used_at[:16].replace('T',' ') if v.used_at else '—' }}</td>
          <td>
            {% if v.active %}
            <form method="POST" action="/admin/revoke/{{ v.id }}" style="display:inline">
              <button class="btn-sm btn-danger">Revoke</button>
            </form>
            {% endif %}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</div>

<!-- ═══════════════ DIAGNOSTICS ═══════════════ -->
<div class="page" id="page-diagnostics">
  <div class="page-title">Network Diagnostics</div>
  <div class="page-sub">Run live checks on connectivity, services and routing</div>

  <div style="display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap;">
    <button class="gen-btn" onclick="runDiagnostics()" id="diag-run-btn">▶ Run All Checks</button>
    <span style="color:var(--muted);font-size:0.82rem;align-self:center;" id="diag-status">Press Run to begin</span>
  </div>

  <div id="diag-results" style="display:flex;flex-direction:column;gap:10px;"></div>

  <!-- Ping tool -->
  <div class="settings-section" style="margin-top:24px;">
    <h2>🏓 Custom Ping Tool</h2>
    <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:14px;">
      <input id="ping-host" class="setting-input" style="width:220px;text-align:left;"
             placeholder="e.g. 8.8.8.8 or google.com" value="8.8.8.8">
      <input id="ping-count" class="setting-input" style="width:70px;" type="number" value="4" min="1" max="20">
      <span style="color:var(--muted);font-size:0.82rem;">packets</span>
      <button class="gen-btn" onclick="runPing()" id="ping-btn">Ping</button>
    </div>
    <pre id="ping-output" style="background:#0d1117;border:1px solid var(--border);border-radius:10px;
         padding:16px;font-family:var(--mono);font-size:0.82rem;color:#94a3b8;
         max-height:220px;overflow-y:auto;white-space:pre-wrap;display:none;"></pre>
  </div>
</div>

<!-- ═══════════════ SETTINGS ═══════════════ -->
<div class="page" id="page-settings">
  <div class="page-title">Portal Settings</div>
  <div class="page-sub">Configure captive portal behaviour and defaults</div>

  <form method="POST" action="/admin/settings">
    <div class="settings-section">
      <h2>Portal Appearance</h2>
      <div class="setting-row">
        <div class="setting-info">
          <h3>Portal Title</h3>
          <p>Main heading shown on the WiFi access page</p>
        </div>
        <input class="setting-input" style="width:200px" type="text" name="portal_title" value="{{ settings.portal_title }}">
      </div>
      <div class="setting-row">
        <div class="setting-info">
          <h3>Portal Subtitle</h3>
          <p>Subtext shown below the title</p>
        </div>
        <input class="setting-input" style="width:200px" type="text" name="portal_subtitle" value="{{ settings.portal_subtitle }}">
      </div>
    </div>

    <div class="settings-section">
      <h2>Session Control</h2>
      <div class="setting-row">
        <div class="setting-info">
          <h3>Allow Session Pausing</h3>
          <p>Users can pause their remaining time from the status page</p>
        </div>
        <label class="toggle">
          <input type="checkbox" name="allow_pause" value="1" {{ 'checked' if settings.allow_pause == '1' else '' }}>
          <span class="slider"></span>
        </label>
      </div>
      <div class="setting-row">
        <div class="setting-info">
          <h3>Default Hard Expiry (hours)</h3>
          <p>Max hours a voucher can exist regardless of pausing. 0 = disabled.</p>
        </div>
        <input class="setting-input" type="number" name="absolute_expiry_hours" min="0" max="720"
               value="{{ settings.absolute_expiry_hours }}">
      </div>
    </div>

    <div class="settings-section">
      <h2>Defaults for New Vouchers</h2>
      <div class="setting-row">
        <div class="setting-info">
          <h3>Default Speed (Mbps)</h3>
          <p>Pre-filled speed on the voucher generator</p>
        </div>
        <input class="setting-input" type="number" name="default_speed" min="1" max="1000"
               value="{{ settings.default_speed or '5' }}">
      </div>
    </div>

    <div class="settings-section">
      <h2>📋 Data Rates / Plans</h2>
      <div class="setting-row">
        <div class="setting-info">
          <h3>Show Plans on Portal</h3>
          <p>Display available plans on the captive portal for users to see pricing</p>
        </div>
        <label class="toggle">
          <input type="checkbox" name="show_rates" value="1" {{ 'checked' if settings.show_rates == '1' else '' }}>
          <span class="slider"></span>
        </label>
      </div>
      <div style="margin-top:16px;">
        <div style="color:var(--muted);font-size:0.72rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:10px;">Plans (one per row: Name | Minutes | Speed Mbps | Price Label)</div>
        <div id="rates-editor" style="display:flex;flex-direction:column;gap:8px;margin-bottom:10px;"></div>
        <button type="button" onclick="addRateRow()" class="btn-sm btn-primary" style="font-size:0.82rem;padding:6px 14px;">+ Add Plan</button>
        <input type="hidden" name="data_rates" id="data-rates-json">
      </div>
    </div>

    <button type="submit" class="save-btn" onclick="serializeRates()">💾 Save Settings</button>
  </form>
</div>

<!-- ═══════════════ ANALYTICS (Feature #3) ═══════════════ -->
<div class="page" id="page-analytics">
  <div class="page-title">📊 Voucher & Usage Analytics</div>
  <div class="page-sub">Real-time insights into system usage patterns</div>
  
  <div id="analytics-loading" style="text-align:center;padding:40px;color:var(--muted);">Loading analytics...</div>
  <div id="analytics-content" style="display:none;">
    <div class="stat-grid">
      <div class="stat-card">
        <div class="s-label">Total Codes</div>
        <div class="s-val c-blue" id="a-total-codes">—</div>
        <div class="s-sub">all time</div>
      </div>
      <div class="stat-card">
        <div class="s-label">Used Codes</div>
        <div class="s-val c-green" id="a-used-codes">—</div>
        <div class="s-sub">% used</div>
      </div>
      <div class="stat-card">
        <div class="s-label">Available</div>
        <div class="s-val c-warn" id="a-available-codes">—</div>
        <div class="s-sub">ready to use</div>
      </div>
      <div class="stat-card">
        <div class="s-label">Total Minutes</div>
        <div class="s-val c-blue" id="a-total-minutes">—</div>
        <div class="s-sub">sold</div>
      </div>
      <div class="stat-card">
        <div class="s-label">Data Transferred</div>
        <div class="s-val c-green" id="a-total-gb">—</div>
        <div class="s-sub">GB total</div>
      </div>
    </div>
  </div>
</div>

<!-- ═══════════════ AUDIT LOGS (Feature #7) ═══════════════ -->
<div class="page" id="page-audit">
  <div class="page-title">📋 Admin Audit Trail</div>
  <div class="page-sub">Complete log of all administrative actions</div>
  
  <div class="table-wrap">
    <table>
      <thead>
        <tr><th>Timestamp</th><th>Action</th><th>Target</th><th>Details</th></tr>
      </thead>
      <tbody id="audit-logs-tbody">
        <tr><td colspan="4" style="text-align:center;color:var(--muted);">Loading audit logs...</td></tr>
      </tbody>
    </table>
  </div>
</div>

<div id="qr-popup-overlay" onclick="closeQrPopup()" style="display:none;position:fixed;inset:0;
     background:rgba(0,0,0,0.82);z-index:9999;align-items:center;justify-content:center;cursor:zoom-out;">
  <div onclick="event.stopPropagation()" style="background:#fff;border-radius:20px;padding:24px;
       box-shadow:0 40px 80px rgba(0,0,0,0.8);text-align:center;animation:qrPopIn 0.2s ease;">
    <img id="qr-popup-img" src="" style="width:280px;height:280px;display:block;border-radius:6px;">
    <div id="qr-popup-code" style="font-family:'IBM Plex Mono',monospace;font-size:1.1rem;
         letter-spacing:4px;color:#0a0e1a;font-weight:700;margin-top:12px;"></div>
    <div style="color:#64748b;font-size:0.75rem;margin-top:4px;">Click outside to close</div>
  </div>
</div>
<style>
@keyframes qrPopIn { from{transform:scale(0.7);opacity:0} to{transform:scale(1);opacity:1} }
</style>

<script>
// ─── Sidebar Toggle (Mobile) ───
function openSidebar() {
  document.getElementById('sidebar').classList.add('open');
  document.getElementById('sidebar-overlay').classList.add('active');
  document.body.style.overflow = 'hidden';
}
function closeSidebar() {
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('sidebar-overlay').classList.remove('active');
  document.body.style.overflow = '';
}
function toggleSidebar() {
  if (document.getElementById('sidebar').classList.contains('open')) {
    closeSidebar();
  } else {
    openSidebar();
  }
}
// Close sidebar on nav click (mobile)
document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', () => {
    if (window.innerWidth < 768) closeSidebar();
  });
});

// ─── QR Popup ───
function showQrPopup(src, code) {
  document.getElementById('qr-popup-img').src = src;
  document.getElementById('qr-popup-code').textContent = code;
  const ov = document.getElementById('qr-popup-overlay');
  ov.style.display = 'flex';
}
function closeQrPopup() {
  document.getElementById('qr-popup-overlay').style.display = 'none';
}
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeQrPopup(); });

function showPage(name, el) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const pageEl = document.getElementById('page-' + name);
  if (pageEl) pageEl.classList.add('active');
  if (el) el.classList.add('active');
  if (name === 'dashboard') startDashboardPolling();
  else stopDashboardPolling();
  if (name === 'sessions') startSessionsPolling();
  else stopSessionsPolling();
  // Load data for new tabs
  if (name === 'analytics') setTimeout(loadAnalytics, 100);
  if (name === 'audit') setTimeout(loadAuditLogs, 100);
  if (name === 'charts') setTimeout(() => {
    updateSystemHealth();
    updateActivityGraph();
    updateTopDevicesChart();
    loadDeviceGroups();
  }, 100);
  // Close mobile sidebar
  if (window.innerWidth < 768) closeSidebar();
  // Update URL hash for bookmarking
  location.hash = name;
}

function setTime(m, el) {
  document.getElementById('minutesInput').value = m;
  document.getElementById('customMin').value = '';
  document.querySelectorAll('.time-btn').forEach(b => b.classList.remove('active'));
  el.classList.add('active');
}
function setCustom(val) {
  document.getElementById('minutesInput').value = val;
  document.querySelectorAll('.time-btn').forEach(b => b.classList.remove('active'));
}

// ─── Real-time Dashboard Polling ───
let _dashTimer = null;
let _bootTimestamp = null;  // set when we first get uptime_secs from API

function startDashboardPolling() {
  if (_dashTimer) return;
  fetchDashboardData();
  _dashTimer = setInterval(fetchDashboardData, 3000);
}
function stopDashboardPolling() {
  if (_dashTimer) { clearInterval(_dashTimer); _dashTimer = null; }
}

async function fetchDashboardData() {
  try {
    const r = await fetch('/admin/api/health');
    const h = await r.json();
    applyDashboard(h);
    document.getElementById('dash-last-updated').textContent =
      'Updated ' + new Date().toLocaleTimeString();
  } catch(e) {
    document.getElementById('dash-last-updated').textContent = '⚠ Fetch error';
  }
}

function colorClass(val, warn, crit) {
  return val >= crit ? 'c-red' : (val >= warn ? 'c-warn' : 'c-green');
}
function fillClass(val, warn, crit) {
  return val >= crit ? 'fill-red' : (val >= warn ? 'fill-warn' : 'fill-green');
}
function setBar(id, pct, warn, crit) {
  const el = document.getElementById(id);
  if (!el) return;
  el.style.width = Math.min(100, pct) + '%';
  el.className = 'progress-fill ' + fillClass(pct, warn, crit);
}
function setDot(id, ok) {
  const el = document.getElementById(id);
  if (el) el.className = ok ? 'dot-ok' : 'dot-err';
}
function setTxt(id, txt) {
  const el = document.getElementById(id);
  if (el) el.textContent = txt;
}
function setColor(id, val, warn, crit) {
  const el = document.getElementById(id);
  if (!el) return;
  el.className = el.className.replace(/c-(green|warn|red)/g, '') + ' ' + colorClass(val, warn, crit);
}

function applyDashboard(h) {
  // Sessions / devices (fetched from a separate quick endpoint)
  fetch('/admin/api/stats').then(r=>r.json()).then(s=>{
    setTxt('d-active-count', s.active_count);
    setTxt('d-total-mins', s.total_mins);
    setTxt('d-device-count', s.device_count);
  }).catch(()=>{});

  // Uptime — derive boot time on first call, then tick in JS
  if (h.uptime_secs && !_bootTimestamp) {
    _bootTimestamp = Date.now() - h.uptime_secs * 1000;
    tickUptime();
  }

  // Network speed
  const rx = h.wan_rx_mbps ?? 0;
  const tx = h.wan_tx_mbps ?? 0;
  setTxt('d-rx-speed', rx.toFixed(2));
  setTxt('d-rx-mb', `Mbps ↓  (${h.wan_iface || 'wan'})`);
  setTxt('d-tx-speed', tx.toFixed(2));
  setTxt('d-tx-mb', `Mbps ↑  (${h.wan_iface || 'wan'})`);
  setBar('d-rx-bar', Math.min(rx / 100 * 100, 100), 50, 80);
  setBar('d-tx-bar', Math.min(tx / 100 * 100, 100), 50, 80);

  // Total data
  const totalGB = h.wan_total_gb ?? 0;
  setTxt('d-total-data', totalGB.toFixed(3) + ' GB');
  setTxt('d-data-sub', `${h.wan_iface || 'wan'} since boot`);
  setTxt('d-rx-total', (h.wan_rx_mb ?? 0).toFixed(0));
  setTxt('d-tx-total', (h.wan_tx_mb ?? 0).toFixed(0));

  // Ping latency
  if (h.upstream_latency !== null && h.upstream_latency !== undefined) {
    setTxt('d-ping', h.upstream_latency + ' ms');
    setTxt('d-ping-sub', 'RTT to 8.8.8.8');
    const pingPct = Math.min(h.upstream_latency / 200 * 100, 100);
    const pb = document.getElementById('d-ping-bar');
    if (pb) {
      pb.style.width = pingPct + '%';
      pb.style.background = h.upstream_latency > 150 ? 'var(--danger)' : (h.upstream_latency > 80 ? 'var(--warn)' : 'var(--accent2)');
    }
  } else {
    setTxt('d-ping', h.upstream_ok ? '—' : '✕');
    setTxt('d-ping-sub', h.upstream_ok ? 'No data' : 'No connection');
  }

  // Status dots
  setDot('d-upstream-dot', h.upstream_ok);
  setTxt('d-upstream-txt', h.upstream_ok ? 'Connected' : 'No Connection');
  setTxt('d-upstream-sub', h.upstream_latency ? `Ping ${h.upstream_latency}ms to 8.8.8.8` : '');
  setDot('d-portal-dot', h.portal_ok);
  setTxt('d-portal-txt', h.portal_ok ? 'Responding' : 'Not Responding');
  setDot('d-eth0-dot', h.eth0_up);
  setTxt('d-eth0-txt', h.eth0_up ? 'UP' : 'DOWN');
  setTxt('d-eth0-ip', `IP: ${h.eth0_ip || 'N/A'}`);

  // CPU
  if (h.cpu_percent >= 0) {
    const cpuEl = document.getElementById('d-cpu-val');
    if (cpuEl) {
      cpuEl.textContent = h.cpu_percent + '%';
      cpuEl.className = 'metric-val ' + colorClass(h.cpu_percent, 60, 85);
    }
    setBar('d-cpu-bar', h.cpu_percent, 60, 85);
    setTxt('d-load', `Load: ${h.load_1} / ${h.load_5} / ${h.load_15}`);
  }

  // CPU Temp
  if (h.cpu_temp !== null && h.cpu_temp !== undefined) {
    const tempEl = document.getElementById('d-temp-val');
    if (tempEl) {
      tempEl.textContent = h.cpu_temp + '°C';
      tempEl.className = 'metric-val ' + colorClass(h.cpu_temp, 65, 80);
    }
    setBar('d-temp-bar', Math.min(h.cpu_temp, 100), 65, 80);
    setTxt('d-temp-sub', h.cpu_temp > 80 ? 'Throttling risk' : (h.cpu_temp > 65 ? 'Warm' : 'Normal'));
  }

  // RAM
  if (h.ram_percent >= 0) {
    const ramEl = document.getElementById('d-ram-val');
    if (ramEl) {
      ramEl.textContent = h.ram_percent + '%';
      ramEl.className = 'metric-val ' + colorClass(h.ram_percent, 70, 90);
    }
    setBar('d-ram-bar', h.ram_percent, 70, 90);
    setTxt('d-ram-sub', `${h.ram_used_mb}MB / ${h.ram_total_mb}MB`);
  }
}

function tickUptime() {
  if (!_bootTimestamp) return;
  const secs = Math.floor((Date.now() - _bootTimestamp) / 1000);
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  const txt = d > 0 ? `${d}d ${h}h ${m}m` : `${h}h ${m}m ${s}s`;
  setTxt('d-uptime', txt);
  setTimeout(tickUptime, 1000);
}

// ─── Diagnostics ───
async function runDiagnostics() {
  const btn = document.getElementById('diag-run-btn');
  const status = document.getElementById('diag-status');
  const results = document.getElementById('diag-results');
  btn.disabled = true;
  btn.textContent = '⏳ Running…';
  status.textContent = 'Tests in progress — this may take 15-30 seconds…';
  results.innerHTML = '';

  // Skeleton cards
  for (let i = 0; i < 10; i++) {
    const div = document.createElement('div');
    div.style.cssText = 'background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:14px 18px;display:flex;align-items:center;gap:12px;opacity:0.4;';
    div.innerHTML = `<div style="width:10px;height:10px;border-radius:50%;background:var(--muted);flex-shrink:0;"></div>
                     <div style="font-size:0.85rem;color:var(--muted);">Waiting…</div>`;
    results.appendChild(div);
  }

  try {
    const r = await fetch('/admin/api/diagnostics');
    const checks = await r.json();
    results.innerHTML = '';
    checks.forEach(c => {
      const div = document.createElement('div');
      div.style.cssText = `background:var(--panel);border:1px solid ${c.ok ? 'rgba(16,185,129,0.25)' : 'rgba(239,68,68,0.25)'};border-radius:10px;padding:14px 18px;display:flex;align-items:flex-start;gap:12px;animation:fadeIn 0.3s ease;`;
      div.innerHTML = `
        <div style="width:10px;height:10px;border-radius:50%;background:${c.ok ? 'var(--accent2)' : 'var(--danger)'};flex-shrink:0;margin-top:4px;"></div>
        <div style="flex:1">
          <div style="font-size:0.88rem;font-weight:600;color:${c.ok ? 'var(--text)' : '#fca5a5'};">${c.name}</div>
          <div style="font-size:0.8rem;color:var(--muted);margin-top:3px;font-family:var(--mono);">${c.detail}</div>
        </div>
        <div class="badge ${c.ok ? 'badge-green' : 'badge-red'}">${c.ok ? '✓ PASS' : '✗ FAIL'}</div>`;
      results.appendChild(div);
    });
    const passed = checks.filter(c => c.ok).length;
    status.textContent = `${passed}/${checks.length} checks passed`;
  } catch(e) {
    status.textContent = '⚠ Error fetching results';
  }
  btn.disabled = false;
  btn.textContent = '▶ Run All Checks';
}

async function runPing() {
  const host = document.getElementById('ping-host').value.trim();
  const count = document.getElementById('ping-count').value || 4;
  const out = document.getElementById('ping-output');
  const btn = document.getElementById('ping-btn');
  if (!host) return;
  btn.disabled = true; btn.textContent = 'Pinging…';
  out.style.display = 'block';
  out.textContent = `Pinging ${host} × ${count}…\n`;
  try {
    const r = await fetch(`/admin/api/ping?host=${encodeURIComponent(host)}&count=${count}`);
    const d = await r.json();
    out.textContent = d.output || d.error || '(no output)';
  } catch(e) {
    out.textContent = 'Error: ' + e.message;
  }
  btn.disabled = false; btn.textContent = 'Ping';
}

// ── Session Edit Modal ──
let _modalBaseRemaining = 0;

function openEditModal(ip, deviceLabel, speed, expiresAt, remainingSecs, isPaused) {
  const overlay = document.getElementById('edit-modal-overlay');
  document.getElementById('modal-device-label').textContent = deviceLabel + '  ·  ' + ip;
  document.getElementById('modal-speed').value = speed;
  document.getElementById('modal-add-min').value = '';
  document.getElementById('modal-expiry').value = '';
  document.getElementById('edit-session-form').action = '/admin/session/edit/' + encodeURIComponent(ip);
  _modalBaseRemaining = isPaused ? remainingSecs : Math.max(0, Math.floor((new Date(expiresAt + 'Z') - new Date()) / 1000));
  document.querySelectorAll('#speed-presets .time-btn').forEach(b => {
    b.classList.toggle('active', parseInt(b.textContent) === speed);
  });
  overlay.style.display = 'flex';
}
function closeEditModal() {
  document.getElementById('edit-modal-overlay').style.display = 'none';
}
function setModalSpeed(v, el) {
  document.getElementById('modal-speed').value = v;
  document.querySelectorAll('#speed-presets .time-btn').forEach(b => b.classList.remove('active'));
  el.classList.add('active');
}
function adjustTime(mins, el) {
  const cur = parseInt(document.getElementById('modal-add-min').value) || 0;
  document.getElementById('modal-add-min').value = cur + mins;
  el.style.borderColor = 'var(--accent2)';
  setTimeout(() => el.style.borderColor = '', 400);
}
document.getElementById('edit-modal-overlay').addEventListener('click', function(e) {
  if (e.target === this) closeEditModal();
});

// Activate correct page from URL hash
window.addEventListener('DOMContentLoaded', () => {
  const hash = location.hash.replace('#','');
  if (hash) {
    const nav = document.querySelector(`.nav-item[onclick*="'${hash}'"]`);
    if (nav) showPage(hash, nav);
  } else {
    // Initialize dashboard on first load
    const dashboardNav = document.querySelector(`.nav-item[onclick*="'dashboard'"]`);
    if (dashboardNav) showPage('dashboard', dashboardNav);
    else startDashboardPolling();
  }
  startCountdowns();
});

// Real-time session countdowns
function startCountdowns() {
  document.querySelectorAll('.session-cd').forEach(el => {
    const expires = el.dataset.expires;
    const paused = el.dataset.paused === '1';
    if (paused) return;
    if (!expires) return;
    const expiresAt = new Date(expires + 'Z');
    function tick() {
      const diff = Math.max(0, Math.floor((expiresAt - new Date()) / 1000));
      const h = Math.floor(diff / 3600);
      const m = Math.floor((diff % 3600) / 60);
      const s = diff % 60;
      el.textContent = String(h).padStart(2,'0') + ':' + String(m).padStart(2,'0') + ':' + String(s).padStart(2,'0');
      if (diff < 300) el.classList.add('low'); else el.classList.remove('low');
      if (diff > 0) setTimeout(tick, 1000);
    }
    tick();
  });
}

// ─── Lobby auto-refresh badge ───
function refreshLobbyBadge() {
  fetch('/admin/api/lobby/count').then(r=>r.json()).then(d=>{
    // update badge in nav
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(ni => {
      if (ni.getAttribute('onclick') && ni.getAttribute('onclick').includes("'lobby'")) {
        let badge = ni.querySelector('.badge-warn');
        if (d.count > 0) {
          if (!badge) { badge = document.createElement('span'); badge.className='badge badge-warn'; badge.style.marginLeft='auto'; ni.appendChild(badge); }
          badge.textContent = d.count;
        } else if (badge) badge.remove();
      }
    });
  }).catch(()=>{});
}

function refreshLobbyTable() {
  fetch('/admin/api/lobby/list').then(r=>r.json()).then(requests=>{
    const page = document.getElementById('page-lobby');
    if (!page) return;

    // Build the full content so we work whether table exists or not
    let tbody = page.querySelector('table tbody');

    if (requests.length === 0) {
      // Show empty state, remove table if present
      const tableWrap = page.querySelector('.table-wrap');
      if (tableWrap) tableWrap.remove();
      let emptyEl = page.querySelector('.lobby-empty');
      if (!emptyEl) {
        emptyEl = document.createElement('div');
        emptyEl.className = 'lobby-empty';
        emptyEl.style.cssText = 'color:var(--muted);padding:50px;text-align:center;background:var(--panel);border:1px solid var(--border);border-radius:14px;';
        emptyEl.innerHTML = '<div style="font-size:2rem;margin-bottom:10px;">🚪</div>No pending requests. Devices on the portal can use the Request tab to ask for access.';
        page.appendChild(emptyEl);
      }
      return;
    }

    // We have requests — ensure table exists
    const emptyEl = page.querySelector('.lobby-empty');
    if (emptyEl) emptyEl.remove();

    if (!tbody) {
      // Create table structure from scratch
      const wrap = document.createElement('div');
      wrap.className = 'table-wrap';
      wrap.innerHTML = '<table><thead><tr><th>Device</th><th>IP</th><th>Plan Requested</th><th>Speed</th><th>Price</th><th>Requested At</th><th>Status</th><th>Grant</th></tr></thead><tbody></tbody></table>';
      page.appendChild(wrap);
      tbody = wrap.querySelector('tbody');
    }

    // Get current row IDs in the DOM
    const currentIds = new Set(Array.from(tbody.querySelectorAll('tr')).map(tr => tr.id.replace('lobby-row-', '')));
    const newIds = new Set(requests.map(r => String(r.id)));
    
    // Remove rows that are no longer in the list
    currentIds.forEach(id => {
      if (!newIds.has(id)) {
        const row = document.getElementById('lobby-row-' + id);
        if (row) row.remove();
      }
    });
    
    // Update or add rows
    requests.forEach((r, idx) => {
      const rowId = 'lobby-row-' + r.id;
      let row = document.getElementById(rowId);
      const statusHtml = r.status === 'pending' ? '<span class="badge badge-warn">Pending</span>' :
                         r.status === 'granted' ? '<span class="badge badge-green">Granted</span>' :
                         '<span class="badge badge-gray">' + r.status + '</span>';
      const actionHtml = r.status === 'pending' ?
        '<form method="POST" action="/admin/lobby/grant/' + r.id + '" style="display:inline">' +
        '<input type="hidden" name="minutes" value="' + (r.plan_minutes || 60) + '">' +
        '<input type="hidden" name="speed" value="' + (r.plan_speed || 5) + '">' +
        '<button class="btn-sm btn-success" style="font-size:0.82rem;padding:6px 14px;">✅ Grant ' + (r.plan_name || '') + '</button>' +
        '</form>' +
        '<form method="POST" action="/admin/lobby/dismiss/' + r.id + '" style="display:inline">' +
        '<button class="btn-sm btn-danger">✕</button></form>' :
        r.status === 'granted' ?
        '<span style="font-family:var(--mono);font-size:0.82rem;color:var(--accent2);">' + (r.granted_code || '') + '</span>' : '';
      
      const newHtml = '<td>' +
        '<div style="font-weight:600;">' + (r.device_name || '—') + '</div>' +
        '<div style="font-family:var(--mono);font-size:0.72rem;color:var(--muted);">' + (r.mac || r.ip) + '</div>' +
        '</td>' +
        '<td style="font-family:var(--mono);font-size:0.84rem;">' + r.ip + '</td>' +
        '<td><span style="font-weight:600;">' + (r.plan_name || 'Custom') + '</span></td>' +
        '<td><span class="badge badge-blue">' + (r.plan_speed || '—') + ' Mbps</span></td>' +
        '<td style="font-weight:700;color:var(--accent2);">' + (r.plan_label || '—') + '</td>' +
        '<td style="font-size:0.8rem;color:var(--muted);">' + r.requested_at.substring(0, 16).replace('T', ' ') + '</td>' +
        '<td>' + statusHtml + '</td>' +
        '<td style="display:flex;gap:5px;flex-wrap:wrap;">' + actionHtml + '</td>';
      
      if (!row) {
        row = document.createElement('tr');
        row.id = rowId;
        tbody.insertBefore(row, tbody.firstChild);
      }
      row.innerHTML = newHtml;
    });
  }).catch(()=>{});
}

setInterval(refreshLobbyBadge, 8000);
setInterval(refreshLobbyTable, 5000);

// ─── Sessions auto-refresh ───
let _sessionsTimer = null;

function refreshSessionsTable() {
  fetch('/admin/api/sessions').then(r=>r.json()).then(sessions=>{
    const page = document.getElementById('page-sessions');
    if (!page) return;
    let tbody = page.querySelector('table tbody');
    if (!tbody) {
      // No table yet — rebuild if we now have sessions
      if (sessions.length === 0) return;
      const emptyMsg = page.querySelector('[style*="No active"]') || page.querySelector('.page-sub + div');
      // If there's a "no sessions" message, replace with table
      const tableWrap = document.createElement('div');
      tableWrap.className = 'table-wrap';
      tableWrap.innerHTML = `<table>
        <thead><tr>
          <th>IP Address</th><th>Device</th><th>Code</th>
          <th>Speed</th><th>Time Remaining</th><th>Expires At</th>
          <th>Status</th><th>Actions</th>
        </tr></thead><tbody></tbody></table>`;
      page.appendChild(tableWrap);
      tbody = tableWrap.querySelector('tbody');
    }
    if (sessions.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--muted);padding:30px;">No active sessions</td></tr>';
      return;
    }
    // Rebuild rows
    tbody.innerHTML = sessions.map(s => {
      const ip = s.used_by || '';
      const code = s.code || '';
      const speed = s.speed_mbps || 5;
      const expires = s.expires_at || '';
      const paused = !!s.paused_at;
      const statusBadge = paused
        ? '<span class="badge badge-warn">⏸ Paused</span>'
        : '<span class="badge badge-green"><span class="live-dot"></span>Active</span>';
      const countdownHtml = paused
        ? (s.remaining_seconds ? formatSecs(s.remaining_seconds) + ' (paused)' : '—')
        : (expires ? `<span class="session-cd" data-expires="${expires}" data-paused="0">…</span>` : '∞');
      return `<tr>
        <td><span class="live-dot" ${paused ? 'style="background:var(--warn)"' : ''}></span> ${ip}</td>
        <td style="font-size:0.85rem;color:var(--muted);">—</td>
        <td style="font-family:var(--mono);font-size:0.85rem;">${code}</td>
        <td><span class="badge badge-blue">${speed} Mbps</span></td>
        <td>${countdownHtml}</td>
        <td style="font-size:0.8rem;color:var(--muted);">${expires ? expires.substring(0,16).replace('T',' ') : '∞'}</td>
        <td>${statusBadge}</td>
        <td>
          <form method="POST" action="/admin/kick/${ip}" style="display:inline"
                onsubmit="return confirm('Kick this session?')">
            <button class="btn-sm btn-danger">Kick</button>
          </form>
        </td>
      </tr>`;
    }).join('');
    // Restart countdowns for new elements
    startCountdowns();
  }).catch(()=>{});
}

function formatSecs(secs) {
  const h = Math.floor(secs/3600), m = Math.floor((secs%3600)/60), s = secs%60;
  return String(h).padStart(2,'0')+':'+String(m).padStart(2,'0')+':'+String(s).padStart(2,'0');
}

function startSessionsPolling() {
  if (_sessionsTimer) return;
  refreshSessionsTable();
  _sessionsTimer = setInterval(refreshSessionsTable, 5000);
}
function stopSessionsPolling() {
  if (_sessionsTimer) { clearInterval(_sessionsTimer); _sessionsTimer = null; }
}

// ─── Data rates editor ───
let _ratesData = [];
try { _ratesData = JSON.parse({{ settings.data_rates | tojson if settings.data_rates else '[]' }}); } catch(e) {}

function renderRates() {
  const ed = document.getElementById('rates-editor');
  if (!ed) return;
  ed.innerHTML = '';
  _ratesData.forEach((r, i) => {
    const row = document.createElement('div');
    row.style.cssText = 'display:flex;gap:8px;align-items:center;';
    row.innerHTML = `
      <input class="setting-input" style="flex:2;text-align:left;" placeholder="Plan name" value="${r.name || ''}"
             oninput="_ratesData[${i}].name=this.value">
      <input class="setting-input" style="width:80px;" type="number" placeholder="Min" min="1" value="${r.minutes || 60}"
             oninput="_ratesData[${i}].minutes=parseInt(this.value)||60">
      <input class="setting-input" style="width:80px;" type="number" placeholder="Mbps" min="1" value="${r.speed || 5}"
             oninput="_ratesData[${i}].speed=parseInt(this.value)||5">
      <input class="setting-input" style="width:90px;text-align:left;" placeholder="Price" value="${r.label || ''}"
             oninput="_ratesData[${i}].label=this.value">
      <button type="button" onclick="_ratesData.splice(${i},1);renderRates()"
              style="background:rgba(239,68,68,0.15);border:1px solid rgba(239,68,68,0.25);color:#fca5a5;border-radius:6px;padding:6px 10px;cursor:pointer;">✕</button>`;
    ed.appendChild(row);
  });
}
function addRateRow() {
  _ratesData.push({name:'', minutes:60, speed:5, label:''});
  renderRates();
}
function serializeRates() {
  const el = document.getElementById('data-rates-json');
  if (el) el.value = JSON.stringify(_ratesData);
}
window.addEventListener('DOMContentLoaded', () => {
  renderRates();
});

// ─── RATE LIMITING MODAL (Feature #5) ───
let _currentRateLimitMac = '';
function openRateLimitModal(mac, daily, hourly) {
  _currentRateLimitMac = mac;
  document.getElementById('rl-device-label').textContent = mac;
  document.getElementById('rl-daily').value = daily;
  document.getElementById('rl-hourly').value = hourly;
  document.getElementById('ratelimit-modal-overlay').style.display = 'flex';
  document.getElementById('rl-form').action = '/admin/device/ratelimit/' + mac;
}
function closeRateLimitModal() {
  document.getElementById('ratelimit-modal-overlay').style.display = 'none';
}
document.getElementById('ratelimit-modal-overlay').addEventListener('click', function(e) {
  if (e.target === this) closeRateLimitModal();
});

// ─── ANALYTICS LOADING (Feature #3) ───
function loadAnalytics() {
  fetch('/admin/api/analytics')
    .then(r => r.json())
    .then(d => {
      document.getElementById('a-total-codes').textContent = d.total_codes;
      const pct = d.total_codes > 0 ? Math.round((d.used_codes / d.total_codes) * 100) : 0;
      document.getElementById('a-used-codes').textContent = d.used_codes + ' (' + pct + '%)';
      document.getElementById('a-available-codes').textContent = d.available_codes;
      document.getElementById('a-total-minutes').textContent = d.total_minutes_sold;
      document.getElementById('a-total-gb').textContent = d.total_gb_transferred;
      document.getElementById('analytics-loading').style.display = 'none';
      document.getElementById('analytics-content').style.display = 'block';
    })
    .catch(e => {
      document.getElementById('analytics-loading').textContent = '⚠ Failed to load analytics';
    });
}

// ─── AUDIT LOG LOADING (Feature #7) ───
function loadAuditLogs() {
  fetch('/admin/api/audit_logs?limit=100')
    .then(r => r.json())
    .then(logs => {
      const tbody = document.getElementById('audit-logs-tbody');
      if (logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--muted);">No audit logs yet</td></tr>';
        return;
      }
      tbody.innerHTML = logs.map(l => `
        <tr>
          <td style="font-size:0.8rem;color:var(--muted);">${l.timestamp.substring(0, 16).replace('T', ' ')}</td>
          <td style="font-weight:600;">${l.action}</td>
          <td style="font-family:var(--mono);font-size:0.82rem;">${l.target || '—'}</td>
          <td style="font-size:0.8rem;">${l.details || '—'}</td>
        </tr>
      `).join('');
    })
    .catch(e => {
      document.getElementById('audit-logs-tbody').innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--danger);">Failed to load logs</td></tr>';
    });
}

// Save device name via fetch
function saveName(mac) {
  const val = document.getElementById('name-' + mac).value;
  fetch('/admin/device/name', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({mac: mac, name: val})
  }).then(r => r.json()).then(d => {
    if (d.ok) {
      const btn = document.querySelector(`[onclick="saveName('${mac}')"]`);
      if (btn) { btn.textContent = '✓'; btn.style.background = '#10b981'; setTimeout(() => { btn.textContent = '✓'; btn.style.background = ''; }, 2000); }
    }
  });
}

// ═════════════════════════════════════════════════════════════
// NEW FEATURES: Charts & Analytics Dashboard
// ═════════════════════════════════════════════════════════════

let activityChart, topDevicesChart;

let _chartIntervals = [];

// Initialize dashboard on page load
function initializeDashboard() {
  // Only start chart polling if the charts tab is visible
  // Charts are initialized when user navigates to the charts tab via showPage()
  // This function just does a one-time load if already on charts tab
  const chartsPage = document.getElementById('page-charts');
  if (chartsPage && chartsPage.classList.contains('active')) {
    updateSystemHealth();
    updateActivityGraph();
    updateTopDevicesChart();
    loadDeviceGroups();
  }
}

// Update System Health Metrics
async function updateSystemHealth() {
  try {
    const response = await fetch('/admin/api/system/health');
    const data = await response.json();
    
    if (!data.error) {
      // CPU
      const cpuVal = data.cpu_percent || 0;
      const cpuEl = document.getElementById('health-cpu-value');
      const cpuBar = document.getElementById('health-cpu-bar');
      if (cpuEl) cpuEl.textContent = cpuVal.toFixed(1) + '%';
      if (cpuBar) cpuBar.style.width = cpuVal + '%';
      
      // Memory
      const memVal = data.memory_percent || 0;
      const memEl = document.getElementById('health-mem-value');
      const memBar = document.getElementById('health-mem-bar');
      if (memEl) memEl.textContent = memVal.toFixed(1) + '%';
      if (memBar) memBar.style.width = memVal + '%';
      
      // Disk
      const diskVal = data.disk_percent || 0;
      const diskEl = document.getElementById('health-disk-value');
      const diskBar = document.getElementById('health-disk-bar');
      if (diskEl) diskEl.textContent = diskVal.toFixed(1) + '%';
      if (diskBar) diskBar.style.width = diskVal + '%';
      
      // Uptime
      const uptimeVal = data.uptime_seconds || 0;
      const uptimeHours = (uptimeVal / 3600).toFixed(1);
      const uptimeEl = document.getElementById('health-uptime-value');
      if (uptimeEl) uptimeEl.textContent = uptimeHours + 'h';
    }
  } catch (e) {
    console.error('System health error:', e);
  }
}

// Update Real-time Activity Graph
async function updateActivityGraph() {
  try {
    const response = await fetch('/admin/api/activity');
    const data = await response.json();
    
    if (!Array.isArray(data) || data.length === 0) return;
    
    const activityChartEl = document.getElementById('activityChart');
    if (!activityChartEl) return;
    
    const ctx = activityChartEl.getContext('2d');
    const labels = data.map((d, i) => i % 6 === 0 ? (d.timestamp ? d.timestamp.substring(11, 16) : '') : '');
    const activeData = data.map(d => d.active_sessions || 0);
    
    if (activityChart) {
      activityChart.data.labels = labels;
      activityChart.data.datasets[0].data = activeData;
      activityChart.update();
    } else {
      activityChart = new Chart(ctx, {
        type: 'line',
        data: {
          labels: labels,
          datasets: [{
            label: 'Active Sessions',
            data: activeData,
            borderColor: '#3b82f6',
            backgroundColor: 'rgba(59, 130, 246, 0.1)',
            borderWidth: 2,
            fill: true,
            tension: 0.4,
            pointRadius: 3,
            pointBackgroundColor: '#3b82f6',
            pointBorderColor: '#0a0e1a'
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              labels: { font: { size: 12 }, color: '#e2e8f0' }
            }
          },
          scales: {
            y: {
              beginAtZero: true,
              ticks: { color: '#64748b', font: { size: 10 } },
              grid: { color: '#1f2d45' }
            },
            x: {
              ticks: { color: '#64748b', font: { size: 9 }, maxRotation: 45 },
              grid: { color: '#1f2d45' }
            }
          }
        }
      });
    }
  } catch (e) {
    console.error('Activity chart error:', e);
  }
}

// Update Top Devices Chart
async function updateTopDevicesChart() {
  try {
    const response = await fetch('/admin/api/top-devices');
    const data = await response.json();
    
    if (!Array.isArray(data) || data.length === 0) return;
    
    const topDevicesEl = document.getElementById('topDevicesChart');
    if (!topDevicesEl) return;
    
    const ctx = topDevicesEl.getContext('2d');
    const colors = ['#3498db', '#e74c3c', '#2ecc71', '#f39c12', '#9b59b6', '#1abc9c', '#34495e', '#e67e22', '#c0392b', '#27ae60'];
    const deviceNames = data.map(d => d.name || d.mac || 'Unknown');
    const bandwidthGb = data.map(d => d.gb || 0);
    
    if (topDevicesChart) {
      topDevicesChart.data.labels = deviceNames;
      topDevicesChart.data.datasets[0].data = bandwidthGb;
      topDevicesChart.data.datasets[0].backgroundColor = colors.slice(0, data.length);
      topDevicesChart.update();
    } else {
      topDevicesChart = new Chart(ctx, {
        type: 'bar',
        data: {
          labels: deviceNames,
          datasets: [{
            label: 'Data Used (GB)',
            data: bandwidthGb,
            backgroundColor: colors.slice(0, data.length),
            borderRadius: 6
          }]
        },
        options: {
          indexAxis: 'y',
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { labels: { font: { size: 12 }, color: '#e2e8f0' } }
          },
          scales: {
            x: {
              ticks: { color: '#64748b', font: { size: 10 } },
              grid: { color: '#1f2d45' }
            },
            y: {
              ticks: { color: '#64748b', font: { size: 10 } },
              grid: { display: false }
            }
          }
        }
      });
    }
  } catch (e) {
    console.error('Top devices chart error:', e);
  }
}

// Load Device Groups
async function loadDeviceGroups() {
  try {
    const response = await fetch('/admin/api/device-groups');
    const data = await response.json();
    
    if (!Array.isArray(data)) return;
    
    const container = document.getElementById('device-groups-list');
    if (!container) return;
    
    container.innerHTML = data.map(g => `
      <div class="group-tag" style="background: ${g.color}20; color: ${g.color}; border: 1px solid ${g.color}">
        ${g.name}
        <button onclick="deleteGroup(${g.id})" style="background: none; border: none; color: inherit; cursor: pointer; margin-left: 6px;">✕</button>
      </div>
    `).join('');
  } catch (e) {
    console.error('Load device groups error:', e);
  }
}

// Create new device group
async function createDeviceGroup() {
  const name = document.getElementById('group-name')?.value;
  const color = document.getElementById('group-color')?.value || '#3498db';
  
  if (!name) {
    alert('Please enter group name');
    return;
  }
  
  try {
    const response = await fetch('/admin/api/device-groups', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, color })
    });
    const data = await response.json();
    
    if (data.id) {
      document.getElementById('group-name').value = '';
      loadDeviceGroups();
    }
  } catch (e) {
    console.error('Create group error:', e);
  }
}

// Delete device group
async function deleteGroup(groupId) {
  if (!confirm('Delete this group?')) return;
  
  try {
    const response = await fetch('/admin/api/device-groups?id=' + groupId, {
      method: 'DELETE'
    });
    const data = await response.json();
    
    if (data.ok) {
      loadDeviceGroups();
    }
  } catch (e) {
    console.error('Delete group error:', e);
  }
}

// Export sessions to CSV
async function exportSessions() {
  try {
    const response = await fetch('/admin/api/sessions/export');
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'sessions-' + new Date().toISOString().split('T')[0] + '.csv';
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  } catch (e) {
    console.error('Export error:', e);
    alert('Export failed');
  }
}

// Initialize on page load or when Charts tab is shown
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initializeDashboard);
} else {
  initializeDashboard();
}
</script>
</body>
</html>"""

ADMIN_LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Admin Login</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@500&family=IBM+Plex+Sans:wght@400;600;700&display=swap');
  * { margin:0; padding:0; box-sizing:border-box; }
  body {
    font-family: 'IBM Plex Sans', sans-serif;
    background: #0a0e1a;
    display: flex; align-items: center; justify-content: center;
    min-height: 100vh;
  }
  .card {
    background: #111827; border: 1px solid #1f2d45;
    border-radius: 16px; padding: 44px 40px;
    width: 360px; color: #e2e8f0;
    box-shadow: 0 40px 80px rgba(0,0,0,0.5);
  }
  h1 { font-size: 1.3rem; margin-bottom: 6px; color: #3b82f6; font-weight: 700; }
  p { color: #64748b; font-size: 0.85rem; margin-bottom: 28px; }
  input[type=password] {
    width: 100%; padding: 12px 14px;
    background: #1a2235; border: 1px solid #1f2d45;
    color: #e2e8f0; border-radius: 8px;
    font-family: 'IBM Plex Mono', monospace; font-size: 0.95rem;
    outline: none; margin-bottom: 14px;
    transition: border-color 0.2s;
  }
  input[type=password]:focus { border-color: #3b82f6; }
  button {
    width: 100%; padding: 12px;
    background: #3b82f6; color: #fff;
    border: none; border-radius: 8px;
    font-family: 'IBM Plex Sans', sans-serif;
    font-size: 0.95rem; font-weight: 700;
    cursor: pointer; transition: filter 0.2s;
  }
  button:hover { filter: brightness(1.15); }
  .error { color: #fca5a5; font-size: 0.84rem; margin-bottom: 12px;
           background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.2);
           border-radius: 8px; padding: 10px 14px; }
</style>
</head>
<body>
<div class="card">
  <h1>🛡️ Admin Login</h1>
  <p>Captive Portal Management</p>
  {% if error %}<div class="error">{{ error }}</div>{% endif %}
  <form method="POST">
    <input type="password" name="password" placeholder="Enter admin password" autofocus>
    <button type="submit">Login →</button>
  </form>
</div>
</body>
</html>"""

# ─────────────────────── PORTAL ROUTES ───────────────────────

@app.route("/", methods=["GET"])
@app.route("/portal", methods=["GET"])
def captive_portal():
    if is_iptables_allowed(request.remote_addr):
        return redirect("http://www.google.com")
    client_ip = request.remote_addr
    prefill_code = request.args.get("code", "")

    # Fetch all settings and data in a single DB connection for better performance
    db = get_db()
    
    # Get all settings we need
    settings = {}
    for key in ["show_rates", "data_rates", "portal_title", "portal_subtitle"]:
        row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        settings[key] = row["value"] if row else None
    
    # Device history
    history = db.execute(
        "SELECT code, duration_minutes, speed_mbps, used_at, expires_at, active "
        "FROM codes WHERE used_by=? ORDER BY id DESC LIMIT 10", (client_ip,)).fetchall()

    # Lobby: check if there's a granted-but-unclaimed code for this IP
    lobby_granted = None
    lr = db.execute(
        "SELECT granted_code FROM lobby_requests WHERE ip=? AND status='granted' "
        "ORDER BY granted_at DESC LIMIT 1", (client_ip,)).fetchone()
    if lr and lr["granted_code"]:
        # Check the code isn't used yet
        code_row = db.execute(
            "SELECT used_by FROM codes WHERE code=?", (lr["granted_code"],)).fetchone()
        if code_row and not code_row["used_by"]:
            lobby_granted = lr["granted_code"]

    # Lobby: did they just submit a request?
    lobby_sent = request.args.get("lobby_sent") == "1"
    db.close()

    # Parse data rates
    show_rates = (settings.get("show_rates") or "1") == "1"
    try:
        data_rates = json.loads(settings.get("data_rates") or "[]")
    except Exception:
        data_rates = []

    return render_template_string(PORTAL_HTML,
        prefill_code=prefill_code, error=None,
        portal_title=settings.get("portal_title") or "WiFi Access",
        portal_subtitle=settings.get("portal_subtitle") or "Scan QR or enter access code to connect",
        show_rates=show_rates, data_rates=data_rates,
        history=[dict(h) for h in history],
        lobby_granted=lobby_granted, lobby_sent=lobby_sent)

@app.route("/portal/login", methods=["POST"])
def portal_login():
    def render_error(error_msg, prefill=""):
        """Helper to render portal with error message"""
        show_rates = get_setting("show_rates", "1") == "1"
        try:
            data_rates = json.loads(get_setting("data_rates", "[]"))
        except Exception:
            data_rates = []
        return render_template_string(PORTAL_HTML,
            prefill_code=prefill,
            error=error_msg,
            portal_title=get_setting("portal_title", "WiFi Access"),
            portal_subtitle=get_setting("portal_subtitle", "Scan QR or enter access code to connect"),
            show_rates=show_rates, data_rates=data_rates,
            history=[], lobby_granted=None, lobby_sent=False)
    
    client_ip = request.remote_addr
    code = request.form.get("code", "").strip().upper()
    
    # Check if device is blocked (feature #1)
    mac = get_mac_for_ip(client_ip)
    if is_device_blocked(mac) or is_device_blocked_by_ip(client_ip):
        return render_error("❌ Your device has been blocked. Contact administrator.", code)
    
    db = get_db()
    row = db.execute(
        "SELECT * FROM codes WHERE code=? AND used_by IS NULL AND active=1", (code,)
    ).fetchone()
    if not row:
        db.close()
        return render_error("Invalid or already-used code.", code)

    # Check rate limits (feature #5)
    if not check_rate_limit(mac) and not check_rate_limit(client_ip):
        db.close()
        return render_error("⚠️ Daily/hourly data limit reached. Try again later.", code)

    now = datetime.utcnow()
    expires = (now + timedelta(minutes=row["duration_minutes"])).isoformat() \
              if row["duration_minutes"] > 0 else None
    speed = dict(row).get("speed_mbps") or 5

    # Handle temporary codes (feature #6)
    temp_expires = None
    if row["temporary"]:
        # Temporary code - set 30 min auto-revoke
        temp_expires = (now + timedelta(minutes=30)).isoformat()

    # Absolute expiry - check global setting
    abs_exp = None
    global_abs = int(get_setting("absolute_expiry_hours", "0"))
    if global_abs > 0:
        abs_exp = (now + timedelta(hours=global_abs)).isoformat()

    remaining_secs = row["duration_minutes"] * 60 if row["duration_minutes"] > 0 else None

    db.execute("UPDATE codes SET used_by=?, used_at=?, expires_at=?, absolute_expiry=?, expires_temporary_at=?, remaining_seconds=? WHERE code=?",
               (client_ip, now.isoformat(), expires, abs_exp, temp_expires, remaining_secs, code))
    
    # Auto-populate device name from dnsmasq leases
    leases = get_dnsmasq_leases()
    lease_name = leases.get(mac.lower()) or leases.get(client_ip)
    db.execute("""
        INSERT INTO devices (mac, ip, first_seen, last_seen, connected, name)
        VALUES (?, ?, ?, ?, 1, ?)
        ON CONFLICT(mac) DO UPDATE SET ip=?, last_seen=?, connected=1,
            name=CASE WHEN devices.name IS NULL THEN ? ELSE devices.name END
    """, (mac, client_ip, now.isoformat(), now.isoformat(), lease_name,
          client_ip, now.isoformat(), lease_name))
    
    code_id = row["id"]
    db.commit()
    db.close()

    # Log session activity (feature #2, #7)
    log_session_activity(code_id, mac, client_ip)
    log_admin_action("code_used", code, f"Device: {lease_name or mac}")

    add_iptables_allow(client_ip, speed)
    return redirect("/status")

@app.route("/portal/pause", methods=["POST"])
def portal_pause():
    if get_setting("allow_pause", "1") != "1":
        return redirect("/status")
    client_ip = request.remote_addr
    db = get_db()
    row = db.execute("SELECT * FROM codes WHERE used_by=? AND active=1", (client_ip,)).fetchone()
    if row and not row["paused_at"] and row["expires_at"]:
        now = datetime.utcnow()
        expires_at = datetime.fromisoformat(row["expires_at"])
        remaining = max(0, int((expires_at - now).total_seconds()))
        db.execute("UPDATE codes SET paused_at=?, remaining_seconds=? WHERE used_by=? AND active=1",
                   (now.isoformat(), remaining, client_ip))
        db.commit()
        remove_iptables_allow(client_ip)
    db.close()
    return redirect("/status")

@app.route("/portal/resume", methods=["POST"])
def portal_resume():
    client_ip = request.remote_addr
    db = get_db()
    row = db.execute("SELECT * FROM codes WHERE used_by=? AND active=1", (client_ip,)).fetchone()
    if row and row["paused_at"] and row["remaining_seconds"]:
        now = datetime.utcnow()
        new_expires = (now + timedelta(seconds=row["remaining_seconds"])).isoformat()
        db.execute("UPDATE codes SET paused_at=NULL, expires_at=? WHERE used_by=? AND active=1",
                   (new_expires, client_ip))
        db.commit()
        speed = dict(row).get("speed_mbps") or 5
        add_iptables_allow(client_ip, speed)
    db.close()
    return redirect("/status")

@app.route("/status")
def status_page():
    client_ip = request.remote_addr
    db = get_db()
    row = db.execute(
        "SELECT expires_at, speed_mbps, paused_at, remaining_seconds FROM codes WHERE used_by=? AND active=1",
        (client_ip,)).fetchone()
    db.close()
    if not row:
        return render_template_string(STATUS_HTML, expires=None, speed=0,
                                      paused=False, remaining_display="",
                                      allow_pause=False)

    paused = bool(row["paused_at"])
    allow_pause = get_setting("allow_pause", "1") == "1"

    remaining_display = "∞"
    if paused and row["remaining_seconds"]:
        secs = row["remaining_seconds"]
        h, r = divmod(secs, 3600)
        m, s = divmod(r, 60)
        remaining_display = f"{h:02d}:{m:02d}:{s:02d}"
    elif row["expires_at"]:
        remaining_display = "..."  # JS will fill in

    return render_template_string(STATUS_HTML,
        expires=row["expires_at"],
        speed=row["speed_mbps"],
        paused=paused,
        remaining_display=remaining_display,
        allow_pause=allow_pause)

@app.route("/generate_204")
@app.route("/gen_204")
@app.route("/hotspot-detect.html")
@app.route("/ncsi.txt")
@app.route("/connecttest.txt")
@app.route("/redirect")
@app.route("/canonical.html")
def captive_check():
    if is_iptables_allowed(request.remote_addr):
        return "", 204
    return redirect(f"http://{PORTAL_HOST}:8080/portal")

# ─────────────────────── ADMIN ROUTES ───────────────────────

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin"):
            return redirect("/admin/login")
        return f(*args, **kwargs)
    return decorated

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if request.form.get("password") == ADMIN_SECRET:
            session["admin"] = True
            return redirect("/admin")
        return render_template_string(ADMIN_LOGIN_HTML, error="Wrong password")
    return render_template_string(ADMIN_LOGIN_HTML, error=None)

@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect("/admin/login")

def build_admin_context(message=None, new_vouchers=None):
    db = get_db()
    raw_vouchers = db.execute("SELECT * FROM codes ORDER BY id DESC LIMIT 100").fetchall()
    devices = db.execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()
    now = datetime.utcnow().isoformat()

    active_sessions_raw = db.execute(
        "SELECT c.*, d.mac, d.name as device_name FROM codes c "
        "LEFT JOIN devices d ON d.ip = c.used_by "
        "WHERE c.active=1 AND c.used_by IS NOT NULL AND (c.expires_at IS NULL OR c.expires_at > ?)",
        (now,)).fetchall()

    active_count = len(active_sessions_raw)
    reset_at = get_setting("stats_reset_at", "")
    if reset_at:
        sales = db.execute(
            "SELECT SUM(duration_minutes) as s FROM codes WHERE used_by IS NOT NULL AND used_at > ?",
            (reset_at,)).fetchone()["s"] or 0
    else:
        sales = db.execute(
            "SELECT SUM(duration_minutes) as s FROM codes WHERE used_by IS NOT NULL"
        ).fetchone()["s"] or 0
    device_count = db.execute("SELECT COUNT(*) as c FROM devices").fetchone()["c"]

    # Lobby requests
    lobby_requests_raw = db.execute(
        "SELECT * FROM lobby_requests ORDER BY requested_at DESC LIMIT 100").fetchall()
    lobby_pending = db.execute(
        "SELECT COUNT(*) as c FROM lobby_requests WHERE status='pending'").fetchone()["c"]

    vouchers = []
    for v in raw_vouchers:
        v_dict = dict(v)
        v_dict["qr"] = generate_qr_base64(v_dict["code"])
        vouchers.append(v_dict)

    settings_rows = db.execute("SELECT key, value FROM settings").fetchall()
    settings = {r["key"]: r["value"] for r in settings_rows}

    db.close()
    health = get_system_health()

    return dict(
        vouchers=vouchers, devices=devices,
        active_sessions=[dict(s) for s in active_sessions_raw],
        active_count=active_count,
        total_mins=sales, device_count=device_count,
        lobby_requests=[dict(r) for r in lobby_requests_raw],
        lobby_pending=lobby_pending,
        new_vouchers=new_vouchers, message=message,
        health=health, settings=settings
    )

@app.route("/admin")
@admin_required
def admin_dashboard():
    ctx = build_admin_context()
    return render_template_string(ADMIN_HTML, **ctx)

@app.route("/admin/generate", methods=["POST"])
@admin_required
def admin_generate():
    try:
        minutes = max(1, min(10080, int(request.form.get("minutes", 60))))  # 1 min - 7 days
        speed = max(1, min(1000, int(request.form.get("speed", 5))))  # 1-1000 Mbps
        qty = min(max(1, int(request.form.get("qty", 1))), 50)
        abs_h = max(0, min(720, int(request.form.get("absolute_expiry_hours", 0))))  # 0-30 days
    except ValueError:
        minutes, speed, qty, abs_h = 60, 5, 1, 0

    db = get_db()
    now = datetime.utcnow()
    now_iso = now.isoformat()
    new_vouchers = []
    for _ in range(qty):
        code = secrets.token_hex(4).upper()[:4] + "-" + secrets.token_hex(4).upper()[:4]
        abs_expiry_iso = (now + timedelta(hours=abs_h)).isoformat() if abs_h > 0 else None
        db.execute(
            "INSERT INTO codes (code, duration_minutes, speed_mbps, created_at, absolute_expiry) VALUES (?, ?, ?, ?, ?)",
            (code, minutes, speed, now_iso, abs_expiry_iso))
        qr_b64 = generate_qr_base64(code)
        new_vouchers.append({"code": code, "minutes": minutes, "speed": speed,
                              "qr": qr_b64, "abs_expiry_h": abs_h if abs_h else None})
    db.commit()
    db.close()

    ctx = build_admin_context(message=f"Generated {qty} code(s)", new_vouchers=new_vouchers)
    return render_template_string(ADMIN_HTML, **ctx)

@app.route("/admin/revoke/<int:code_id>", methods=["POST"])
@admin_required
def admin_revoke(code_id):
    db = get_db()
    row = db.execute("SELECT used_by FROM codes WHERE id=?", (code_id,)).fetchone()
    if row and row["used_by"]:
        remove_iptables_allow(row["used_by"])
    db.execute("UPDATE codes SET active=0, paused_at=NULL WHERE id=?", (code_id,))
    db.commit()
    db.close()
    return redirect("/admin#vouchers")

@app.route("/admin/whitelist/<mac>", methods=["POST"])
@admin_required
def admin_whitelist(mac):
    db = get_db()
    row = db.execute("SELECT ip FROM devices WHERE mac=?", (mac,)).fetchone()
    db.execute("UPDATE devices SET whitelisted=1 WHERE mac=?", (mac,))
    db.commit()
    db.close()
    if row and row["ip"]:
        add_iptables_allow(row["ip"])
    return redirect("/admin#devices")

@app.route("/admin/unwhitelist/<mac>", methods=["POST"])
@admin_required
def admin_unwhitelist(mac):
    db = get_db()
    row = db.execute("SELECT ip FROM devices WHERE mac=?", (mac,)).fetchone()
    db.execute("UPDATE devices SET whitelisted=0 WHERE mac=?", (mac,))
    db.commit()
    db.close()
    if row and row["ip"]:
        remove_iptables_allow(row["ip"])
    return redirect("/admin#devices")

@app.route("/admin/kick/<ip>", methods=["POST"])
@admin_required
def admin_kick(ip):
    remove_iptables_allow(ip)
    db = get_db()
    db.execute("UPDATE devices SET connected=0 WHERE ip=?", (ip,))
    db.execute("UPDATE codes SET active=0, paused_at=NULL WHERE used_by=?", (ip,))
    db.commit()
    db.close()
    return redirect("/admin#sessions")

@app.route("/admin/device/name", methods=["POST"])
@admin_required
def admin_device_name():
    data = request.get_json()
    mac = data.get("mac", "").strip()
    name = data.get("name", "").strip()[:64]
    if not mac:
        return jsonify({"ok": False})
    db = get_db()
    db.execute("UPDATE devices SET name=? WHERE mac=?", (name or None, mac))
    db.commit()
    db.close()
    return jsonify({"ok": True})

@app.route("/admin/settings", methods=["POST"])
@admin_required
def admin_settings_save():
    keys = ["portal_title", "portal_subtitle", "allow_pause",
            "absolute_expiry_hours", "default_speed", "show_rates", "data_rates"]
    db = get_db()
    for k in keys:
        if k in ("allow_pause", "show_rates"):
            val = "1" if request.form.get(k) == "1" else "0"
        else:
            val = request.form.get(k, "").strip()
        if val or k in ("allow_pause", "show_rates"):
            db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (k, val))
    db.commit()
    db.close()
    ctx = build_admin_context(message="Settings saved.")
    return render_template_string(ADMIN_HTML, **ctx)

@app.route("/admin/session/edit/<ip>", methods=["POST"])
@admin_required
def admin_session_edit(ip):
    speed_mbps  = request.form.get("speed_mbps", "").strip()
    add_minutes = request.form.get("add_minutes", "").strip()
    set_expiry  = request.form.get("set_expiry", "").strip()

    db = get_db()
    row = db.execute("SELECT * FROM codes WHERE used_by=? AND active=1", (ip,)).fetchone()
    if not row:
        db.close()
        return redirect("/admin#sessions")

    now = datetime.utcnow()
    updates = {}

    # ── Speed change ──
    if speed_mbps:
        try:
            spd = max(1, min(1000, int(speed_mbps)))
            updates["speed_mbps"] = spd
            remove_speed_limit(ip)
            if not row["paused_at"]:
                set_speed_limit(ip, spd)
        except ValueError:
            pass

    # ── Time adjustment or explicit expiry set ──
    if set_expiry:
        # Admin typed an explicit UTC datetime
        try:
            new_exp = datetime.fromisoformat(set_expiry)
            updates["expires_at"] = new_exp.isoformat()
            diff = max(0, int((new_exp - now).total_seconds()))
            updates["remaining_seconds"] = diff
            if row["paused_at"]:
                updates["remaining_seconds"] = diff  # update paused snapshot too
        except ValueError:
            pass
    elif add_minutes:
        try:
            delta_secs = int(float(add_minutes) * 60)
            if row["paused_at"] and row["remaining_seconds"] is not None:
                # Paused — adjust the stored snapshot
                new_rem = max(0, row["remaining_seconds"] + delta_secs)
                updates["remaining_seconds"] = new_rem
            elif row["expires_at"]:
                # Active — shift expiry
                cur_exp = datetime.fromisoformat(row["expires_at"])
                new_exp = cur_exp + timedelta(seconds=delta_secs)
                if new_exp < now:
                    new_exp = now + timedelta(seconds=1)
                updates["expires_at"] = new_exp.isoformat()
                updates["remaining_seconds"] = max(0, int((new_exp - now).total_seconds()))
        except ValueError:
            pass

    if updates:
        # Use a whitelist of allowed columns to prevent SQL injection
        allowed_cols = {"speed_mbps", "expires_at", "remaining_seconds"}
        safe_updates = {k: v for k, v in updates.items() if k in allowed_cols}
        if safe_updates:
            set_clause = ", ".join(f"{k}=?" for k in safe_updates)
            vals = list(safe_updates.values()) + [ip]
            db.execute(f"UPDATE codes SET {set_clause} WHERE used_by=?", vals)
            db.commit()

    db.close()
    return redirect("/admin#sessions")

@app.route("/portal/lobby/request", methods=["POST"])
def portal_lobby_request():
    client_ip = request.remote_addr
    plan_name    = request.form.get("plan_name", "").strip()[:100]
    plan_minutes = request.form.get("plan_minutes", "").strip()
    plan_speed   = request.form.get("plan_speed", "").strip()
    plan_label   = request.form.get("plan_label", "").strip()[:50]
    now = datetime.utcnow().isoformat()
    mac = get_mac_for_ip(client_ip)
    leases = get_dnsmasq_leases()
    device_name = leases.get(mac.lower()) or leases.get(client_ip)
    db = get_db()
    # Only allow one pending request per IP
    existing = db.execute(
        "SELECT id FROM lobby_requests WHERE ip=? AND status='pending'", (client_ip,)).fetchone()
    if existing:
        db.execute(
            "UPDATE lobby_requests SET plan_name=?, plan_minutes=?, plan_speed=?, plan_label=?, "
            "requested_at=?, device_name=?, mac=? WHERE id=?",
            (plan_name, int(plan_minutes) if plan_minutes.isdigit() else None,
             int(plan_speed) if plan_speed.isdigit() else None,
             plan_label, now, device_name, mac, existing["id"]))
    else:
        db.execute(
            "INSERT INTO lobby_requests (ip, mac, device_name, plan_name, plan_minutes, "
            "plan_speed, plan_label, requested_at) VALUES (?,?,?,?,?,?,?,?)",
            (client_ip, mac, device_name, plan_name,
             int(plan_minutes) if plan_minutes.isdigit() else None,
             int(plan_speed) if plan_speed.isdigit() else None,
             plan_label, now))
    db.commit()
    db.close()
    return redirect("/portal?lobby_sent=1")

@app.route("/admin/lobby/grant/<int:req_id>", methods=["POST"])
@admin_required
def admin_lobby_grant(req_id):
    try:
        minutes = max(1, min(10080, int(request.form.get("minutes", 60))))  # 1 min - 7 days
        speed = max(1, min(1000, int(request.form.get("speed", 5))))  # 1-1000 Mbps
    except ValueError:
        minutes, speed = 60, 5
    
    db = get_db()
    lr = db.execute("SELECT * FROM lobby_requests WHERE id=?", (req_id,)).fetchone()
    if not lr:
        db.close()
        return redirect("/admin#lobby")
    now = datetime.utcnow()
    code = secrets.token_hex(4).upper()[:4] + "-" + secrets.token_hex(4).upper()[:4]
    db.execute(
        "INSERT INTO codes (code, duration_minutes, speed_mbps, created_at) VALUES (?,?,?,?)",
        (code, minutes, speed, now.isoformat()))
    db.execute(
        "UPDATE lobby_requests SET status='granted', granted_code=?, granted_at=? WHERE id=?",
        (code, now.isoformat(), req_id))
    db.commit()
    db.close()
    ctx = build_admin_context(message=f"Granted code {code} to {lr['ip']} ({lr['device_name'] or 'unknown'})")
    return render_template_string(ADMIN_HTML, **ctx)

@app.route("/admin/lobby/dismiss/<int:req_id>", methods=["POST"])
@admin_required
def admin_lobby_dismiss(req_id):
    db = get_db()
    db.execute("UPDATE lobby_requests SET status='dismissed' WHERE id=?", (req_id,))
    db.commit()
    db.close()
    return redirect("/admin#lobby")

@app.route("/admin/api/lobby/count")
@admin_required
def api_lobby_count():
    db = get_db()
    count = db.execute("SELECT COUNT(*) as c FROM lobby_requests WHERE status='pending'").fetchone()["c"]
    db.close()
    return jsonify({"count": count})

@app.route("/admin/api/lobby/list")
@admin_required
def api_lobby_list():
    """Return list of all lobby requests as JSON for auto-refresh."""
    db = get_db()
    lobby_requests = db.execute(
        "SELECT * FROM lobby_requests ORDER BY requested_at DESC LIMIT 100"
    ).fetchall()
    db.close()
    # Convert to dictionaries
    return jsonify([dict(r) for r in lobby_requests])

# ═══════════════════════════════════════════════════════════════
# NEW FEATURE APIs: Real-time graphs, device management, etc.
# ═══════════════════════════════════════════════════════════════

@app.route("/admin/api/activity")
@admin_required
def api_activity():
    """Return activity history for real-time graph (last 24 hours)."""
    db = get_db()
    # Get last 24 hours of activity at 10-minute intervals
    now = datetime.utcnow()
    start = now - timedelta(hours=24)
    data = db.execute("""
        SELECT timestamp, active_sessions, bytes_up, bytes_down
        FROM activity_history 
        WHERE timestamp > ? 
        ORDER BY timestamp ASC LIMIT 144
    """, (start.isoformat(),)).fetchall()
    db.close()
    return jsonify([dict(r) for r in data])

@app.route("/admin/api/top-devices")
@admin_required
def api_top_devices():
    """Return top devices by bandwidth usage."""
    db = get_db()
    devices = db.execute("""
        SELECT sl.device_mac,
               SUM(sl.bytes_up + sl.bytes_down) as total_bytes,
               d.name
        FROM session_logs sl
        LEFT JOIN devices d ON d.mac = sl.device_mac
        WHERE sl.timestamp > datetime('now', '-24 hours')
        GROUP BY sl.device_mac
        ORDER BY total_bytes DESC
        LIMIT 10
    """).fetchall()
    db.close()
    result = []
    for device in devices:
        result.append({
            'mac': device['device_mac'],
            'name': device['name'] or 'Unknown',
            'bytes': device['total_bytes'],
            'gb': round(device['total_bytes'] / (1024**3), 2)
        })
    return jsonify(result)

@app.route("/admin/api/device-groups", methods=["GET", "POST", "DELETE"])
@admin_required
def api_device_groups():
    """Manage device groups/labels."""
    db = get_db()
    if request.method == "GET":
        groups = db.execute("SELECT * FROM device_groups ORDER BY name").fetchall()
        db.close()
        return jsonify([dict(g) for g in groups])
    elif request.method == "POST":
        data = request.json
        name = data.get('name', '').strip()
        color = data.get('color', '#3b82f6')
        try:
            cursor = db.execute(
                "INSERT INTO device_groups (name, color, created_at) VALUES (?, ?, ?)",
                (name, color, datetime.utcnow().isoformat())
            )
            db.commit()
            group_id = cursor.lastrowid
            db.close()
            return jsonify({"id": group_id, "name": name, "color": color}), 201
        except Exception as e:
            db.close()
            return jsonify({"error": str(e)}), 400
    elif request.method == "DELETE":
        group_id = request.args.get('id')
        db.execute("DELETE FROM device_tags WHERE group_id = ?", (group_id,))
        db.execute("DELETE FROM device_groups WHERE id = ?", (group_id,))
        db.commit()
        db.close()
        return jsonify({"ok": True})

@app.route("/admin/api/device/<mac>/group", methods=["POST"])
@admin_required
def api_device_group(mac):
    """Assign device to group."""
    db = get_db()
    data = request.json
    group_id = data.get('group_id')
    
    # Remove existing group
    db.execute("DELETE FROM device_tags WHERE device_mac = ?", (mac,))
    
    # Add new group if specified
    if group_id:
        try:
            db.execute(
                "INSERT INTO device_tags (device_mac, group_id) VALUES (?, ?)",
                (mac, group_id)
            )
        except Exception:
            pass
    
    db.commit()
    db.close()
    return jsonify({"ok": True})

@app.route("/admin/api/device/<mac>/limit", methods=["POST"])
@admin_required
def api_device_speed_limit(mac):
    """Set bandwidth limit for device."""
    db = get_db()
    data = request.json
    daily_limit_gb = data.get('daily_limit_gb', 0)
    hourly_limit_mb = data.get('hourly_limit_mb', 0)
    
    # Update device quota
    db.execute(
        "UPDATE devices SET daily_quota_mb = ?, hourly_quota_mb = ? WHERE mac = ?",
        (int(daily_limit_gb * 1024) if daily_limit_gb else None,
         int(hourly_limit_mb) if hourly_limit_mb else None,
         mac)
    )
    db.commit()
    db.close()
    return jsonify({"ok": True, "message": "Device limits updated"})

@app.route("/admin/api/sessions/export")
@admin_required
def api_export_sessions():
    """Export sessions as CSV."""
    import csv
    from io import StringIO
    
    db = get_db()
    sessions = db.execute("""
        SELECT s.*, d.name, c.code 
        FROM session_logs s
        LEFT JOIN devices d ON s.device_mac = d.mac
        LEFT JOIN codes c ON s.code_id = c.id
        WHERE s.timestamp > datetime('now', '-30 days')
        ORDER BY s.timestamp DESC
    """).fetchall()
    db.close()
    
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Timestamp', 'Device', 'MAC', 'Code', 'Upload (MB)', 'Download (MB)', 'Total (MB)'])
    
    for s in sessions:
        up_mb = round(s['bytes_up'] / (1024**2), 2)
        down_mb = round(s['bytes_down'] / (1024**2), 2)
        total_mb = round((s['bytes_up'] + s['bytes_down']) / (1024**2), 2)
        writer.writerow([
            s['timestamp'],
            s['name'] or 'Unknown',
            s['device_mac'],
            s['code'] or 'N/A',
            up_mb,
            down_mb,
            total_mb
        ])
    
    response = Response(output.getvalue(), mimetype='text/csv')
    response.headers['Content-Disposition'] = 'attachment; filename=sessions_export.csv'
    return response

@app.route("/admin/api/system/health")
@admin_required
def api_system_health():
    """Return system health information."""
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        return jsonify({
            "cpu_percent": cpu_percent,
            "memory_percent": memory.percent,
            "memory_used_gb": round(memory.used / (1024**3), 2),
            "memory_total_gb": round(memory.total / (1024**3), 2),
            "disk_percent": disk.percent,
            "disk_used_gb": round(disk.used / (1024**3), 2),
            "disk_total_gb": round(disk.total / (1024**3), 2),
            "uptime_seconds": int(datetime.utcnow().timestamp() - psutil.boot_time()),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/sync/leases", methods=["POST"])
@admin_required
def admin_sync_leases():
    """Manually trigger a dnsmasq lease sync."""
    sync_device_names_from_leases()
    ctx = build_admin_context(message="Device names synced from dnsmasq leases.")
    return render_template_string(ADMIN_HTML, **ctx)

@app.route("/admin/reset_stats", methods=["POST"])
@admin_required
def admin_reset_stats():
    set_setting("stats_reset_at", datetime.utcnow().isoformat())
    ctx = build_admin_context(message="Minutes sold counter reset to 0.")
    return render_template_string(ADMIN_HTML, **ctx)

# ─── DEVICE MANAGEMENT (Feature #1: Blocking) ───
@app.route("/admin/device/block/<mac>", methods=["POST"])
@admin_required
def admin_device_block(mac):
    db = get_db()
    db.execute("UPDATE devices SET blocked=1 WHERE mac=?", (mac,))
    db.commit()
    db.close()
    log_admin_action("device_blocked", mac, "Device banned")
    return redirect("/admin#devices")

@app.route("/admin/device/unblock/<mac>", methods=["POST"])
@admin_required
def admin_device_unblock(mac):
    db = get_db()
    db.execute("UPDATE devices SET blocked=0 WHERE mac=?", (mac,))
    db.commit()
    db.close()
    log_admin_action("device_unblocked", mac, "Device unbanned")
    return redirect("/admin#devices")

# ─── RATE LIMITING (Feature #5) ───
@app.route("/admin/device/ratelimit/<mac>", methods=["POST"])
@admin_required
def admin_device_ratelimit(mac):
    try:
        daily = max(0, int(request.form.get("daily_quota_mb", 0)))
        hourly = max(0, int(request.form.get("hourly_quota_mb", 0)))
    except ValueError:
        daily, hourly = 0, 0
    db = get_db()
    db.execute("UPDATE devices SET daily_quota_mb=?, hourly_quota_mb=? WHERE mac=?", (daily, hourly, mac))
    db.commit()
    db.close()
    log_admin_action("ratelimit_set", mac, f"Daily:{daily}MB Hourly:{hourly}MB")
    return redirect("/admin#devices")

# ─── ANALYTICS API (Feature #3, #2) ───
@app.route("/admin/api/analytics")
@admin_required
def api_analytics():
    """Voucher usage analytics (feature #3)"""
    db = get_db()
    
    # Total codes generated
    total_codes = db.execute("SELECT COUNT(*) as c FROM codes").fetchone()["c"]
    used_codes = db.execute("SELECT COUNT(*) as c FROM codes WHERE used_by IS NOT NULL").fetchone()["c"]
    available_codes = total_codes - used_codes
    
    # Revenue/minutes
    total_minutes = db.execute("SELECT SUM(duration_minutes) as s FROM codes WHERE used_by IS NOT NULL").fetchone()["s"] or 0
    
    # Usage by plan (if in data_rates)
    plan_usage = db.execute(
        "SELECT duration_minutes, COUNT(*) as count FROM codes WHERE used_by IS NOT NULL GROUP BY duration_minutes"
    ).fetchall()
    
    # Session logs summary
    session_total_bytes = db.execute("SELECT SUM(bytes_up + bytes_down) as total FROM session_logs").fetchone()["total"] or 0
    
    db.close()
    return jsonify({
        "total_codes": total_codes,
        "used_codes": used_codes,
        "available_codes": available_codes,
        "total_minutes_sold": total_minutes,
        "plan_usage": [{"duration": p["duration_minutes"], "count": p["count"]} for p in plan_usage],
        "total_bytes_transferred": session_total_bytes,
        "total_gb_transferred": round(session_total_bytes / 1e9, 2)
    })

# ─── ADMIN LOGS API (Feature #7) ───
@app.route("/admin/api/audit_logs")
@admin_required
def api_audit_logs():
    """Get admin audit trail"""
    db = get_db()
    limit = min(int(request.args.get("limit", 100)), 500)
    logs = db.execute(
        "SELECT * FROM admin_logs ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    db.close()
    return jsonify([dict(l) for l in logs])

# ─── SESSION ANALYTICS (Feature # 2) ───
@app.route("/admin/api/session_logs")
@admin_required
def api_session_logs():
    """Get session bandwidth logs"""
    db = get_db()
    mac = request.args.get("mac", "")
    limit = min(int(request.args.get("limit", 100)), 500)
    
    if mac:
        logs = db.execute(
            "SELECT * FROM session_logs WHERE device_mac=? ORDER BY timestamp DESC LIMIT ?",
            (mac, limit)
        ).fetchall()
    else:
        logs = db.execute(
            "SELECT * FROM session_logs ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
    db.close()
    return jsonify([dict(l) for l in logs])

# ─── BULK VOUCHER EXPORT (Feature #8) ───
@app.route("/admin/export/vouchers")
@admin_required
def export_vouchers_csv():
    """Export vouchers as CSV for printing/management"""
    db = get_db()
    vouchers = db.execute(
        "SELECT code, duration_minutes, speed_mbps, created_at, used_at, expires_at, active FROM codes ORDER BY id DESC LIMIT 1000"
    ).fetchall()
    db.close()
    
    from io import StringIO
    import csv
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["Code", "Duration (min)", "Speed (Mbps)", "Created", "Used At", "Expires", "Status"])
    for v in vouchers:
        status = "Used" if v["used_at"] else ("Active" if v["active"] else "Revoked")
        writer.writerow([v["code"], v["duration_minutes"], v["speed_mbps"], v["created_at"][:10], 
                        v["used_at"][:10] if v["used_at"] else "-", v["expires_at"][:10] if v["expires_at"] else "-", status])
    
    response = Response(output.getvalue(), mimetype="text/csv")
    response.headers["Content-Disposition"] = "attachment;filename=vouchers.csv"
    return response

# ─── BULK VOUCHER IMPORT (Feature #8) ───
@app.route("/admin/import/vouchers", methods=["POST"])
@admin_required
def import_vouchers_csv():
    """Bulk import vouchers from CSV"""
    if "file" not in request.files:
        ctx = build_admin_context(message="No file uploaded")
        return render_template_string(ADMIN_HTML, **ctx)
    
    from io import TextIOWrapper
    import csv
    file = request.files["file"]
    count = 0
    try:
        stream = TextIOWrapper(file.stream, encoding="utf8")
        reader = csv.DictReader(stream)
        db = get_db()
        now = datetime.utcnow().isoformat()
        for row in reader:
            if "code" not in row or not row["code"].strip():
                continue
            code = row["code"].strip().upper()
            minutes = int(row.get("Duration (min)", 60))
            speed = int(row.get("Speed (Mbps)", 5))
            db.execute(
                "INSERT OR IGNORE INTO codes (code, duration_minutes, speed_mbps, created_at, active) VALUES (?,?,?,?,1)",
                (code, minutes, speed, now))
            count += 1
        db.commit()
        db.close()
        log_admin_action("bulk_import_vouchers", "", f"Imported {count} vouchers")
        ctx = build_admin_context(message=f"Imported {count} voucher(s)")
    except Exception as e:
        ctx = build_admin_context(message=f"Import error: {str(e)}")
    return render_template_string(ADMIN_HTML, **ctx)

# ─── TEMPORARY CODE GENERATION (Feature #6) ───
@app.route("/admin/generate_temporary", methods=["POST"])
@admin_required
def admin_generate_temporary():
    """Generate temporary guest codes that auto-revoke after 30 min"""
    try:
        qty = min(max(1, int(request.form.get("qty", 1))), 10)
        speed = max(1, min(1000, int(request.form.get("speed", 5))))
    except ValueError:
        qty, speed = 1, 5
    
    db = get_db()
    now = datetime.utcnow()
    temp_codes = []
    for _ in range(qty):
        code = secrets.token_hex(4).upper()[:4] + "-" + secrets.token_hex(4).upper()[:4]
        db.execute(
            "INSERT INTO codes (code, duration_minutes, speed_mbps, created_at, temporary, expires_temporary_at) VALUES (?,?,?,?,1,?)",
            (code, 30, speed, now.isoformat(), (now + timedelta(minutes=30)).isoformat())
        )
        temp_codes.append({"code": code, "qr": generate_qr_base64(code)})
    db.commit()
    db.close()
    
    log_admin_action("generate_temporary", "", f"Generated {qty} temporary codes")
    ctx = build_admin_context(message=f"Generated {qty} temporary code(s)", new_vouchers=temp_codes)
    return render_template_string(ADMIN_HTML, **ctx)

@app.route("/admin/api/stats")
@admin_required
def api_stats():
    """Lightweight endpoint for real-time dashboard stat counters."""
    db = get_db()
    now = datetime.utcnow().isoformat()
    reset_at = get_setting("stats_reset_at", "")
    if reset_at:
        sales = db.execute(
            "SELECT SUM(duration_minutes) as s FROM codes WHERE used_by IS NOT NULL AND used_at > ?",
            (reset_at,)).fetchone()["s"] or 0
    else:
        sales = db.execute(
            "SELECT SUM(duration_minutes) as s FROM codes WHERE used_by IS NOT NULL"
        ).fetchone()["s"] or 0
    active_count = db.execute(
        "SELECT COUNT(*) as c FROM codes WHERE active=1 AND used_by IS NOT NULL "
        "AND (expires_at IS NULL OR expires_at > ?)", (now,)).fetchone()["c"]
    device_count = db.execute("SELECT COUNT(*) as c FROM devices").fetchone()["c"]
    db.close()
    return jsonify({"active_count": active_count, "total_mins": sales, "device_count": device_count})

@app.route("/admin/api/diagnostics")
@admin_required
def api_diagnostics():
    checks = run_diagnostics()
    return jsonify(checks)

@app.route("/admin/api/ping")
@admin_required
def api_ping():
    import shlex
    host = request.args.get("host", "8.8.8.8").strip()
    count = min(int(request.args.get("count", 4)), 20)
    # Sanitise — only allow hostname chars
    import re
    if not re.match(r'^[a-zA-Z0-9.\-]+$', host):
        return jsonify({"error": "Invalid host"})
    try:
        result = subprocess.run(
            ["ping", "-c", str(count), "-W", "2", host],
            capture_output=True, text=True, timeout=count * 3 + 5)
        return jsonify({"output": result.stdout + result.stderr})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/admin/api/sessions")
@admin_required
def api_sessions():
    db = get_db()
    now = datetime.utcnow().isoformat()
    rows = db.execute(
        "SELECT * FROM codes WHERE active=1 AND used_by IS NOT NULL AND (expires_at IS NULL OR expires_at > ?)",
        (now,)).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

@app.route("/admin/api/health")
@admin_required
def api_health():
    return jsonify(get_system_health())

# ─────────────────────── MAIN ───────────────────────

if __name__ == "__main__":
    init_db()
    _warmup_net_stats()  # prime _prev_net baseline
    threading.Thread(target=expiry_checker, daemon=True).start()
    # Take a second net sample after 3s so the first dashboard poll has a real delta
    def _delayed_warmup():
        time.sleep(3)
        wan = _detect_wan_iface()
        get_net_speed(wan)
        if wan != "eth0":
            get_net_speed("eth0")
    threading.Thread(target=_delayed_warmup, daemon=True).start()
    from werkzeug.serving import make_server
    portal_server = make_server("0.0.0.0", 8080, app)
    admin_server  = make_server("0.0.0.0", 8081, app)
    t1 = threading.Thread(target=portal_server.serve_forever, daemon=True)
    t2 = threading.Thread(target=admin_server.serve_forever, daemon=True)
    t1.start()
    t2.start()
    print("Captive Portal : http://192.168.50.1:8080")
    print("Admin Dashboard: http://192.168.50.1:8081/admin")
    t1.join()