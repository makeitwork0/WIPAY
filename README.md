# 🌐 WiPay — Raspberry Pi Captive Portal & Piso WiFi System

> A lightweight, feature-rich captive portal built for Raspberry Pi. Turn your Pi into a fully managed WiFi hotspot with voucher-based authentication, remote administration, and real-time analytics.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🎫 **Voucher Authentication** | Generate and manage time-limited access codes with configurable durations and speeds |
| 📱 **QR Code Support** | Users can scan QR codes directly on the portal page for quick login |
| 🔥 **Automated Firewall** | Integrated `iptables` management handles traffic redirection and per-device blocking |
| 📶 **Bandwidth Control** | Per-user speed limiting via Linux Traffic Control (`tc`) with configurable Mbps caps |
| 🌍 **Remote Admin Panel** | Access your dashboard from anywhere using a Cloudflare Tunnel — no port forwarding needed |
| 📧 **Email Notifications** | Automatically emails you the dynamic tunnel URL whenever it changes |
| 📊 **Real-time Analytics** | Monitor system health, connected devices, active sessions, and bandwidth usage |
| ⏸️ **Session Pause/Resume** | Users can pause their sessions to preserve remaining time |
| 📋 **Lobby Queue** | Users can request access plans; admin approves and grants codes from the dashboard |
| 🔒 **Device Management** | Whitelist, block, or assign groups/quotas to devices by MAC address |
| 📁 **Audit Logs** | Full admin action history with timestamps and session logs |
| 💾 **Data Export** | Export vouchers and session data as CSV from the admin dashboard |

---

## 📁 Project Structure

```
WIPAY/
├── Project-files/
│   ├── app4.py              # Core Flask application — portal UI, admin dashboard, REST API
│   ├── setup_firewall.sh    # Configures iptables NAT, forwarding rules, and tc bandwidth tree
│   └── tunnel_mailer.py     # Starts Cloudflare Tunnel and emails the admin URL on startup
├── README.md
└── LICENSE
```

### Key Components

**`app4.py`** — The heart of WiPay. Handles:
- User-facing captive portal (voucher entry, QR scan, lobby request)
- Admin dashboard (voucher generation, session management, analytics)
- REST API endpoints for real-time data (`/admin/api/...`)
- SQLite database with WAL mode for concurrent read performance
- iptables integration for granting/revoking internet access per device
- Per-IP speed limiting via Linux `tc` HTB queuing discipline

**`setup_firewall.sh`** — Run once on boot to configure:
- IPv4 forwarding
- NAT masquerading for internet sharing
- Custom `CAPTIVE_PORTAL` iptables chain to redirect HTTP traffic to Flask
- `tc` root bandwidth tree on the hotspot interface

**`tunnel_mailer.py`** — Optional but recommended for remote access:
- Launches `cloudflared` as a subprocess
- Parses stdout for the `trycloudflare.com` URL
- Sends the URL to your Gmail inbox
- Auto-restarts the tunnel if it crashes

---

## 🗄️ Database Schema

WiPay uses a SQLite database (`portal.db`) with the following tables:

| Table | Purpose |
|---|---|
| `codes` | Voucher records — duration, speed, expiry, pause state, device assignment |
| `devices` | Known devices — MAC, name, IP, whitelist/block status, quotas |
| `settings` | Key-value store for portal title, rates, quotas, feature flags |
| `lobby_requests` | Pending access requests from users awaiting admin approval |
| `session_logs` | Per-session bandwidth usage records |
| `admin_logs` | Admin action audit trail |
| `device_groups` | Named groups with optional speed limits for batch device management |
| `bandwidth_profiles` | Reusable speed/quota templates assignable to devices |
| `activity_history` | Time-series snapshots of active sessions and throughput |

---

## 🔐 Security Highlights

- **ADMIN_SECRET enforcement** — The app refuses to start without a strong `ADMIN_SECRET` environment variable set.
- **Input validation** — All IP addresses and hostnames are validated with regex before being used in system calls.
- **iptables caching** — Firewall checks are cached with a 10-second TTL to prevent slow subprocess calls on every request.
- **No interactive sudo** — All system commands use `sudo -n` (non-interactive) to prevent password prompt hangs.
- **Response cache control** — Real-time API endpoints always return `no-store` headers; static assets are cached appropriately.

---

## 🖥️ Admin Dashboard

Access the admin panel at `http://<your-pi-ip>:8080/admin` (or via your Cloudflare Tunnel URL).

**Dashboard capabilities:**
- View and manage all voucher codes (active, used, expired)
- Generate single or bulk vouchers with custom duration, speed cap, and expiry
- Monitor live connected devices and session timers
- Approve or deny lobby access requests
- Block or whitelist devices by MAC address
- Assign devices to groups with shared speed profiles
- View bandwidth usage charts and system health metrics (CPU, RAM, disk)
- Export data to CSV
- Configure portal appearance, pricing plans, and quota settings

---

## 🔗 User Flow

1. User connects to the hotspot Wi-Fi network.
2. Any HTTP request is intercepted by `iptables` and redirected to the Flask portal on port 8080.
3. The portal displays the branded login page with a voucher entry field, QR scan option, and available plans.
4. User enters a valid voucher code or submits a lobby request.
5. On success, their IP is added to `iptables FORWARD` with an `ACCEPT` rule, granting internet access.
6. A countdown timer tracks remaining session time; the app automatically revokes access on expiry.
7. Users may pause/resume their session if the feature is enabled by the admin.

---

## ⚙️ Configuration Reference

Key settings managed through the admin panel (`/admin/settings`):

| Setting | Default | Description |
|---|---|---|
| `portal_title` | `WiFi Access` | Main heading shown on the portal login page |
| `portal_subtitle` | *(descriptive text)* | Subtitle shown below the title |
| `show_rates` | `1` | Show pricing plans on the portal |
| `data_rates` | *(JSON array)* | Plan definitions: name, minutes, speed (Mbps), label (price) |
| `allow_pause` | `1` | Allow users to pause active sessions |
| `max_pause_seconds` | `0` | Max cumulative pause time per session (0 = unlimited) |
| `absolute_expiry_hours` | `0` | Hard wall-clock expiry regardless of pausing (0 = disabled) |
| `default_daily_quota_mb` | `0` | Default daily bandwidth cap per device (0 = unlimited) |
| `default_hourly_quota_mb` | `0` | Default hourly bandwidth cap per device (0 = unlimited) |
| `enable_audit_logs` | `1` | Record admin actions to the audit log |
| `enable_session_logs` | `1` | Record session bandwidth data |
| `qr_logo_url` | *(empty)* | URL to an image overlaid on generated QR codes |

---

## 🛠️ Tech Stack

- **Python 3** with **Flask** — Web framework for portal and admin API
- **SQLite** (WAL mode) — Embedded database for vouchers, devices, and logs
- **iptables** — Firewall-level per-device internet access control
- **Linux tc (Traffic Control)** — Per-IP bandwidth limiting using HTB queuing
- **Cloudflare Tunnel** (`cloudflared`) — Secure remote access without port forwarding
- **qrcode** — QR code generation for vouchers
- **psutil** — System health metrics (CPU, RAM, disk, network)
- **dnsmasq** — DHCP lease parsing for device hostname resolution

---

## 📄 License

See [LICENSE](./LICENSE) for full terms.

---

*WiPay is designed for deployment on Raspberry Pi OS but should work on any Debian/Ubuntu-based Linux system with two network interfaces.*
