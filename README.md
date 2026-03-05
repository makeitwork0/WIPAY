# WiPay: Raspberry Pi Captive Portal & Piso WiFi System

WiPay is a lightweight and robust captive portal solution designed for Raspberry Pi. It transforms your Pi into a managed WiFi hotspot where users must authenticate via a voucher code to access the internet.

## 🌟 Key Features

* **Voucher Authentication**: Generate and manage time-limited access codes.
* **QR Code Support**: Users can scan QR codes for quick login.
* **Automated Firewall**: Integrated `iptables` management for traffic redirection and blocking.
* **Bandwidth Control**: Traffic control (tc) foundations for managing user speeds.
* **Remote Admin Panel**: Access your dashboard from anywhere via a Cloudflare Tunnel with automated URL email notifications.
* **Real-time Analytics**: Monitor system health, connected devices, and session status.

## 📁 Project Structure

* `app4.py`: The core Flask application handling the portal and admin dashboard.
* `setup_firewall.sh`: Shell script to configure NAT, packet forwarding, and captive portal redirection.
* `tunnel_mailer.py`: Automates Cloudflare Tunneling and emails the dynamic admin URL to the owner.
* `portal.db`: SQLite database for storing vouchers, device logs, and settings.

---

### **Setup Instructions**

Follow these steps to set up the WiPay system on your Raspberry Pi.

#### **1. Prerequisites**

* **Hardware**: Raspberry Pi with two network interfaces (e.g., `eth0` for hotspot, `wlan0` for internet).
* **OS**: Raspberry Pi OS (Lite recommended).
* **Dependencies**: Install required system packages:
```bash
sudo apt update
sudo apt install python3-flask python3-psutil sqlite3 iptables cloudflared

```



#### **2. Firewall Configuration**

Configure the network interfaces and portal redirection:

1. Open `setup_firewall.sh` and verify the interface names (`HOTSPOT_IF` and `INTERNET_IF`).
2. Make the script executable and run it:
```bash
chmod +x setup_firewall.sh
sudo ./setup_firewall.sh

```


*Note: This script enables IPv4 forwarding and redirects HTTP traffic to port 8080.*

#### **3. Remote Admin Setup (Optional but Recommended)**

To access the admin panel remotely without port forwarding:

1. Open `tunnel_mailer.py`.
2. Configure your Gmail App Password and receiver email in the configuration section.
3. The script will start a Cloudflare tunnel and email you the `trycloudflare.com` link whenever it changes.

#### **4. Launching the Application**

1. Set your secure admin secret as an environment variable:
```bash
export ADMIN_SECRET="your_very_secure_password"

```


2. Run the Flask application:
```bash
sudo -E python3 app4.py

```


*Note: `sudo` is required because the app manages system `iptables` for user sessions.*

#### **5. Usage**

* **User Portal**: Users connecting to the hotspot will be redirected to `http://192.168.50.1:8080`.
* **Admin Dashboard**: Access the dashboard at `http://<your-pi-ip>:8080/admin` (or via the Cloudflare URL).
