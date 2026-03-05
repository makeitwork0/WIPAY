#!/bin/bash

# Interfaces
HOTSPOT_IF="eth0"
INTERNET_IF="wlan0"
PORTAL_PORT="8080"
GATEWAY_IP="192.168.50.1"

echo "Setting up Captive Portal Firewall..."

# 1. Enable IPv4 Forwarding in the kernel
echo "1" > /proc/sys/net/ipv4/ip_forward

# 2. Flush existing rules to start fresh
iptables -F
iptables -t nat -F
iptables -X
iptables -t nat -X CAPTIVE_PORTAL 2>/dev/null

# 3. Setup Internet Masquerading (NAT)
iptables -t nat -A POSTROUTING -o $INTERNET_IF -j MASQUERADE

# 4. Create the Custom NAT Chain for the Portal
iptables -t nat -N CAPTIVE_PORTAL

# IMPORTANT: Allow traffic to the Portal IP/Port itself so it doesn't loop
iptables -t nat -A PREROUTING -i $HOTSPOT_IF -d $GATEWAY_IP -p tcp --dport $PORTAL_PORT -j ACCEPT

# Send all HTTP traffic (Port 80) to the custom chain
iptables -t nat -A PREROUTING -i $HOTSPOT_IF -p tcp --dport 80 -j CAPTIVE_PORTAL

# Default action: Redirect to the Flask portal
iptables -t nat -A CAPTIVE_PORTAL -p tcp --dport 80 -j REDIRECT --to-ports $PORTAL_PORT

# 5. Configure FORWARD rules (The Gatekeeper)

# A. Allow existing/return traffic from the internet back to phones
iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# B. Allow DNS (Critical: phones need this to stay connected)
iptables -A FORWARD -i $HOTSPOT_IF -p udp --dport 53 -j ACCEPT
iptables -A FORWARD -i $HOTSPOT_IF -p tcp --dport 53 -j ACCEPT

# C. Block all other forwarding traffic by default
# (Python app will insert 'ACCEPT' rules at position 1 to bypass this)
iptables -A FORWARD -i $HOTSPOT_IF -j DROP

echo "Firewall setup complete!"
# --- NEW: Bandwidth Limiting (Traffic Control) Foundation ---
# Clear any old limits
tc qdisc del dev $HOTSPOT_IF root 2>/dev/null
# Create the root bandwidth tree
tc qdisc add dev $HOTSPOT_IF root handle 1: htb default 10
# Class 1:10 is for unauthenticated/portal traffic (unlimited so the portal loads fast)
tc class add dev $HOTSPOT_IF parent 1: classid 1:10 htb rate 1000mbit
