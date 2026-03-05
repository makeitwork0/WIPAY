import subprocess
import re
import smtplib
from email.message import EmailMessage
import time

# --- CONFIGURATION ---
EMAIL_SENDER = "erosrohantorres@gmail.com"
EMAIL_PASSWORD = "nwppybvouutzfufa" # No spaces
EMAIL_RECEIVER = "erosrohantorres@gmail.com" # Can be the same as sender
PORTAL_PORT = "8081"
# ---------------------

def send_email(url):
    msg = EmailMessage()
    msg.set_content(f"Your Piso WiFi Admin Panel is online!\n\nClick here to access it:\n{url}/admin")
    msg['Subject'] = '🟢 Pi Admin URL Updated'
    msg['From'] = EMAIL_SENDER
    msg['To'] = EMAIL_RECEIVER

    try:
        print("Attempting to send email...")
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        print(f"✅ Success! Email sent with URL: {url}/admin")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")

def main():
    print("Starting Cloudflare Tunnel...")
    # Start the cloudflared process and read its output
    process = subprocess.Popen(
        ['cloudflared', 'tunnel', '--url', f'http://127.0.0.1:{PORTAL_PORT}'],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )

    url_found = False

    # Check every line Cloudflare prints in the background
    for line in process.stdout:
        # Search for the trycloudflare URL
        if not url_found:
            match = re.search(r'(https://[a-zA-Z0-9-]+\.trycloudflare\.com)', line)
            if match:
                url = match.group(1)
                print(f"\n--- 🌐 FOUND TUNNEL URL: {url} ---\n")
                send_email(url)
                url_found = True # Stop it from sending 100 emails

    process.wait()

if __name__ == '__main__':
    # Keep the script alive forever. If the tunnel crashes, restart it.
    while True:
        main()
        print("Tunnel closed. Restarting in 10 seconds...")
        time.sleep(10)
