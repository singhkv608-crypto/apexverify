"""
ApexVerify Standalone Launcher
Run this script from any terminal:
   python run.py
It will automatically verify dependencies, launch the server on localhost:5000,
and open your browser.
"""

import sys
import os
import subprocess
import webbrowser
import threading
import time

PORT = 5000
HOST = "127.0.0.1"
URL = f"http://localhost:{PORT}"

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

def check_and_install_dependencies():
    required_packages = ["fastapi", "uvicorn", "dns", "multipart", "pydantic"]
    missing = []
    
    for pkg in required_packages:
        try:
            if pkg == "dns":
                import dns.resolver
            elif pkg == "multipart":
                import multipart
            else:
                __import__(pkg)
        except ImportError:
            missing.append(pkg)
            
    if missing:
        print(f"[*] Installing required dependencies ({', '.join(missing)})...")
        req_file = os.path.join(os.path.dirname(__file__), "requirements.txt")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", req_file])
        print("[+] All dependencies installed successfully!\n")

def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0

def is_apex_running(url: str) -> bool:
    try:
        import urllib.request
        req = urllib.request.Request(f"{url}/api/health", headers={"User-Agent": "ApexVerify-Launcher"})
        with urllib.request.urlopen(req, timeout=1.0) as resp:
            return resp.status == 200
    except Exception:
        return False

def open_browser(url: str):
    time.sleep(1.2)
    print(f"[*] Opening browser at {url}...")
    webbrowser.open(url)

def main():
    global PORT, URL
    print("=" * 60)
    print("     APEXVERIFY — GENUINE BULK EMAIL VERIFIER")
    print("=" * 60)
    
    check_and_install_dependencies()
    
    # Check if port 5000 is already in use
    if is_port_in_use(PORT, HOST):
        if is_apex_running(URL):
            print(f"[+] ApexVerify is already running active on: {URL}")
            print("[*] Opening your browser...")
            webbrowser.open(URL)
            print("=" * 60)
            return
        else:
            # Port is occupied by another app; find next open port
            for candidate in range(5001, 5020):
                if not is_port_in_use(candidate, HOST):
                    PORT = candidate
                    URL = f"http://localhost:{PORT}"
                    print(f"[!] Port 5000 is occupied; switched to open port: {PORT}")
                    break

    print(f"[*] Starting local server on: {URL}")
    print("[*] Press Ctrl+C at any time in this terminal to stop.")
    print("=" * 60)
    
    # Open browser in a separate thread
    threading.Thread(target=open_browser, args=(URL,), daemon=True).start()
    
    import uvicorn
    # Run uvicorn server
    uvicorn.run("app:app", host=HOST, port=PORT, log_level="info")

if __name__ == "__main__":
    main()
