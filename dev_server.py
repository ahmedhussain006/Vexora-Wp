#!/usr/bin/env python3
"""
Local Development Server for VexoraWP Web UI
Simulates Vercel Serverless Function routing locally.
Run with: python dev_server.py
"""

import sys
import os
from http.server import HTTPServer, SimpleHTTPRequestHandler
import urllib.parse
import json

# Ensure root directory is on sys.path
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from api.scan import handler as ScanHandler

class VercelLocalDevHandler(ScanHandler, SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        SimpleHTTPRequestHandler.__init__(self, *args, directory=ROOT_DIR, **kwargs)

    def do_OPTIONS(self):
        if self.path.startswith("/api/scan"):
            ScanHandler.do_OPTIONS(self)
        else:
            self.send_response(200)
            self.end_headers()

    def do_GET(self):
        if self.path.startswith("/api/scan"):
            ScanHandler.do_GET(self)
        else:
            if self.path == "/" or self.path == "":
                self.path = "/index.html"
            SimpleHTTPRequestHandler.do_GET(self)

    def do_POST(self):
        if self.path.startswith("/api/scan"):
            ScanHandler.do_POST(self)
        else:
            self.send_error(404, "Not Found")

def run(port=3000):
    server_address = ('', port)
    httpd = HTTPServer(server_address, VercelLocalDevHandler)
    print(f"\n[+] VexoraWP Local Web Server running at: http://localhost:{port}")
    print(f"[+] Simulating Vercel serverless environment on /api/scan")
    print(f"[+] Press Ctrl+C to stop.\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
    run(port)
