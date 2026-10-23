#!/usr/bin/env python3
import json
import urllib.parse
import sys
import os
from http.server import BaseHTTPRequestHandler

# Add root directory to sys.path so VexoraWp module can be imported
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import VexoraWp

class handler(BaseHTTPRequestHandler):
    def _send_cors(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')

    def do_OPTIONS(self):
        self.send_response(200)
        self._send_cors()
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        target = qs.get("url", [None])[0]
        mode = qs.get("mode", ["quick"])[0]

        if not target:
            self.send_response(400)
            self._send_cors()
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Missing required 'url' parameter"}).encode('utf-8'))
            return

        self._execute_scan(target, mode)

    def do_POST(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length) if content_length > 0 else b'{}'
            data = json.loads(body.decode('utf-8'))
            target = data.get("url")
            mode = data.get("mode", "full")

            if not target:
                self.send_response(400)
                self._send_cors()
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Missing 'url' field in request payload"}).encode('utf-8'))
                return

            self._execute_scan(target, mode)
        except Exception as e:
            self.send_response(500)
            self._send_cors()
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": f"Internal scan error: {str(e)}"}).encode('utf-8'))

    def _execute_scan(self, target, mode):
        try:
            # Set serverless-optimized thread counts and timeouts
            threads = 20 if mode == "full" else 15
            timeout = 7 if mode == "full" else 5

            report = VexoraWp.run_audit(
                url=target,
                mode=mode,
                threads=threads,
                timeout=timeout
            )

            self.send_response(200)
            self._send_cors()
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(report, default=str).encode('utf-8'))
        except Exception as e:
            self.send_response(500)
            self._send_cors()
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                "error": str(e),
                "target": target
            }).encode('utf-8'))
