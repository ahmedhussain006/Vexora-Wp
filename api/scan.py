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

try:
    import VexoraWp
    _import_err = None
except Exception as e:
    VexoraWp = None
    _import_err = str(e)


class handler(BaseHTTPRequestHandler):
    def _send_cors(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')

    def _serve_file(self, rel_path, content_type):
        """Serve static files if requested or if root entrypoint receives browser traffic"""
        candidates = [
            os.path.join(ROOT_DIR, rel_path),
            os.path.join(ROOT_DIR, "public", rel_path),
        ]
        file_path = next((p for p in candidates if os.path.isfile(p)), None)
        if not file_path:
            return False

        try:
            with open(file_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(content)))
            self.send_header('Cache-Control', 'public, max-age=3600')
            self._send_cors()
            self.end_headers()
            self.wfile.write(content)
            return True
        except Exception:
            return False

    def do_OPTIONS(self):
        self.send_response(200)
        self._send_cors()
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip('/')
        qs = urllib.parse.parse_qs(parsed.query)

        # 1. Serve static frontend assets
        if path == "" or path == "/index.html":
            if self._serve_file("index.html", "text/html; charset=utf-8"):
                return
        elif path == "/style.css":
            if self._serve_file("style.css", "text/css; charset=utf-8"):
                return
        elif path == "/app.js":
            if self._serve_file("app.js", "application/javascript; charset=utf-8"):
                return

        # 2. Handle scan API requests (e.g. /api/scan?url=...)
        target = qs.get("url", [None])[0]
        mode = qs.get("mode", ["quick"])[0]

        if path.startswith("/api") or target:
            if not target:
                self.send_response(400)
                self._send_cors()
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Missing required 'url' parameter"}).encode('utf-8'))
                return
            self._execute_scan(target, mode)
            return

        # 3. Default fallback: serve index.html or 404
        if not self._serve_file("index.html", "text/html; charset=utf-8"):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

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
        if VexoraWp is None:
            self.send_response(500)
            self._send_cors()
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                "error": f"Serverless backend initialization failed: {_import_err}. Ensure dependencies are installed in pyproject.toml."
            }).encode('utf-8'))
            return

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

