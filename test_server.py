"""简单的HTTP测试服务器，用于验证重定向功能和集合测试
"""
import http.server
import threading
import time
import json
import uuid


class TestHandler(http.server.BaseHTTPRequestHandler):
    def _send_json(self, status_code, data):
        response = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def _check_auth(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        return auth[7:]

    def do_GET(self):
        if self.path == "/redirect1":
            self.send_response(302)
            self.send_header("Location", "/redirect2")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/redirect2":
            self.send_response(301)
            self.send_header("Location", "/final")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/redirect_lowercase":
            self.send_response(302)
            self.wfile.write(b"HTTP/1.1 302 Found\r\n")
            self.wfile.write(b"location: /final\r\n")
            self.wfile.write(b"Content-Length: 0\r\n")
            self.wfile.write(b"\r\n")
        elif self.path == "/redirect_uppercase":
            self.send_response(302)
            self.wfile.write(b"HTTP/1.1 302 Found\r\n")
            self.wfile.write(b"LOCATION: /final\r\n")
            self.wfile.write(b"Content-Length: 0\r\n")
            self.wfile.write(b"\r\n")
        elif self.path == "/redirect_loop":
            self.send_response(302)
            self.send_header("Location", "/redirect_loop2")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/redirect_loop2":
            self.send_response(302)
            self.send_header("Location", "/redirect_loop")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/final":
            body = b"Final destination"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/user":
            token = self._check_auth()
            if not token:
                self._send_json(401, {"error": "Unauthorized", "message": "Missing or invalid token"})
                return
            self._send_json(200, {
                "id": 12345,
                "username": "testuser",
                "email": "test@example.com",
                "token": token,
            })
        elif self.path.startswith("/api/resource/"):
            token = self._check_auth()
            if not token:
                self._send_json(401, {"error": "Unauthorized"})
                return
            resource_id = self.path.split("/")[-1]
            self._send_json(200, {
                "id": resource_id,
                "name": f"Resource {resource_id}",
                "status": "active",
                "created_at": "2024-01-01T00:00:00Z",
            })
        elif self.path == "/api/resources":
            token = self._check_auth()
            if not token:
                self._send_json(401, {"error": "Unauthorized"})
                return
            self._send_json(200, {
                "items": [
                    {"id": "res_001", "name": "Resource 1"},
                    {"id": "res_002", "name": "Resource 2"},
                ],
                "total": 2,
            })
        elif self.path == "/api/status":
            self._send_json(200, {"status": "ok", "timestamp": int(time.time())})
        elif self.path == "/api/slow":
            time.sleep(0.5)
            self._send_json(200, {"status": "slow_response"})
        else:
            body = b"Hello World"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        if self.path == "/api/login":
            try:
                data = json.loads(body.decode())
                username = data.get("username", "")
                password = data.get("password", "")
            except json.JSONDecodeError:
                username = ""
                password = ""

            if username and password:
                token = str(uuid.uuid4()).replace("-", "")[:32]
                self._send_json(200, {
                    "token": token,
                    "expires_in": 3600,
                    "user": {"id": 12345, "username": username},
                })
            else:
                self._send_json(400, {"error": "Invalid credentials"})
        elif self.path == "/api/resource":
            token = self._check_auth()
            if not token:
                self._send_json(401, {"error": "Unauthorized"})
                return
            try:
                data = json.loads(body.decode())
            except json.JSONDecodeError:
                data = {}
            resource_id = str(uuid.uuid4()).replace("-", "")[:16]
            self._send_json(201, {
                "id": resource_id,
                "name": data.get("name", "New Resource"),
                "status": "created",
            })
        else:
            response = f"Received POST data: {body.decode()}"
            response_bytes = response.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(response_bytes)))
            self.end_headers()
            self.wfile.write(response_bytes)

    def log_message(self, format, *args):
        pass


def start_test_server(port=8765):
    server = http.server.HTTPServer(("127.0.0.1", port), TestHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    return server, port


if __name__ == "__main__":
    server, port = start_test_server()
    print(f"Test server running on port {port}")
    print("Available endpoints:")
    print("  GET / -> 200 Hello World")
    print("  GET /redirect1 -> 302 /redirect2")
    print("  GET /redirect2 -> 301 /final")
    print("  GET /redirect_lowercase -> 302 (location header lowercase)")
    print("  GET /redirect_uppercase -> 302 (LOCATION header uppercase)")
    print("  GET /redirect_loop -> redirect loop for testing max redirects")
    print("  GET /final -> 200 Final destination")
    print("  POST / -> 200 echo POST data")
    print()
    print("Collection test endpoints:")
    print("  POST /api/login -> 200 {token: '...'} (need username/password)")
    print("  GET  /api/user -> 200 user info (need Bearer token)")
    print("  POST /api/resource -> 201 create resource (need Bearer token)")
    print("  GET  /api/resource/{id} -> 200 resource info (need Bearer token)")
    print("  GET  /api/resources -> 200 resource list (need Bearer token)")
    print("  GET  /api/status -> 200 status ok")
    print("  GET  /api/slow -> 200 slow response (500ms delay)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.shutdown()
