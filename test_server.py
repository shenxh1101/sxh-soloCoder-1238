"""简单的HTTP测试服务器，用于验证重定向功能
"""
import http.server
import threading
import time


class TestHandler(http.server.BaseHTTPRequestHandler):
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
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.shutdown()
