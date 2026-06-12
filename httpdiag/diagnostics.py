import socket
import ssl
import time
import http.client
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, Optional, List, Tuple


@dataclass
class TimingInfo:
    dns_lookup: float = 0.0
    tcp_connect: float = 0.0
    tls_handshake: float = 0.0
    request_send: float = 0.0
    time_to_first_byte: float = 0.0
    content_download: float = 0.0
    total: float = 0.0

    @property
    def server_processing(self) -> float:
        return self.time_to_first_byte - self.request_send - self.tcp_connect - self.tls_handshake - self.dns_lookup


@dataclass
class DiagnosticsResult:
    url: str
    method: str
    status_code: int
    status_text: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    body_preview: str = ""
    timing: TimingInfo = field(default_factory=TimingInfo)
    ip_address: str = ""
    is_https: bool = False
    error: Optional[str] = None


class HttpDiagnostics:
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self._dns_cache: Dict[str, str] = {}

    def request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
    ) -> DiagnosticsResult:
        method = method.upper()
        parsed = urllib.parse.urlparse(url)
        is_https = parsed.scheme == "https"
        host = parsed.hostname
        port = parsed.port or (443 if is_https else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        result = DiagnosticsResult(
            url=url,
            method=method,
            status_code=0,
            status_text="",
            is_https=is_https,
        )

        total_start = time.time()
        sock = None
        try:
            dns_start = time.time()
            addr_info = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
            ip_address = addr_info[0][4][0]
            result.ip_address = ip_address
            result.timing.dns_lookup = time.time() - dns_start

            tcp_start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip_address, port))
            result.timing.tcp_connect = time.time() - tcp_start

            if is_https:
                tls_start = time.time()
                context = ssl.create_default_context()
                context.check_hostname = True
                context.verify_mode = ssl.CERT_REQUIRED
                sock = context.wrap_socket(sock, server_hostname=host)
                result.timing.tls_handshake = time.time() - tls_start

            req_send_start = time.time()
            request_lines = [f"{method} {path} HTTP/1.1"]
            request_lines.append(f"Host: {host}")

            if headers:
                for key, value in headers.items():
                    request_lines.append(f"{key}: {value}")

            has_content_length = False
            if headers:
                has_content_length = any(k.lower() == "content-length" for k in headers.keys())

            if body and not has_content_length:
                request_lines.append(f"Content-Length: {len(body.encode('utf-8'))}")

            has_connection = any(k.lower() == "connection" for k in headers or {})
            if not has_connection:
                request_lines.append("Connection: close")

            request_lines.append("")
            if body:
                request_lines.append(body)
            else:
                request_lines.append("")

            request_data = "\r\n".join(request_lines).encode("utf-8")
            sock.sendall(request_data)
            result.timing.request_send = time.time() - req_send_start

            response_data = b""
            first_byte_received = False
            header_end = -1
            resp_headers: Dict[str, str] = {}
            is_complete = False

            while not is_complete:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    if not first_byte_received:
                        result.timing.time_to_first_byte = time.time() - total_start
                        first_byte_received = True
                    response_data += chunk

                    if header_end == -1:
                        header_end = response_data.find(b"\r\n\r\n")
                        if header_end != -1:
                            header_data = response_data[:header_end].decode("utf-8", errors="replace")
                            header_lines = header_data.split("\r\n")
                            for line in header_lines[1:]:
                                if ":" in line:
                                    key, value = line.split(":", 1)
                                    resp_headers[key.strip()] = value.strip()

                    if header_end != -1:
                        body_data = response_data[header_end + 4:]
                        transfer_encoding = resp_headers.get("Transfer-Encoding", "").lower()
                        content_length = resp_headers.get("Content-Length")

                        if content_length:
                            try:
                                content_length_int = int(content_length)
                                if len(body_data) >= content_length_int:
                                    is_complete = True
                            except ValueError:
                                pass
                        elif "chunked" in transfer_encoding:
                            if self._is_chunked_complete(body_data):
                                is_complete = True
                        else:
                            pass
                except socket.timeout:
                    raise

            if not first_byte_received:
                result.timing.time_to_first_byte = time.time() - total_start

            download_end = time.time()

            if header_end == -1:
                raise ValueError("Invalid HTTP response: no header separator found")

            header_data = response_data[:header_end].decode("utf-8", errors="replace")
            body_data = response_data[header_end + 4:]

            header_lines = header_data.split("\r\n")
            status_line = header_lines[0]
            status_parts = status_line.split(" ", 2)
            if len(status_parts) >= 2:
                result.status_code = int(status_parts[1])
            if len(status_parts) >= 3:
                result.status_text = status_parts[2]

            resp_headers: Dict[str, str] = {}
            for line in header_lines[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    resp_headers[key.strip()] = value.strip()
            result.headers = resp_headers

            transfer_encoding = resp_headers.get("Transfer-Encoding", "").lower()
            content_length = resp_headers.get("Content-Length")

            if "chunked" in transfer_encoding:
                body_data = self._decode_chunked(body_data)
            elif content_length:
                try:
                    content_length_int = int(content_length)
                    body_data = body_data[:content_length_int]
                except ValueError:
                    pass

            result.timing.total = download_end - total_start
            result.timing.content_download = result.timing.total - result.timing.time_to_first_byte

            content_type = resp_headers.get("Content-Type", "")
            encoding = "utf-8"
            if "charset=" in content_type:
                charset_part = content_type.split("charset=")[1]
                encoding = charset_part.split(";")[0].strip()

            try:
                result.body = body_data.decode(encoding, errors="replace")
            except (LookupError, UnicodeDecodeError):
                result.body = body_data.decode("utf-8", errors="replace")

            result.body_preview = result.body[:200]

        except Exception as e:
            result.error = str(e)
            result.timing.total = time.time() - total_start
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

        return result

    def _is_chunked_complete(self, data: bytes) -> bool:
        pos = 0
        while pos < len(data):
            crlf = data.find(b"\r\n", pos)
            if crlf == -1:
                return False
            size_str = data[pos:crlf].decode("ascii", errors="replace").strip()
            if not size_str:
                pos = crlf + 2
                continue
            try:
                chunk_size = int(size_str, 16)
            except ValueError:
                return False
            pos = crlf + 2
            if chunk_size == 0:
                return True
            if pos + chunk_size + 2 > len(data):
                return False
            pos += chunk_size + 2
        return False

    def _decode_chunked(self, data: bytes) -> bytes:
        result = b""
        pos = 0
        while pos < len(data):
            crlf = data.find(b"\r\n", pos)
            if crlf == -1:
                break
            size_str = data[pos:crlf].decode("ascii", errors="replace").strip()
            if not size_str:
                pos = crlf + 2
                continue
            try:
                chunk_size = int(size_str, 16)
            except ValueError:
                break
            pos = crlf + 2
            if chunk_size == 0:
                break
            if pos + chunk_size <= len(data):
                result += data[pos : pos + chunk_size]
            else:
                result += data[pos:]
                break
            pos += chunk_size + 2
        return result
