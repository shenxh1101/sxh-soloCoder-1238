import socket
import ssl
import time
import json
import urllib.parse
from dataclasses import dataclass, field, asdict
from typing import Dict, Optional, List, Any


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

    def to_dict(self) -> Dict[str, float]:
        return {
            "dns_lookup_ms": round(self.dns_lookup * 1000, 3),
            "tcp_connect_ms": round(self.tcp_connect * 1000, 3),
            "tls_handshake_ms": round(self.tls_handshake * 1000, 3),
            "request_send_ms": round(self.request_send * 1000, 3),
            "time_to_first_byte_ms": round(self.time_to_first_byte * 1000, 3),
            "content_download_ms": round(self.content_download * 1000, 3),
            "total_ms": round(self.total * 1000, 3),
        }


@dataclass
class DiagnosticsResult:
    url: str
    method: str
    status_code: int = 0
    status_text: str = ""
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    response_body_preview: str = ""
    response_body_size: int = 0
    timing: TimingInfo = field(default_factory=TimingInfo)
    ip_address: str = ""
    is_https: bool = False
    error: Optional[str] = None

    @property
    def headers(self) -> Dict[str, str]:
        return self.response_headers

    @headers.setter
    def headers(self, value: Dict[str, str]):
        self.response_headers = value

    @property
    def body(self) -> str:
        return self.response_body

    @body.setter
    def body(self, value: str):
        self.response_body = value

    @property
    def body_preview(self) -> str:
        return self.response_body_preview

    @body_preview.setter
    def body_preview(self, value: str):
        self.response_body_preview = value

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "url": self.url,
            "method": self.method,
            "status_code": self.status_code,
            "status_text": self.status_text,
            "ip_address": self.ip_address,
            "is_https": self.is_https,
            "request_headers": self.request_headers,
            "request_body": self.request_body,
            "response_headers": self.response_headers,
            "response_body_preview": self.response_body_preview,
            "response_body_size": self.response_body_size,
            "timing": self.timing.to_dict(),
        }
        if self.error:
            data["error"] = self.error
        return data

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)


class HttpDiagnostics:
    def __init__(self, timeout: int = 30):
        self.timeout = timeout

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
        host = parsed.hostname or ""
        port = parsed.port or (443 if is_https else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        result = DiagnosticsResult(
            url=url,
            method=method,
            is_https=is_https,
            request_body=body or "",
        )

        actual_request_headers: Dict[str, str] = {}
        actual_request_headers["Host"] = host
        if headers:
            for k, v in headers.items():
                actual_request_headers[k] = v

        has_content_length = any(k.lower() == "content-length" for k in actual_request_headers.keys())
        if body and not has_content_length:
            actual_request_headers["Content-Length"] = str(len(body.encode("utf-8")))

        has_connection = any(k.lower() == "connection" for k in actual_request_headers.keys())
        if not has_connection:
            actual_request_headers["Connection"] = "close"

        result.request_headers = actual_request_headers

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
            for k, v in actual_request_headers.items():
                request_lines.append(f"{k}: {v}")
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
                        transfer_encoding = self._get_header_ci(resp_headers, "Transfer-Encoding", "").lower()
                        content_length = self._get_header_ci(resp_headers, "Content-Length")

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
            result.response_headers = resp_headers

            transfer_encoding = self._get_header_ci(resp_headers, "Transfer-Encoding", "").lower()
            content_length = self._get_header_ci(resp_headers, "Content-Length")

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

            content_type = self._get_header_ci(resp_headers, "Content-Type", "")
            encoding = "utf-8"
            if "charset=" in content_type:
                charset_part = content_type.split("charset=")[1]
                encoding = charset_part.split(";")[0].strip()

            try:
                result.response_body = body_data.decode(encoding, errors="replace")
            except (LookupError, UnicodeDecodeError):
                result.response_body = body_data.decode("utf-8", errors="replace")

            result.response_body_size = len(result.response_body.encode("utf-8"))
            result.response_body_preview = result.response_body[:200]

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

    def _get_header_ci(self, headers: Dict[str, str], name: str, default: Optional[str] = None) -> Optional[str]:
        name_lower = name.lower()
        for k, v in headers.items():
            if k.lower() == name_lower:
                return v
        return default

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
