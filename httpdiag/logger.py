import os
import time
from typing import Optional, Dict

from .diagnostics import DiagnosticsResult
from .redirect import RedirectChain


class RequestLogger:
    def __init__(self, log_dir: str = "./logs"):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)

    def save_single_request(self, result: DiagnosticsResult, filename: Optional[str] = None) -> str:
        if filename is None:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"request_{timestamp}.log"

        filepath = os.path.join(self.log_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 70 + "\n")
            f.write("HTTP DIAGNOSTICS REQUEST LOG\n")
            f.write("=" * 70 + "\n\n")

            f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"URL: {result.url}\n")
            f.write(f"Method: {result.method}\n")
            f.write(f"IP Address: {result.ip_address}\n")
            f.write(f"HTTPS: {'Yes' if result.is_https else 'No'}\n")
            f.write(f"Status: {result.status_code} {result.status_text}\n\n")

            f.write("-" * 70 + "\n")
            f.write("TIMING BREAKDOWN\n")
            f.write("-" * 70 + "\n")
            f.write(f"  DNS Lookup:       {result.timing.dns_lookup * 1000:.3f} ms\n")
            f.write(f"  TCP Connect:      {result.timing.tcp_connect * 1000:.3f} ms\n")
            if result.is_https:
                f.write(f"  TLS Handshake:    {result.timing.tls_handshake * 1000:.3f} ms\n")
            f.write(f"  Request Send:     {result.timing.request_send * 1000:.3f} ms\n")
            f.write(f"  Time to First Byte: {result.timing.time_to_first_byte * 1000:.3f} ms\n")
            f.write(f"  Content Download: {result.timing.content_download * 1000:.3f} ms\n")
            f.write(f"  TOTAL:            {result.timing.total * 1000:.3f} ms\n\n")

            f.write("-" * 70 + "\n")
            f.write("REQUEST\n")
            f.write("-" * 70 + "\n")
            f.write(f"{result.method} {result.url} HTTP/1.1\n")
            f.write(f"Host: {_get_host(result.url)}\n")
            for key, value in _get_request_headers(result).items():
                f.write(f"{key}: {value}\n")
            f.write("\n")

            f.write("-" * 70 + "\n")
            f.write("RESPONSE HEADERS\n")
            f.write("-" * 70 + "\n")
            f.write(f"HTTP/1.1 {result.status_code} {result.status_text}\n")
            for key, value in result.headers.items():
                f.write(f"{key}: {value}\n")
            f.write("\n")

            f.write("-" * 70 + "\n")
            f.write("RESPONSE BODY\n")
            f.write("-" * 70 + "\n")
            f.write(result.body)
            f.write("\n\n")

            if result.error:
                f.write("-" * 70 + "\n")
                f.write("ERROR\n")
                f.write("-" * 70 + "\n")
                f.write(f"{result.error}\n\n")

            f.write("=" * 70 + "\n")
            f.write("END OF LOG\n")
            f.write("=" * 70 + "\n")

        return filepath

    def save_redirect_chain(self, chain: RedirectChain, filename: Optional[str] = None) -> str:
        if filename is None:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"redirect_chain_{timestamp}.log"

        filepath = os.path.join(self.log_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 70 + "\n")
            f.write("HTTP DIAGNOSTICS REDIRECT CHAIN LOG\n")
            f.write("=" * 70 + "\n\n")

            f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Redirects: {chain.total_redirects}\n")
            f.write(f"Total Time: {chain.total_time * 1000:.3f} ms\n\n")

            for i, step in enumerate(chain.steps, 1):
                f.write("-" * 70 + "\n")
                f.write(f"REDIRECT STEP {i}: {step.status_code}\n")
                f.write("-" * 70 + "\n")
                f.write(f"  From: {step.from_url}\n")
                f.write(f"  To:   {step.to_url}\n")
                f.write(f"  Time: {step.result.timing.total * 1000:.3f} ms\n\n")

                f.write(f"  Response Headers:\n")
                for key, value in step.result.headers.items():
                    f.write(f"    {key}: {value}\n")
                f.write("\n")

            if chain.final_result:
                f.write("-" * 70 + "\n")
                f.write(f"FINAL RESPONSE: {chain.final_result.status_code}\n")
                f.write("-" * 70 + "\n")
                f.write(f"  URL: {chain.final_result.url}\n")
                f.write(f"  Time: {chain.final_result.timing.total * 1000:.3f} ms\n\n")

                f.write(f"  Response Headers:\n")
                for key, value in chain.final_result.headers.items():
                    f.write(f"    {key}: {value}\n")
                f.write("\n")

                f.write(f"  Response Body (first 500 chars):\n")
                f.write(f"    {chain.final_result.body[:500]}\n\n")

            f.write("=" * 70 + "\n")
            f.write("END OF LOG\n")
            f.write("=" * 70 + "\n")

        return filepath


def _get_host(url: str) -> str:
    from urllib.parse import urlparse
    parsed = urlparse(url)
    return parsed.hostname or ""


def _get_request_headers(result: DiagnosticsResult) -> Dict[str, str]:
    headers = {
        "User-Agent": "httpdiag/1.0",
        "Accept": "*/*",
    }
    return headers
