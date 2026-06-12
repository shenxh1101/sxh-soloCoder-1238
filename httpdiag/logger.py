import os
import time
from typing import Optional, Dict

from .diagnostics import DiagnosticsResult
from .redirect import RedirectChain
from .compare import CompareResult
from .batch import BatchResult


class RequestLogger:
    def __init__(self, log_dir: str = "./logs"):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)

    def _gen_filename(self, prefix: str, ext: str = "log") -> str:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        return f"{prefix}_{timestamp}.{ext}"

    def save_single_request(self, result: DiagnosticsResult, filename: Optional[str] = None) -> str:
        if filename is None:
            filename = self._gen_filename("request")

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
            f.write("REQUEST (ACTUALLY SENT)\n")
            f.write("-" * 70 + "\n")
            parsed_url = self._parse_url(result.url)
            f.write(f"{result.method} {parsed_url['path']} HTTP/1.1\n")
            for key, value in result.request_headers.items():
                f.write(f"{key}: {value}\n")
            f.write("\n")
            if result.request_body:
                f.write(f"{result.request_body}\n")
            f.write("\n")

            f.write("-" * 70 + "\n")
            f.write("RESPONSE HEADERS\n")
            f.write("-" * 70 + "\n")
            f.write(f"HTTP/1.1 {result.status_code} {result.status_text}\n")
            for key, value in result.response_headers.items():
                f.write(f"{key}: {value}\n")
            f.write("\n")

            f.write("-" * 70 + "\n")
            f.write(f"RESPONSE BODY ({result.response_body_size} bytes)\n")
            f.write("-" * 70 + "\n")
            f.write(result.response_body)
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
            filename = self._gen_filename("redirect_chain")

        filepath = os.path.join(self.log_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 70 + "\n")
            f.write("HTTP DIAGNOSTICS REDIRECT CHAIN LOG\n")
            f.write("=" * 70 + "\n\n")

            f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Redirects: {chain.total_redirects}\n")
            f.write(f"Total Time: {chain.total_time * 1000:.3f} ms\n")
            if chain.max_redirects_exceeded:
                f.write(f"WARNING: Max redirects exceeded!\n")
            f.write("\n")

            for i, step in enumerate(chain.steps, 1):
                f.write("=" * 70 + "\n")
                f.write(f"REDIRECT STEP {i}: {step.status_code}\n")
                f.write("=" * 70 + "\n")
                f.write(f"  From: {step.from_url}\n")
                f.write(f"  To:   {step.to_url}\n")
                f.write(f"  Time: {step.result.timing.total * 1000:.3f} ms\n\n")

                self._write_exchange(f, step.result, indent="  ")

            if chain.final_result:
                f.write("=" * 70 + "\n")
                f.write(f"FINAL RESPONSE: {chain.final_result.status_code}\n")
                f.write("=" * 70 + "\n")
                f.write(f"  URL: {chain.final_result.url}\n")
                f.write(f"  Time: {chain.final_result.timing.total * 1000:.3f} ms\n\n")

                self._write_exchange(f, chain.final_result, indent="  ")

            f.write("=" * 70 + "\n")
            f.write("END OF LOG\n")
            f.write("=" * 70 + "\n")

        return filepath

    def save_compare(self, compare: CompareResult, filename: Optional[str] = None) -> str:
        if filename is None:
            filename = self._gen_filename("compare")

        filepath = os.path.join(self.log_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 70 + "\n")
            f.write("HTTP DIAGNOSTICS COMPARE LOG\n")
            f.write("=" * 70 + "\n\n")

            f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            for i, item in enumerate(compare.items, 1):
                f.write("-" * 70 + "\n")
                f.write(f"REQUEST {i}: {item.name} - {item.url}\n")
                f.write("-" * 70 + "\n")
                self._write_exchange(f, item.result)

            f.write("=" * 70 + "\n")
            f.write("END OF LOG\n")
            f.write("=" * 70 + "\n")

        return filepath

    def save_batch(self, batch: BatchResult, filename: Optional[str] = None) -> str:
        if filename is None:
            filename = self._gen_filename("batch")

        filepath = os.path.join(self.log_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 70 + "\n")
            f.write("HTTP DIAGNOSTICS BATCH TEST LOG\n")
            f.write("=" * 70 + "\n\n")

            f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"URL: {batch.url}\n")
            f.write(f"Method: {batch.method}\n")
            f.write(f"Count: {batch.count}\n")
            f.write(f"Success: {batch.success_count}\n")
            f.write(f"Failure: {batch.failure_count}\n")
            f.write(f"Total Time: {batch.total_time * 1000:.3f} ms\n\n")

            if batch.status_codes:
                f.write("Status Code Distribution:\n")
                for code, cnt in sorted(batch.status_codes.items()):
                    f.write(f"  {code}: {cnt}\n")
                f.write("\n")

            f.write("Timing Stats:\n")
            for key, stats in batch.timing_breakdown.items():
                f.write(f"  {key}:\n")
                f.write(f"    min:    {stats.min * 1000:.3f} ms\n")
                f.write(f"    max:    {stats.max * 1000:.3f} ms\n")
                f.write(f"    avg:    {stats.avg * 1000:.3f} ms\n")
                f.write(f"    median: {stats.median * 1000:.3f} ms\n")
                f.write(f"    p95:    {stats.p95 * 1000:.3f} ms\n")
                f.write(f"    p99:    {stats.p99 * 1000:.3f} ms\n")
            f.write("\n")

            for i, r in enumerate(batch.results, 1):
                f.write("-" * 70 + "\n")
                f.write(f"REQUEST #{i}\n")
                f.write("-" * 70 + "\n")
                self._write_exchange(f, r)

            f.write("=" * 70 + "\n")
            f.write("END OF LOG\n")
            f.write("=" * 70 + "\n")

        return filepath

    def _write_exchange(self, f, result: DiagnosticsResult, indent: str = ""):
        f.write(f"{indent}Timing:\n")
        f.write(f"{indent}  DNS Lookup:       {result.timing.dns_lookup * 1000:.3f} ms\n")
        f.write(f"{indent}  TCP Connect:      {result.timing.tcp_connect * 1000:.3f} ms\n")
        if result.is_https:
            f.write(f"{indent}  TLS Handshake:    {result.timing.tls_handshake * 1000:.3f} ms\n")
        f.write(f"{indent}  TTFB:             {result.timing.time_to_first_byte * 1000:.3f} ms\n")
        f.write(f"{indent}  Download:         {result.timing.content_download * 1000:.3f} ms\n")
        f.write(f"{indent}  TOTAL:            {result.timing.total * 1000:.3f} ms\n\n")

        parsed_url = self._parse_url(result.url)
        f.write(f"{indent}Request:\n")
        f.write(f"{indent}  {result.method} {parsed_url['path']} HTTP/1.1\n")
        for key, value in result.request_headers.items():
            f.write(f"{indent}  {key}: {value}\n")
        f.write("\n")
        if result.request_body:
            preview = result.request_body[:200]
            f.write(f"{indent}  Body ({len(result.request_body)} bytes): {preview}\n")
            if len(result.request_body) > 200:
                f.write(f"{indent}  ... (truncated)\n")
            f.write("\n")

        f.write(f"{indent}Response:\n")
        f.write(f"{indent}  HTTP/1.1 {result.status_code} {result.status_text}\n")
        for key, value in list(result.response_headers.items())[:15]:
            f.write(f"{indent}  {key}: {value}\n")
        if len(result.response_headers) > 15:
            f.write(f"{indent}  ... ({len(result.response_headers) - 15} more headers)\n")
        f.write("\n")

        if result.error:
            f.write(f"{indent}Error: {result.error}\n")
            f.write("\n")

    def _parse_url(self, url: str) -> Dict[str, str]:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        return {
            "scheme": parsed.scheme,
            "host": parsed.hostname or "",
            "port": parsed.port,
            "path": path,
        }
