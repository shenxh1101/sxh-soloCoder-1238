from typing import List, Optional, Dict
from dataclasses import dataclass, field

from .diagnostics import HttpDiagnostics, DiagnosticsResult
from .utils import format_duration


@dataclass
class CompareItem:
    name: str
    url: str
    result: DiagnosticsResult


@dataclass
class CompareResult:
    items: List[CompareItem] = field(default_factory=list)

    def get_diff(self, index_a: int = 0, index_b: int = 1) -> Dict[str, float]:
        if len(self.items) < 2:
            return {}

        a = self.items[index_a].result
        b = self.items[index_b].result

        return {
            "dns_lookup": b.timing.dns_lookup - a.timing.dns_lookup,
            "tcp_connect": b.timing.tcp_connect - a.timing.tcp_connect,
            "tls_handshake": b.timing.tls_handshake - a.timing.tls_handshake,
            "time_to_first_byte": b.timing.time_to_first_byte - a.timing.time_to_first_byte,
            "content_download": b.timing.content_download - a.timing.content_download,
            "total": b.timing.total - a.timing.total,
        }

    def format_table(self) -> str:
        if not self.items:
            return "No items to compare."

        timing_fields = [
            ("DNS Lookup", "dns_lookup"),
            ("TCP Connect", "tcp_connect"),
            ("TLS Handshake", "tls_handshake"),
            ("TTFB", "time_to_first_byte"),
            ("Content Download", "content_download"),
            ("Total Time", "total"),
        ]

        col_width = 25
        name_width = max(len(item.name) for item in self.items)
        name_width = max(name_width, 10)

        header = f"{'Metric':<20}"
        for item in self.items:
            header += f" | {item.name:^{name_width}}"
        if len(self.items) >= 2:
            header += f" | {'Diff (B-A)':^{name_width}}"
        header += "\n"
        header += "-" * len(header) + "\n"

        rows = []
        for metric_name, field_name in timing_fields:
            row = f"{metric_name:<20}"
            values = []
            for item in self.items:
                timing = item.result.timing
                value = getattr(timing, field_name)
                values.append(value)
                row += f" | {format_duration(value):>{name_width}}"

            if len(values) >= 2:
                diff = values[1] - values[0]
                pct = (diff / values[0] * 100) if values[0] != 0 else 0
                diff_str = f"{diff*1000:+.2f}ms ({pct:+.1f}%)"
                row += f" | {diff_str:>{name_width}}"

            rows.append(row)

        extra_rows = []
        status_row = f"{'Status Code':<20}"
        for item in self.items:
            status_row += f" | {str(item.result.status_code):>{name_width}}"
        extra_rows.append(status_row)

        body_row = f"{'Body Size':<20}"
        for item in self.items:
            size = len(item.result.body)
            body_row += f" | {f'{size} bytes':>{name_width}}"
        extra_rows.append(body_row)

        ip_row = f"{'IP Address':<20}"
        for item in self.items:
            ip_row += f" | {item.result.ip_address:>{name_width}}"
        extra_rows.append(ip_row)

        all_rows = [header] + rows + [""] + extra_rows

        return "\n".join(all_rows)


class CompareMode:
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.diagnostics = HttpDiagnostics(timeout=timeout)

    def compare_urls(
        self,
        urls: List[str],
        names: Optional[List[str]] = None,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
    ) -> CompareResult:
        result = CompareResult()

        if names is None:
            names = [f"URL {i+1}" for i in range(len(urls))]

        for i, url in enumerate(urls):
            name = names[i] if i < len(names) else f"URL {i+1}"
            diag_result = self.diagnostics.request(
                url,
                method=method,
                headers=headers,
                body=body,
            )
            result.items.append(CompareItem(name=name, url=url, result=diag_result))

        return result
