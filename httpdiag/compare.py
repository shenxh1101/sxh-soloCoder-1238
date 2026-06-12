import json
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
import statistics

from .diagnostics import HttpDiagnostics, DiagnosticsResult
from .utils import format_duration


@dataclass
class CompareItem:
    name: str
    url: str
    result: DiagnosticsResult

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "url": self.url,
            "result": self.result.to_dict(),
        }


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

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "items": [item.to_dict() for item in self.items],
        }
        if len(self.items) >= 2:
            diff = self.get_diff()
            data["diff"] = {
                "dns_lookup_ms": round(diff["dns_lookup"] * 1000, 3),
                "tcp_connect_ms": round(diff["tcp_connect"] * 1000, 3),
                "tls_handshake_ms": round(diff["tls_handshake"] * 1000, 3),
                "time_to_first_byte_ms": round(diff["time_to_first_byte"] * 1000, 3),
                "content_download_ms": round(diff["content_download"] * 1000, 3),
                "total_ms": round(diff["total"] * 1000, 3),
            }
            a_total = self.items[0].result.timing.total
            if a_total > 0:
                data["diff_pct"] = {
                    "dns_lookup_pct": round(diff["dns_lookup"] / self.items[0].result.timing.dns_lookup * 100, 2) if self.items[0].result.timing.dns_lookup > 0 else 0,
                    "tcp_connect_pct": round(diff["tcp_connect"] / self.items[0].result.timing.tcp_connect * 100, 2) if self.items[0].result.timing.tcp_connect > 0 else 0,
                    "tls_handshake_pct": round(diff["tls_handshake"] / self.items[0].result.timing.tls_handshake * 100, 2) if self.items[0].result.timing.tls_handshake > 0 else 0,
                    "time_to_first_byte_pct": round(diff["time_to_first_byte"] / self.items[0].result.timing.time_to_first_byte * 100, 2) if self.items[0].result.timing.time_to_first_byte > 0 else 0,
                    "content_download_pct": round(diff["content_download"] / self.items[0].result.timing.content_download * 100, 2) if self.items[0].result.timing.content_download > 0 else 0,
                    "total_pct": round(diff["total"] / a_total * 100, 2),
                }
        return data

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

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
            size = item.result.response_body_size
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
