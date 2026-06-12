import json
import time
import statistics
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field

from .diagnostics import HttpDiagnostics, DiagnosticsResult, TimingInfo
from .utils import format_duration


@dataclass
class TimingStats:
    min: float = 0.0
    max: float = 0.0
    avg: float = 0.0
    median: float = 0.0
    stdev: float = 0.0
    p90: float = 0.0
    p95: float = 0.0
    p99: float = 0.0

    def to_dict(self) -> Dict[str, float]:
        return {
            "min_ms": round(self.min * 1000, 3),
            "max_ms": round(self.max * 1000, 3),
            "avg_ms": round(self.avg * 1000, 3),
            "median_ms": round(self.median * 1000, 3),
            "stdev_ms": round(self.stdev * 1000, 3),
            "p90_ms": round(self.p90 * 1000, 3),
            "p95_ms": round(self.p95 * 1000, 3),
            "p99_ms": round(self.p99 * 1000, 3),
        }


def _calc_stats(values: List[float]) -> TimingStats:
    if not values:
        return TimingStats()
    sorted_vals = sorted(values)
    n = len(sorted_vals)

    def percentile(p: float) -> float:
        k = (n - 1) * p
        f = int(k)
        c = min(f + 1, n - 1)
        if f == c:
            return sorted_vals[f]
        return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)

    return TimingStats(
        min=min(values),
        max=max(values),
        avg=statistics.mean(values),
        median=statistics.median(values),
        stdev=statistics.stdev(values) if n > 1 else 0.0,
        p90=percentile(0.90),
        p95=percentile(0.95),
        p99=percentile(0.99),
    )


@dataclass
class BatchResult:
    url: str
    method: str
    count: int
    success_count: int
    failure_count: int
    results: List[DiagnosticsResult] = field(default_factory=list)
    timing_breakdown: Dict[str, TimingStats] = field(default_factory=dict)
    status_codes: Dict[int, int] = field(default_factory=dict)
    total_time: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "count": self.count,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "total_time_ms": round(self.total_time * 1000, 3),
            "status_codes": self.status_codes,
            "timing_breakdown": {k: v.to_dict() for k, v in self.timing_breakdown.items()},
            "results": [r.to_dict() for r in self.results],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    def format_table(self, show_details: bool = True) -> str:
        lines = []
        lines.append(f"  URL:          {self.url}")
        lines.append(f"  方法:          {self.method}")
        lines.append(f"  请求次数:      {self.count}")
        lines.append(f"  成功:          {self.success_count}")
        lines.append(f"  失败:          {self.failure_count}")
        lines.append(f"  总耗时:        {format_duration(self.total_time)}")
        lines.append("")

        if self.status_codes:
            lines.append("  状态码分布:")
            for code, cnt in sorted(self.status_codes.items()):
                pct = cnt / self.count * 100
                lines.append(f"    {code}: {cnt} 次 ({pct:.1f}%)")
            lines.append("")

        lines.append("  各阶段耗时统计 (单位: ms):")
        lines.append(f"    {'阶段':<20} {'min':>10} {'max':>10} {'avg':>10} {'median':>10} {'p95':>10} {'p99':>10}")
        lines.append(f"    {'-'*20} {'-'*10} {'-'*10} {'-'*10} {'-'*10} {'-'*10} {'-'*10}")

        timing_labels = [
            ("dns_lookup", "DNS解析"),
            ("tcp_connect", "TCP连接"),
            ("tls_handshake", "TLS握手"),
            ("time_to_first_byte", "首字节时间"),
            ("content_download", "内容下载"),
            ("total", "总耗时"),
        ]

        for key, label in timing_labels:
            if key in self.timing_breakdown:
                s = self.timing_breakdown[key]
                lines.append(
                    f"    {label:<20} "
                    f"{s.min*1000:>10.2f} "
                    f"{s.max*1000:>10.2f} "
                    f"{s.avg*1000:>10.2f} "
                    f"{s.median*1000:>10.2f} "
                    f"{s.p95*1000:>10.2f} "
                    f"{s.p99*1000:>10.2f}"
                )

        if show_details and self.results:
            lines.append("")
            lines.append("  各次请求详情:")
            for i, r in enumerate(self.results, 1):
                status = f"{r.status_code}" if not r.error else f"ERROR: {r.error}"
                lines.append(
                    f"    [{i:>3}] {r.timing.total*1000:>8.2f}ms  {status}"
                )

        return "\n".join(lines)


class BatchTester:
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.diagnostics = HttpDiagnostics(timeout=timeout)

    def run(
        self,
        url: str,
        count: int = 10,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        delay: float = 0.0,
        follow_redirects: bool = False,
        on_progress=None,
    ) -> BatchResult:
        from .redirect import RedirectTracker

        method = method.upper()
        results: List[DiagnosticsResult] = []
        total_start = time.time()

        tracker = None
        if follow_redirects:
            tracker = RedirectTracker(timeout=self.timeout)

        for i in range(count):
            if follow_redirects and tracker:
                chain = tracker.follow(url, method=method, headers=headers, body=body)
                if chain.final_result:
                    results.append(chain.final_result)
                else:
                    r = DiagnosticsResult(url=url, method=method)
                    r.error = "No final result"
                    results.append(r)
            else:
                r = self.diagnostics.request(url, method=method, headers=headers, body=body)
                results.append(r)

            if on_progress:
                on_progress(i + 1, count, results[-1])

            if delay > 0 and i < count - 1:
                time.sleep(delay)

        total_time = time.time() - total_start

        success_count = sum(1 for r in results if not r.error and r.status_code > 0)
        failure_count = count - success_count

        status_codes: Dict[int, int] = {}
        for r in results:
            if r.status_code > 0:
                status_codes[r.status_code] = status_codes.get(r.status_code, 0) + 1

        timing_fields = [
            "dns_lookup",
            "tcp_connect",
            "tls_handshake",
            "time_to_first_byte",
            "content_download",
            "total",
        ]

        timing_breakdown: Dict[str, TimingStats] = {}
        for field_name in timing_fields:
            values = []
            for r in results:
                if not r.error:
                    values.append(getattr(r.timing, field_name))
            if values:
                timing_breakdown[field_name] = _calc_stats(values)

        return BatchResult(
            url=url,
            method=method,
            count=count,
            success_count=success_count,
            failure_count=failure_count,
            results=results,
            timing_breakdown=timing_breakdown,
            status_codes=status_codes,
            total_time=total_time,
        )
