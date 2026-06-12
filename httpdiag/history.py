import json
import os
import time
import statistics
from typing import Dict, Optional, List, Any, Tuple
from dataclasses import dataclass, field


DEFAULT_DATA_DIR = os.path.join(os.path.expanduser("~"), ".httpdiag")

DEFAULT_ANOMALY_THRESHOLD = {
    "time_slow_pct": 50.0,
    "time_fast_pct": 30.0,
    "failure_rate_pct": 5.0,
}


@dataclass
class HistoryEntry:
    id: str
    timestamp: str
    timestamp_unix: float
    url: str
    method: str
    profile_name: Optional[str]
    mode: str
    status_code: int
    total_time_ms: float
    ttfb_ms: float
    error: Optional[str]
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "timestamp_unix": self.timestamp_unix,
            "url": self.url,
            "method": self.method,
            "profile_name": self.profile_name,
            "mode": self.mode,
            "status_code": self.status_code,
            "total_time_ms": self.total_time_ms,
            "ttfb_ms": self.ttfb_ms,
            "error": self.error,
            "extra": self.extra,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HistoryEntry":
        return cls(
            id=data["id"],
            timestamp=data["timestamp"],
            timestamp_unix=data["timestamp_unix"],
            url=data["url"],
            method=data["method"],
            profile_name=data.get("profile_name"),
            mode=data.get("mode", "single"),
            status_code=data["status_code"],
            total_time_ms=data["total_time_ms"],
            ttfb_ms=data.get("ttfb_ms", 0),
            error=data.get("error"),
            extra=data.get("extra", {}),
        )


@dataclass
class Baseline:
    key: str
    key_type: str
    avg_total_ms: float
    avg_ttfb_ms: float
    p95_total_ms: float
    failure_rate: float
    status_codes: Dict[int, int]
    sample_count: int
    created_at: str
    threshold_time_slow_pct: float = 50.0
    threshold_time_fast_pct: float = 30.0
    threshold_failure_rate_pct: float = 5.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "key_type": self.key_type,
            "avg_total_ms": self.avg_total_ms,
            "avg_ttfb_ms": self.avg_ttfb_ms,
            "p95_total_ms": self.p95_total_ms,
            "failure_rate": self.failure_rate,
            "status_codes": self.status_codes,
            "sample_count": self.sample_count,
            "created_at": self.created_at,
            "threshold_time_slow_pct": self.threshold_time_slow_pct,
            "threshold_time_fast_pct": self.threshold_time_fast_pct,
            "threshold_failure_rate_pct": self.threshold_failure_rate_pct,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Baseline":
        return cls(
            key=data["key"],
            key_type=data["key_type"],
            avg_total_ms=data["avg_total_ms"],
            avg_ttfb_ms=data["avg_ttfb_ms"],
            p95_total_ms=data.get("p95_total_ms", data["avg_total_ms"]),
            failure_rate=data["failure_rate"],
            status_codes=data["status_codes"],
            sample_count=data["sample_count"],
            created_at=data["created_at"],
            threshold_time_slow_pct=data.get("threshold_time_slow_pct", 50.0),
            threshold_time_fast_pct=data.get("threshold_time_fast_pct", 30.0),
            threshold_failure_rate_pct=data.get("threshold_failure_rate_pct", 5.0),
        )


@dataclass
class AnomalyAlert:
    type: str
    severity: str
    message: str
    details: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "severity": self.severity,
            "message": self.message,
            "details": self.details,
        }


@dataclass
class TrendStats:
    url: str
    count: int
    success_count: int
    failure_count: int
    failure_rate: float
    avg_total_ms: float
    avg_ttfb_ms: float
    min_total_ms: float
    max_total_ms: float
    status_codes: Dict[int, int]
    timeline: List[Dict[str, Any]]
    baseline: Optional[Baseline] = None
    baseline_diff_pct: Optional[float] = None
    anomalies: List[AnomalyAlert] = field(default_factory=list)

    def format_table(self) -> str:
        lines = []
        lines.append(f"  URL:           {self.url}")
        lines.append(f"  请求次数:      {self.count}")
        lines.append(f"  成功:          {self.success_count}")
        lines.append(f"  失败:          {self.failure_count}")
        lines.append(f"  失败率:        {self.failure_rate:.1f}%")
        lines.append(f"  平均总耗时:    {self.avg_total_ms:.2f}ms")
        lines.append(f"  平均首字节:    {self.avg_ttfb_ms:.2f}ms")
        lines.append(f"  最快/最慢:     {self.min_total_ms:.2f}ms / {self.max_total_ms:.2f}ms")

        if self.baseline:
            lines.append("")
            lines.append(f"  基线对比:")
            lines.append(f"    基线平均:      {self.baseline.avg_total_ms:.2f}ms (样本数: {self.baseline.sample_count})")
            if self.baseline_diff_pct is not None:
                diff_symbol = "+" if self.baseline_diff_pct >= 0 else ""
                color_tag = ""
                if self.baseline_diff_pct > self.baseline.threshold_time_slow_pct:
                    color_tag = "[!] "
                elif self.baseline_diff_pct < -self.baseline.threshold_time_fast_pct:
                    color_tag = "[↓] "
                lines.append(f"    当前对比:      {diff_symbol}{self.baseline_diff_pct:.1f}% {color_tag}")
                lines.append(f"    基线创建:    {self.baseline.created_at}")

        if self.anomalies:
            lines.append("")
            lines.append(f"  异常提醒:")
            for a in self.anomalies:
                severity_mark = "⚠️" if a.severity == "warning" else "🔴"
                lines.append(f"    {severity_mark} [{a.severity.upper()}] {a.message}")

        lines.append("")
        lines.append(f"  状态码分布:")
        for code, cnt in sorted(self.status_codes.items()):
            pct = cnt / self.count * 100
            lines.append(f"    {code}: {cnt} 次 ({pct:.1f}%)")
        lines.append("")
        lines.append(f"  时间线 (最近 {len(self.timeline)} 次):")
        for i, item in enumerate(self.timeline, 1):
            status = f"{item['status_code']}" if not item.get("error") else "ERR"
            lines.append(
                f"    [{i:>3}] {item['timestamp']}  "
                f"{item['total_time_ms']:>8.2f}ms  {status}"
            )
        return "\n".join(lines)


class HistoryManager:
    def __init__(self, data_dir: str = DEFAULT_DATA_DIR):
        self.data_dir = data_dir
        self.history_dir = os.path.join(data_dir, "history")
        os.makedirs(self.history_dir, exist_ok=True)
        self._history_file = os.path.join(self.history_dir, "history.json")
        self._baselines_file = os.path.join(self.history_dir, "baselines.json")
        self._ensure_file()
        self._ensure_baselines_file()

    def _ensure_file(self):
        if not os.path.exists(self._history_file):
            with open(self._history_file, "w", encoding="utf-8") as f:
                json.dump([], f, ensure_ascii=False, indent=2)

    def _load_all(self) -> List[HistoryEntry]:
        self._ensure_file()
        try:
            with open(self._history_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            return [HistoryEntry.from_dict(d) for d in data]
        except (json.JSONDecodeError, FileNotFoundError):
            return []

    def _save_all(self, entries: List[HistoryEntry]):
        data = [e.to_dict() for e in entries]
        with open(self._history_file, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def add(
        self,
        url: str,
        method: str,
        status_code: int,
        total_time_ms: float,
        ttfb_ms: float = 0,
        error: Optional[str] = None,
        profile_name: Optional[str] = None,
        mode: str = "single",
        extra: Optional[Dict[str, Any]] = None,
    ) -> HistoryEntry:
        import uuid
        entries = self._load_all()
        now = time.time()
        entry = HistoryEntry(
            id=str(uuid.uuid4())[:8],
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            timestamp_unix=now,
            url=url,
            method=method.upper(),
            profile_name=profile_name,
            mode=mode,
            status_code=status_code,
            total_time_ms=round(total_time_ms, 3),
            ttfb_ms=round(ttfb_ms, 3),
            error=error,
            extra=extra or {},
        )
        entries.append(entry)
        if len(entries) > 5000:
            entries = entries[-5000:]
        self._save_all(entries)
        return entry

    def add_from_result(self, result, profile_name: Optional[str] = None, mode: str = "single",
                        extra: Optional[Dict[str, Any]] = None):
        return self.add(
            url=result.url,
            method=result.method,
            status_code=result.status_code,
            total_time_ms=result.timing.total * 1000,
            ttfb_ms=result.timing.time_to_first_byte * 1000,
            error=result.error,
            profile_name=profile_name,
            mode=mode,
            extra=extra,
        )

    def query(
        self,
        url: Optional[str] = None,
        profile_name: Optional[str] = None,
        mode: Optional[str] = None,
        limit: int = 20,
    ) -> List[HistoryEntry]:
        entries = self._load_all()
        if url:
            entries = [e for e in entries if url in e.url]
        if profile_name:
            entries = [e for e in entries if e.profile_name == profile_name]
        if mode:
            entries = [e for e in entries if e.mode == mode]
        entries = sorted(entries, key=lambda e: e.timestamp_unix, reverse=True)
        return entries[:limit]

    def get_trend(
        self,
        url: Optional[str] = None,
        profile_name: Optional[str] = None,
        limit: int = 30,
        check_anomalies: bool = True,
    ) -> TrendStats:
        entries = self.query(url=url, profile_name=profile_name, limit=limit)
        if not entries:
            return TrendStats(
                url=url or profile_name or "unknown",
                count=0,
                success_count=0,
                failure_count=0,
                failure_rate=0,
                avg_total_ms=0,
                avg_ttfb_ms=0,
                min_total_ms=0,
                max_total_ms=0,
                status_codes={},
                timeline=[],
            )

        success_entries = [e for e in entries if e.status_code > 0 and not e.error]
        failure_entries = [e for e in entries if e.status_code == 0 or e.error]
        total_times = [e.total_time_ms for e in success_entries]
        ttfbs = [e.ttfb_ms for e in success_entries if e.ttfb_ms > 0]

        status_codes: Dict[int, int] = {}
        for e in entries:
            if e.status_code > 0:
                status_codes[e.status_code] = status_codes.get(e.status_code, 0) + 1

        timeline = []
        for e in reversed(entries):
            timeline.append({
                "timestamp": e.timestamp,
                "total_time_ms": e.total_time_ms,
                "ttfb_ms": e.ttfb_ms,
                "status_code": e.status_code,
                "error": e.error,
            })

        avg_total = statistics.mean(total_times) if total_times else 0
        failure_rate = len(failure_entries) / len(entries) * 100 if entries else 0

        trend = TrendStats(
            url=url or profile_name or entries[0].url,
            count=len(entries),
            success_count=len(success_entries),
            failure_count=len(failure_entries),
            failure_rate=failure_rate,
            avg_total_ms=avg_total,
            avg_ttfb_ms=statistics.mean(ttfbs) if ttfbs else 0,
            min_total_ms=min(total_times) if total_times else 0,
            max_total_ms=max(total_times) if total_times else 0,
            status_codes=status_codes,
            timeline=timeline,
        )

        baseline_key = profile_name or url
        baseline_key_type = "profile" if profile_name else "url"
        baseline = self.get_baseline(baseline_key, baseline_key_type) if baseline_key else None

        if baseline:
            trend.baseline = baseline
            if baseline.avg_total_ms > 0:
                trend.baseline_diff_pct = ((avg_total - baseline.avg_total_ms) / baseline.avg_total_ms) * 100

            if check_anomalies:
                trend.anomalies = self.detect_anomalies(trend, baseline)

        return trend

    def detect_anomalies(self, trend: TrendStats, baseline: Baseline) -> List[AnomalyAlert]:
        anomalies = []

        if trend.baseline_diff_pct is not None:
            if trend.baseline_diff_pct > baseline.threshold_time_slow_pct:
                anomalies.append(AnomalyAlert(
                    type="performance",
                    severity="warning",
                    message=f"响应耗时比基线慢 {trend.baseline_diff_pct:.1f}%",
                    details={
                        "baseline_ms": baseline.avg_total_ms,
                        "current_ms": trend.avg_total_ms,
                        "diff_pct": trend.baseline_diff_pct,
                        "threshold_pct": baseline.threshold_time_slow_pct,
                    }
                ))

        if trend.failure_rate > baseline.threshold_failure_rate_pct and baseline.failure_rate < baseline.threshold_failure_rate_pct:
            anomalies.append(AnomalyAlert(
                type="failure_rate",
                severity="error",
                message=f"失败率从 {baseline.failure_rate:.1f}% 上升到 {trend.failure_rate:.1f}%",
                details={
                    "baseline_failure_rate": baseline.failure_rate,
                    "current_failure_rate": trend.failure_rate,
                    "threshold_pct": baseline.threshold_failure_rate_pct,
                }
            ))

        if baseline.status_codes and trend.status_codes:
            baseline_main_codes = set(baseline.status_codes.keys())
            current_main_codes = set(trend.status_codes.keys())
            new_error_codes = current_main_codes - baseline_main_codes
            error_codes = [c for c in new_error_codes if c >= 400]
            if error_codes:
                anomalies.append(AnomalyAlert(
                    type="status_code",
                    severity="error",
                    message=f"出现新的错误状态码: {', '.join(map(str, sorted(error_codes)))}",
                    details={
                        "baseline_codes": sorted(baseline.status_codes.keys()),
                        "current_codes": sorted(trend.status_codes.keys()),
                        "new_error_codes": sorted(error_codes),
                    }
                ))

        return anomalies

    def _ensure_baselines_file(self):
        if not os.path.exists(self._baselines_file):
            with open(self._baselines_file, "w", encoding="utf-8") as f:
                json.dump({}, f, ensure_ascii=False, indent=2)

    def _load_baselines(self) -> Dict[str, Baseline]:
        self._ensure_baselines_file()
        try:
            with open(self._baselines_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            return {k: Baseline.from_dict(v) for k, v in data.items()}
        except (json.JSONDecodeError, FileNotFoundError):
            return {}

    def _save_baselines(self, baselines: Dict[str, Baseline]):
        data = {k: v.to_dict() for k, v in baselines.items()}
        with open(self._baselines_file, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def _get_baseline_key(self, key: str, key_type: str) -> str:
        return f"{key_type}:{key}"

    def set_baseline(
        self,
        key: str,
        key_type: str,
        limit: int = 30,
        thresholds: Optional[Dict[str, float]] = None,
    ) -> Optional[Baseline]:
        if key_type == "url":
            trend = self.get_trend(url=key, limit=limit, check_anomalies=False)
        elif key_type == "profile":
            trend = self.get_trend(profile_name=key, limit=limit, check_anomalies=False)
        else:
            raise ValueError(f"Unknown key_type: {key_type}")

        if trend.count == 0:
            return None

        success_entries = [e for e in self.query(url=key if key_type == "url" else None,
                                                  profile_name=key if key_type == "profile" else None,
                                                  limit=limit)
                          if e.status_code > 0 and not e.error]
        total_times = sorted([e.total_time_ms for e in success_entries])
        p95_idx = int(len(total_times) * 0.95) if total_times else 0
        p95_total_ms = total_times[p95_idx] if total_times else trend.avg_total_ms

        th = thresholds or DEFAULT_ANOMALY_THRESHOLD
        baseline = Baseline(
            key=key,
            key_type=key_type,
            avg_total_ms=trend.avg_total_ms,
            avg_ttfb_ms=trend.avg_ttfb_ms,
            p95_total_ms=p95_total_ms,
            failure_rate=trend.failure_rate,
            status_codes=trend.status_codes,
            sample_count=trend.count,
            created_at=time.strftime("%Y-%m-%d %H:%M:%S"),
            threshold_time_slow_pct=th.get("time_slow_pct", 50.0),
            threshold_time_fast_pct=th.get("time_fast_pct", 30.0),
            threshold_failure_rate_pct=th.get("failure_rate_pct", 5.0),
        )

        baselines = self._load_baselines()
        storage_key = self._get_baseline_key(key, key_type)
        baselines[storage_key] = baseline
        self._save_baselines(baselines)
        return baseline

    def get_baseline(self, key: str, key_type: str) -> Optional[Baseline]:
        baselines = self._load_baselines()
        storage_key = self._get_baseline_key(key, key_type)
        return baselines.get(storage_key)

    def list_baselines(self) -> List[Baseline]:
        baselines = self._load_baselines()
        return sorted(baselines.values(), key=lambda b: (b.key_type, b.key))

    def clear_baseline(self, key: str, key_type: str) -> bool:
        baselines = self._load_baselines()
        storage_key = self._get_baseline_key(key, key_type)
        if storage_key in baselines:
            del baselines[storage_key]
            self._save_baselines(baselines)
            return True
        return False

    def clear_all_baselines(self) -> int:
        count = len(self._load_baselines())
        self._save_baselines({})
        return count

    def list_profiles(self) -> List[str]:
        entries = self._load_all()
        profiles = set()
        for e in entries:
            if e.profile_name:
                profiles.add(e.profile_name)
        return sorted(profiles)

    def clear(self) -> int:
        count = len(self._load_all())
        self._save_all([])
        return count
