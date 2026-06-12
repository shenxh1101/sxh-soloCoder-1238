import json
import os
import time
import statistics
from typing import Dict, Optional, List, Any
from dataclasses import dataclass, field


DEFAULT_DATA_DIR = os.path.join(os.path.expanduser("~"), ".httpdiag")


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
        self._ensure_file()

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

        return TrendStats(
            url=url or profile_name or entries[0].url,
            count=len(entries),
            success_count=len(success_entries),
            failure_count=len(failure_entries),
            failure_rate=len(failure_entries) / len(entries) * 100 if entries else 0,
            avg_total_ms=statistics.mean(total_times) if total_times else 0,
            avg_ttfb_ms=statistics.mean(ttfbs) if ttfbs else 0,
            min_total_ms=min(total_times) if total_times else 0,
            max_total_ms=max(total_times) if total_times else 0,
            status_codes=status_codes,
            timeline=timeline,
        )

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
