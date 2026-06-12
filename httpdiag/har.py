import json
import time
from typing import List, Dict, Any, Optional
import urllib.parse

from .diagnostics import DiagnosticsResult
from .redirect import RedirectChain
from .compare import CompareResult
from .batch import BatchResult


class HarExporter:
    CREATOR = {
        "name": "httpdiag",
        "version": "1.1.0",
        "comment": "HTTP Diagnostics Tool",
    }

    @classmethod
    def _result_to_entry(cls, result: DiagnosticsResult, started_ts: Optional[float] = None) -> Dict[str, Any]:
        if started_ts is None:
            started_ts = time.time() * 1000

        parsed = urllib.parse.urlparse(result.url)
        query_string = []
        if parsed.query:
            for param in parsed.query.split("&"):
                if "=" in param:
                    k, v = param.split("=", 1)
                    query_string.append({"name": urllib.parse.unquote(k), "value": urllib.parse.unquote(v)})
                else:
                    query_string.append({"name": urllib.parse.unquote(param), "value": ""})

        request_headers = [
            {"name": k, "value": v} for k, v in result.request_headers.items()
        ]

        response_headers = [
            {"name": k, "value": v} for k, v in result.response_headers.items()
        ]

        post_data = None
        if result.request_body:
            post_data = {
                "mimeType": result.request_headers.get("Content-Type", "text/plain"),
                "text": result.request_body,
            }

        content = {
            "size": result.response_body_size,
            "mimeType": result.response_headers.get("Content-Type", "text/plain"),
            "text": result.response_body,
        }

        timings = {
            "dns": round(result.timing.dns_lookup * 1000, 3),
            "connect": round(result.timing.tcp_connect * 1000, 3),
            "ssl": round(result.timing.tls_handshake * 1000, 3) if result.is_https else -1,
            "send": round(result.timing.request_send * 1000, 3),
            "wait": round(
                (result.timing.time_to_first_byte - result.timing.dns_lookup - result.timing.tcp_connect
                 - result.timing.tls_handshake - result.timing.request_send) * 1000, 3
            ),
            "receive": round(result.timing.content_download * 1000, 3),
            "_blocked": 0,
        }

        entry = {
            "startedDateTime": time.strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(started_ts % 1000):03d}" + time.strftime("%z"),
            "time": round(result.timing.total * 1000, 3),
            "request": {
                "method": result.method,
                "url": result.url,
                "httpVersion": "HTTP/1.1",
                "cookies": [],
                "headers": request_headers,
                "queryString": query_string,
                "headersSize": -1,
                "bodySize": len(result.request_body.encode("utf-8")) if result.request_body else 0,
            },
            "response": {
                "status": result.status_code,
                "statusText": result.status_text,
                "httpVersion": "HTTP/1.1",
                "cookies": [],
                "headers": response_headers,
                "content": content,
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": result.response_body_size,
            },
            "cache": {},
            "timings": timings,
            "serverIPAddress": result.ip_address,
            "connection": "",
        }

        if post_data:
            entry["request"]["postData"] = post_data

        if result.error:
            entry["_error"] = result.error

        return entry

    @classmethod
    def from_single_result(cls, result: DiagnosticsResult) -> str:
        entries = [cls._result_to_entry(result)]
        har = cls._build_har(entries, result.timing.total)
        return json.dumps(har, ensure_ascii=False, indent=2)

    @classmethod
    def from_redirect_chain(cls, chain: RedirectChain) -> str:
        entries = []
        total_time = 0.0

        for step in chain.steps:
            entries.append(cls._result_to_entry(step.result))
            total_time += step.result.timing.total

        if chain.final_result:
            entries.append(cls._result_to_entry(chain.final_result))
            total_time += chain.final_result.timing.total

        har = cls._build_har(entries, total_time)
        return json.dumps(har, ensure_ascii=False, indent=2)

    @classmethod
    def from_compare_result(cls, compare: CompareResult) -> str:
        entries = []
        total_time = 0.0

        for item in compare.items:
            entries.append(cls._result_to_entry(item.result))
            total_time += item.result.timing.total

        har = cls._build_har(entries, total_time)
        return json.dumps(har, ensure_ascii=False, indent=2)

    @classmethod
    def from_batch_result(cls, batch: BatchResult) -> str:
        entries = []
        for r in batch.results:
            entries.append(cls._result_to_entry(r))

        har = cls._build_har(entries, batch.total_time)
        return json.dumps(har, ensure_ascii=False, indent=2)

    @classmethod
    def _build_har(cls, entries: List[Dict[str, Any]], total_time: float) -> Dict[str, Any]:
        return {
            "log": {
                "version": "1.2",
                "creator": cls.CREATOR,
                "pages": [
                    {
                        "startedDateTime": entries[0]["startedDateTime"] if entries else "",
                        "id": "page_1",
                        "title": "httpdiag capture",
                        "pageTimings": {
                            "onContentLoad": -1,
                            "onLoad": round(total_time * 1000, 3),
                        },
                    }
                ],
                "entries": entries,
            }
        }
