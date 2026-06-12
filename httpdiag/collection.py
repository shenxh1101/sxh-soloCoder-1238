import json
import os
import re
import time
from typing import Dict, Optional, List, Any, Tuple
from dataclasses import dataclass, field

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

from .diagnostics import HttpDiagnostics, DiagnosticsResult
from .redirect import RedirectTracker


class VariableExtractor:
    @staticmethod
    def extract_jsonpath(response_body: str, expr: str) -> Optional[str]:
        try:
            import jsonpath_ng
            data = json.loads(response_body)
            jsonpath_expr = jsonpath_ng.parse(expr)
            matches = [m.value for m in jsonpath_expr.find(data)]
            if matches:
                return str(matches[0])
        except Exception:
            pass
        return None

    @staticmethod
    def extract_regex(response_body: str, pattern: str) -> Optional[str]:
        try:
            match = re.search(pattern, response_body)
            if match:
                if match.groups():
                    return match.group(1)
                return match.group(0)
        except Exception:
            pass
        return None

    @staticmethod
    def extract(response_body: str, extract_config: Dict[str, str]) -> Optional[str]:
        if "jsonpath" in extract_config:
            return VariableExtractor.extract_jsonpath(response_body, extract_config["jsonpath"])
        elif "regex" in extract_config:
            return VariableExtractor.extract_regex(response_body, extract_config["regex"])
        elif "header" in extract_config:
            return None
        return None

    @staticmethod
    def extract_from_result(result: DiagnosticsResult, extract_config: Dict[str, Any]) -> Optional[str]:
        if "header" in extract_config:
            header_name = extract_config["header"]
            for k, v in result.response_headers.items():
                if k.lower() == header_name.lower():
                    return v
            return None

        response_body = result.response_body or result.response_body_preview or ""
        if not response_body and result.response_body_preview:
            response_body = result.response_body_preview

        return VariableExtractor.extract(response_body, extract_config)


@dataclass
class CollectionStep:
    name: str
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    timeout: int = 30
    follow_redirects: bool = True
    extract: Dict[str, Dict[str, str]] = field(default_factory=dict)
    skip_on_failure: bool = False

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CollectionStep":
        return cls(
            name=data.get("name", data.get("url", "unnamed")),
            method=data.get("method", "GET").upper(),
            url=data["url"],
            headers=data.get("headers", {}),
            body=data.get("body", ""),
            timeout=data.get("timeout", 30),
            follow_redirects=data.get("follow_redirects", True),
            extract=data.get("extract", {}),
            skip_on_failure=data.get("skip_on_failure", False),
        )


@dataclass
class CollectionStepResult:
    step: CollectionStep
    result: Optional[DiagnosticsResult]
    success: bool
    error: Optional[str]
    duration_ms: float
    actual_url: str = ""
    extracted_variables: Dict[str, str] = field(default_factory=dict)
    skipped: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.step.name,
            "url": self.actual_url or self.step.url,
            "url_template": self.step.url,
            "method": self.step.method,
            "success": self.success,
            "skipped": self.skipped,
            "error": self.error,
            "duration_ms": round(self.duration_ms, 3),
            "status_code": self.result.status_code if self.result else 0,
            "extracted_variables": self.extracted_variables,
        }


@dataclass
class CollectionResult:
    name: str
    steps: List[CollectionStepResult]
    total_duration_ms: float
    success_count: int
    failure_count: int
    skipped_count: int
    variables: Dict[str, str] = field(default_factory=dict)

    @property
    def success(self) -> bool:
        return self.failure_count == 0

    @property
    def success_rate(self) -> float:
        total = len(self.steps)
        return (self.success_count / total * 100) if total > 0 else 0

    def format_table(self) -> str:
        lines = []
        lines.append(f"  集合名称:    {self.name}")
        lines.append(f"  总耗时:      {self.total_duration_ms:.2f}ms")
        lines.append(f"  步骤总数:    {len(self.steps)}")
        lines.append(f"  成功:        {self.success_count}")
        lines.append(f"  失败:        {self.failure_count}")
        lines.append(f"  跳过:        {self.skipped_count}")
        lines.append(f"  成功率:      {self.success_rate:.1f}%")
        lines.append("")
        lines.append(f"  步骤详情:")
        lines.append(f"  {'#':>3} {'状态':<6} {'耗时':>10} {'名称':<30} URL")
        lines.append(f"  {'─' * 78}")
        for i, sr in enumerate(self.steps, 1):
            if sr.skipped:
                status = "SKIP"
                status_color = ""
            elif sr.success:
                status = "OK"
                status_color = ""
            else:
                status = "FAIL"
                status_color = ""
            display_url = sr.actual_url or sr.step.url
            url_preview = display_url[:50] + ("..." if len(display_url) > 50 else "")
            lines.append(
                f"  {i:>3} {status:<6} {sr.duration_ms:>9.2f}ms {sr.step.name[:28]:<28} {url_preview}"
            )
            if not sr.success and sr.error:
                lines.append(f"       错误: {sr.error}")
            if sr.extracted_variables:
                for k, v in sr.extracted_variables.items():
                    v_preview = v[:40] + ("..." if len(v) > 40 else "")
                    lines.append(f"       ↳ {k} = {v_preview}")
        if self.variables:
            lines.append("")
            lines.append(f"  提取的变量:")
            for k, v in self.variables.items():
                v_preview = v[:60] + ("..." if len(v) > 60 else "")
                lines.append(f"    {k} = {v_preview}")
        return "\n".join(lines)

    def to_json(self) -> str:
        data = {
            "name": self.name,
            "total_duration_ms": round(self.total_duration_ms, 3),
            "success": self.success,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "skipped_count": self.skipped_count,
            "success_rate_pct": round(self.success_rate, 2),
            "variables": self.variables,
            "steps": [sr.to_dict() for sr in self.steps],
        }
        return json.dumps(data, ensure_ascii=False, indent=2)


class CollectionRunner:
    def __init__(self, timeout: int = 30, max_redirects: int = 10):
        self.default_timeout = timeout
        self.max_redirects = max_redirects

    @staticmethod
    def load_collection(filepath: str) -> Dict[str, Any]:
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Collection file not found: {filepath}")

        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        if filepath.endswith((".yaml", ".yml")):
            if not HAS_YAML:
                raise ImportError("PyYAML is required for YAML files. Install with: pip install pyyaml")
            return yaml.safe_load(content)
        else:
            return json.loads(content)

    @staticmethod
    def substitute_variables(value: str, variables: Dict[str, str]) -> str:
        if not value or not isinstance(value, str):
            return value

        def replacer(match):
            var_name = match.group(1)
            return variables.get(var_name, match.group(0))

        return re.sub(r"\{\{\s*(\w+)\s*\}\}", replacer, value)

    def _substitute_step(self, step: CollectionStep, variables: Dict[str, str]) -> CollectionStep:
        substituted_headers = {}
        for k, v in step.headers.items():
            substituted_headers[k] = self.substitute_variables(v, variables)

        return CollectionStep(
            name=step.name,
            method=step.method,
            url=self.substitute_variables(step.url, variables),
            headers=substituted_headers,
            body=self.substitute_variables(step.body, variables),
            timeout=step.timeout,
            follow_redirects=step.follow_redirects,
            extract=step.extract,
            skip_on_failure=step.skip_on_failure,
        )

    def run(self, collection_config: Dict[str, Any],
            base_headers: Optional[Dict[str, str]] = None,
            initial_variables: Optional[Dict[str, str]] = None) -> CollectionResult:
        name = collection_config.get("name", "unnamed")
        steps_data = collection_config.get("steps", [])
        variables = dict(initial_variables or {})
        step_results: List[CollectionStepResult] = []
        total_start = time.time()

        for step_data in steps_data:
            step = CollectionStep.from_dict(step_data)
            if base_headers:
                for k, v in base_headers.items():
                    if k not in step.headers:
                        step.headers[k] = v

            step = self._substitute_step(step, variables)

            previous_failed = any(not sr.success and not sr.step.skip_on_failure for sr in step_results)
            if previous_failed and not step.skip_on_failure:
                step_results.append(CollectionStepResult(
                    step=step,
                    result=None,
                    success=False,
                    error="Previous step failed",
                    duration_ms=0,
                    skipped=True,
                ))
                continue

            start_time = time.time()
            result = None
            error = None
            success = False
            extracted: Dict[str, str] = {}

            try:
                timeout = step.timeout or self.default_timeout
                if step.follow_redirects:
                    tracker = RedirectTracker(max_redirects=self.max_redirects, timeout=timeout)
                    chain = tracker.follow(step.url, method=step.method,
                                           headers=step.headers, body=step.body)
                    result = chain.final_result
                    if result and not result.error and result.status_code < 400:
                        success = True
                        error = None
                    else:
                        error = result.error if result and result.error else f"HTTP {result.status_code if result else 'unknown'}"
                else:
                    diag = HttpDiagnostics(timeout=timeout)
                    result = diag.request(step.url, method=step.method,
                                          headers=step.headers, body=step.body)
                    if not result.error and result.status_code < 400:
                        success = True
                        error = None
                    else:
                        error = result.error if result.error else f"HTTP {result.status_code}"
            except Exception as e:
                error = str(e)
                success = False

            duration_ms = (time.time() - start_time) * 1000

            if success and result and step.extract:
                for var_name, extract_config in step.extract.items():
                    value = VariableExtractor.extract_from_result(result, extract_config)
                    if value is not None:
                        extracted[var_name] = value
                        variables[var_name] = value

            step_results.append(CollectionStepResult(
                step=step,
                result=result,
                success=success,
                error=error,
                duration_ms=duration_ms,
                actual_url=result.url if result else step.url,
                extracted_variables=extracted,
            ))

            if not success and not step.skip_on_failure:
                break

        total_duration_ms = (time.time() - total_start) * 1000
        success_count = sum(1 for sr in step_results if sr.success)
        failure_count = sum(1 for sr in step_results if not sr.success and not sr.skipped)
        skipped_count = sum(1 for sr in step_results if sr.skipped)

        return CollectionResult(
            name=name,
            steps=step_results,
            total_duration_ms=total_duration_ms,
            success_count=success_count,
            failure_count=failure_count,
            skipped_count=skipped_count,
            variables=variables,
        )

    def run_from_file(self, filepath: str,
                      base_headers: Optional[Dict[str, str]] = None,
                      initial_variables: Optional[Dict[str, str]] = None) -> CollectionResult:
        collection_config = self.load_collection(filepath)
        return self.run(collection_config, base_headers=base_headers,
                        initial_variables=initial_variables)
