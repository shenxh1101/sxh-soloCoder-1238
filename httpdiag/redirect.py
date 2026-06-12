import urllib.parse
from typing import List, Dict, Optional
from dataclasses import dataclass, field

from .diagnostics import HttpDiagnostics, DiagnosticsResult


@dataclass
class RedirectStep:
    step: int
    from_url: str
    to_url: str
    status_code: int
    result: DiagnosticsResult


@dataclass
class RedirectChain:
    steps: List[RedirectStep] = field(default_factory=list)
    final_result: Optional[DiagnosticsResult] = None

    @property
    def total_redirects(self) -> int:
        return len(self.steps)

    @property
    def total_time(self) -> float:
        total = 0.0
        for step in self.steps:
            total += step.result.timing.total
        if self.final_result:
            total += self.final_result.timing.total
        return total


class RedirectTracker:
    def __init__(self, max_redirects: int = 10, timeout: int = 30):
        self.max_redirects = max_redirects
        self.timeout = timeout
        self.diagnostics = HttpDiagnostics(timeout=timeout)

    def follow(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
    ) -> RedirectChain:
        chain = RedirectChain()
        current_url = url
        current_method = method.upper()
        current_body = body
        current_headers = dict(headers) if headers else {}
        step_count = 0

        while step_count <= self.max_redirects:
            result = self.diagnostics.request(
                current_url,
                method=current_method,
                headers=current_headers,
                body=current_body,
            )

            if result.error:
                chain.final_result = result
                break

            if 300 <= result.status_code < 400:
                location = result.headers.get("Location", "")
                if not location:
                    chain.final_result = result
                    break

                next_url = urllib.parse.urljoin(current_url, location)

                step = RedirectStep(
                    step=step_count + 1,
                    from_url=current_url,
                    to_url=next_url,
                    status_code=result.status_code,
                    result=result,
                )
                chain.steps.append(step)

                if result.status_code in (303,):
                    current_method = "GET"
                    current_body = None

                current_url = next_url
                step_count += 1

                if step_count > self.max_redirects:
                    result.error = f"Too many redirects (max {self.max_redirects})"
                    chain.final_result = result
                    break
            else:
                chain.final_result = result
                break

        return chain
