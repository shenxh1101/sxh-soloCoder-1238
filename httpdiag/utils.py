import os
from typing import Dict, Optional


def load_headers_from_file(file_path: str) -> Dict[str, str]:
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Headers file not found: {file_path}")

    headers = {}
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()
    return headers


def format_duration(seconds: float) -> str:
    if seconds >= 1.0:
        return f"{seconds:.3f}s"
    elif seconds >= 0.001:
        return f"{seconds * 1000:.2f}ms"
    else:
        return f"{seconds * 1000000:.2f}μs"


def format_size(num_bytes: int) -> str:
    if num_bytes < 1024:
        return f"{num_bytes}B"
    elif num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.2f}KB"
    else:
        return f"{num_bytes / (1024 * 1024):.2f}MB"
