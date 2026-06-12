import json
import os
from typing import Dict, Optional, List, Any
from dataclasses import dataclass, field, asdict


DEFAULT_DATA_DIR = os.path.join(os.path.expanduser("~"), ".httpdiag")


@dataclass
class Profile:
    name: str
    method: str = "GET"
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    timeout: int = 30
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "method": self.method,
            "url": self.url,
            "headers": self.headers,
            "body": self.body,
            "timeout": self.timeout,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Profile":
        return cls(
            name=data["name"],
            method=data.get("method", "GET"),
            url=data.get("url", ""),
            headers=data.get("headers", {}),
            body=data.get("body", ""),
            timeout=data.get("timeout", 30),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
        )


class ProfileManager:
    def __init__(self, data_dir: str = DEFAULT_DATA_DIR):
        self.data_dir = data_dir
        self.profiles_dir = os.path.join(data_dir, "profiles")
        os.makedirs(self.profiles_dir, exist_ok=True)
        self._profiles_file = os.path.join(self.profiles_dir, "profiles.json")
        self._ensure_file()

    def _ensure_file(self):
        if not os.path.exists(self._profiles_file):
            with open(self._profiles_file, "w", encoding="utf-8") as f:
                json.dump({}, f, ensure_ascii=False, indent=2)

    def _load_all(self) -> Dict[str, Profile]:
        self._ensure_file()
        try:
            with open(self._profiles_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            return {k: Profile.from_dict(v) for k, v in data.items()}
        except (json.JSONDecodeError, FileNotFoundError):
            return {}

    def _save_all(self, profiles: Dict[str, Profile]):
        data = {k: v.to_dict() for k, v in profiles.items()}
        with open(self._profiles_file, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def save(
        self,
        name: str,
        method: str = "GET",
        url: str = "",
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        timeout: int = 30,
        overwrite: bool = False,
    ) -> Profile:
        import time
        profiles = self._load_all()
        now = time.strftime("%Y-%m-%d %H:%M:%S")

        if name in profiles and not overwrite:
            raise ValueError(f"Profile '{name}' already exists. Use --overwrite to replace it.")

        profile = Profile(
            name=name,
            method=method.upper(),
            url=url,
            headers=headers or {},
            body=body,
            timeout=timeout,
            created_at=profiles[name].created_at if name in profiles else now,
            updated_at=now,
        )

        profiles[name] = profile
        self._save_all(profiles)
        return profile

    def get(self, name: str) -> Optional[Profile]:
        profiles = self._load_all()
        return profiles.get(name)

    def list(self) -> List[Profile]:
        profiles = self._load_all()
        return sorted(profiles.values(), key=lambda p: p.name)

    def delete(self, name: str) -> bool:
        profiles = self._load_all()
        if name in profiles:
            del profiles[name]
            self._save_all(profiles)
            return True
        return False

    def apply(self, name: str) -> Profile:
        profile = self.get(name)
        if profile is None:
            raise ValueError(f"Profile '{name}' not found.")
        return profile
