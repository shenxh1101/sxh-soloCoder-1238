import json
import os
import re
import time
from typing import Dict, Optional, List, Any
from dataclasses import dataclass, field


DEFAULT_DATA_DIR = os.path.join(os.path.expanduser("~"), ".httpdiag")
DEFAULT_ENV = "default"

DEFAULT_SENSITIVE_PATTERNS = [
    r"(?i)authorization",
    r"(?i)auth",
    r"(?i)token",
    r"(?i)secret",
    r"(?i)password",
    r"(?i)passwd",
    r"(?i)pwd",
    r"(?i)key",
    r"(?i)apikey",
    r"(?i)api-key",
    r"(?i)api_key",
    r"(?i)cookie",
    r"(?i)session",
]


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
    env: str = DEFAULT_ENV

    def to_dict(self, mask_sensitive: bool = False, sensitive_patterns: Optional[List[str]] = None) -> Dict[str, Any]:
        headers = self.headers
        if mask_sensitive:
            headers = self._mask_headers(headers, sensitive_patterns)
        body = self.body
        if mask_sensitive and self._is_body_sensitive():
            body = "[SENSITIVE BODY HIDDEN]"
        return {
            "name": self.name,
            "method": self.method,
            "url": self.url,
            "headers": headers,
            "body": body,
            "timeout": self.timeout,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "env": self.env,
        }

    def _is_body_sensitive(self) -> bool:
        body_lower = self.body.lower()
        keywords = ["password", "token", "secret", "apikey", "private_key", "pwd"]
        return any(kw in body_lower for kw in keywords)

    def _mask_headers(self, headers: Dict[str, str], patterns: Optional[List[str]] = None) -> Dict[str, str]:
        if patterns is None:
            patterns = DEFAULT_SENSITIVE_PATTERNS
        result = {}
        for k, v in headers.items():
            is_sensitive = any(re.search(p, k) for p in patterns)
            if is_sensitive and v:
                if len(v) > 8:
                    result[k] = v[:4] + "****" + v[-4:]
                else:
                    result[k] = "****"
            else:
                result[k] = v
        return result

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
            env=data.get("env", DEFAULT_ENV),
        )

    def merge_with_env(self, env_config: "EnvConfig") -> "Profile":
        merged_headers = dict(env_config.headers)
        merged_headers.update(self.headers)
        merged_body = self.body or env_config.body
        url = self.url
        if url and env_config.base_url and not url.startswith("http"):
            url = env_config.base_url.rstrip("/") + "/" + url.lstrip("/")
        return Profile(
            name=self.name,
            method=self.method,
            url=url,
            headers=merged_headers,
            body=merged_body,
            timeout=self.timeout if self.timeout != 30 else env_config.timeout,
            created_at=self.created_at,
            updated_at=self.updated_at,
            env=env_config.name,
        )


@dataclass
class EnvConfig:
    name: str
    base_url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    timeout: int = 30
    variables: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "base_url": self.base_url,
            "headers": self.headers,
            "body": self.body,
            "timeout": self.timeout,
            "variables": self.variables,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EnvConfig":
        return cls(
            name=data["name"],
            base_url=data.get("base_url", ""),
            headers=data.get("headers", {}),
            body=data.get("body", ""),
            timeout=data.get("timeout", 30),
            variables=data.get("variables", {}),
        )


class ProfileManager:
    def __init__(self, data_dir: str = DEFAULT_DATA_DIR):
        self.data_dir = data_dir
        self.profiles_dir = os.path.join(data_dir, "profiles")
        os.makedirs(self.profiles_dir, exist_ok=True)
        self._profiles_file = os.path.join(self.profiles_dir, "profiles.json")
        self._envs_file = os.path.join(self.profiles_dir, "envs.json")
        self._current_env_file = os.path.join(self.profiles_dir, "current_env")
        self._ensure_files()

    def _ensure_files(self):
        if not os.path.exists(self._profiles_file):
            with open(self._profiles_file, "w", encoding="utf-8") as f:
                json.dump({}, f, ensure_ascii=False, indent=2)
        if not os.path.exists(self._envs_file):
            default_env = EnvConfig(name=DEFAULT_ENV)
            with open(self._envs_file, "w", encoding="utf-8") as f:
                json.dump({DEFAULT_ENV: default_env.to_dict()}, f, ensure_ascii=False, indent=2)
        if not os.path.exists(self._current_env_file):
            with open(self._current_env_file, "w", encoding="utf-8") as f:
                f.write(DEFAULT_ENV)

    def _load_profiles(self) -> Dict[str, Profile]:
        try:
            with open(self._profiles_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            return {k: Profile.from_dict(v) for k, v in data.items()}
        except (json.JSONDecodeError, FileNotFoundError):
            return {}

    def _save_profiles(self, profiles: Dict[str, Profile]):
        data = {k: v.to_dict() for k, v in profiles.items()}
        with open(self._profiles_file, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def _load_envs(self) -> Dict[str, EnvConfig]:
        try:
            with open(self._envs_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            return {k: EnvConfig.from_dict(v) for k, v in data.items()}
        except (json.JSONDecodeError, FileNotFoundError):
            return {DEFAULT_ENV: EnvConfig(name=DEFAULT_ENV)}

    def _save_envs(self, envs: Dict[str, EnvConfig]):
        data = {k: v.to_dict() for k, v in envs.items()}
        with open(self._envs_file, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def get_current_env(self) -> str:
        try:
            with open(self._current_env_file, "r", encoding="utf-8") as f:
                return f.read().strip() or DEFAULT_ENV
        except FileNotFoundError:
            return DEFAULT_ENV

    def set_current_env(self, env_name: str) -> bool:
        envs = self._load_envs()
        if env_name not in envs:
            return False
        with open(self._current_env_file, "w", encoding="utf-8") as f:
            f.write(env_name)
        return True

    def get_env(self, env_name: Optional[str] = None) -> Optional[EnvConfig]:
        if env_name is None:
            env_name = self.get_current_env()
        envs = self._load_envs()
        return envs.get(env_name)

    def list_envs(self) -> List[str]:
        envs = self._load_envs()
        return sorted(envs.keys())

    def save_env(
        self,
        env_name: str,
        base_url: str = "",
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        timeout: int = 30,
        variables: Optional[Dict[str, str]] = None,
        overwrite: bool = False,
    ) -> EnvConfig:
        envs = self._load_envs()
        if env_name in envs and not overwrite:
            raise ValueError(f"Environment '{env_name}' already exists. Use --overwrite to replace it.")
        env = EnvConfig(
            name=env_name,
            base_url=base_url,
            headers=headers or {},
            body=body,
            timeout=timeout,
            variables=variables or {},
        )
        envs[env_name] = env
        self._save_envs(envs)
        return env

    def delete_env(self, env_name: str) -> bool:
        if env_name == DEFAULT_ENV:
            raise ValueError(f"Cannot delete default environment.")
        envs = self._load_envs()
        if env_name in envs:
            del envs[env_name]
            self._save_envs(envs)
            if self.get_current_env() == env_name:
                self.set_current_env(DEFAULT_ENV)
            return True
        return False

    def save(
        self,
        name: str,
        method: str = "GET",
        url: str = "",
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        timeout: int = 30,
        overwrite: bool = False,
        env: Optional[str] = None,
    ) -> Profile:
        profiles = self._load_profiles()
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        env_name = env or self.get_current_env()

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
            env=env_name,
        )

        profiles[name] = profile
        self._save_profiles(profiles)
        return profile

    def get(self, name: str) -> Optional[Profile]:
        profiles = self._load_profiles()
        return profiles.get(name)

    def apply(self, name: str, env_name: Optional[str] = None) -> Profile:
        profile = self.get(name)
        if profile is None:
            raise ValueError(f"Profile '{name}' not found.")
        if env_name is None:
            env_name = self.get_current_env()
        env_config = self.get_env(env_name)
        if env_config:
            return profile.merge_with_env(env_config)
        return profile

    def list(self, env: Optional[str] = None) -> List[Profile]:
        profiles = self._load_profiles()
        result = list(profiles.values())
        if env:
            result = [p for p in result if p.env == env]
        return sorted(result, key=lambda p: (p.env, p.name))

    def delete(self, name: str) -> bool:
        profiles = self._load_profiles()
        if name in profiles:
            del profiles[name]
            self._save_profiles(profiles)
            return True
        return False

    def export(
        self,
        filepath: str,
        profile_names: Optional[List[str]] = None,
        mask_sensitive: bool = False,
        include_envs: bool = True,
        sensitive_patterns: Optional[List[str]] = None,
    ) -> int:
        profiles = self._load_profiles()
        if profile_names:
            selected = {k: v for k, v in profiles.items() if k in profile_names}
            missing = [n for n in profile_names if n not in profiles]
            if missing:
                raise ValueError(f"Profiles not found: {', '.join(missing)}")
        else:
            selected = profiles

        data = {
            "version": "1.0",
            "profiles": {k: v.to_dict(mask_sensitive=mask_sensitive, sensitive_patterns=sensitive_patterns)
                       for k, v in selected.items()},
        }
        if include_envs:
            envs = self._load_envs()
            if mask_sensitive:
                profile_temp = Profile(name="__mask_temp__")
                env_dicts = {}
                for k, v in envs.items():
                    env_dict = v.to_dict()
                    env_dict["headers"] = profile_temp._mask_headers(v.headers, sensitive_patterns)
                    env_dicts[k] = env_dict
                data["envs"] = env_dicts
            else:
                data["envs"] = {k: v.to_dict() for k, v in envs.items()}
            data["current_env"] = self.get_current_env()

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return len(selected)

    def import_file(self, filepath: str, overwrite: bool = False) -> Dict[str, int]:
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        profiles_data = data.get("profiles", {})
        envs_data = data.get("envs", {})

        existing_profiles = self._load_profiles()
        imported_profiles = 0
        skipped_profiles = 0

        for name, profile_data in profiles_data.items():
            if name in existing_profiles and not overwrite:
                skipped_profiles += 1
                continue
            profile = Profile.from_dict(profile_data)
            profile.updated_at = time.strftime("%Y-%m-%d %H:%M:%S")
            if name not in existing_profiles:
                profile.created_at = profile.updated_at
            existing_profiles[name] = profile
            imported_profiles += 1
        self._save_profiles(existing_profiles)

        imported_envs = 0
        skipped_envs = 0
        if envs_data:
            existing_envs = self._load_envs()
            for name, env_data in envs_data.items():
                if name in existing_envs and not overwrite:
                    skipped_envs += 1
                    continue
                existing_envs[name] = EnvConfig.from_dict(env_data)
                imported_envs += 1
            self._save_envs(existing_envs)

        if data.get("current_env"):
            self.set_current_env(data["current_env"])

        return {
            "imported_profiles": imported_profiles,
            "skipped_profiles": skipped_profiles,
            "imported_envs": imported_envs,
            "skipped_envs": skipped_envs,
        }
