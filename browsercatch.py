#!/usr/bin/env python3
"""
BrowserCatch - lightweight collaborator-style inbound listener for pentest workflows.

Use cases:
- Detect blind SSRF / RCE callbacks
- Capture CSRF / XSS beacon requests
- Log inbound requests with concise risk hints
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import secrets
import signal
import shutil
import sys
import threading
import textwrap
from collections import deque
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

SERVER_VERSION = "BrowserCatch/2.1"
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8080
DEFAULT_BASE_PATH = "/c"
DEFAULT_MAX_BODY = 65536
DEFAULT_RESULTS_DIR = "results"
DEFAULT_LOG_JSONL_NAME = "events.jsonl"
DEFAULT_LOG_MARKDOWN_NAME = "Results-browsercatch.md"
DEFAULT_EVENT_FILES_SUBDIR = "events"
DEFAULT_LATEST_JSON_NAME = "latest.json"
DEFAULT_SUMMARY_JSON_NAME = "summary.json"
BUILTIN_COLLECTOR_PATH = "/__browsercatch_collect"

CLIENT_HINT_PATTERNS = [
    ("server-side-http-client", re.compile(r"curl|wget|python-requests|java|go-http-client|libwww-perl|powershell", re.I)),
    ("browser", re.compile(r"mozilla|chrome|safari|firefox|edg", re.I)),
]

RCE_HINT_PATTERNS = [
    re.compile(r"\$\{jndi:", re.I),
    re.compile(r"whoami|id\b|uname\b|/etc/passwd|cmd\.exe|powershell", re.I),
    re.compile(r"nslookup|ping\s+-[cn]|curl\s+https?://|wget\s+https?://", re.I),
]

XSS_HINT_PATTERNS = [
    re.compile(r"<script", re.I),
    re.compile(r"onerror=|onload=|javascript:", re.I),
]

SSRF_HINT_PATTERNS = [
    re.compile(r"169\.254\.169\.254"),
    re.compile(r"metadata\.google\.internal", re.I),
    re.compile(r"100\.100\.100\.200"),
    re.compile(r"127\.0\.0\.1|localhost", re.I),
]

CSRF_HINT_PATTERNS = [
    re.compile(r"csrf", re.I),
    re.compile(r"origin|referer", re.I),
]

BOT_UA_PATTERNS = [
    re.compile(r"\bbot\b|crawler|spider|slurp|bingpreview|facebookexternalhit|discordbot|telegrambot", re.I),
    re.compile(r"headlesschrome|phantomjs|selenium|puppeteer|playwright", re.I),
]

SERVER_SIDE_UA_PATTERNS = [
    re.compile(r"curl|wget|python-requests|httpx|aiohttp|java|go-http-client|libwww-perl|powershell", re.I),
]

SCANNER_PATH_PATTERNS = [
    re.compile(r"^/\.(?:git|env|svn|hg|DS_Store)", re.I),
    re.compile(r"(?:backup|dump|database|wp-config|config|credentials|passwd|shadow).*(?:\.sql|\.bak|\.old|\.save|\.yml|\.yaml|\.php)?$", re.I),
    re.compile(r"^/(?:phpinfo\.php|server-status|actuator/|vendor/phpunit|\.aws/)", re.I),
    re.compile(r"^/___proxy_subdomain_", re.I),
]

SENSITIVE_PROBE_PATTERNS = [
    re.compile(r"/\.git/(?:HEAD|config)", re.I),
    re.compile(r"/\.env", re.I),
    re.compile(r"/\.aws/credentials", re.I),
    re.compile(r"/wp-config", re.I),
    re.compile(r"/(?:backup|dump)\.sql", re.I),
]

PRINT_LOCK = threading.Lock()


@dataclass
class Config:
    host: str
    port: int
    token: str
    base_path: str
    public_url: str | None
    serve_file: Path | None
    static_dir: Path | None
    run_id: str
    results_dir: Path
    log_jsonl: Path
    log_markdown: Path
    event_files_dir: Path
    latest_json: Path
    summary_json: Path
    max_body: int
    quiet: bool
    stdout_json: bool
    live: bool
    once: bool


def normalize_path(path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    return path.rstrip("/") or "/"


def iso_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def build_callback_url(cfg: Config) -> str:
    base = cfg.public_url.rstrip("/") if cfg.public_url else f"http://127.0.0.1:{cfg.port}"
    return f"{base}{cfg.base_path}/{cfg.token}"


class EventStore:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.count = 0
        self.stop_requested = threading.Event()
        self._lock = threading.Lock()
        self._recent: deque[dict[str, Any]] = deque(maxlen=250)
        self._source_ips: set[str] = set()
        self._hint_counts: dict[str, int] = {}
        self._actor_counts: dict[str, int] = {}
        self._prepare_output_paths()
        self._write_bootstrap_files()

    def _prepare_output_paths(self) -> None:
        self.cfg.results_dir.mkdir(parents=True, exist_ok=True)
        self.cfg.log_jsonl.parent.mkdir(parents=True, exist_ok=True)
        self.cfg.log_markdown.parent.mkdir(parents=True, exist_ok=True)
        self.cfg.event_files_dir.mkdir(parents=True, exist_ok=True)
        self.cfg.latest_json.parent.mkdir(parents=True, exist_ok=True)
        self.cfg.summary_json.parent.mkdir(parents=True, exist_ok=True)

    def _atomic_write_json(self, path: Path, payload: dict[str, Any]) -> None:
        tmp_path = path.with_name(f".{path.name}.tmp")
        with tmp_path.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=True, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)

    def _write_bootstrap_files(self) -> None:
        callback_url = build_callback_url(self.cfg)
        self._atomic_write_json(
            self.cfg.summary_json,
            {
                "status": "running",
                "run_id": self.cfg.run_id,
                "started_at": iso_now(),
                "event_count": 0,
                "unique_source_ips": [],
                "hint_counts": {},
                "actor_counts": {},
                "callback_url": callback_url,
                "results_dir": str(self.cfg.results_dir),
                "jsonl_log": str(self.cfg.log_jsonl),
                "latest_json": str(self.cfg.latest_json),
                "event_files_dir": str(self.cfg.event_files_dir),
            },
        )
        self._atomic_write_json(
            self.cfg.latest_json,
            {
                "status": "waiting-for-events",
                "run_id": self.cfg.run_id,
                "callback_url": callback_url,
                "event": None,
            },
        )

    def recent_events(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._recent)[-limit:]

    def write_event(self, event: dict[str, Any]) -> None:
        with self._lock:
            self.count += 1
            event["event_id"] = self.count
            event["run_id"] = self.cfg.run_id
            event_file = self.cfg.event_files_dir / f"event-{self.count:08d}.json"
            event["event_file"] = str(event_file)

            with self.cfg.log_jsonl.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, ensure_ascii=True) + "\n")
                fh.flush()

            self._atomic_write_json(event_file, event)
            self._atomic_write_json(self.cfg.latest_json, event)

            self._recent.append(dict(event))

            source_ip = event.get("source_ip")
            if source_ip:
                self._source_ips.add(str(source_ip))
            for hint in event.get("hints", []):
                self._hint_counts[hint] = self._hint_counts.get(hint, 0) + 1
            actor_label = get_nested(event, ["client_profile", "actor", "label"])
            if actor_label:
                self._actor_counts[str(actor_label)] = self._actor_counts.get(str(actor_label), 0) + 1

            self._write_summary(event)
            self._merge_markdown(event)

    def _write_summary(self, event: dict[str, Any]) -> None:
        summary = {
            "status": "running",
            "run_id": self.cfg.run_id,
            "updated_at": event["timestamp_iso"],
            "event_count": self.count,
            "unique_source_ips": sorted(self._source_ips),
            "hint_counts": {k: self._hint_counts[k] for k in sorted(self._hint_counts)},
            "actor_counts": {k: self._actor_counts[k] for k in sorted(self._actor_counts)},
            "last_event_id": event["event_id"],
            "last_event_file": event["event_file"],
            "callback_url": build_callback_url(self.cfg),
            "results_dir": str(self.cfg.results_dir),
            "jsonl_log": str(self.cfg.log_jsonl),
            "latest_json": str(self.cfg.latest_json),
            "event_files_dir": str(self.cfg.event_files_dir),
        }
        self._atomic_write_json(self.cfg.summary_json, summary)

    def _merge_markdown(self, event: dict[str, Any]) -> None:
        now = event["timestamp_iso"]
        module_header = "# BrowserCatch Results"
        summary_header = "## Known Findings"
        notes_header = "## Evidence / Notes"
        next_header = "## Open Questions / Next Steps"
        run_log_header = "## Run Log"

        existing = ""
        if self.cfg.log_markdown.exists():
            existing = self.cfg.log_markdown.read_text(encoding="utf-8")

        if not existing.strip():
            existing = (
                f"{module_header}\n\n"
                f"- Last Updated: {now}\n\n"
                f"{summary_header}\n"
                f"- unique_source_ips: none yet\n"
                f"- suspected_techniques: none yet\n\n"
                f"{notes_header}\n"
                f"- Waiting for inbound requests.\n\n"
                f"{next_header}\n"
                f"- Verify callback URLs are reachable from target infrastructure.\n\n"
                f"{run_log_header}\n"
            )

        lines = existing.splitlines()

        def replace_line(prefix: str, new_line: str) -> None:
            for idx, line in enumerate(lines):
                if line.startswith(prefix):
                    lines[idx] = new_line
                    return
            lines.insert(1, new_line)

        replace_line("- Last Updated:", f"- Last Updated: {now}")
        unique_ips = ", ".join(sorted(self._source_ips)) if self._source_ips else "none yet"
        replace_line("- unique_source_ips:", f"- unique_source_ips: {unique_ips}")
        techniques = ", ".join(sorted(self._hint_counts)) if self._hint_counts else "none yet"
        replace_line("- suspected_techniques:", f"- suspected_techniques: {techniques}")

        waiting_line = "- Waiting for inbound requests."
        if waiting_line in lines:
            lines.remove(waiting_line)

        source_ip = event.get("source_ip", "unknown")
        hints = ", ".join(event.get("hints", [])) or "none"
        actor = get_nested(event, ["client_profile", "actor", "label"]) or "unknown"
        finding_line = (
            f"- event-{event['event_id']}: {event['method']} {event['path']} "
            f"from {source_ip} | actor: {actor} | hints: {hints}"
        )

        if summary_header in lines:
            idx = lines.index(summary_header)
            insert_at = idx + 1
            if finding_line not in lines:
                lines.insert(insert_at, finding_line)

        note_line = (
            f"- event-{event['event_id']}: ua={event.get('user_agent', '')} "
            f"query_keys={','.join(sorted(event.get('query', {}).keys())) if event.get('query') else '-'} "
            f"actor={actor}"
        )
        if notes_header in lines and note_line not in lines:
            idx = lines.index(notes_header)
            lines.insert(idx + 1, note_line)

        run_entry = (
            f"- {event['timestamp_iso']} ({event['timestamp_unix']}): "
            f"added event-{event['event_id']} with hints [{hints}]"
        )
        if run_log_header in lines:
            idx = lines.index(run_log_header)
            lines.insert(idx + 1, run_entry)

        self.cfg.log_markdown.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def parse_body(handler: BaseHTTPRequestHandler, max_body: int) -> tuple[str, bytes]:
    content_len = handler.headers.get("Content-Length")
    if not content_len:
        return "", b""
    try:
        length = min(int(content_len), max_body)
    except ValueError:
        return "", b""
    raw = handler.rfile.read(length)
    ctype = handler.headers.get("Content-Type", "")
    return ctype, raw


def decode_body(content_type: str, raw: bytes) -> dict[str, Any]:
    text = raw.decode("utf-8", errors="replace")
    parsed: dict[str, Any] = {
        "body_preview": text[:500],
        "body_len": len(raw),
    }
    if "application/json" in content_type:
        try:
            parsed["json"] = json.loads(text)
        except json.JSONDecodeError:
            parsed["json_parse_error"] = True
    elif "application/x-www-form-urlencoded" in content_type:
        parsed["form"] = {k: v if len(v) > 1 else v[0] for k, v in parse_qs(text).items()}
    return parsed


def classify_hints(event: dict[str, Any]) -> list[str]:
    haystack_parts = [
        event.get("path", ""),
        event.get("user_agent", ""),
        json.dumps(event.get("query", {}), ensure_ascii=True),
        event.get("body_preview", ""),
    ]
    blob = "\n".join(haystack_parts)

    hints: set[str] = set()

    ua = event.get("user_agent", "")
    for label, rx in CLIENT_HINT_PATTERNS:
        if rx.search(ua):
            hints.add(label)

    if any(rx.search(blob) for rx in SSRF_HINT_PATTERNS):
        hints.add("possible-ssrf")
    if any(rx.search(blob) for rx in RCE_HINT_PATTERNS):
        hints.add("possible-rce-probe")
    if any(rx.search(blob) for rx in XSS_HINT_PATTERNS):
        hints.add("possible-xss-beacon")
    if any(rx.search(blob) for rx in CSRF_HINT_PATTERNS) and event.get("method") in {"POST", "PUT", "PATCH", "DELETE"}:
        hints.add("possible-csrf-related")
    if any(rx.search(event.get("path", "")) for rx in SCANNER_PATH_PATTERNS):
        hints.add("likely-scanner")
    if any(rx.search(event.get("path", "")) for rx in SENSITIVE_PROBE_PATTERNS):
        hints.add("sensitive-file-probe")

    if event.get("token_match"):
        hints.add("token-matched-callback")

    if not hints:
        hints.add("unclassified-callback")

    return sorted(hints)


def get_nested(data: Any, path: list[str]) -> Any:
    current = data
    for part in path:
        if not isinstance(current, dict):
            return None
        lowered = {str(key).lower(): key for key in current}
        key = lowered.get(part.lower())
        if key is None:
            return None
        current = current[key]
    return current


def first_present(event: dict[str, Any], names: list[str]) -> Any:
    candidates: list[Any] = [event.get("query", {})]
    if isinstance(event.get("json"), dict):
        candidates.append(event["json"])
    if isinstance(event.get("form"), dict):
        candidates.append(event["form"])

    lowered_names = {name.lower() for name in names}
    for source in candidates:
        if not isinstance(source, dict):
            continue
        for name in names:
            if "." in name:
                value = get_nested(source, name.split("."))
                if value not in ("", None, [], {}):
                    return value
        for key, value in source.items():
            if str(key).lower() in lowered_names and value not in ("", None, [], {}):
                return value
    return None


def make_dimension(width: Any, height: Any) -> str | None:
    if width in ("", None) or height in ("", None):
        return None
    return f"{width}x{height}"


def summarize_user_agent(user_agent: str) -> str:
    if not user_agent:
        return "not supplied"

    browser = "unknown browser"
    browser_patterns = [
        ("Edge", r"Edg/([0-9.]+)"),
        ("Chrome", r"Chrome/([0-9.]+)"),
        ("Firefox", r"Firefox/([0-9.]+)"),
        ("Safari", r"Version/([0-9.]+).*Safari/"),
        ("curl", r"curl/([0-9.]+)"),
        ("wget", r"Wget/([0-9.]+)"),
        ("Python requests", r"python-requests/([0-9.]+)"),
    ]
    for name, pattern in browser_patterns:
        match = re.search(pattern, user_agent, re.I)
        if match:
            browser = f"{name} {match.group(1)}"
            break

    os_name = "unknown OS"
    os_patterns = [
        ("Windows", r"Windows NT ([0-9.]+)"),
        ("Android", r"Android ([0-9.]+)"),
        ("iOS", r"(?:iPhone|iPad).*OS ([0-9_]+)"),
        ("macOS", r"Mac OS X ([0-9_]+)"),
        ("Linux", r"Linux"),
    ]
    for name, pattern in os_patterns:
        match = re.search(pattern, user_agent, re.I)
        if match:
            version = match.group(1).replace("_", ".") if match.groups() else ""
            os_name = f"{name} {version}".strip()
            break

    return f"{browser} on {os_name}"


def parse_user_agent(user_agent: str) -> dict[str, str]:
    if not user_agent:
        return {"browser": "unknown", "browser_version": "", "os": "unknown", "device": "unknown"}

    browser = "unknown"
    browser_version = ""
    browser_patterns = [
        ("Edge", r"Edg/([0-9.]+)"),
        ("Opera", r"OPR/([0-9.]+)"),
        ("Chrome", r"Chrome/([0-9.]+)"),
        ("Firefox", r"Firefox/([0-9.]+)"),
        ("Safari", r"Version/([0-9.]+).*Safari/"),
        ("curl", r"curl/([0-9.]+)"),
        ("wget", r"Wget/([0-9.]+)"),
        ("Python requests", r"python-requests/([0-9.]+)"),
    ]
    for name, pattern in browser_patterns:
        match = re.search(pattern, user_agent, re.I)
        if match:
            browser = name
            browser_version = match.group(1)
            break

    os_name = "unknown"
    os_patterns = [
        ("Windows", r"Windows NT ([0-9.]+)"),
        ("Android", r"Android ([0-9.]+)"),
        ("iOS", r"(?:iPhone|iPad).*OS ([0-9_]+)"),
        ("macOS", r"Mac OS X ([0-9_]+)"),
        ("Linux", r"Linux"),
    ]
    for name, pattern in os_patterns:
        match = re.search(pattern, user_agent, re.I)
        if match:
            version = match.group(1).replace("_", ".") if match.groups() else ""
            os_name = f"{name} {version}".strip()
            break

    if re.search(r"Mobile|Android|iPhone", user_agent, re.I):
        device = "mobile"
    elif re.search(r"iPad|Tablet", user_agent, re.I):
        device = "tablet"
    else:
        device = "desktop-or-server"

    return {"browser": browser, "browser_version": browser_version, "os": os_name, "device": device}


def classify_actor(event: dict[str, Any]) -> str:
    return classify_actor_detail(event)["label"]


def classify_actor_detail(event: dict[str, Any]) -> dict[str, Any]:
    ua = event.get("user_agent", "")
    headers = event.get("headers", {})
    reasons: list[str] = []
    score = 0

    if any(rx.search(ua) for rx in BOT_UA_PATTERNS):
        score += 4
        reasons.append("bot-like User-Agent token")
    if any(rx.search(ua) for rx in SERVER_SIDE_UA_PATTERNS):
        score += 5
        reasons.append("server-side HTTP client User-Agent")
    if any(rx.search(event.get("path", "")) for rx in SCANNER_PATH_PATTERNS):
        score += 4
        reasons.append("known scanner/probe path")
    if any(rx.search(event.get("path", "")) for rx in SENSITIVE_PROBE_PATTERNS):
        score += 3
        reasons.append("sensitive file discovery path")
    if event.get("method") not in {"GET", "POST", "HEAD", "OPTIONS"}:
        score += 1
        reasons.append("less common HTTP method")

    browser_headers = 0
    for header_name in ("sec-fetch-site", "sec-fetch-mode", "sec-ch-ua", "sec-ch-ua-platform", "accept-language"):
        if headers.get(header_name):
            browser_headers += 1
    if headers.get("sec-fetch-site") or headers.get("sec-ch-ua"):
        reasons.append("modern browser headers present")
    if browser_headers >= 2:
        score -= 2
    if event.get("token_match") and first_present(event, ["fingerprint", "screen", "viewport", "userAgentData"]):
        score -= 3
        reasons.append("browser collector payload present")

    if score >= 6:
        label = "likely bot / scanner"
        confidence = "high"
    elif score >= 3:
        label = "suspicious automation"
        confidence = "medium"
    elif browser_headers >= 2 or first_present(event, ["fingerprint", "screen", "viewport", "plugins"]):
        label = "browser-like human"
        confidence = "medium"
    elif any(rx.search(ua) for rx in SERVER_SIDE_UA_PATTERNS):
        label = "server-side client"
        confidence = "high"
    elif "browser" in event.get("hints", []):
        label = "browser-like unknown"
        confidence = "low"
    else:
        label = "unknown"
        confidence = "low"

    return {"label": label, "confidence": confidence, "score": score, "reasons": reasons or ["insufficient signal"]}


def build_client_profile(event: dict[str, Any]) -> dict[str, Any]:
    headers = event.get("headers", {})
    ua_info = parse_user_agent(event.get("user_agent", ""))
    screen_width = first_present(event, ["screen.width", "screenWidth", "screen_width"])
    screen_height = first_present(event, ["screen.height", "screenHeight", "screen_height"])
    viewport_width = first_present(event, ["viewport.width", "innerWidth", "viewportWidth", "viewport_width"])
    viewport_height = first_present(event, ["viewport.height", "innerHeight", "viewportHeight", "viewport_height"])
    outer_width = first_present(event, ["viewport.outerWidth", "outerWidth", "outer_width"])
    outer_height = first_present(event, ["viewport.outerHeight", "outerHeight", "outer_height"])

    profile = {
        "actor": classify_actor_detail(event),
        "ua": ua_info,
        "network": {
            "source": f"{event.get('source_ip')}:{event.get('source_port')}",
            "host": headers.get("host"),
            "forwarded_for": headers.get("x-forwarded-for") or headers.get("forwarded"),
            "real_ip": headers.get("x-real-ip") or headers.get("cf-connecting-ip"),
            "referer": headers.get("referer"),
            "origin": headers.get("origin"),
        },
        "browser": {
            "user_agent": event.get("user_agent", ""),
            "client_hints": {
                "sec_ch_ua": headers.get("sec-ch-ua"),
                "platform": headers.get("sec-ch-ua-platform"),
                "mobile": headers.get("sec-ch-ua-mobile"),
                "ua_full_version": headers.get("sec-ch-ua-full-version"),
                "architecture": headers.get("sec-ch-ua-arch"),
                "bitness": headers.get("sec-ch-ua-bitness"),
                "model": headers.get("sec-ch-ua-model"),
                "platform_version": headers.get("sec-ch-ua-platform-version"),
            },
            "ua_data": first_present(event, ["userAgentData", "uaData"]),
            "language": headers.get("accept-language") or first_present(event, ["language", "lang"]),
            "languages": first_present(event, ["languages"]),
            "platform": first_present(event, ["platform", "navigatorPlatform"]),
            "vendor": first_present(event, ["vendor"]),
            "webdriver": first_present(event, ["webdriver", "navigator.webdriver"]),
            "do_not_track": headers.get("dnt") or first_present(event, ["doNotTrack"]),
            "cookies_enabled": first_present(event, ["cookiesEnabled", "cookieEnabled"]),
        },
        "display": {
            "screen": make_dimension(screen_width, screen_height) or first_present(event, ["screen", "screen_resolution", "resolution"]),
            "screen_width": screen_width,
            "screen_height": screen_height,
            "available": first_present(event, ["screen.available", "screen.avail"]) or make_dimension(
                first_present(event, ["screen.availWidth", "availWidth"]),
                first_present(event, ["screen.availHeight", "availHeight"]),
            ),
            "viewport": make_dimension(viewport_width, viewport_height) or first_present(event, ["viewport", "window", "innerSize"]),
            "viewport_width": viewport_width,
            "viewport_height": viewport_height,
            "outer_window": make_dimension(outer_width, outer_height),
            "device_pixel_ratio": first_present(event, ["viewport.devicePixelRatio", "devicePixelRatio", "pixelRatio"]),
            "color_depth": first_present(event, ["screen.colorDepth", "colorDepth"]),
            "pixel_depth": first_present(event, ["screen.pixelDepth", "pixelDepth"]),
        },
        "device": {
            "timezone": first_present(event, ["timezone", "timezoneOffset", "tz"]),
            "timezone_offset": first_present(event, ["timezoneOffset"]),
            "hardware_concurrency": first_present(event, ["hardwareConcurrency", "cpuCores"]),
            "device_memory": first_present(event, ["deviceMemory", "memory"]),
            "touch_support": first_present(event, ["touchSupport"]),
            "max_touch_points": first_present(event, ["touchSupport.maxTouchPoints", "maxTouchPoints", "touchPoints"]),
        },
        "capabilities": {
            "plugins": first_present(event, ["plugins", "plugin_list", "navigatorPlugins"]),
            "mime_types": first_present(event, ["mimeTypes"]),
            "pdf_viewer_enabled": first_present(event, ["pdfViewerEnabled"]),
            "storage": first_present(event, ["storage"]),
            "webgl": first_present(event, ["webgl", "webGlBasics"]),
            "canvas": first_present(event, ["canvas"]),
            "media": first_present(event, ["media"]),
            "extension_surface": first_present(event, ["extensionSurface", "extensions"]),
        },
    }
    return profile


def format_value(value: Any) -> str:
    if value in (None, "", [], {}):
        return "-"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=True, sort_keys=True)
    return str(value)


def summarize_plugins(value: Any) -> str:
    if not value:
        return "-"
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        names = []
        for item in value:
            if isinstance(item, dict):
                name = item.get("name") or item.get("type")
                if name:
                    names.append(str(name))
            else:
                names.append(str(item))
        if not names:
            return f"{len(value)} entries"
        suffix = "" if len(names) <= 8 else f" (+{len(names) - 8} more)"
        return ", ".join(names[:8]) + suffix
    return format_value(value)


def summarize_webgl(value: Any) -> str:
    if not isinstance(value, dict):
        return format_value(value)
    if value.get("available") is False:
        return "not available"
    renderer = value.get("rendererUnmasked") or value.get("renderer")
    vendor = value.get("vendorUnmasked") or value.get("vendor")
    version = value.get("version")
    extensions = value.get("extensions")
    extension_count = len(extensions) if isinstance(extensions, list) else 0
    parts = [part for part in [vendor, renderer, version] if part]
    if extension_count:
        parts.append(f"{extension_count} extensions")
    return " | ".join(str(part) for part in parts) or format_value(value)


def summarize_canvas(value: Any) -> str:
    if not isinstance(value, dict):
        return format_value(value)
    if value.get("available") is False:
        return "not available"
    if value.get("hash"):
        return f"hash={value.get('hash')} length={value.get('length', '-')}"
    return format_value(value)


def summarize_profile_list(value: Any) -> str:
    if isinstance(value, dict):
        return ", ".join(f"{key}={value[key]}" for key in sorted(value) if value[key] not in ("", None, [], {})) or "-"
    return format_value(value)


def terminal_width() -> int:
    return max(88, min(140, shutil.get_terminal_size((110, 24)).columns))


def render_rows(rows: list[tuple[str, Any]], *, width: int) -> list[str]:
    label_width = min(24, max((len(label) for label, _ in rows), default=0))
    value_width = max(30, width - label_width - 5)
    lines: list[str] = []
    for label, raw_value in rows:
        value = format_value(raw_value)
        wrapped = textwrap.wrap(value, value_width, replace_whitespace=False, drop_whitespace=False) or ["-"]
        lines.append(f"{label:<{label_width}} : {wrapped[0]}")
        for continuation in wrapped[1:]:
            lines.append(f"{'':<{label_width}} : {continuation}")
    return lines


def render_section(title: str, rows: list[tuple[str, Any]], *, width: int) -> list[str]:
    if not rows:
        return []
    lines = [f"[{title}]"]
    lines.extend(render_rows(rows, width=width))
    return lines


def preview_headers(headers: dict[str, Any]) -> list[tuple[str, Any]]:
    preferred = [
        "host",
        "user-agent",
        "accept",
        "accept-language",
        "accept-encoding",
        "referer",
        "origin",
        "sec-ch-ua",
        "sec-ch-ua-platform",
        "sec-ch-ua-mobile",
        "sec-fetch-site",
        "sec-fetch-mode",
        "x-forwarded-for",
        "x-real-ip",
        "cf-connecting-ip",
        "forwarded",
    ]
    rows = [(name, headers.get(name)) for name in preferred if headers.get(name)]
    other_security = sorted(
        (key, value)
        for key, value in headers.items()
        if key.startswith(("x-", "cf-", "sec-")) and key not in {name for name, _ in rows}
    )
    rows.extend(other_security[:12])
    return rows


def render_live_event(event: dict[str, Any]) -> str:
    width = terminal_width()
    rule = "=" * width
    subrule = "-" * width
    headers = event.get("headers", {})
    profile = event.get("client_profile") if isinstance(event.get("client_profile"), dict) else build_client_profile(event)
    actor = profile.get("actor", {})
    ua = profile.get("ua", {})
    browser = profile.get("browser", {})
    display = profile.get("display", {})
    device = profile.get("device", {})
    capabilities = profile.get("capabilities", {})
    network = profile.get("network", {})

    sections = [
        render_section(
            "Request",
            [
                ("Event", f"event-{event.get('event_id', 0):08d}"),
                ("Time UTC", event.get("timestamp_iso")),
                ("Method / path", f"{event.get('method')} {event.get('path')}"),
                ("Source", f"{event.get('source_ip')}:{event.get('source_port')}"),
                ("Actor guess", f"{actor.get('label', classify_actor(event))} ({actor.get('confidence', 'low')})"),
                ("Actor reasons", "; ".join(actor.get("reasons", []))),
                ("Hints", ", ".join(event.get("hints", []))),
                ("Token match", event.get("token_match")),
            ],
            width=width,
        ),
        render_section(
            "Client",
            [
                ("User-Agent", event.get("user_agent") or "not supplied"),
                ("UA summary", f"{ua.get('browser', 'unknown')} {ua.get('browser_version', '')} on {ua.get('os', 'unknown')}".strip()),
                ("Device class", ua.get("device")),
                ("Client hints", headers.get("sec-ch-ua")),
                ("UA data", summarize_profile_list(browser.get("ua_data"))),
                ("Language", browser.get("language")),
                ("Languages", browser.get("languages")),
                ("Platform", browser.get("platform")),
                ("Vendor", browser.get("vendor")),
                ("WebDriver", browser.get("webdriver")),
                ("Do Not Track", browser.get("do_not_track")),
                ("Cookies", browser.get("cookies_enabled")),
            ],
            width=width,
        ),
        render_section(
            "Display / Device",
            [
                ("Screen", display.get("screen")),
                ("Available screen", display.get("available")),
                ("Viewport", display.get("viewport")),
                ("Outer window", display.get("outer_window")),
                ("Device pixel ratio", display.get("device_pixel_ratio")),
                ("Color depth", display.get("color_depth")),
                ("Pixel depth", display.get("pixel_depth")),
                ("Timezone", device.get("timezone")),
                ("Timezone offset", device.get("timezone_offset")),
                ("CPU cores", device.get("hardware_concurrency")),
                ("Device memory", device.get("device_memory")),
                ("Touch support", summarize_profile_list(device.get("touch_support"))),
                ("Max touch points", device.get("max_touch_points")),
            ],
            width=width,
        ),
        render_section(
            "Browser Capabilities",
            [
                ("Plugins", summarize_plugins(capabilities.get("plugins"))),
                ("MIME types", summarize_plugins(capabilities.get("mime_types"))),
                ("PDF viewer", capabilities.get("pdf_viewer_enabled")),
                ("Storage", summarize_profile_list(capabilities.get("storage"))),
                ("WebGL", summarize_webgl(capabilities.get("webgl"))),
                ("Canvas", summarize_canvas(capabilities.get("canvas"))),
                ("Media prefs", summarize_profile_list(capabilities.get("media"))),
                ("Extension surface", summarize_profile_list(capabilities.get("extension_surface"))),
            ],
            width=width,
        ),
        render_section(
            "Routing / Context",
            [
                ("Host", network.get("host")),
                ("Referer", network.get("referer")),
                ("Origin", network.get("origin")),
                ("Forwarded for", network.get("forwarded_for")),
                ("Real IP header", network.get("real_ip")),
                ("Fetch site", headers.get("sec-fetch-site")),
                ("Fetch mode", headers.get("sec-fetch-mode")),
                ("Accept", headers.get("accept")),
            ],
            width=width,
        ),
        render_section(
            "Parameters / Body",
            [
                ("Query", event.get("query")),
                ("JSON", event.get("json")),
                ("Form", event.get("form")),
                ("Body bytes", event.get("body_len")),
                ("Body preview", event.get("body_preview")),
            ],
            width=width,
        ),
        render_section("Interesting Headers", preview_headers(headers), width=width),
        render_section(
            "Persistence",
            [
                ("Event file", event.get("event_file")),
                ("Run ID", event.get("run_id")),
            ],
            width=width,
        ),
    ]

    lines = [
        "",
        rule,
        f"NEW REQUEST: event-{event.get('event_id', 0):08d} | {event.get('method')} {event.get('path')}",
        rule,
    ]
    visible_sections = [section for section in sections if section]
    for idx, section in enumerate(visible_sections):
        lines.extend(section)
        if idx < len(visible_sections) - 1:
            lines.append(subrule)
    return "\n".join(lines)


def read_json_file(path: Path, default: dict[str, Any]) -> dict[str, Any]:
    if not path.exists():
        return default
    try:
        raw = path.read_text(encoding="utf-8")
        return json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return default


def render_template(file_path: Path, callback_url: str, cfg: Config) -> str:
    html = file_path.read_text(encoding="utf-8")
    html = html.replace("__CALLBACK_URL__", callback_url)
    html = html.replace("__TOKEN__", cfg.token)
    html = html.replace("__LISTENER_HOST__", cfg.host)
    html = html.replace("__LISTENER_PORT__", str(cfg.port))
    return html


def render_builtin_collector(callback_url: str, cfg: Config) -> str:
    collector_url = f"{cfg.base_path}/{cfg.token}"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>BrowserCatch Collector</title>
  <style>
    body {{ font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 2rem; line-height: 1.45; }}
    code {{ background: #f2f4f7; padding: .15rem .35rem; border-radius: 4px; }}
  </style>
</head>
<body>
  <h1>BrowserCatch</h1>
  <p>Collector active. Callback: <code>{callback_url}</code></p>
  <p id="status">Collecting browser details...</p>
  <script>
    (function () {{
      var callback = "{collector_url}";

      function safe(fn, fallback) {{
        try {{ return fn(); }} catch (e) {{ return fallback; }}
      }}

      function storageAvailable(name) {{
        return safe(function () {{
          var store = window[name];
          var key = "__browsercatch_test__";
          store.setItem(key, key);
          store.removeItem(key);
          return true;
        }}, false);
      }}

      function getPlugins() {{
        return safe(function () {{
          return Array.prototype.slice.call(navigator.plugins || []).map(function (plugin) {{
            return {{
              name: plugin.name,
              description: plugin.description,
              filename: plugin.filename,
              mimeTypes: Array.prototype.slice.call(plugin || []).map(function (mime) {{
                return {{ type: mime.type, suffixes: mime.suffixes, description: mime.description }};
              }})
            }};
          }});
        }}, []);
      }}

      function getMimeTypes() {{
        return safe(function () {{
          return Array.prototype.slice.call(navigator.mimeTypes || []).map(function (mime) {{
            return {{ type: mime.type, suffixes: mime.suffixes, description: mime.description }};
          }});
        }}, []);
      }}

      function getTouchSupport() {{
        var touchEvent = safe(function () {{
          document.createEvent("TouchEvent");
          return true;
        }}, false);
        return {{
          maxTouchPoints: navigator.maxTouchPoints || navigator.msMaxTouchPoints || 0,
          touchEvent: touchEvent,
          touchStart: "ontouchstart" in window
        }};
      }}

      function getWebGl() {{
        return safe(function () {{
          var canvas = document.createElement("canvas");
          var gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
          if (!gl) return {{ available: false }};
          var debugInfo = gl.getExtension("WEBGL_debug_renderer_info");
          return {{
            available: true,
            version: gl.getParameter(gl.VERSION),
            shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
            vendor: gl.getParameter(gl.VENDOR),
            renderer: gl.getParameter(gl.RENDERER),
            vendorUnmasked: debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : "",
            rendererUnmasked: debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : "",
            extensions: gl.getSupportedExtensions() || []
          }};
        }}, {{ available: false, error: true }});
      }}

      function getCanvasSignal() {{
        return safe(function () {{
          var canvas = document.createElement("canvas");
          canvas.width = 240;
          canvas.height = 60;
          var ctx = canvas.getContext("2d");
          if (!ctx) return {{ available: false }};
          ctx.textBaseline = "top";
          ctx.font = "16px Arial";
          ctx.fillStyle = "#f60";
          ctx.fillRect(2, 2, 120, 35);
          ctx.fillStyle = "#069";
          ctx.fillText("BrowserCatch fp", 4, 8);
          ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
          ctx.fillText("BrowserCatch fp", 6, 10);
          var data = canvas.toDataURL();
          var hash = 0;
          for (var i = 0; i < data.length; i++) {{
            hash = ((hash << 5) - hash + data.charCodeAt(i)) | 0;
          }}
          return {{ available: true, hash: String(hash), length: data.length }};
        }}, {{ available: false, error: true }});
      }}

      function mediaQuery(query) {{
        return safe(function () {{ return matchMedia(query).matches; }}, null);
      }}

      async function getUserAgentData() {{
        var uaData = navigator.userAgentData;
        if (!uaData) return null;
        var result = {{
          brands: uaData.brands || [],
          mobile: uaData.mobile,
          platform: uaData.platform
        }};
        if (uaData.getHighEntropyValues) {{
          try {{
            result.highEntropy = await uaData.getHighEntropyValues([
              "architecture", "bitness", "model", "platformVersion", "uaFullVersion", "fullVersionList", "wow64"
            ]);
          }} catch (e) {{
            result.highEntropyError = e && e.name ? e.name : "error";
          }}
        }}
        return result;
      }}

      async function collect() {{
        var uaData = await getUserAgentData();
        var payload = {{
          source: "browsercatch-built-in-collector",
          collectionVersion: 2,
          page: {{
            href: location.href,
            origin: location.origin,
            pathname: location.pathname,
            referrer: document.referrer || "",
            title: document.title || ""
          }},
          userAgent: navigator.userAgent || "",
          userAgentData: uaData,
          app: {{
            appName: navigator.appName || "",
            appVersion: navigator.appVersion || "",
            product: navigator.product || "",
            productSub: navigator.productSub || "",
            vendor: navigator.vendor || "",
            vendorSub: navigator.vendorSub || ""
          }},
          language: navigator.language || "",
          languages: navigator.languages || [],
          platform: navigator.platform || "",
          cookieEnabled: navigator.cookieEnabled,
          doNotTrack: navigator.doNotTrack || window.doNotTrack || "",
          webdriver: navigator.webdriver === true,
          pdfViewerEnabled: navigator.pdfViewerEnabled,
          online: navigator.onLine,
          hardwareConcurrency: navigator.hardwareConcurrency || null,
          deviceMemory: navigator.deviceMemory || null,
          maxTouchPoints: navigator.maxTouchPoints || 0,
          touchSupport: getTouchSupport(),
          screen: {{
            width: screen ? screen.width : null,
            height: screen ? screen.height : null,
            availWidth: screen ? screen.availWidth : null,
            availHeight: screen ? screen.availHeight : null,
            colorDepth: screen ? screen.colorDepth : null,
            pixelDepth: screen ? screen.pixelDepth : null,
            orientation: screen && screen.orientation ? {{
              type: screen.orientation.type,
              angle: screen.orientation.angle
            }} : null
          }},
          viewport: {{
            width: window.innerWidth,
            height: window.innerHeight,
            outerWidth: window.outerWidth,
            outerHeight: window.outerHeight,
            devicePixelRatio: window.devicePixelRatio || 1
          }},
          timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "",
          timezoneOffset: new Date().getTimezoneOffset(),
          dateTimeLocale: Intl.DateTimeFormat().resolvedOptions(),
          storage: {{
            localStorage: storageAvailable("localStorage"),
            sessionStorage: storageAvailable("sessionStorage"),
            indexedDB: !!window.indexedDB,
            openDatabase: !!window.openDatabase
          }},
          plugins: getPlugins(),
          mimeTypes: getMimeTypes(),
          webgl: getWebGl(),
          canvas: getCanvasSignal(),
          media: {{
            colorGamut: mediaQuery("(color-gamut: rec2020)") ? "rec2020" : (mediaQuery("(color-gamut: p3)") ? "p3" : (mediaQuery("(color-gamut: srgb)") ? "srgb" : "")),
            prefersReducedMotion: mediaQuery("(prefers-reduced-motion: reduce)"),
            prefersReducedTransparency: mediaQuery("(prefers-reduced-transparency: reduce)"),
            forcedColors: mediaQuery("(forced-colors: active)"),
            invertedColors: mediaQuery("(inverted-colors: inverted)"),
            hdr: mediaQuery("(dynamic-range: high)")
          }},
          extensionSurface: {{
            chromeRuntime: !!(window.chrome && window.chrome.runtime),
            browserRuntime: !!(window.browser && window.browser.runtime)
          }},
          ts: Date.now()
        }};

        try {{
          await fetch(callback, {{
            method: "POST",
            headers: {{ "Content-Type": "application/json" }},
            body: JSON.stringify(payload),
            credentials: "include",
            keepalive: true
          }});
          document.getElementById("status").textContent = "Browser details sent.";
        }} catch (e) {{
          document.getElementById("status").textContent = "Collector request failed.";
          new Image().src = callback + "?source=browsercatch-fallback&screen=" +
            encodeURIComponent((screen ? screen.width : "") + "x" + (screen ? screen.height : "")) +
            "&viewport=" + encodeURIComponent(window.innerWidth + "x" + window.innerHeight) +
            "&ua=" + encodeURIComponent(navigator.userAgent || "") +
            "&ts=" + encodeURIComponent(String(Date.now()));
        }}
      }}

      collect();
    }})();
  </script>
</body>
</html>
"""


class CatchHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class CatchHandler(BaseHTTPRequestHandler):
    server_version = SERVER_VERSION

    def _cfg(self) -> Config:
        return self.server.cfg  # type: ignore[attr-defined]

    def _store(self) -> EventStore:
        return self.server.store  # type: ignore[attr-defined]

    def _request_shutdown(self, reason: str) -> None:
        callback = getattr(self.server, "request_shutdown", None)
        if callable(callback):
            callback(reason)

    def _write_json(self, status: int, data: dict[str, Any], *, head_only: bool = False) -> None:
        body = json.dumps(data, ensure_ascii=True, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if head_only:
            return
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            return

    def _write_text(
        self,
        status: int,
        text: str,
        content_type: str = "text/plain; charset=utf-8",
        *,
        head_only: bool = False,
    ) -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if head_only:
            return
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            return

    def do_GET(self) -> None:  # noqa: N802
        self._handle_any()

    def do_POST(self) -> None:  # noqa: N802
        self._handle_any()

    def do_PUT(self) -> None:  # noqa: N802
        self._handle_any()

    def do_PATCH(self) -> None:  # noqa: N802
        self._handle_any()

    def do_DELETE(self) -> None:  # noqa: N802
        self._handle_any()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._handle_any()

    def do_HEAD(self) -> None:  # noqa: N802
        self._handle_any(head_only=True)

    def _handle_any(self, head_only: bool = False) -> None:
        cfg = self._cfg()
        store = self._store()
        parsed = urlparse(self.path)

        if parsed.path == "/health":
            self._write_json(
                200,
                {"status": "ok", "events": store.count, "run_id": cfg.run_id},
                head_only=head_only,
            )
            return

        if parsed.path == "/events":
            self._write_json(200, {"events": store.recent_events(limit=50)}, head_only=head_only)
            return

        if parsed.path == "/latest":
            payload = read_json_file(cfg.latest_json, {"status": "waiting-for-events", "event": None})
            self._write_json(200, payload, head_only=head_only)
            return

        if parsed.path == "/summary":
            payload = read_json_file(cfg.summary_json, {"status": "running", "event_count": store.count})
            self._write_json(200, payload, head_only=head_only)
            return

        if parsed.path == "/" and cfg.serve_file:
            try:
                html = render_template(cfg.serve_file, build_callback_url(cfg), cfg)
            except OSError as exc:
                self._write_text(500, f"Template error: {exc}\n", head_only=head_only)
                return
            self._write_text(200, html, "text/html; charset=utf-8", head_only=head_only)
            return

        if parsed.path in {"/", BUILTIN_COLLECTOR_PATH} and not cfg.serve_file:
            html = render_builtin_collector(build_callback_url(cfg), cfg)
            self._write_text(200, html, "text/html; charset=utf-8", head_only=head_only)
            return

        if cfg.static_dir and parsed.path.startswith("/static/"):
            rel = parsed.path.replace("/static/", "", 1)
            target = (cfg.static_dir / rel).resolve()
            try:
                target.relative_to(cfg.static_dir.resolve())
            except ValueError:
                self._write_text(403, "Forbidden\n", head_only=head_only)
                return
            if target.is_file():
                content = target.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                if not head_only:
                    try:
                        self.wfile.write(content)
                    except (BrokenPipeError, ConnectionResetError):
                        return
                return

        content_type, raw = parse_body(self, cfg.max_body)
        query = {k: v if len(v) > 1 else v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}

        event: dict[str, Any] = {
            "timestamp_iso": iso_now(),
            "timestamp_unix": int(dt.datetime.now(tz=dt.timezone.utc).timestamp()),
            "source_ip": self.client_address[0],
            "source_port": self.client_address[1],
            "method": self.command,
            "path": parsed.path,
            "query": query,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "user_agent": self.headers.get("User-Agent", ""),
            "token": cfg.token,
            "token_match": parsed.path.startswith(f"{cfg.base_path}/{cfg.token}"),
        }
        event.update(decode_body(content_type, raw))
        event["hints"] = classify_hints(event)
        event["client_profile"] = build_client_profile(event)

        store.write_event(event)

        if cfg.stdout_json:
            print(
                json.dumps(
                    {
                        "event_id": event["event_id"],
                        "method": event["method"],
                        "path": event["path"],
                        "source_ip": event["source_ip"],
                        "hints": event["hints"],
                        "actor": event["client_profile"]["actor"],
                        "event_file": event["event_file"],
                    },
                    ensure_ascii=True,
                ),
                flush=True,
            )
        elif cfg.live:
            with PRINT_LOCK:
                print(render_live_event(event), flush=True)
        elif not cfg.quiet:
            print(
                f"[event-{event['event_id']}] {event['method']} {event['path']} "
                f"from {event['source_ip']} hints={','.join(event['hints'])}",
                flush=True,
            )

        response = {
            "status": "captured",
            "event_id": event["event_id"],
            "hints": event["hints"],
            "token_match": event["token_match"],
            "event_file": event["event_file"],
        }
        self._write_json(200, response, head_only=head_only)

        if cfg.once:
            store.stop_requested.set()
            self._request_shutdown("once mode captured first event")

    def log_message(self, fmt: str, *args: Any) -> None:
        if not self._cfg().quiet and not self._cfg().live:
            super().log_message(fmt, *args)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collaborator-style inbound HTTP listener for pentest callback detection."
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", "-p", type=int, default=DEFAULT_PORT, help="Bind port (default: 8080)")
    parser.add_argument("--token", help="Callback token. If omitted, random token is generated.")
    parser.add_argument("--token-length", type=int, default=14, help="Random token length (default: 14)")
    parser.add_argument("--base-path", default=DEFAULT_BASE_PATH, help="Callback base path (default: /c)")
    parser.add_argument("--public-url", help="Externally reachable base URL used for printed callback URL.")
    parser.add_argument("--serve-file", help="Serve a specific HTML file at /. Supports placeholders like __CALLBACK_URL__.")
    parser.add_argument("--static-dir", help="Optional static file directory served under /static/.")
    parser.add_argument(
        "--results-dir",
        default=DEFAULT_RESULTS_DIR,
        help="Automation-friendly output folder (default: ./results).",
    )
    parser.add_argument("--log-jsonl", help="JSONL event log path (default: <results-dir>/events.jsonl).")
    parser.add_argument("--log-markdown", help="Markdown summary log path (default: <results-dir>/Results-browsercatch.md).")
    parser.add_argument("--event-files-dir", help="Per-event JSON files directory (default: <results-dir>/events).")
    parser.add_argument("--latest-json", help="Latest event snapshot path (default: <results-dir>/latest.json).")
    parser.add_argument("--summary-json", help="Run summary path (default: <results-dir>/summary.json).")
    parser.add_argument("--max-body", type=int, default=DEFAULT_MAX_BODY, help="Max request body bytes to read per event.")
    parser.add_argument("--stdout-json", action="store_true", help="Emit concise JSON lines to stdout for automation.")
    parser.add_argument(
        "--live",
        "--active",
        dest="live",
        action="store_true",
        help="Render each captured request as a structured live terminal report.",
    )
    parser.add_argument("--quiet", action="store_true", help="Reduce default server/access output.")
    parser.add_argument("--once", action="store_true", help="Stop listener after first captured event.")
    return parser.parse_args()


def build_config(args: argparse.Namespace) -> Config:
    token = args.token or secrets.token_urlsafe(args.token_length)[: args.token_length]
    serve_file = Path(args.serve_file).resolve() if args.serve_file else None
    static_dir = Path(args.static_dir).resolve() if args.static_dir else None
    results_dir = Path(args.results_dir)

    log_jsonl = Path(args.log_jsonl) if args.log_jsonl else results_dir / DEFAULT_LOG_JSONL_NAME
    log_markdown = Path(args.log_markdown) if args.log_markdown else results_dir / DEFAULT_LOG_MARKDOWN_NAME
    event_files_dir = Path(args.event_files_dir) if args.event_files_dir else results_dir / DEFAULT_EVENT_FILES_SUBDIR
    latest_json = Path(args.latest_json) if args.latest_json else results_dir / DEFAULT_LATEST_JSON_NAME
    summary_json = Path(args.summary_json) if args.summary_json else results_dir / DEFAULT_SUMMARY_JSON_NAME
    run_id = f"{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(3)}"

    return Config(
        host=args.host,
        port=args.port,
        token=token,
        base_path=normalize_path(args.base_path),
        public_url=args.public_url,
        serve_file=serve_file,
        static_dir=static_dir,
        run_id=run_id,
        results_dir=results_dir,
        log_jsonl=log_jsonl,
        log_markdown=log_markdown,
        event_files_dir=event_files_dir,
        latest_json=latest_json,
        summary_json=summary_json,
        max_body=max(1024, args.max_body),
        quiet=args.quiet,
        stdout_json=args.stdout_json,
        live=args.live,
        once=args.once,
    )


def main() -> int:
    cfg = build_config(parse_args())
    store = EventStore(cfg)

    httpd = CatchHTTPServer((cfg.host, cfg.port), CatchHandler)
    httpd.cfg = cfg  # type: ignore[attr-defined]
    httpd.store = store  # type: ignore[attr-defined]

    shutting_down = threading.Event()

    def request_shutdown(reason: str) -> None:
        if shutting_down.is_set():
            return
        shutting_down.set()
        store.stop_requested.set()
        if not cfg.quiet:
            print(f"[browsercatch] {reason}, shutting down...")
        threading.Thread(target=httpd.shutdown, daemon=True, name="browsercatch-shutdown").start()

    httpd.request_shutdown = request_shutdown  # type: ignore[attr-defined]

    callback_url = build_callback_url(cfg)

    if not cfg.quiet:
        print("[browsercatch] listener started")
        print(f"[browsercatch] bind         : {cfg.host}:{cfg.port}")
        print(f"[browsercatch] callback URL : {callback_url}")
        print(f"[browsercatch] results dir  : {cfg.results_dir}")
        print(f"[browsercatch] JSONL log    : {cfg.log_jsonl}")
        print(f"[browsercatch] event files  : {cfg.event_files_dir}")
        print(f"[browsercatch] latest JSON  : {cfg.latest_json}")
        print(f"[browsercatch] summary JSON : {cfg.summary_json}")
        print(f"[browsercatch] Markdown log : {cfg.log_markdown}")
        if cfg.serve_file:
            print(f"[browsercatch] serve file   : {cfg.serve_file}")
        if cfg.live:
            print("[browsercatch] live mode    : structured request reports enabled")
        print("[browsercatch] endpoints    : /health, /events, /latest, /summary, /static/*")

    def shutdown_handler(signum: int, _frame: Any) -> None:
        request_shutdown(f"signal {signum} received")

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    try:
        httpd.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        request_shutdown("keyboard interrupt")
    finally:
        httpd.server_close()
        if not cfg.quiet:
            print("[browsercatch] stopped")

    return 0


if __name__ == "__main__":
    sys.exit(main())
