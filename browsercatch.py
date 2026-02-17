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
import sys
import threading
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
        finding_line = f"- event-{event['event_id']}: {event['method']} {event['path']} from {source_ip} | hints: {hints}"

        if summary_header in lines:
            idx = lines.index(summary_header)
            insert_at = idx + 1
            if finding_line not in lines:
                lines.insert(insert_at, finding_line)

        note_line = (
            f"- event-{event['event_id']}: ua={event.get('user_agent', '')} "
            f"query_keys={','.join(sorted(event.get('query', {}).keys())) if event.get('query') else '-'}"
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

    if event.get("token_match"):
        hints.add("token-matched-callback")

    if not hints:
        hints.add("unclassified-callback")

    return sorted(hints)


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

        if parsed.path == "/" and not cfg.serve_file:
            info = (
                "BrowserCatch listener is running.\n"
                f"Callback URL: {build_callback_url(cfg)}\n"
                f"Results folder: {cfg.results_dir}\n"
                "Use /health, /events, /latest, /summary.\n"
            )
            self._write_text(200, info, head_only=head_only)
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
                        "event_file": event["event_file"],
                    },
                    ensure_ascii=True,
                ),
                flush=True,
            )
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
        if not self._cfg().quiet:
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
