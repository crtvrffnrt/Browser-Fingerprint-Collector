# Browser Fingerprint Collector (BrowserCatch)

`browsercatch.py` is a lightweight collaborator-style inbound listener designed for authorized pentesting workflows!

It captures inbound HTTP callbacks (GET/POST/PUT/PATCH/DELETE/OPTIONS/HEAD), logs request details, and adds quick risk hints for possible SSRF, RCE-probe, CSRF, and XSS-beacon style traffic.

## What This Project Is For
- Blind callback detection during web/API pentests
- Alternative to external collaborator services when you want a local script
- Easy integration with Gemini CLI skills/agents

## Key Capabilities
- Multi-method inbound capture
- Tokenized callback paths (`/c/<token>` by default)
- Structured logs:
  - JSONL event stream for automation
  - Per-event JSON files for file watcher pipelines
  - `latest.json` + `summary.json` snapshots for polling-based tools
  - Markdown summary with incremental run log
- Built-in endpoints:
  - `/health` for liveness
  - `/events` for recent captured events
  - `/latest` for the latest captured event snapshot
  - `/summary` for run metadata and hint counters
- Optional HTML lure/template serving with placeholder replacement
- Single-shot mode (`--once`) for automation jobs
- Clean one-shot `Ctrl+C` shutdown on Debian/Linux (`SIGINT`/`SIGTERM` guarded)

## Quick Start

```bash
cd Browser-Fingerprint-Collector
python3 browsercatch.py --port 8080
```

The script prints a callback URL like:

```text
http://127.0.0.1:8080/c/<token>
```

## CLI Usage

```bash
python3 browsercatch.py [flags]
```

### Common Flags
- `--host 0.0.0.0` bind interface
- `--port 8080` listener port
- `--token abc123` fixed callback token (optional)
- `--base-path /c` callback path prefix
- `--public-url https://your-domain.tld` printed callback base for external targets
- `--serve-file index.html` serve a custom HTML template at `/`
- `--static-dir .` expose files under `/static/*`
- `--results-dir results` base folder for automation outputs
- `--stdout-json` emit concise JSON event lines for automation
- `--once` stop after first captured event
- `--log-jsonl results/events.jsonl`
- `--log-markdown results/Results-browsercatch.md`
- `--event-files-dir results/events`
- `--latest-json results/latest.json`
- `--summary-json results/summary.json`

## HTML Template Placeholders
When using `--serve-file`, these placeholders are auto-replaced:
- `__CALLBACK_URL__`
- `__TOKEN__`
- `__LISTENER_HOST__`
- `__LISTENER_PORT__`

## Example Runs

### 1) Basic listener
```bash
python3 browsercatch.py --port 8080
```

### 2) Serve test template and stop on first callback!
```bash
python3 browsercatch.py \
  --port 8080 \
  --serve-file index-interactwebhook.html \
  --once
```

### 3) Gemini-friendly JSON output
```bash
python3 browsercatch.py --port 8080 --stdout-json --quiet
```

### 4) Force all machine outputs into `./results` for tooling
```bash
python3 browsercatch.py \
  --port 8080 \
  --results-dir results \
  --stdout-json
```

### 5) Public callback URL for remote target testing
```bash
python3 browsercatch.py \
  --host 0.0.0.0 \
  --port 8080 \
  --public-url https://collab.example.com
```

## Logs
By default:
- `results/events.jsonl` contains one JSON object per request
- `results/events/event-*.json` is an append-only per-event stream for file-watch automations
- `results/latest.json` always contains the most recent event
- `results/summary.json` tracks run stats (`event_count`, unique IPs, hint counters, paths)
- `results/Results-browsercatch.md` keeps compact cumulative notes and run history

## Notes
- Use only on authorized targets and scopes.
- Keep listener reachable from target infrastructure (NAT/firewall/DNS).
