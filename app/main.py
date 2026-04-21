from __future__ import annotations

import asyncio
import base64
import hashlib
import html
import io
import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import pycurl
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from starlette.datastructures import UploadFile

DUMP_DIR = Path(os.getenv("DUMP_DIR", "/dumps"))
MAX_INLINE_FILE_BYTES = int(os.getenv("MAX_INLINE_FILE_BYTES", "1048576"))
GATEWAY_BASE_URL = os.getenv("GATEWAY_BASE_URL", "https://192.168.15.127").rstrip("/")
GATEWAY_USERPWD = os.getenv("GATEWAY_USERPWD", "admin:admin")
GATEWAY_SEND_SMS_PATH = os.getenv("GATEWAY_SEND_SMS_PATH", "/api/send_sms")
ALL_METHODS = [
    "DELETE",
    "GET",
    "HEAD",
    "OPTIONS",
    "PATCH",
    "POST",
    "PUT",
    "TRACE",
]

app = FastAPI(
    title="Dinstar Push Gateway",
    description="Catch-all HTTP endpoint that stores every request as a JSON dump.",
    version="0.1.0",
)


class SendSmsRequest(BaseModel):
    text: str = Field(..., min_length=1, description="SMS message text")
    numbers: list[str] = Field(..., min_length=1, description="Destination phone numbers")
    ports: list[int] = Field(default_factory=lambda: [0], min_length=1, description="Gateway ports to use")
    request_status_report: bool = Field(default=True, description="Ask Dinstar for delivery status reporting")
    user_id_start: int = Field(default=1, ge=1, description="Starting user_id used for generated recipients")


class GatewaySettings(BaseModel):
    base_url: str
    userpwd: str
    send_sms_path: str

    @property
    def send_sms_url(self) -> str:
        return f"{self.base_url}{self.send_sms_path}"

    @property
    def username(self) -> str:
        username, _, _password = self.userpwd.partition(":")
        return username

    @property
    def password(self) -> str:
        _username, separator, password = self.userpwd.partition(":")
        if not separator:
            raise ValueError("GATEWAY_USERPWD must be in the form username:password")
        return password

    @property
    def masked_userpwd(self) -> str:
        return f"{self.username}:********"

    @property
    def uses_https(self) -> bool:
        return self.base_url.lower().startswith("https://")


def utc_now() -> datetime:
    return datetime.now(UTC)


def ensure_dump_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def collapse_multi_items(items: list[tuple[str, Any]]) -> dict[str, list[Any]]:
    data: dict[str, list[Any]] = {}
    for key, value in items:
        data.setdefault(key, []).append(value)
    return data


def make_dump_path(timestamp: datetime, request_id: str, prefix: str = "request") -> Path:
    dated_dir = DUMP_DIR / timestamp.strftime("%Y") / timestamp.strftime("%m") / timestamp.strftime("%d")
    ensure_dump_dir(dated_dir)
    filename = f"{timestamp.strftime('%H%M%S_%f')}_{prefix}_{request_id}.json"
    return dated_dir / filename


def decode_text(raw_body: bytes) -> str | None:
    if not raw_body:
        return ""
    try:
        return raw_body.decode("utf-8")
    except UnicodeDecodeError:
        return None


def summarize_body(raw_body: bytes, content_type: str | None) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "size_bytes": len(raw_body),
        "sha256": hashlib.sha256(raw_body).hexdigest(),
        "content_type": content_type,
    }
    if not raw_body:
        summary["text"] = ""
        return summary

    text_body = decode_text(raw_body)
    if text_body is not None:
        summary["text"] = text_body
        if content_type and "application/json" in content_type:
            try:
                summary["json"] = json.loads(text_body)
            except json.JSONDecodeError as exc:
                summary["json_error"] = str(exc)
        elif content_type and "application/x-www-form-urlencoded" in content_type:
            summary["form_urlencoded"] = parse_qs(text_body, keep_blank_values=True)
    else:
        summary["base64"] = base64.b64encode(raw_body).decode("ascii")

    return summary


def get_gateway_settings() -> GatewaySettings:
    return GatewaySettings(
        base_url=GATEWAY_BASE_URL,
        userpwd=GATEWAY_USERPWD,
        send_sms_path=GATEWAY_SEND_SMS_PATH,
    )


def build_sms_payload(payload: SendSmsRequest) -> dict[str, Any]:
    params = [
        {
            "number": number,
            "user_id": payload.user_id_start + index,
        }
        for index, number in enumerate(payload.numbers)
    ]
    return {
        "text": payload.text,
        "port": payload.ports,
        "param": params,
        "request_status_report": payload.request_status_report,
    }


def parse_http_header_blocks(raw_headers: str) -> tuple[list[dict[str, Any]], dict[str, str]]:
    blocks: list[dict[str, Any]] = []
    current_status_line: str | None = None
    current_headers: dict[str, str] = {}

    for raw_line in raw_headers.splitlines():
        line = raw_line.strip().rstrip("\r")
        if not line:
            if current_status_line is not None or current_headers:
                blocks.append(
                    {
                        "status_line": current_status_line,
                        "headers": current_headers,
                    }
                )
            current_status_line = None
            current_headers = {}
            continue

        if line.upper().startswith("HTTP/"):
            if current_status_line is not None or current_headers:
                blocks.append(
                    {
                        "status_line": current_status_line,
                        "headers": current_headers,
                    }
                )
            current_status_line = line
            current_headers = {}
            continue

        if ":" in line and current_status_line is not None:
            name, value = line.split(":", 1)
            current_headers[name.strip()] = value.strip()

    if current_status_line is not None or current_headers:
        blocks.append(
            {
                "status_line": current_status_line,
                "headers": current_headers,
            }
        )

    final_headers = {}
    for block in reversed(blocks):
        if block.get("status_line"):
            final_headers = block["headers"]
            break
    return blocks, final_headers


def get_header_ignore_case(headers: dict[str, str], name: str) -> str | None:
    target = name.lower()
    for header_name, value in headers.items():
        if header_name.lower() == target:
            return value
    return None


def send_sms_via_pycurl_sync(settings: GatewaySettings, sms_payload: dict[str, Any]) -> dict[str, Any]:
    payload_json = json.dumps(sms_payload, ensure_ascii=False)
    body_buffer = io.BytesIO()
    header_buffer = io.BytesIO()
    curl = pycurl.Curl()
    try:
        curl.setopt(pycurl.URL, settings.send_sms_url)
        curl.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_ANY)
        curl.setopt(pycurl.USERPWD, settings.userpwd)
        curl.setopt(pycurl.HTTPHEADER, ["Content-Type: application/json;"])
        curl.setopt(pycurl.POST, 1)
        curl.setopt(pycurl.POSTFIELDS, payload_json.encode("utf-8"))
        curl.setopt(pycurl.FOLLOWLOCATION, 1)
        curl.setopt(pycurl.SSL_VERIFYPEER, 0)
        curl.setopt(pycurl.SSL_VERIFYHOST, 0)
        curl.setopt(pycurl.TIMEOUT, 30)
        curl.setopt(pycurl.CONNECTTIMEOUT, 10)
        curl.setopt(pycurl.WRITEDATA, body_buffer)
        curl.setopt(pycurl.HEADERFUNCTION, header_buffer.write)
        curl.perform()
        status_code = curl.getinfo(pycurl.RESPONSE_CODE)
        effective_url = curl.getinfo(pycurl.EFFECTIVE_URL)
    except pycurl.error as exc:
        errno, message = exc.args
        raise RuntimeError(f"pycurl error {errno}: {message}") from exc
    finally:
        curl.close()

    raw_headers = header_buffer.getvalue().decode("iso-8859-1", errors="replace")
    header_blocks, final_headers = parse_http_header_blocks(raw_headers)
    content_type = get_header_ignore_case(final_headers, "content-type")

    return {
        "status_code": status_code,
        "effective_url": effective_url,
        "headers": final_headers,
        "header_blocks": header_blocks,
        "raw_headers": raw_headers,
        "body": summarize_body(body_buffer.getvalue(), content_type),
        "pycurl_options": {
            "httpauth": "any",
            "followlocation": True,
            "ssl_verifypeer": False,
            "ssl_verifyhost": False,
            "timeout_seconds": 30,
        },
    }


async def send_sms_via_pycurl(settings: GatewaySettings, sms_payload: dict[str, Any]) -> dict[str, Any]:
    return await asyncio.to_thread(send_sms_via_pycurl_sync, settings, sms_payload)


def build_gateway_html(settings: GatewaySettings) -> str:
    default_config = {
        "gatewayBaseUrl": settings.base_url,
        "sendSmsUrl": "/api/send-sms",
        "defaultPorts": "0",
        "statusReport": True,
    }
    transport_label = (
        "HTTP auth any, HTTPS with SSL verification disabled, sent by pycurl"
        if settings.uses_https
        else "HTTP Basic over plain HTTP"
    )
    intro_transport = (
        "HTTPS with disabled SSL verification"
        if settings.uses_https
        else "plain HTTP"
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Dinstar SMS Console</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f4efe6;
      --panel: #fffaf2;
      --border: #d8ccb7;
      --ink: #1e2430;
      --muted: #6a7587;
      --accent: #0b6e4f;
      --accent-2: #e0f1dc;
      --danger: #8f2d2d;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
      background:
        radial-gradient(circle at top left, rgba(224, 241, 220, 0.95), transparent 35%),
        linear-gradient(135deg, #f4efe6, #efe8db 55%, #e6edf2);
      color: var(--ink);
      min-height: 100vh;
    }}
    main {{
      max-width: 960px;
      margin: 0 auto;
      padding: 32px 20px 48px;
    }}
    .hero {{
      margin-bottom: 24px;
    }}
    h1 {{
      margin: 0 0 8px;
      font-size: clamp(2rem, 4vw, 3.2rem);
      line-height: 1;
      letter-spacing: -0.04em;
    }}
    .sub {{
      margin: 0;
      color: var(--muted);
      max-width: 760px;
      font-size: 1.02rem;
    }}
    .grid {{
      display: grid;
      grid-template-columns: 1.2fr 0.8fr;
      gap: 20px;
    }}
    .card {{
      background: rgba(255, 250, 242, 0.94);
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 20px;
      box-shadow: 0 18px 50px rgba(62, 76, 89, 0.08);
      backdrop-filter: blur(6px);
    }}
    label {{
      display: block;
      margin: 0 0 8px;
      font-weight: 600;
      font-size: 0.95rem;
    }}
    input, textarea {{
      width: 100%;
      border: 1px solid #c6baa6;
      border-radius: 12px;
      padding: 12px 14px;
      font: inherit;
      background: rgba(255, 255, 255, 0.85);
      color: var(--ink);
    }}
    textarea {{
      min-height: 120px;
      resize: vertical;
    }}
    .row {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
    }}
    .field {{
      margin-bottom: 16px;
    }}
    .toggle {{
      display: flex;
      align-items: center;
      gap: 10px;
      margin: 8px 0 20px;
    }}
    .toggle input {{
      width: 18px;
      height: 18px;
    }}
    button {{
      border: 0;
      border-radius: 999px;
      padding: 13px 22px;
      font: inherit;
      font-weight: 700;
      cursor: pointer;
      background: linear-gradient(135deg, var(--accent), #0c8d63);
      color: white;
      box-shadow: 0 10px 25px rgba(11, 110, 79, 0.26);
    }}
    button:disabled {{
      opacity: 0.65;
      cursor: wait;
    }}
    pre {{
      margin: 0;
      white-space: pre-wrap;
      word-break: break-word;
      font-family: "SFMono-Regular", "Consolas", monospace;
      font-size: 0.9rem;
    }}
    .meta {{
      display: grid;
      gap: 10px;
      color: var(--muted);
      font-size: 0.95rem;
    }}
    .status {{
      min-height: 24px;
      font-weight: 600;
      margin-bottom: 14px;
    }}
    .status.ok {{ color: var(--accent); }}
    .status.error {{ color: var(--danger); }}
    .hint {{
      margin-top: 12px;
      color: var(--muted);
      font-size: 0.92rem;
    }}
    @media (max-width: 800px) {{
      .grid, .row {{
        grid-template-columns: 1fr;
      }}
      main {{
        padding-inline: 14px;
      }}
    }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <h1>Dinstar SMS Console</h1>
      <p class="sub">This page calls the local gateway API, which forwards the request to the Dinstar UC2000 over {html.escape(intro_transport)} with HTTP basic auth, matching the behavior of your PHP cURL snippet.</p>
    </section>

    <section class="grid">
      <form class="card" id="sms-form">
        <div class="field">
          <label for="numbers">Phone Numbers</label>
          <textarea id="numbers" name="numbers" placeholder="One number per line, or comma-separated"></textarea>
        </div>

        <div class="field">
          <label for="message">Message</label>
          <textarea id="message" name="message" placeholder="Type the SMS text here"></textarea>
        </div>

        <div class="row">
          <div class="field">
            <label for="ports">Ports</label>
            <input id="ports" name="ports" value="0" placeholder="Example: 0 or 0,1">
          </div>
          <div class="field">
            <label for="user-id-start">Starting user_id</label>
            <input id="user-id-start" name="userIdStart" type="number" min="1" value="1">
          </div>
        </div>

        <label class="toggle">
          <input id="status-report" name="requestStatusReport" type="checkbox" checked>
          <span>Request delivery status report</span>
        </label>

        <button id="submit-button" type="submit">Send SMS</button>
        <p class="hint">Configured gateway: {html.escape(settings.base_url)}<br>Configured user: {html.escape(settings.username)}</p>
      </form>

      <section class="card">
        <div id="status" class="status">Idle</div>
        <div class="meta">
          <div>Backend API: <code>/api/send-sms</code></div>
          <div>Gateway endpoint: <code>{html.escape(settings.send_sms_url)}</code></div>
          <div>Auth mode: {html.escape(transport_label)}</div>
        </div>
        <div style="margin-top: 18px;">
          <pre id="result">Submit a message to see the gateway response here.</pre>
        </div>
      </section>
    </section>
  </main>

  <script>
    const config = {json.dumps(default_config)};
    const form = document.getElementById("sms-form");
    const submitButton = document.getElementById("submit-button");
    const result = document.getElementById("result");
    const status = document.getElementById("status");

    function parseList(value) {{
      return value
        .split(/[\\n,]/)
        .map((item) => item.trim())
        .filter(Boolean);
    }}

    form.addEventListener("submit", async (event) => {{
      event.preventDefault();
      status.textContent = "Sending...";
      status.className = "status";
      submitButton.disabled = true;
      result.textContent = "Waiting for gateway response...";

      const payload = {{
        text: document.getElementById("message").value.trim(),
        numbers: parseList(document.getElementById("numbers").value),
        ports: parseList(document.getElementById("ports").value).map((item) => Number(item)),
        request_status_report: document.getElementById("status-report").checked,
        user_id_start: Number(document.getElementById("user-id-start").value || 1)
      }};

      try {{
        const response = await fetch(config.sendSmsUrl, {{
          method: "POST",
          headers: {{
            "Content-Type": "application/json"
          }},
          body: JSON.stringify(payload)
        }});
        const data = await response.json();
        result.textContent = JSON.stringify(data, null, 2);
        if (response.ok) {{
          status.textContent = "Gateway request sent";
          status.className = "status ok";
        }} else {{
          status.textContent = "Gateway request failed";
          status.className = "status error";
        }}
      }} catch (error) {{
        status.textContent = "Request failed";
        status.className = "status error";
        result.textContent = String(error);
      }} finally {{
        submitButton.disabled = false;
      }}
    }});
  </script>
</body>
</html>"""


async def serialize_upload(upload: UploadFile) -> dict[str, Any]:
    content = await upload.read()
    await upload.seek(0)
    serialized: dict[str, Any] = {
        "kind": "file",
        "filename": upload.filename,
        "content_type": upload.content_type,
        "size_bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }
    if len(content) <= MAX_INLINE_FILE_BYTES:
        serialized["base64"] = base64.b64encode(content).decode("ascii")
    else:
        serialized["base64_omitted"] = True
    return serialized


async def parse_form_data(request: Request) -> tuple[dict[str, list[Any]] | None, str | None]:
    content_type = request.headers.get("content-type", "")
    if "multipart/form-data" not in content_type and "application/x-www-form-urlencoded" not in content_type:
        return None, None

    try:
        form = await request.form()
    except Exception as exc:  # pragma: no cover - defensive guard for unexpected payloads
        return None, str(exc)

    result: dict[str, list[Any]] = {}
    for key, value in form.multi_items():
        if isinstance(value, UploadFile):
            result.setdefault(key, []).append(await serialize_upload(value))
        else:
            result.setdefault(key, []).append(value)
    return result, None


async def build_dump(request: Request, full_path: str) -> tuple[dict[str, Any], str]:
    request_id = uuid.uuid4().hex
    timestamp = utc_now()
    raw_body = await request.body()
    form_data, form_error = await parse_form_data(request)

    dump: dict[str, Any] = {
        "request_id": request_id,
        "captured_at_utc": timestamp.isoformat(),
        "request": {
            "method": request.method,
            "url": str(request.url),
            "base_url": str(request.base_url),
            "path": request.url.path,
            "captured_path_parameter": full_path,
            "query_string": request.url.query,
            "path_params": dict(request.path_params),
            "query_params": collapse_multi_items(list(request.query_params.multi_items())),
            "headers": dict(request.headers),
            "cookies": request.cookies,
            "client": {
                "host": request.client.host if request.client else None,
                "port": request.client.port if request.client else None,
            },
            "http_version": request.scope.get("http_version"),
        },
        "body": summarize_body(raw_body, request.headers.get("content-type")),
    }

    if form_data is not None:
        dump["body"]["form"] = form_data
    if form_error is not None:
        dump["body"]["form_error"] = form_error

    dump_path = make_dump_path(timestamp, request_id)
    dump_path.write_text(json.dumps(dump, indent=2, ensure_ascii=False), encoding="utf-8")
    return dump, str(dump_path)


def write_json_dump(payload: dict[str, Any], prefix: str) -> str:
    timestamp = utc_now()
    request_id = uuid.uuid4().hex
    dump_path = make_dump_path(timestamp, request_id, prefix=prefix)
    dump_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return str(dump_path)


@app.get("/healthz")
async def healthcheck() -> dict[str, str]:
    ensure_dump_dir(DUMP_DIR)
    return {"status": "ok"}


@app.get("/sms", response_class=HTMLResponse)
async def sms_page() -> HTMLResponse:
    ensure_dump_dir(DUMP_DIR)
    return HTMLResponse(build_gateway_html(get_gateway_settings()))


@app.post("/api/send-sms")
async def send_sms(payload: SendSmsRequest) -> JSONResponse:
    ensure_dump_dir(DUMP_DIR)
    settings = get_gateway_settings()
    sms_payload = build_sms_payload(payload)
    request_dump = {
        "captured_at_utc": utc_now().isoformat(),
        "gateway": {
            "base_url": settings.base_url,
            "send_sms_url": settings.send_sms_url,
            "userpwd": settings.masked_userpwd,
            "driver": "pycurl",
            "verify_ssl": False,
            "follow_redirects": True,
            "httpauth": "any",
        },
        "request_payload": sms_payload,
    }

    try:
        response_data = await send_sms_via_pycurl(settings, sms_payload)
    except ValueError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    except RuntimeError as exc:
        request_dump["error"] = {
            "type": "PycurlRequestError",
            "message": str(exc),
        }
        saved_to = write_json_dump(request_dump, prefix="gateway_send_sms_error")
        return JSONResponse(
            status_code=502,
            content={
                "ok": False,
                "error": str(exc),
                "saved_to": saved_to,
                "gateway_url": settings.send_sms_url,
            },
        )

    request_dump["response"] = {
        "status_code": response_data["status_code"],
        "effective_url": response_data["effective_url"],
        "headers": response_data["headers"],
        "header_blocks": response_data["header_blocks"],
        "raw_headers": response_data["raw_headers"],
        "body": response_data["body"],
        "pycurl_options": response_data["pycurl_options"],
    }
    saved_to = write_json_dump(request_dump, prefix="gateway_send_sms")

    content = {
        "ok": 200 <= response_data["status_code"] < 300,
        "saved_to": saved_to,
        "gateway": {
            "url": response_data["effective_url"],
            "userpwd": settings.masked_userpwd,
        },
        "request_payload": sms_payload,
        "gateway_response": {
            "status_code": response_data["status_code"],
            "headers": response_data["headers"],
            "body": response_data["body"],
            "pycurl_options": response_data["pycurl_options"],
        },
    }
    return JSONResponse(status_code=response_data["status_code"], content=content)


@app.api_route("/", methods=ALL_METHODS)
@app.api_route("/{full_path:path}", methods=ALL_METHODS)
async def capture_request(request: Request, full_path: str = "") -> JSONResponse:
    ensure_dump_dir(DUMP_DIR)
    dump, dump_path = await build_dump(request, full_path)
    return JSONResponse(
        {
            "ok": True,
            "request_id": dump["request_id"],
            "saved_to": dump_path,
        }
    )
