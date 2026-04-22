from __future__ import annotations

import asyncio
import base64
import hashlib
import html
import io
import json
import os
import re
import secrets
import socket
import threading
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
ASTERISK_HOST = os.getenv("ASTERISK_HOST", "").strip()
ASTERISK_PORT = int(os.getenv("ASTERISK_PORT", "5060"))
FORWARD_TO_SIP = os.getenv("FORWARD_TO_SIP", "").strip()
SIP_FROM_DOMAIN = os.getenv("SIP_FROM_DOMAIN", "dinstar-push.local").strip() or "dinstar-push.local"
SIP_USERNAME = os.getenv("SIP_USERNAME", "dinstar-http-gw").strip() or "dinstar-http-gw"
SIP_PASSWORD = os.getenv("SIP_PASSWORD", "").strip()
REGISTER_STATE_PATH = DUMP_DIR / "_runtime_state.json"
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


class SipForwardRoute(BaseModel):
    port: str
    sip_number: str


class AsteriskSettings(BaseModel):
    host: str
    port: int
    from_domain: str
    sip_username: str
    sip_password: str
    forward_to_sip: list[SipForwardRoute]

    @property
    def enabled(self) -> bool:
        return bool(self.host and self.forward_to_sip)


class RegisterState(BaseModel):
    updated_at_utc: str | None = None
    numbers_by_imsi: dict[str, str] = Field(default_factory=dict)
    numbers_by_port: dict[str, str] = Field(default_factory=dict)
    last_register_events: list[dict[str, Any]] = Field(default_factory=list)


REGISTER_STATE_LOCK = threading.Lock()
REGISTER_STATE = RegisterState()


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


def normalize_phone_number(value: str | int | None) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    keep_plus = text.startswith("+")
    digits = "".join(character for character in text if character.isdigit())
    if not digits:
        return text.lower()
    return f"+{digits}" if keep_plus else digits


def sanitize_sip_user(value: str | int | None, fallback: str = "sms") -> str:
    text = str(value or "").strip()
    sanitized = re.sub(r"[^A-Za-z0-9_.!~*'()%&=+$,;?/-]", "-", text)
    sanitized = sanitized.strip("-")
    return sanitized or fallback


def parse_forward_to_sip(raw_value: str) -> list[SipForwardRoute]:
    if not raw_value.strip():
        return []

    routes: list[SipForwardRoute] = []
    parts = [item.strip() for item in re.split(r"[\n,]+", raw_value) if item.strip()]
    for part in parts:
        if ":" not in part:
            raise ValueError(f"Invalid FORWARD_TO_SIP entry '{part}'. Expected port:sip_number")
        port, sip_number = part.rsplit(":", 1)
        port = port.strip()
        sip_number = sip_number.strip()
        if not port or not sip_number or not port.isdigit():
            raise ValueError(f"Invalid FORWARD_TO_SIP entry '{part}'. Expected port:sip_number")
        routes.append(
            SipForwardRoute(
                port=port,
                sip_number=sip_number,
            )
        )
    return routes


def get_gateway_settings() -> GatewaySettings:
    return GatewaySettings(
        base_url=GATEWAY_BASE_URL,
        userpwd=GATEWAY_USERPWD,
        send_sms_path=GATEWAY_SEND_SMS_PATH,
    )


def get_asterisk_settings() -> AsteriskSettings:
    return AsteriskSettings(
        host=ASTERISK_HOST,
        port=ASTERISK_PORT,
        from_domain=SIP_FROM_DOMAIN,
        sip_username=SIP_USERNAME,
        sip_password=SIP_PASSWORD,
        forward_to_sip=parse_forward_to_sip(FORWARD_TO_SIP),
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


def load_register_state() -> RegisterState:
    if not REGISTER_STATE_PATH.exists():
        return RegisterState()
    try:
        return RegisterState.model_validate_json(REGISTER_STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return RegisterState()


def save_register_state(state: RegisterState) -> None:
    REGISTER_STATE_PATH.write_text(state.model_dump_json(indent=2), encoding="utf-8")


def rebuild_register_state_from_dumps() -> RegisterState:
    rebuilt = RegisterState()
    latest_register_events: list[dict[str, Any]] = []
    latest_timestamp: str | None = None

    for dump_path in sorted(DUMP_DIR.rglob("*.json")):
        if dump_path == REGISTER_STATE_PATH:
            continue
        try:
            payload = json.loads(dump_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue

        body_json = payload.get("body", {}).get("json")
        if not isinstance(body_json, dict):
            continue

        register_events = body_json.get("register")
        if not isinstance(register_events, list) or not register_events:
            continue

        for register_event in register_events:
            number = str(register_event.get("number") or "").strip()
            imsi = str(register_event.get("imsi") or "").strip()
            port = register_event.get("port")
            if number:
                if imsi:
                    rebuilt.numbers_by_imsi[imsi] = number
                if port is not None:
                    rebuilt.numbers_by_port[str(port)] = number

        timestamp = str(payload.get("captured_at_utc") or "")
        if timestamp and (latest_timestamp is None or timestamp >= latest_timestamp):
            latest_timestamp = timestamp
            latest_register_events = register_events

    rebuilt.updated_at_utc = latest_timestamp
    rebuilt.last_register_events = latest_register_events
    return rebuilt


def get_register_state() -> RegisterState:
    with REGISTER_STATE_LOCK:
        global REGISTER_STATE
        if not REGISTER_STATE.updated_at_utc and REGISTER_STATE_PATH.exists():
            REGISTER_STATE = load_register_state()
        if not REGISTER_STATE.numbers_by_imsi and not REGISTER_STATE.numbers_by_port:
            REGISTER_STATE = rebuild_register_state_from_dumps()
            if REGISTER_STATE.numbers_by_imsi or REGISTER_STATE.numbers_by_port:
                save_register_state(REGISTER_STATE)
        return RegisterState.model_validate(REGISTER_STATE.model_dump())


def update_register_state(register_events: list[dict[str, Any]]) -> RegisterState:
    timestamp = utc_now().isoformat()
    with REGISTER_STATE_LOCK:
        global REGISTER_STATE
        if not REGISTER_STATE.updated_at_utc and REGISTER_STATE_PATH.exists():
            REGISTER_STATE = load_register_state()

        for register_event in register_events:
            number = str(register_event.get("number") or "").strip()
            imsi = str(register_event.get("imsi") or "").strip()
            port = register_event.get("port")
            if number:
                if imsi:
                    REGISTER_STATE.numbers_by_imsi[imsi] = number
                if port is not None:
                    REGISTER_STATE.numbers_by_port[str(port)] = number

        REGISTER_STATE.updated_at_utc = timestamp
        REGISTER_STATE.last_register_events = register_events
        save_register_state(REGISTER_STATE)
        return RegisterState.model_validate(REGISTER_STATE.model_dump())


def resolve_gsm_number_for_sms(sms_event: dict[str, Any], state: RegisterState) -> str | None:
    imsi = str(sms_event.get("imsi") or "").strip()
    if imsi and imsi in state.numbers_by_imsi:
        return state.numbers_by_imsi[imsi]

    port = sms_event.get("port")
    if port is not None:
        return state.numbers_by_port.get(str(port))

    return None


def find_forward_route_for_sms(
    settings: AsteriskSettings,
    sms_event: dict[str, Any],
) -> SipForwardRoute | None:
    sms_port = sms_event.get("port")
    for route in settings.forward_to_sip:
        if str(route.port) == str(sms_port):
            return route
    return None


def build_forward_message_body(
    sms_event: dict[str, Any],
    matched_gsm_number: str | None,
    target_extension: str,
) -> str:
    lines = [
        "Dinstar inbound SMS",
        f"Gateway GSM: {matched_gsm_number or 'unknown'}",
        f"Forwarded to SIP: {target_extension}",
        f"From: {sms_event.get('number') or 'unknown'}",
        f"SMSC: {sms_event.get('smsc') or 'unknown'}",
        f"Port: {sms_event.get('port') if sms_event.get('port') is not None else 'unknown'}",
        f"Timestamp: {sms_event.get('timestamp') or 'unknown'}",
        f"IMSI: {sms_event.get('imsi') or 'unknown'}",
        "",
        str(sms_event.get("text") or ""),
    ]
    return "\r\n".join(lines)


def parse_sip_response(response_packet: str) -> tuple[int | None, str | None, dict[str, str]]:
    lines = response_packet.splitlines()
    status_line = lines[0].strip() if lines else None
    status_code: int | None = None
    if status_line:
        parts = status_line.split()
        if len(parts) >= 2 and parts[0].upper().startswith("SIP/2.0"):
            try:
                status_code = int(parts[1])
            except ValueError:
                status_code = None

    headers: dict[str, str] = {}
    for line in lines[1:]:
        stripped = line.strip()
        if not stripped:
            break
        if ":" not in stripped:
            continue
        name, value = stripped.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    return status_code, status_line, headers


def parse_digest_challenge(header_value: str) -> dict[str, str]:
    challenge = header_value.strip()
    if challenge.lower().startswith("digest "):
        challenge = challenge[7:].strip()

    attributes: dict[str, str] = {}
    for key, quoted, unquoted in re.findall(r'(\w+)=("([^"]*)"|[^,]+)', challenge):
        attributes[key.lower()] = quoted[1:-1] if quoted.startswith('"') else unquoted.strip()
    return attributes


def build_sip_digest_authorization(
    *,
    username: str,
    password: str,
    realm: str,
    nonce: str,
    uri: str,
    method: str,
    algorithm: str,
    qop: str | None,
    opaque: str | None,
) -> str:
    algorithm_name = algorithm or "MD5"
    if algorithm_name.upper() != "MD5":
        raise RuntimeError(f"Unsupported SIP digest algorithm: {algorithm_name}")

    ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode("utf-8")).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode("utf-8")).hexdigest()

    if qop:
        cnonce = secrets.token_hex(8)
        nc_value = "00000001"
        response = hashlib.md5(f"{ha1}:{nonce}:{nc_value}:{cnonce}:{qop}:{ha2}".encode("utf-8")).hexdigest()
        fields = [
            f'username="{username}"',
            f'realm="{realm}"',
            f'nonce="{nonce}"',
            f'uri="{uri}"',
            f'response="{response}"',
            f'algorithm={algorithm_name}',
            f'qop={qop}',
            f'nc={nc_value}',
            f'cnonce="{cnonce}"',
        ]
    else:
        response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode("utf-8")).hexdigest()
        fields = [
            f'username="{username}"',
            f'realm="{realm}"',
            f'nonce="{nonce}"',
            f'uri="{uri}"',
            f'response="{response}"',
            f'algorithm={algorithm_name}',
        ]

    if opaque:
        fields.append(f'opaque="{opaque}"')
    return "Digest " + ", ".join(fields)


def send_sip_message_sync(
    settings: AsteriskSettings,
    target_extension: str,
    sms_event: dict[str, Any],
    matched_gsm_number: str | None,
) -> dict[str, Any]:
    request_id = uuid.uuid4().hex
    sender = str(sms_event.get("number") or "sms")
    from_display = sender.replace('"', "'")
    from_user = sanitize_sip_user(sender, fallback="sms")
    body = build_forward_message_body(sms_event, matched_gsm_number, target_extension)
    branch = f"z9hG4bK-{uuid.uuid4().hex}"
    tag = uuid.uuid4().hex[:10]
    call_id = f"{uuid.uuid4().hex}@{settings.from_domain}"
    to_uri = f"sip:{sanitize_sip_user(target_extension, fallback='1000')}@{settings.host}"

    raw_response_packets: list[str] = []
    final_status_code: int | None = None
    final_status_line: str | None = None

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3.0)
        sock.connect((settings.host, settings.port))
        local_ip, local_port = sock.getsockname()
        auth_attempted = False

        def send_request(cseq: int, authorization_header: str | None = None) -> None:
            request_lines = [
                f"MESSAGE {to_uri} SIP/2.0",
                f"Via: SIP/2.0/UDP {local_ip}:{local_port};branch={branch}",
                "Max-Forwards: 70",
                f'From: "{from_display}" <sip:{from_user}@{settings.from_domain}>;tag={tag}',
                f"To: <{to_uri}>",
                f"Call-ID: {call_id}",
                f"CSeq: {cseq} MESSAGE",
                f"Contact: <sip:dinstar-push@{local_ip}:{local_port}>",
            ]
            if authorization_header:
                request_lines.append(authorization_header)
            request_lines.extend(
                [
                    "Content-Type: text/plain; charset=utf-8",
                    f"Content-Length: {len(body.encode('utf-8'))}",
                    "",
                    body,
                ]
            )
            sock.send("\r\n".join(request_lines).encode("utf-8"))

        send_request(cseq=1)

        while True:
            response_packet = sock.recv(65535).decode("utf-8", errors="replace")
            raw_response_packets.append(response_packet)
            status_code, status_line, headers = parse_sip_response(response_packet)
            if status_code is None:
                continue

            final_status_code = status_code
            final_status_line = status_line

            if status_code in {401, 407} and settings.sip_password and not auth_attempted:
                challenge_header_name = "www-authenticate" if status_code == 401 else "proxy-authenticate"
                challenge_header_value = headers.get(challenge_header_name)
                if not challenge_header_value:
                    break
                challenge = parse_digest_challenge(challenge_header_value)
                qop_options = challenge.get("qop")
                qop = None
                if qop_options:
                    qop = qop_options.split(",")[0].strip()
                auth_value = build_sip_digest_authorization(
                    username=settings.sip_username,
                    password=settings.sip_password,
                    realm=challenge.get("realm", ""),
                    nonce=challenge.get("nonce", ""),
                    uri=to_uri,
                    method="MESSAGE",
                    algorithm=challenge.get("algorithm", "MD5"),
                    qop=qop,
                    opaque=challenge.get("opaque"),
                )
                header_name = "Authorization" if status_code == 401 else "Proxy-Authorization"
                auth_attempted = True
                send_request(cseq=2, authorization_header=f"{header_name}: {auth_value}")
                continue

            if status_code >= 200:
                break

    if final_status_code is None:
        raise RuntimeError("Asterisk did not return a SIP response")
    if final_status_code >= 300:
        raise RuntimeError(f"Asterisk rejected SIP MESSAGE: {final_status_line}")

    return {
        "request_id": request_id,
        "target_extension": target_extension,
        "target_uri": to_uri,
        "matched_gsm_number": matched_gsm_number,
        "status_code": final_status_code,
        "status_line": final_status_line,
        "request_body": body,
        "raw_response_packets": raw_response_packets,
    }


async def send_sip_message(
    settings: AsteriskSettings,
    target_extension: str,
    sms_event: dict[str, Any],
    matched_gsm_number: str | None,
) -> dict[str, Any]:
    return await asyncio.to_thread(
        send_sip_message_sync,
        settings,
        target_extension,
        sms_event,
        matched_gsm_number,
    )


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


async def process_push_payload(dump: dict[str, Any], dump_path: str) -> dict[str, Any] | None:
    body_json = dump.get("body", {}).get("json")
    if not isinstance(body_json, dict):
        return None

    processing: dict[str, Any] = {
        "captured_at_utc": utc_now().isoformat(),
        "source_request_id": dump["request_id"],
        "source_dump_path": dump_path,
    }
    changed = False

    register_events = body_json.get("register")
    if isinstance(register_events, list) and register_events:
        register_state = update_register_state(register_events)
        processing["register"] = {
            "events": register_events,
            "state": register_state.model_dump(),
        }
        changed = True

    sms_events = body_json.get("sms")
    if isinstance(sms_events, list) and sms_events:
        asterisk_settings = get_asterisk_settings()
        register_state = get_register_state()
        sms_results: list[dict[str, Any]] = []

        for sms_event in sms_events:
            result: dict[str, Any] = {
                "sms_event": sms_event,
            }
            matched_gsm_number = resolve_gsm_number_for_sms(sms_event, register_state)
            result["matched_gsm_number"] = matched_gsm_number

            route = find_forward_route_for_sms(asterisk_settings, sms_event)
            if route is None:
                result["forwarded"] = False
                if not asterisk_settings.enabled:
                    result["reason"] = "SIP forwarding is not enabled"
                else:
                    result["reason"] = "No FORWARD_TO_SIP route matched the inbound SMS port"
            else:
                try:
                    response = await send_sip_message(
                        asterisk_settings,
                        route.sip_number,
                        sms_event,
                        matched_gsm_number,
                    )
                except (OSError, TimeoutError, RuntimeError) as exc:
                    result["forwarded"] = False
                    result["target_sip_number"] = route.sip_number
                    result["error"] = str(exc)
                else:
                    result["forwarded"] = True
                    result["target_sip_number"] = route.sip_number
                    result["sip_response"] = response

            sms_results.append(result)

        processing["sms_forwarding"] = {
            "asterisk": {
                "host": asterisk_settings.host or None,
                "port": asterisk_settings.port,
                "forward_to_sip": [route.model_dump() for route in asterisk_settings.forward_to_sip],
            },
            "results": sms_results,
        }
        changed = True

    if not changed:
        return None

    processing_dump_path = write_json_dump(processing, prefix="push_processing")
    processing["saved_to"] = processing_dump_path
    return processing


@app.get("/healthz")
async def healthcheck() -> dict[str, str]:
    ensure_dump_dir(DUMP_DIR)
    get_register_state()
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
    processing = await process_push_payload(dump, dump_path)
    response = {
        "ok": True,
        "request_id": dump["request_id"],
        "saved_to": dump_path,
    }
    if processing is not None:
        response["processing"] = processing
    return JSONResponse(response)
