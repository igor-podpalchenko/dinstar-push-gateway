#!/usr/bin/env python3
from __future__ import annotations

import argparse
import socket
import uuid
from datetime import UTC, datetime


def build_body(sender: str, gateway_gsm: str, target: str, text: str, timestamp: str) -> str:
    lines = [
        "Dinstar inbound SMS",
        f"Gateway GSM: {gateway_gsm}",
        f"Forwarded to SIP: {target}",
        f"From: {sender}",
        f"Timestamp: {timestamp}",
        "",
        text,
    ]
    return "\r\n".join(lines)


def send_message(
    *,
    host: str,
    port: int,
    target: str,
    sender: str,
    gateway_gsm: str,
    from_domain: str,
    text: str,
    timeout: float,
) -> int:
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    body = build_body(sender=sender, gateway_gsm=gateway_gsm, target=target, text=text, timestamp=now)
    branch = f"z9hG4bK-{uuid.uuid4().hex}"
    tag = uuid.uuid4().hex[:10]
    call_id = f"{uuid.uuid4().hex}@{from_domain}"

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.connect((host, port))
        local_ip, local_port = sock.getsockname()

        request = "\r\n".join(
            [
                f"MESSAGE sip:{target}@{host} SIP/2.0",
                f"Via: SIP/2.0/UDP {local_ip}:{local_port};branch={branch}",
                "Max-Forwards: 70",
                f'From: "{sender}" <sip:{sender}@{from_domain}>;tag={tag}',
                f"To: <sip:{target}@{host}>",
                f"Call-ID: {call_id}",
                "CSeq: 1 MESSAGE",
                f"Contact: <sip:dinstar-push@{local_ip}:{local_port}>",
                "Content-Type: text/plain; charset=utf-8",
                f"Content-Length: {len(body.encode('utf-8'))}",
                "",
                body,
            ]
        ).encode("utf-8")

        print(f"local_ip={local_ip} local_port={local_port}")
        sock.send(request)

        while True:
            response = sock.recv(65535).decode("utf-8", errors="replace")
            print("--- response ---")
            print(response)
            status_line = response.splitlines()[0].strip() if response else ""
            parts = status_line.split()
            if len(parts) >= 2 and parts[0].startswith("SIP/2.0"):
                status_code = int(parts[1])
                if status_code >= 200:
                    return status_code


def main() -> int:
    parser = argparse.ArgumentParser(description="Send a test SIP SIMPLE MESSAGE to Asterisk over UDP.")
    parser.add_argument("--host", default="192.168.1.170", help="Asterisk host")
    parser.add_argument("--port", type=int, default=5060, help="Asterisk UDP port")
    parser.add_argument("--target", default="1000", help="Target SIP extension")
    parser.add_argument("--sender", default="+38097000000", help="Displayed sender in the SIP From header")
    parser.add_argument("--gateway-gsm", default="+3805000000", help="Receiving GSM number shown in the test body")
    parser.add_argument("--from-domain", default="dinstar-push.local", help="Domain used in SIP From/Call-ID")
    parser.add_argument(
        "--text",
        default="Test SIP SIMPLE delivery from scripts/test_sip_message.py.",
        help="Message body tail text",
    )
    parser.add_argument("--timeout", type=float, default=5.0, help="UDP receive timeout in seconds")
    args = parser.parse_args()

    status_code = send_message(
        host=args.host,
        port=args.port,
        target=args.target,
        sender=args.sender,
        gateway_gsm=args.gateway_gsm,
        from_domain=args.from_domain,
        text=args.text,
        timeout=args.timeout,
    )
    return 0 if 200 <= status_code < 300 else 1


if __name__ == "__main__":
    raise SystemExit(main())
