# Dinstar Push Gateway

FastAPI service for two jobs:

- capture every inbound Dinstar push request as JSON
- send outbound SMS through the Dinstar UC2000-VE HTTP API
- forward inbound Dinstar SMS events to Asterisk as SIP `MESSAGE`

The original idea was to point the Dinstar UC2000-VE "New Version" push URL at this service first, observe the exact payloads the gateway sends, and only then implement a stricter integration. That recorder is still in place, and now there is also a simple SMS sender UI and API.

## What it captures

Each request is saved as an individual JSON file under `./dumps` locally or `/dumps` inside the container. Every dump includes:

- HTTP method
- Full URL and query string
- Headers and cookies
- Client IP and port
- Path parameters and query parameters
- Raw request body summary
- Parsed JSON payload when applicable
- Parsed form fields for `application/x-www-form-urlencoded` and `multipart/form-data`
- Uploaded file metadata, hashes, and inline base64 for small files

## Run with Docker

Start:

```bash
docker compose up -d
```

Health check:

```bash
curl http://localhost:24800/healthz
```

Example capture test:

```bash
curl -X POST "http://localhost:24800/test/path?foo=bar&foo=baz" \
  -H "Content-Type: application/json" \
  -d '{"hello":"world"}'
```

Captured dumps are written into:

- Host: `/volume3/docker/dinstar-push-gateway/dumps`
- Container: `/dumps`

## Configuration

The Compose file now passes the Dinstar connection settings through environment variables:

- `GATEWAY_BASE_URL=https://192.168.15.127`
- `GATEWAY_USERPWD=admin:...`
- `GATEWAY_SEND_SMS_PATH=/api/send_sms`
- `ASTERISK_HOST=192.168.1.170`
- `ASTERISK_PORT=5065`
- `FORWARD_TO_SIP=0:1000`
- `SIP_FROM_DOMAIN=dinstar-push.local`

If the password contains `#` or other YAML-sensitive characters, quote the whole value in `docker-compose.yml`.

These settings are used by the SMS sender endpoint and web page. The HTTP client behavior intentionally matches your PHP cURL snippet as closely as practical:

- HTTP basic auth
- JSON `Content-Type`
- POST request
- follow redirects
- SSL peer verification disabled
- SSL host verification disabled
- forwarding performed by Python `pycurl` so the send path stays in Python while still matching the original cURL behavior closely

`FORWARD_TO_SIP` is a comma-separated or newline-separated list of routing rules in the form `port:sip_extension`. Example:

```text
0:1000
```

The gateway now prefers direct `port` matching for inbound SMS, which is more reliable because the Dinstar inbound `sms` event always contains `port`. For example, with your dumps:

- `imsi=25501123322342`
- `port=0`
- `gsm_number=38067000001`

So `0:1000` routes inbound SMS received on modem port `0` to SIP extension `1000`.

## Inbound SMS forwarding to Asterisk

When a push payload contains:

```json
{"sms":[...]}
```

the gateway now:

1. resolves which GSM number received the SMS using the saved Dinstar register state
2. matches the inbound SMS `port` against `FORWARD_TO_SIP`
3. sends a SIP `MESSAGE` over UDP to Asterisk at `ASTERISK_HOST:ASTERISK_PORT`
4. writes a `push_processing_*.json` dump with the forwarding result

If you configure Asterisk to challenge SIP `MESSAGE` requests, the gateway can retry once with SIP digest auth using `SIP_USERNAME` and `SIP_PASSWORD`. In the dedicated-port no-auth setup, those variables can be omitted.

For a direct host-side SIP SIMPLE probe outside the gateway runtime, you can use:

```bash
python3 scripts/test_sip_message.py --host 192.168.1.170 --port 5065 --target 1000
```

The SIP message body includes:

- receiving GSM number
- target SIP extension
- sender number or alphanumeric sender
- SMSC
- port
- timestamp
- IMSI
- original text

If Asterisk is unreachable, no route matches, or the GSM number cannot be resolved yet, the original Dinstar capture still succeeds and the failure reason is recorded in the processing dump.

## SMS UI and API

Open the web page:

```text
http://YOUR_SERVER_IP:24800/sms
```

The page calls the backend API:

```text
POST /api/send-sms
```

Example request:

```bash
curl -X POST http://localhost:24800/api/send-sms \
  -H "Content-Type: application/json" \
  -d '{
    "text": "hello from gateway",
    "numbers": ["380XXXXXXXXX"],
    "ports": [0],
    "request_status_report": true,
    "user_id_start": 1
  }'
```

The backend transforms that into the Dinstar gateway payload shape and forwards it to:

```text
https://192.168.15.127/api/send_sms
```

Each outbound SMS attempt is also written to the dump volume, including:

- rendered gateway payload
- target URL
- masked credentials
- gateway response headers
- gateway response body

## Pointing UC2000-VE to this gateway

In the Dinstar web UI, go to `Mobile Configuration -> Basic Configuration`, select `API -> New Version`, enable the push events you want to observe, and set the URL to this service, for example:

```text
http://YOUR_SERVER_IP:24800/dinstar/push
```

Because the FastAPI app is catch-all, it will also accept `/`, `/api/...`, or any other path you configure on the device.

For SIP forwarding to work after a restart, keep Dinstar `Push Register Status` enabled as well so the app can rebuild the GSM-number-to-IMSI/port mapping automatically.

## Dinstar HTTP API research

The most relevant official reference I found is the Dinstar PDF `Dinstar GSM Gateway HTTP API (v201910)`. It documents the "new version" HTTP API and states that:

- The API is HTTP plus JSON.
- The feature must be enabled in `Mobile Configuration -> Basic Configuration` by selecting `new-version API`.
- Support requires gateway firmware `1102` or later.
- Requests use gateway authentication; the examples use HTTP basic auth with the gateway username and password.

### Send SMS

Official request shape:

```text
POST https://gateway_ip/api/send_sms
Content-Type: application/json
Authorization: Basic ...
```

Typical request body:

```json
{
  "text": "test message",
  "port": [0],
  "param": [
    {
      "number": "380XXXXXXXXX",
      "user_id": 1
    }
  ],
  "request_status_report": true
}
```

The same document also shows a templated variant using `#param#` in `text` and matching `text_param` arrays per recipient. Dinstar recommends using a unique `user_id` per destination so you can correlate later results back to your original request.

Typical accepted response:

```json
{
  "error_code": 202,
  "sn": "xxxx-xxxx-xxxx-xxxx",
  "sms_in_queue": 1,
  "task_id": 1
}
```

The `task_id` is then used with:

- `POST /api/query_sms_result`
- `POST /api/query_sms_deliver_status`
- `POST /api/get_port_info`
- `POST /api/get_status`

Example `curl` against the gateway:

```bash
curl -k --anyauth -u admin:admin \
  -H "Content-Type: application/json" \
  -d '{"text":"test message","port":[0],"param":[{"number":"380XXXXXXXXX","user_id":1}],"request_status_report":true}' \
  https://GATEWAY_IP/api/send_sms
```

### Notes for our capture phase

- Dinstar supports multiple push types from the UI, including Push SMS, Push SMS Result, Push SMS Deliver Status, Push USSD, Push Device, Push CDR, and others.
- The official PDF includes push payload examples, but we still want to capture the real requests from your specific UC2000-VE firmware and configuration before we implement business logic.
- Official push examples from the PDF include:

```json
{"sn":"xxxx-xxxx-xxxx-xxxx","sms":[{"incoming_sms_id":1,"port":1,"number":"6717","smsc":"+8613800757511","timestamp":"2016-07-12 15:46:18","text":"test"}]}
```

```json
{"sn":"xxxx-xxxx-xxxx-xxxx","sms_result":[{"port":1,"number":"10086","time":"2016-07-12 01:46:02","status":"DELIVERED","count":1,"succ_count":1,"ref_id":215,"imsi":"4600"}]}
```

```json
{"sn":"xxxx-xxxx-xxxx-xxxx","sms_deliver_status":[{"port":1,"number":"10086","time":"2016-07-12 15:46:53","ref_id":215,"status_code":0,"imsi":"4600"}]}
```

```json
{"sn":"xxxx-xxxx-xxxx-xxxx","ussd":[{"port":1,"text":"Thank you!"}]}
```
- Dinstar also has an official technical blog post explaining how to inspect UC2000 HTTP API logs to determine which channel was used when sending SMS.

## Official sources

- Dinstar HTTP API PDF: https://www.dinstar.com/WEB/files/15278/2018-10-19/Dinstar%20GSM%20Gateway%20HTTP%20API%28v201910%29.pdf
- UC2000-VE product page: https://www.dinstar.com/GSM-3G-LTE-voip-gateway/4-8-ports
- Dinstar tools page: https://www.dinstar.com/tools/
- Dinstar technical guide on HTTP API log analysis: https://www.dinstar.com/blog/technical-guide/how-to-analyze-which-channel-is-included-in-http-api-log/
