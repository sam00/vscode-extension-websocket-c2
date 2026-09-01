# Using with Mythic (WebSocket C2 profile)

This extension implements the Mythic WebSocket profile wire protocol
(`aes256_hmac` envelope, optional EKE staging).

## 1. Create the payload in Mythic

1. Mythic UI → **Payloads** → **Create New Payload**
2. Choose any agent type that supports the **websocket** C2 profile
   (Poseidon, Hades, etc.). You are only doing this to mint a
   payload UUID + AES PSK; you will not deploy the generated binary.
3. Under C2 profiles, add **websocket** and configure:
   - `callback_host`: your redirector hostname/IP
   - `callback_port`: `443`
   - `ENDPOINT_REPLACE`: `/`
   - `encrypted_exchange_check`: `false` (simplest) — or `true` if you want
     RSA EKE staging (supported by this extension via
     `encryptedExchangeCheck: true`)
4. Build the payload.

## 2. Extract the config values

From the build output (or the payload's details page), note:

- **Payload UUID** → `payloadUUID`
- **AESPSK** (base64) → `aesPSK`
- **callback_host / port / endpoint** → `wsUrl`

Fill these into `config.json`:

```json
{
  "wsUrl": "wss://redirector.example.com:443/",
  "payloadUUID": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "aesPSK": "base64key==",
  "encryptedExchangeCheck": false
}
```

## 3. Traffic shape

- One persistent `wss://` connection per agent.
- Client frames are JSON text: `{"client": true, "data": "<b64 envelope>", "tag": ""}`
- Envelope: `base64( UUID[36] + IV[16] + AES-256-CBC(JSON) + HMAC-SHA256[32] )`
- Before checkin completes, the envelope UUID is the payload UUID; after
  checkin it is the assigned callback UUID.

## 4. Recommended redirector

Terminate TLS at the redirector and pass the WebSocket upgrade through to the
Mythic websocket profile container, e.g. with nginx:

```nginx
location / {
    proxy_pass http://127.0.0.1:WS_PROFILE_PORT;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_read_timeout 3600s;
}
```

Point `wsUrl` at the redirector — never directly at the Mythic host.
