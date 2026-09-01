# Custom listener — wire protocol reference

Use this spec to implement a compatible listener for any C2 framework.

## Transport

- WebSocket (`ws://` or `wss://`), JSON **text** frames.
- Client → server frame: `{"client": true, "data": "<base64 envelope>", "tag": ""}`
- Server → client frame: `{"client": false, "data": "<base64 envelope>", "tag": ""}`

## Envelope (aes256_hmac)

```
plaintext  = UTF-8 JSON message
IV         = 16 random bytes
ct         = AES-256-CBC-PKCS7(key, IV, plaintext)
mac        = HMAC-SHA256(key, IV || ct)
envelope   = base64( uuid[36 bytes ASCII] || IV || ct || mac )
```

- `key` is the 32-byte value from `aesPSK` (base64-decoded), or the EKE
  session key if staging was performed.
- `uuid` is the `payloadUUID` before checkin, and the assigned callback UUID
  afterwards.

## Message flow

### 1. Checkin (agent → server)

```json
{
  "action": "checkin",
  "uuid": "<payloadUUID>",
  "os": "Darwin 25.6.0",
  "architecture": "x86_64",
  "user": "operator",
  "host": "workstation",
  "pid": 1234,
  "ip": "10.0.0.5",
  "domain": "",
  "integrity_level": 2,
  "external_ip": "",
  "process_name": "extension-host"
}
```

Server responds:

```json
{ "action": "checkin", "status": "success", "id": "<callbackUUID>" }
```

### 2. Optional EKE staging (when `encryptedExchangeCheck: true`)

Agent sends:

```json
{
  "action": "staging_rsa",
  "pub_key": "<base64 PEM, SPKI, RSA-4096>",
  "session_id": "<20 alnum>"
}
```

Server responds with `session_key`: the fresh 32-byte AES key, RSA-encrypted
with the agent's public key (**RSA-OAEP, SHA-1** hash) and base64-encoded:

```json
{ "action": "staging_rsa", "session_id": "...", "session_key": "<b64>", "uuid": "<callbackUUID>" }
```

All subsequent envelopes use the session key.

### 3. Tasking (agent polls)

```json
{ "action": "get_tasking", "tasking_size": -1, "delegates": [] }
```

Server responds (possibly empty):

```json
{
  "action": "get_tasking",
  "tasks": [
    { "id": "<task uuid>", "command": "shell", "parameters": "whoami" }
  ]
}
```

### 4. Response (agent → server)

```json
{
  "action": "post_response",
  "responses": [
    { "task_id": "<task uuid>", "user_output": "...", "completed": true, "status": "success" }
  ],
  "delegates": []
}
```

## Commands the agent implements

| Command | Parameters | Behavior |
|---|---|---|
| `shell` | string | run via system shell (`/bin/zsh` / `cmd.exe`) |
| `cd` / `pwd` / `ls` / `cat` | path string or `{"path": ...}` | filesystem ops |
| `download` | path | base64 file contents in `user_output` |
| `upload` | `{"path", "content"(b64)}` | write file |
| `whoami` / `hostname` / `id` / `ps` / `ifconfig` / `getenv` | — | host recon |
| `sleep` | `{"interval": N}` | change poll interval |
| `exit` | — | stop agent loop |

Any unrecognized command is executed as `<command> <parameters>` via the shell.
