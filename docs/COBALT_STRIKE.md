# Using with Cobalt Strike (External C2 bridge)

Cobalt Strike does not natively speak the Mythic WebSocket envelope. To use
this extension with Cobalt Strike, run a small bridge that:

1. Accepts the extension's WebSocket connection (same JSON frame format),
2. Translates tasking to/from Cobalt Strike's **External C2** interface
   (named pipe / TCP listener).

```
extension ──WSS──> bridge ──External C2──> Cobalt Strike team server
```

## Bridge skeleton (Python)

```python
import asyncio, json, base64, websockets

CS_HOST, CS_PORT = "127.0.0.1", 2222   # External C2 listener (TCP)

async def handle(ws):
    cs = asyncio.open_connection(CS_HOST, CS_PORT)
    # Translate frames:
    #   extension -> bridge: {"client": true, "data": b64_payload}
    #   bridge -> CS: External C2 framing (4-byte length + payload)
    #   CS -> bridge: tasking
    #   bridge -> extension: {"data": b64_response}
    ...

async def main():
    async with websockets.serve(handle, "0.0.0.0", 443):
        await asyncio.Future()

asyncio.run(main())
```

## Design notes

- Cobalt Strike's External C2 spec uses a simple length-prefixed binary
  framing (`[4-byte len][payload]`). The bridge owns the translation; the
  extension does not need to know it is talking to CS.
- If you want encrypted envelopes on the extension side, reuse the Mythic
  envelope format (`aes256_hmac`) and decrypt in the bridge — the key and
  UUID are whatever you put in `config.json`; they need not correspond to a
  Mythic payload at all.
- Alternatively, skip encryption in the bridge deployment
  (`aesPSK` may be any 32-byte base64 value used only by your bridge).

## References

- Cobalt Strike External C2 specification (Help → Arsenal → External C2)
- `external-c2` example controllers in the Cobalt Strike Arsenal kit
