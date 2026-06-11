import webview
import json
import os
import re
import base64
import ctypes
import ctypes.wintypes
import ssl
import urllib.request

# ── DPAPI decryption ──────────────────────────────────────────────────────────

class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", ctypes.wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_char))
    ]

def dpapi_decrypt(encrypted_bytes):
    inp = DATA_BLOB(
        len(encrypted_bytes),
        ctypes.cast(ctypes.c_char_p(encrypted_bytes), ctypes.POINTER(ctypes.c_char))
    )
    out = DATA_BLOB()
    ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(inp), None, None, None, None, 0, ctypes.byref(out)
    )
    return ctypes.string_at(out.pbData, out.cbData)

def get_master_key(local_state_path):
    try:
        with open(local_state_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        raw_key = base64.b64decode(data["os_crypt"]["encrypted_key"])[5:]
        return dpapi_decrypt(raw_key)
    except Exception:
        return None

def aes_gcm_decrypt(key, payload):
    try:
        from Crypto.Cipher import AES
        nonce = payload[3:15]
        ciphertext = payload[15:-16]
        return AES.new(key, AES.MODE_GCM, nonce).decrypt(ciphertext).decode("utf-8", errors="ignore").strip("\x00").strip()
    except Exception:
        return ""

# ── Token extraction ──────────────────────────────────────────────────────────

TOKEN_REGEX = re.compile(r"[\w-]{24,26}\.[\w-]{6}\.[\w-]{25,110}")

def extract_tokens_from_leveldb(ldb_path, master_key):
    tokens = []
    if not os.path.exists(ldb_path):
        return tokens
    for filename in os.listdir(ldb_path):
        if not filename.endswith((".log", ".ldb")):
            continue
        try:
            raw = open(os.path.join(ldb_path, filename), "rb").read()
        except Exception:
            continue
        if master_key:
            for match in re.finditer(rb"v1[01].{12}.{15,200}", raw):
                token = aes_gcm_decrypt(master_key, match.group(0))
                if TOKEN_REGEX.fullmatch(token) and token not in tokens:
                    tokens.append(token)
        for token in TOKEN_REGEX.findall(raw.decode("utf-8", errors="ignore")):
            if token not in tokens:
                tokens.append(token)
    return tokens

def validate_token(token):
    try:
        request = urllib.request.Request(
            "https://discord.com/api/v9/users/@me",
            headers={
                "Authorization": token,
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                              "(KHTML, like Gecko) discord/1.0.9163 Chrome/124.0.6367.243 "
                              "Electron/30.4.0 Safari/537.36",
                "X-Super-Properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCIsInJlbGVhc2VfY2hhbm5lbCI6InN0YWJsZSJ9"
            }
        )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(request, timeout=5, context=ctx) as response:
            data = json.loads(response.read())
            return data.get("username")
    except Exception:
        return None

APPDATA       = os.getenv("APPDATA", "")
LOCAL_APPDATA = os.getenv("LOCALAPPDATA", "")

SOURCES = [
    # ── Official Discord clients
    ("Discord",        f"{APPDATA}\\discord\\Local State",                             f"{APPDATA}\\discord\\Local Storage\\leveldb"),
    ("Discord Canary", f"{APPDATA}\\discordcanary\\Local State",                       f"{APPDATA}\\discordcanary\\Local Storage\\leveldb"),
    ("Discord PTB",    f"{APPDATA}\\discordptb\\Local State",                          f"{APPDATA}\\discordptb\\Local Storage\\leveldb"),
    # ── Vencord / Equicord — Vesktop desktop app
    ("Vesktop",        f"{APPDATA}\\vesktop\\Local State",                             f"{APPDATA}\\vesktop\\Local Storage\\leveldb"),
    ("Vesktop",        f"{APPDATA}\\Vesktop\\Local State",                             f"{APPDATA}\\Vesktop\\Local Storage\\leveldb"),
    # ── Other modded clients
    ("Legcord",        f"{APPDATA}\\Legcord\\Local State",                             f"{APPDATA}\\Legcord\\Local Storage\\leveldb"),
    ("ArmCord",        f"{APPDATA}\\ArmCord\\Local State",                             f"{APPDATA}\\ArmCord\\Local Storage\\leveldb"),
    ("GoofCord",       f"{APPDATA}\\GoofCord\\Local State",                            f"{APPDATA}\\GoofCord\\Local Storage\\leveldb"),
    ("WebCord",        f"{APPDATA}\\WebCord\\Local State",                             f"{APPDATA}\\WebCord\\Local Storage\\leveldb"),
    # ── Browsers
    ("Chrome",         f"{LOCAL_APPDATA}\\Google\\Chrome\\User Data\\Local State",      f"{LOCAL_APPDATA}\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb"),
    ("Edge",           f"{LOCAL_APPDATA}\\Microsoft\\Edge\\User Data\\Local State",     f"{LOCAL_APPDATA}\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb"),
    ("Brave",          f"{LOCAL_APPDATA}\\BraveSoftware\\Brave-Browser\\User Data\\Local State", f"{LOCAL_APPDATA}\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb"),
    ("Opera",          f"{APPDATA}\\Opera Software\\Opera Stable\\Local State",         f"{APPDATA}\\Opera Software\\Opera Stable\\Local Storage\\leveldb"),
    ("Opera GX",       f"{APPDATA}\\Opera Software\\Opera GX Stable\\Local State",      f"{APPDATA}\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb"),
]

def find_all_tokens():
    results, seen = [], set()
    for source_name, local_state_path, ldb_path in SOURCES:
        master_key = get_master_key(local_state_path) if os.path.exists(local_state_path) else None
        for token in extract_tokens_from_leveldb(ldb_path, master_key):
            if token not in seen:
                seen.add(token)
                results.append({"source": source_name, "token": token})
    return results

# ── Clipboard — no subprocess, no CMD flash ───────────────────────────────────

def copy_to_clipboard(text):
    CF_UNICODETEXT = 13
    buf    = ctypes.create_unicode_buffer(text)
    size   = ctypes.sizeof(buf)
    handle = ctypes.windll.kernel32.GlobalAlloc(0x0002, size)
    ptr    = ctypes.windll.kernel32.GlobalLock(handle)
    ctypes.memmove(ptr, buf, size)
    ctypes.windll.kernel32.GlobalUnlock(handle)
    ctypes.windll.user32.OpenClipboard(0)
    ctypes.windll.user32.EmptyClipboard()
    ctypes.windll.user32.SetClipboardData(CF_UNICODETEXT, handle)
    ctypes.windll.user32.CloseClipboard()

# ── Python ↔ JS bridge ────────────────────────────────────────────────────────

class API:
    def scan(self):
        tokens = find_all_tokens()
        results = []
        for item in tokens:
            username = validate_token(item["token"])
            results.append({
                "source":   item["source"],
                "token":    item["token"],
                "valid":    bool(username),
                "username": username or ""
            })
        return json.dumps(results)

    def copy(self, text):
        copy_to_clipboard(text)

    def minimize(self):
        window.minimize()

    def close(self):
        window.destroy()

# ── UI ────────────────────────────────────────────────────────────────────────

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>TokenFinder</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }

:root {
  --bg:      #09090d;
  --bg2:     #101015;
  --bg3:     #18181e;
  --red:     #dc2626;
  --red2:    #ef4444;
  --red-dim: rgba(220,38,38,.15);
  --border:  rgba(220,38,38,.18);
  --text:    #f5f5f5;
  --sub:     #525252;
  --radius:  8px;
}

html, body {
  width: 100%; height: 100%; overflow: hidden;
  background: var(--bg);
  font-family: 'Inter', system-ui, sans-serif;
  color: var(--text);
  user-select: none;
}

/* ── Grid bg ── */
body::before {
  content: '';
  position: fixed; inset: 0; z-index: 0; pointer-events: none;
  background-image:
    linear-gradient(rgba(220,38,38,.04) 1px, transparent 1px),
    linear-gradient(90deg, rgba(220,38,38,.04) 1px, transparent 1px);
  background-size: 40px 40px;
}

/* ── Titlebar ── */
#titlebar {
  position: fixed; top: 0; left: 0; right: 0; height: 42px;
  display: flex; align-items: center; padding: 0 14px;
  background: rgba(9,9,13,.92); backdrop-filter: blur(20px);
  border-bottom: 1px solid var(--border);
  -webkit-app-region: drag; z-index: 100; gap: 9px;
}
.titlebar-icon {
  width: 20px; height: 20px; border-radius: 4px;
  background: var(--red); display: flex; align-items: center;
  justify-content: center; font-size: 10px; font-weight: 700;
  color: #fff; flex-shrink: 0; letter-spacing: -.5px;
}
.titlebar-name { font-size: 12px; font-weight: 600; color: var(--text); letter-spacing: .2px; }
.titlebar-ver  { font-size: 10px; color: var(--sub); }
.titlebar-controls {
  margin-left: auto; display: flex; gap: 2px;
  -webkit-app-region: no-drag;
}
.ctrl {
  width: 26px; height: 22px; border: none; background: transparent;
  color: var(--sub); font-size: 12px; cursor: pointer; border-radius: 4px;
  transition: background .12s, color .12s; display: flex;
  align-items: center; justify-content: center;
}
.ctrl:hover { background: rgba(255,255,255,.06); color: var(--text); }
.ctrl.x:hover { background: rgba(220,38,38,.2); color: var(--red); }

/* ── App ── */
#app {
  position: relative; z-index: 1;
  padding: 58px 20px 20px;
  height: 100vh; display: flex; flex-direction: column; gap: 14px;
}

/* ── Hero ── */
.hero { text-align: center; }
.hero-eyebrow {
  font-size: 10px; font-weight: 600; letter-spacing: 2px;
  color: var(--red); text-transform: uppercase; margin-bottom: 6px;
}
.hero-title {
  font-size: 24px; font-weight: 700; letter-spacing: -.5px; color: var(--text);
}
.hero-sub { font-size: 11px; color: var(--sub); margin-top: 4px; }

/* ── Scan button ── */
.scan-wrap { display: flex; justify-content: center; }
#scan-btn {
  display: flex; align-items: center; gap: 8px;
  padding: 9px 26px; border: 1px solid rgba(220,38,38,.4); border-radius: var(--radius);
  cursor: pointer; font-size: 12px; font-weight: 600; color: var(--text);
  background: var(--red-dim);
  box-shadow: 0 0 20px rgba(220,38,38,.15);
  transition: background .2s, box-shadow .2s, transform .15s;
  font-family: 'Inter', system-ui, sans-serif; letter-spacing: .3px;
}
#scan-btn:hover:not(:disabled) {
  background: rgba(220,38,38,.25);
  box-shadow: 0 0 30px rgba(220,38,38,.25);
}
#scan-btn:active:not(:disabled) { transform: scale(.97); }
#scan-btn:disabled { opacity: .4; cursor: not-allowed; }

.dot-pulse {
  width: 6px; height: 6px; border-radius: 50%; background: var(--red);
  animation: pulse-red 1.4s ease infinite;
}
@keyframes pulse-red {
  0%, 100% { opacity: 1; box-shadow: 0 0 0 0 rgba(220,38,38,.5); }
  50%       { opacity: .6; box-shadow: 0 0 0 5px rgba(220,38,38,0); }
}
.spinner-ring {
  width: 12px; height: 12px; border: 1.5px solid rgba(220,38,38,.3);
  border-top-color: var(--red); border-radius: 50%; display: none;
  animation: spin .6s linear infinite;
}
#scan-btn.loading .dot-pulse { display: none; }
#scan-btn.loading .spinner-ring { display: block; }
@keyframes spin { to { transform: rotate(360deg); } }

/* ── Status ── */
#status { font-size: 11px; color: var(--sub); text-align: center; min-height: 16px; }

/* ── Divider ── */
.divider { height: 1px; background: var(--border); }

/* ── Results ── */
#results { flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 7px; padding-right: 2px; }
#results::-webkit-scrollbar { width: 2px; }
#results::-webkit-scrollbar-track { background: transparent; }
#results::-webkit-scrollbar-thumb { background: rgba(220,38,38,.3); border-radius: 2px; }

.empty-state {
  flex: 1; display: flex; flex-direction: column;
  align-items: center; justify-content: center; gap: 8px;
  color: var(--sub); font-size: 12px;
  animation: fadeUp .4s ease forwards;
}
.empty-icon { font-size: 24px; opacity: .4; }

/* ── Card ── */
.card {
  background: var(--bg3); border: 1px solid rgba(255,255,255,.05);
  border-radius: var(--radius); padding: 12px 14px;
  opacity: 0; animation: fadeUp .3s ease forwards;
  transition: border-color .2s;
}
.card:hover { border-color: rgba(220,38,38,.25); }
@keyframes fadeUp {
  from { opacity: 0; transform: translateY(8px); }
  to   { opacity: 1; transform: translateY(0); }
}

.card-top {
  display: flex; align-items: center;
  justify-content: space-between; margin-bottom: 9px;
}
.source-row { display: flex; align-items: center; gap: 6px; font-size: 12px; font-weight: 600; }
.source-dot { width: 6px; height: 6px; border-radius: 50%; }
.badge { font-size: 10px; font-weight: 600; padding: 2px 8px; border-radius: 20px; }
.valid-badge   { background: rgba(74,222,128,.1); color: #4ade80; border: 1px solid rgba(74,222,128,.2); }
.invalid-badge { background: rgba(220,38,38,.1);  color: var(--red2); border: 1px solid rgba(220,38,38,.2); }

.token-row { display: flex; align-items: center; gap: 6px; }
.token-display {
  flex: 1; background: var(--bg2); border: 1px solid rgba(255,255,255,.05);
  border-radius: 6px; padding: 6px 10px;
  font-family: 'Consolas', monospace; font-size: 10.5px;
  color: var(--sub); letter-spacing: .3px;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  transition: color .15s;
}
.token-display.revealed { color: #a1a1aa; }

.act-btn {
  padding: 5px 10px; border: 1px solid rgba(255,255,255,.07); border-radius: 6px;
  cursor: pointer; font-size: 10px; font-weight: 600; white-space: nowrap;
  font-family: 'Inter', system-ui, sans-serif; transition: all .12s; color: var(--sub);
  background: var(--bg2);
}
.act-btn:hover { color: var(--text); border-color: rgba(255,255,255,.15); }
.act-btn.copy-btn { color: #4ade80; border-color: rgba(74,222,128,.2); background: rgba(74,222,128,.07); }
.act-btn.copy-btn:hover { background: rgba(74,222,128,.14); }
.act-btn.copy-btn.copied { background: rgba(74,222,128,.2); }

/* ── Toast ── */
#toast {
  position: fixed; bottom: 16px; left: 50%;
  transform: translateX(-50%) translateY(60px);
  background: rgba(16,16,21,.97); backdrop-filter: blur(20px);
  border: 1px solid rgba(220,38,38,.3); color: var(--red2);
  padding: 8px 16px; border-radius: 8px;
  font-size: 11px; font-weight: 600;
  transition: transform .25s cubic-bezier(.34,1.4,.64,1); z-index: 999;
}
#toast.show { transform: translateX(-50%) translateY(0); }
</style>
</head>
<body>

<div id="titlebar">
  <div class="titlebar-icon">TF</div>
  <span class="titlebar-name">TokenFinder</span>
  <span class="titlebar-ver">&nbsp;v2.2</span>
  <div class="titlebar-controls">
    <button class="ctrl" onclick="pywebview.api.minimize()">─</button>
    <button class="ctrl x" onclick="pywebview.api.close()">✕</button>
  </div>
</div>

<div id="app">
  <div class="hero">
    <div class="hero-eyebrow">Discord Token Finder</div>
    <div class="hero-title">Find your token</div>
    <div class="hero-sub">Supports Discord · Vencord · Equicord · Vesktop · Legcord · browsers</div>
  </div>

  <div class="scan-wrap">
    <button id="scan-btn" onclick="startScan()">
      <span class="dot-pulse"></span>
      <div class="spinner-ring"></div>
      Scan
    </button>
  </div>

  <div id="status"></div>
  <div class="divider"></div>
  <div id="results"></div>
</div>

<div id="toast">Token copied</div>

<script>
const store = {};
let toastTimer;

const COLORS = {
  Discord:        '#4ade80',
  'Discord Canary':'#818cf8',
  'Discord PTB':  '#c084fc',
  Vesktop:        '#f472b6',
  Legcord:        '#fb923c',
  ArmCord:        '#facc15',
  GoofCord:       '#38bdf8',
  WebCord:        '#60a5fa',
  Chrome:         '#f87171',
  Edge:           '#22d3ee',
  Brave:          '#fb923c',
  Opera:          '#f87171',
  'Opera GX':     '#c084fc',
};

function startScan() {
  const btn = document.getElementById('scan-btn');
  document.getElementById('results').innerHTML = '';
  document.getElementById('status').textContent = '';
  btn.disabled = true;
  btn.classList.add('loading');

  pywebview.api.scan().then(raw => {
    const data = JSON.parse(raw);
    btn.disabled = false;
    btn.classList.remove('loading');

    if (!data.length) {
      document.getElementById('results').innerHTML =
        '<div class="empty-state"><div class="empty-icon">◎</div><span>No tokens found</span></div>';
      return;
    }

    const valid = data.filter(d => d.valid).length;
    document.getElementById('status').innerHTML =
      `<span style="color:#dc2626">${data.length}</span> token${data.length > 1 ? 's' : ''} found &nbsp;·&nbsp; ` +
      `<span style="color:#4ade80">${valid}</span> valid`;

    data.forEach((item, i) => setTimeout(() => renderCard(item), i * 60));
  });
}

function renderCard(item) {
  const id    = 'tk_' + Math.random().toString(36).slice(2, 8);
  store[id]   = item.token;
  const color = COLORS[item.source] || '#737373';

  const badge   = item.valid
    ? `<span class="badge valid-badge">✓ ${item.username}</span>`
    : `<span class="badge invalid-badge">✗ invalid</span>`;
  const copyBtn = item.valid
    ? `<button class="act-btn copy-btn" id="cp_${id}" onclick="copyToken('${id}')">Copy</button>`
    : '';

  const card = document.createElement('div');
  card.className = 'card';
  card.innerHTML = `
    <div class="card-top">
      <div class="source-row">
        <span class="source-dot" style="background:${color}"></span>
        ${item.source}
      </div>
      ${badge}
    </div>
    <div class="token-row">
      <div class="token-display" id="${id}">••••••••••••••••••••••••••••••••</div>
      ${copyBtn}
      <button class="act-btn show-btn" onclick="toggleReveal('${id}')">Show</button>
    </div>`;
  document.getElementById('results').appendChild(card);
}

function toggleReveal(id) {
  const el  = document.getElementById(id);
  const btn = el.parentElement.querySelector('.show-btn');
  const on  = el.classList.toggle('revealed');
  el.textContent  = on ? store[id] : '••••••••••••••••••••••••••••••••';
  if (btn) btn.textContent = on ? 'Hide' : 'Show';
}

function copyToken(id) {
  pywebview.api.copy(store[id]);
  const btn = document.getElementById('cp_' + id);
  if (btn) {
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 2000);
  }
  const t = document.getElementById('toast');
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 2000);
}
</script>
</body>
</html>"""

# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    api = API()
    window = webview.create_window(
        "TokenFinder",
        html=HTML,
        js_api=api,
        width=540,
        height=620,
        resizable=False,
        frameless=True,
        background_color="#09090d"
    )
    webview.start(debug=False)
