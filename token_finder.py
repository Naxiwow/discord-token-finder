import webview, threading, json, os, re, base64, ctypes, ctypes.wintypes, ssl, urllib.request

# ══ CRYPTO ═══════════════════════════════════════════════════
class DATA_BLOB(ctypes.Structure):
    _fields_=[("cbData",ctypes.wintypes.DWORD),("pbData",ctypes.POINTER(ctypes.c_char))]

def dpapi_decrypt(data):
    inp=DATA_BLOB(len(data),ctypes.cast(ctypes.c_char_p(data),ctypes.POINTER(ctypes.c_char)))
    out=DATA_BLOB()
    ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(inp),None,None,None,None,0,ctypes.byref(out))
    return ctypes.string_at(out.pbData,out.cbData)

def get_key(ls):
    try:
        d=json.load(open(ls,"r",encoding="utf-8"))
        return dpapi_decrypt(base64.b64decode(d["os_crypt"]["encrypted_key"])[5:])
    except: return None

def aes_dec(key,payload):
    try:
        from Crypto.Cipher import AES
        return AES.new(key,AES.MODE_GCM,payload[3:15]).decrypt(payload[15:])[:-16].decode("utf-8",errors="ignore").strip("\x00").strip()
    except: return ""

TOKEN_RE=re.compile(r"[\w-]{24,26}\.[\w-]{6}\.[\w-]{25,110}")

def scan_ldb(ldb,key):
    tokens=[]
    if not os.path.exists(ldb): return tokens
    for f in os.listdir(ldb):
        if not f.endswith((".log",".ldb")): continue
        try: raw=open(os.path.join(ldb,f),"rb").read()
        except: continue
        if key:
            for m in re.finditer(rb"v1[01].{12}.{15,200}",raw):
                t=aes_dec(key,m.group(0))
                if TOKEN_RE.fullmatch(t) and t not in tokens: tokens.append(t)
        for t in TOKEN_RE.findall(raw.decode("utf-8",errors="ignore")):
            if t not in tokens: tokens.append(t)
    return tokens

def validate(token):
    try:
        req=urllib.request.Request("https://discord.com/api/v9/users/@me",headers={
            "Authorization":token,
            "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9163 Chrome/124.0.6367.243 Electron/30.4.0 Safari/537.36",
            "X-Super-Properties":"eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCIsInJlbGVhc2VfY2hhbm5lbCI6InN0YWJsZSJ9"
        })
        ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        with urllib.request.urlopen(req,timeout=5,context=ctx) as r:
            d=json.loads(r.read()); return d["username"]
    except: return None

AD,LA=os.getenv("APPDATA",""),os.getenv("LOCALAPPDATA","")
SOURCES=[
    ("Discord",       f"{AD}\\discord\\Local State",              f"{AD}\\discord\\Local Storage\\leveldb"),
    ("Discord Canary",f"{AD}\\discordcanary\\Local State",         f"{AD}\\discordcanary\\Local Storage\\leveldb"),
    ("Discord PTB",   f"{AD}\\discordptb\\Local State",            f"{AD}\\discordptb\\Local Storage\\leveldb"),
    ("Chrome",        f"{LA}\\Google\\Chrome\\User Data\\Local State",f"{LA}\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb"),
    ("Edge",          f"{LA}\\Microsoft\\Edge\\User Data\\Local State",f"{LA}\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb"),
    ("Brave",         f"{LA}\\BraveSoftware\\Brave-Browser\\User Data\\Local State",f"{LA}\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb"),
    ("Opera",         f"{AD}\\Opera Software\\Opera Stable\\Local State",f"{AD}\\Opera Software\\Opera Stable\\Local Storage\\leveldb"),
    ("Opera GX",      f"{AD}\\Opera Software\\Opera GX Stable\\Local State",f"{AD}\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb"),
]

def find_all_tokens():
    results,seen=[],set()
    for name,ls,ldb in SOURCES:
        key=get_key(ls) if os.path.exists(ls) else None
        for t in scan_ldb(ldb,key):
            if t not in seen: seen.add(t); results.append({"source":name,"token":t})
    return results

# ══ API ═══════════════════════════════════════════════════════
class API:
    def scan(self):
        tokens=find_all_tokens()
        results=[]
        for item in tokens:
            u=validate(item["token"])
            results.append({"source":item["source"],"token":item["token"],"valid":bool(u),"username":u or ""})
        return json.dumps(results)

    def copy(self,text):
        try:
            import subprocess
            subprocess.run(['clip'], input=text.encode('utf-16-le'), check=True)
        except Exception as e:
            print(f"Clipboard error: {e}")

    def close_app(self):
        w.destroy()
        import sys; sys.exit(0)

    def minimize_app(self):
        w.minimize()

HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Token Finder</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box;}
  :root{
    --bg:#070710;--bg2:#0d0d1a;--bg3:#13132b;
    --accent:#6366f1;--accent2:#818cf8;--cyan:#22d3ee;
    --green:#4ade80;--red:#f87171;
    --text:#f1f5f9;--sub:#64748b;--border:#1e1e3f;
  }
  html,body{width:100%;height:100%;overflow:hidden;background:var(--bg);font-family:'Segoe UI',system-ui,sans-serif;color:var(--text);}

  /* STARS */
  #stars{position:fixed;inset:0;pointer-events:none;z-index:0;}

  /* TITLEBAR */
  #titlebar{
    position:fixed;top:0;left:0;right:0;height:46px;
    background:rgba(13,13,26,.95);backdrop-filter:blur(20px);
    border-bottom:1px solid var(--border);
    display:flex;align-items:center;padding:0 16px;
    -webkit-app-region:drag;z-index:100;
  }
  #titlebar .logo{font-size:18px;margin-right:8px;}
  #titlebar .title{font-size:13px;font-weight:700;color:var(--text);}
  #titlebar .version{font-size:10px;color:var(--sub);margin-left:6px;}
  #titlebar .controls{margin-left:auto;display:flex;gap:2px;-webkit-app-region:no-drag;}
  #titlebar .btn-ctrl{
    width:32px;height:26px;border:none;background:transparent;
    color:var(--sub);font-size:12px;cursor:pointer;border-radius:4px;
    transition:all .15s;
  }
  #titlebar .btn-ctrl:hover{background:rgba(255,255,255,.08);color:var(--text);}
  #titlebar .btn-ctrl.close:hover{background:#f87171;color:#fff;}

  /* MAIN */
  #main{position:relative;z-index:1;padding:70px 24px 24px;height:100vh;display:flex;flex-direction:column;}

  /* HERO */
  .hero{text-align:center;margin-bottom:28px;}
  .hero h1{
    font-size:26px;font-weight:800;letter-spacing:-.5px;
    background:linear-gradient(135deg,var(--accent2),var(--cyan));
    -webkit-background-clip:text;-webkit-text-fill-color:transparent;
    animation:shimmer 3s ease infinite;background-size:200%;
  }
  @keyframes shimmer{0%,100%{background-position:0%}50%{background-position:100%}}
  .hero p{font-size:12px;color:var(--sub);margin-top:6px;}

  /* SCAN BTN */
  .scan-row{display:flex;align-items:center;justify-content:center;gap:16px;margin-bottom:20px;}
  #scanBtn{
    padding:11px 32px;border:none;border-radius:10px;cursor:pointer;
    font-size:13px;font-weight:700;color:#fff;letter-spacing:.3px;
    background:linear-gradient(135deg,var(--accent),#4f46e5);
    box-shadow:0 0 20px rgba(99,102,241,.4);
    transition:all .2s cubic-bezier(.34,1.56,.64,1);
    position:relative;overflow:hidden;
  }
  #scanBtn:hover{transform:scale(1.05);box-shadow:0 0 30px rgba(99,102,241,.6);}
  #scanBtn:active{transform:scale(.97);}
  #scanBtn::before{
    content:'';position:absolute;inset:0;
    background:linear-gradient(135deg,rgba(255,255,255,.15),transparent);
    border-radius:inherit;
  }

  /* SPINNER */
  .spinner{width:28px;height:28px;display:none;}
  .spinner svg{animation:spin 1s linear infinite;}
  .spinner.active{display:block;}
  @keyframes spin{to{transform:rotate(360deg)}}

  #status{font-size:11px;color:var(--sub);text-align:center;margin-bottom:16px;min-height:16px;}

  /* DIVIDER */
  .divider{height:1px;background:var(--border);margin-bottom:16px;}

  /* RESULTS */
  #results{flex:1;overflow-y:auto;padding-right:4px;}
  #results::-webkit-scrollbar{width:4px;}
  #results::-webkit-scrollbar-track{background:transparent;}
  #results::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px;}

  /* CARD */
  .card{
    background:rgba(19,19,43,.7);backdrop-filter:blur(20px);
    border:1px solid var(--border);border-radius:14px;
    padding:16px 18px;margin-bottom:10px;
    opacity:0;transform:translateY(20px) scale(.97);
    transition:border-color .3s,box-shadow .3s;
    animation:cardIn .4s cubic-bezier(.34,1.2,.64,1) forwards;
  }
  @keyframes cardIn{
    to{opacity:1;transform:translateY(0) scale(1);}
  }
  .card:hover{border-color:rgba(99,102,241,.4);box-shadow:0 0 20px rgba(99,102,241,.1);}
  .card-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;}
  .source{display:flex;align-items:center;gap:8px;font-weight:700;font-size:13px;}
  .badge{
    padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;
    animation:pulse 2s ease infinite;
  }
  .badge.valid{background:rgba(74,222,128,.15);color:var(--green);border:1px solid rgba(74,222,128,.3);}
  .badge.invalid{background:rgba(248,113,113,.15);color:var(--red);border:1px solid rgba(248,113,113,.3);}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.7}}
  .token-row{display:flex;align-items:center;gap:8px;margin-bottom:10px;}
  .token-field{
    flex:1;background:rgba(7,7,16,.6);border:1px solid var(--border);
    border-radius:8px;padding:8px 12px;font-family:Consolas,monospace;
    font-size:11px;color:var(--sub);letter-spacing:.5px;
    white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
  }
  .btn-small{
    padding:7px 14px;border:none;border-radius:8px;cursor:pointer;
    font-size:11px;font-weight:700;transition:all .15s;white-space:nowrap;
  }
  .btn-copy{background:rgba(74,222,128,.15);color:var(--green);border:1px solid rgba(74,222,128,.25);}
  .btn-copy:hover{background:rgba(74,222,128,.25);transform:scale(1.03);}
  .btn-show{background:rgba(99,102,241,.15);color:var(--accent2);border:1px solid rgba(99,102,241,.25);}
  .btn-show:hover{background:rgba(99,102,241,.25);transform:scale(1.03);}
  .btn-copy:active,.btn-show:active{transform:scale(.97);}

  /* TOAST */
  #toast{
    position:fixed;bottom:20px;left:50%;transform:translateX(-50%) translateY(60px);
    background:rgba(74,222,128,.15);border:1px solid rgba(74,222,128,.3);
    color:var(--green);padding:10px 20px;border-radius:10px;
    font-size:12px;font-weight:700;backdrop-filter:blur(20px);
    transition:transform .3s cubic-bezier(.34,1.56,.64,1);z-index:999;
  }
  #toast.show{transform:translateX(-50%) translateY(0);}
</style>
</head>
<body>
<canvas id="stars"></canvas>

<div id="titlebar">
  <span class="logo">◈</span>
  <span class="title">Token Finder</span>
  <span class="version">v2.0</span>
  <div class="controls">
    <button class="btn-ctrl" onclick="pywebview.api.minimize_app()">–</button>
    <button class="btn-ctrl close" onclick="pywebview.api.close_app()">✕</button>
  </div>
</div>

<div id="main">
  <div class="hero">
    <h1>Discord Token Finder</h1>
    <p>Scanne & vérifie tous tes tokens automatiquement</p>
  </div>

  <div class="scan-row">
    <button id="scanBtn" onclick="scan()">◉  Scanner</button>
    <div class="spinner" id="spinner">
      <svg viewBox="0 0 28 28" fill="none">
        <circle cx="14" cy="14" r="11" stroke="#6366f1" stroke-width="2.5" stroke-dasharray="55 15" stroke-linecap="round"/>
        <circle cx="14" cy="14" r="6" stroke="#22d3ee" stroke-width="1.5" stroke-dasharray="25 15" stroke-linecap="round" style="animation:spin .7s linear infinite reverse"/>
      </svg>
    </div>
  </div>

  <div id="status"></div>
  <div class="divider"></div>
  <div id="results"></div>
</div>

<div id="toast">✓ Token copié !</div>

<script>
// ── Stars ──────────────────────────────────────────────────
const cv=document.getElementById('stars');
const cx=cv.getContext('2d');
let stars=[];
function initStars(){
  cv.width=window.innerWidth; cv.height=window.innerHeight;
  stars=Array.from({length:150},()=>({
    x:Math.random()*cv.width, y:Math.random()*cv.height,
    r:Math.random()*1.5+.3, v:Math.random()*.3+.05,
    b:Math.random(), phase:Math.random()*Math.PI*2,
    color:Math.random()<.3?'#818cf8':Math.random()<.5?'#22d3ee':'#ffffff'
  }));
}
function drawStars(t){
  cx.clearRect(0,0,cv.width,cv.height);
  stars.forEach(s=>{
    s.x=(s.x-s.v+cv.width)%cv.width;
    const b=.3+.7*(.5+.5*Math.sin(t*.001+s.phase));
    cx.globalAlpha=b*.8;
    cx.fillStyle=s.color;
    cx.beginPath();cx.arc(s.x,s.y,s.r,0,Math.PI*2);cx.fill();
  });
  cx.globalAlpha=1;
  requestAnimationFrame(drawStars);
}
window.addEventListener('resize',initStars);
initStars(); requestAnimationFrame(drawStars);

// ── Token store ───────────────────────────────────────────
const TOKEN_STORE={};

// ── Icons ──────────────────────────────────────────────────
const ICONS={
  'Discord':'<span style="color:#4ade80">●</span>',
  'Discord Canary':'<span style="color:#818cf8">●</span>',
  'Discord PTB':'<span style="color:#c084fc">●</span>',
  'Chrome':'<span style="color:#f87171">●</span>',
  'Edge':'<span style="color:#22d3ee">●</span>',
  'Brave':'<span style="color:#fb923c">●</span>',
  'Opera':'<span style="color:#f87171">●</span>',
  'Opera GX':'<span style="color:#c084fc">●</span>',
  'Firefox':'<span style="color:#fb923c">●</span>',
};

// ── Scan ───────────────────────────────────────────────────
let shown={};
function scan(){
  document.getElementById('results').innerHTML='';
  document.getElementById('status').textContent='';
  document.getElementById('spinner').classList.add('active');
  document.getElementById('scanBtn').disabled=true;
  shown={};
  pywebview.api.scan().then(res=>{
    const data=JSON.parse(res);
    document.getElementById('spinner').classList.remove('active');
    document.getElementById('scanBtn').disabled=false;
    if(!data.length){document.getElementById('status').innerHTML='<span style="color:#f87171">Aucun token trouvé.</span>';return;}
    const v=data.filter(d=>d.valid).length;
    document.getElementById('status').innerHTML=
      `<span style="color:#4ade80">${data.length}</span> token(s) trouvé(s) &nbsp;·&nbsp; <span style="color:#4ade80">${v}</span> valide(s)`;
    data.forEach((item,i)=>{
      setTimeout(()=>addCard(item),i*80);
    });
  });
}

function addCard(item){
  const div=document.createElement('div');
  div.className='card';
  div.style.animationDelay='0ms';
  const icon=ICONS[item.source]||'<span>●</span>';
  const badge=item.valid
    ?`<span class="badge valid">✓ ${item.username}</span>`
    :`<span class="badge invalid">✗ Invalide</span>`;
  const masked='•'.repeat(32);
  const id='t'+Math.random().toString(36).slice(2);
  TOKEN_STORE[id]=item.token;
  div.innerHTML=`
    <div class="card-header">
      <div class="source">${icon} ${item.source}</div>
      ${badge}
    </div>
    <div class="token-row">
      <div class="token-field" id="${id}">${masked}</div>
      ${item.valid?`<button class="btn-small btn-copy" onclick="copyToken('${id}')">📋 Copier</button>`:''}
      <button class="btn-small btn-show" onclick="toggleShow('${id}')">👁</button>
    </div>`;
  document.getElementById('results').appendChild(div);
}

let showState={};
function toggleShow(id){
  const el=document.getElementById(id);
  const token=TOKEN_STORE[id]||'';
  showState[id]=!showState[id];
  el.textContent=showState[id]?token:'•'.repeat(32);
  el.style.color=showState[id]?'#94a3b8':'#475569';
}

let copyTimeout;
document.addEventListener('keydown',e=>{
  if(e.ctrlKey && e.key==='c'){
    const sel=window.getSelection().toString();
    if(sel) pywebview.api.copy(sel);
  }
});

function copyToken(id){
  const token=TOKEN_STORE[id]||'';
  pywebview.api.copy(token);
  const t=document.getElementById('toast');
  t.classList.add('show');
  clearTimeout(copyTimeout);
  copyTimeout=setTimeout(()=>t.classList.remove('show'),2000);
}
</script>
</body>
</html>"""

if __name__=="__main__":
    api=API()
    w=webview.create_window(
        "Token Finder",html=HTML,
        js_api=api,width=560,height=660,
        resizable=False,frameless=True,
        background_color="#070710"
    )
    webview.start(debug=False)
