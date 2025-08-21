# streamlit_app.py — Control de Gastos y Ventas (login + roles + admin + refresco)
# Ejecuta:
#   pip install -r requirements.txt
#   pip install extra-streamlit-components bcrypt
#   streamlit run streamlit_app.py
#.\.venv\Scripts\Activate

from __future__ import annotations
import streamlit as st
import streamlit.components.v1 as components 

st.set_page_config(
    page_title="Control de Gastos y Ventas",
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.markdown("""
<style>
/* 1) Sin relleno extra arriba, pero sin romper títulos */
[data-testid="stAppViewContainer"] > .main{ padding-top:0 !important; }
[data-testid="stAppViewContainer"] > .main .block-container{ padding-top:0 !important; }

/* 2) Recupera un poco de separación entre bloques (antes lo dejé en 0) */
[data-testid="stVerticalBlock"]{ gap:6px !important; row-gap:6px !important; }
[data-testid="stHorizontalBlock"]{ column-gap:12px !important; row-gap:6px !important; }

/* 3) Colapsa SOLO wrappers vacíos de utilidades (no toques contenedores con contenido) */
.block-container > div:has(> style:only-child),
.block-container > div:has(> iframe[height="0"]:only-child),
.block-container > div:has(> iframe[style*="height: 0px"]:only-child){
  margin:0 !important; padding:0 !important; min-height:0 !important; line-height:0 !important;
}

/* 5) Si algún H1/H2 es el primer hijo, quítale el margen superior del navegador, no su altura */
.block-container h1:first-child,
.block-container h2:first-child{ margin-top:0 !important; }
</style>
""", unsafe_allow_html=True)

components.html("""
<script>
(function(){
  try{
    if (!window.matchMedia("(max-width: 900px)").matches) return;
    var url = new URL(window.location.href);
    var changed = false;
    if (url.searchParams.get("compact")!=="1"){ url.searchParams.set("compact","1"); changed = true; }
    if (url.searchParams.get("m")!=="1"){ url.searchParams.set("m","1"); changed = true; }
    if (changed){
      history.replaceState(null, "", url.toString());
      setTimeout(function(){ location.reload(); }, 0);
    }
  }catch(e){}
})();
</script>
""", height=0, width=0)

import hashlib
from pathlib import Path

APP_BUILD = "TickeTo · 2025-08-13 nav-left-fix"

def _app_sig() -> str:
    try:
        return hashlib.sha1(Path(__file__).read_bytes()).hexdigest()[:10]
    except Exception:
        return "nohash"

st.markdown('<meta name="google" content="notranslate">', unsafe_allow_html=True)

# with st.sidebar:
#     p = pathlib.Path(__file__).resolve()
#     st.caption(f"🧩 Build: {APP_BUILD}")
#     st.caption(f"📄 Script: {p.name}")
#     st.caption(f"📁 Carpeta: {p.parent}")
#     st.caption(f"🔑 App sig: {_app_sig()}")

# --- Mantener header nativo (recupera la hamburguesa) ---
st.markdown("""
<style>
/* No ocultes el header; si molesta la banda de color, solo achícala */
div[data-testid="stDecoration"]{ height:0 !important; }
</style>
""", unsafe_allow_html=True) 
        

st.markdown("""
<style>
[data-testid="stAppViewContainer"] > .main .block-container{
  padding-top: 0 !important;
}
@media (max-width: 900px){
  [data-testid="stAppViewContainer"] > .main .block-container{
    padding-top: 0 !important;
  }
}
</style>
""", unsafe_allow_html=True)

# st.markdown("""
# <style>
# @media (prefers-color-scheme: dark) {
#   [data-testid="stMetric"]{ background:#0b0f19; border-color:#1f2937; }
#   details[data-testid="stExpander"]{ background:#0b0f19; border-color:#1f2937; }
#   .stButton > button[kind="primary"]{ background:#6366f1 !important; border-color:#6366f1 !important; }
#   [data-testid="stDataFrame"] table tbody tr:nth-child(odd){ background:#0f172a; }
#   [data-testid="stDataFrame"] table thead th{ background:#0b0f19; }
# }
# </style>
# """, unsafe_allow_html=True)


st.markdown("""
<style>
/* Botón primario consistente */
.stButton > button[kind="primary"]{
  background:#4f46e5 !important; border:1px solid #4f46e5 !important;
  color:#fff !important; border-radius:12px !important; font-weight:600;
}
.stButton > button:hover[kind="primary"]{ filter:brightness(0.95); }

/* Métricas como tarjetas */
[data-testid="stMetric"]{
  padding:14px 16px; border:1px solid rgba(120,120,135,.18);
  border-radius:14px; box-shadow:0 1px 2px rgba(0,0,0,.04);
  background:#fff;
}

/* Expanders como secciones */
details[data-testid="stExpander"]{
  border:1px solid rgba(120,120,135,.18); border-radius:14px; overflow:hidden;
  background:#fff;
}
details[data-testid="stExpander"] > summary{ padding:12px 14px; font-weight:700; }


/* Tablas: zebra + encabezado fijo */
[data-testid="stDataFrame"] table tbody tr:nth-child(odd){ background:#fafafa; }
[data-testid="stDataFrame"] table thead th{
  position: sticky; top: 0; background:#ffffff; z-index: 2;
  box-shadow: 0 1px 0 rgba(0,0,0,.06);
}
[data-testid="stDataFrame"] table td,
[data-testid="stDataFrame"] table th{
  white-space:nowrap;
}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<style>
:root{
  --card-bg:#ffffff; --card-br:rgba(120,120,135,.16); --text-1:#111827; --text-2:#6b7280;
}
@media (prefers-color-scheme: dark){
  :root{
    --card-bg:#0b0f19; --card-br:#1f2937; --text-1:#e5e7eb; --text-2:#9ca3af;
  }
}

/* ==== Stat cards elegantes ==== */
.tt-grid{ display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:14px; }
@media (max-width: 1024px){ .tt-grid{ grid-template-columns:repeat(2,minmax(0,1fr)); } }
@media (max-width: 640px){ .tt-grid{ grid-template-columns:1fr; } }

.tt-stat{
  display:flex; gap:12px; align-items:center;
  padding:16px 16px; border:1px solid var(--card-br); border-radius:16px;
  background:var(--card-bg); box-shadow:0 4px 12px rgba(0,0,0,.05);
}
.tt-stat .ic{
  width:44px; height:44px; border-radius:12px;
  display:flex; align-items:center; justify-content:center;
  font-size:22px; color:white; box-shadow:0 8px 18px rgba(0,0,0,.15) inset;
}
.tt-stat .meta{ min-width:0 }
.tt-stat .lbl{
  font-size:12px; letter-spacing:.08em; text-transform:uppercase;
  color:var(--text-2); font-weight:700; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;
}
.tt-stat .val{ font-size:26px; font-weight:800; color:var(--text-1); line-height:1.15; }

/* Paletas para el recuadro del icono */
.tt-indigo .ic{ background:linear-gradient(135deg,#6366f1,#8b5cf6); }
.tt-emerald .ic{ background:linear-gradient(135deg,#10b981,#34d399); }
.tt-rose    .ic{ background:linear-gradient(135deg,#f43f5e,#fb7185); }
.tt-amber   .ic{ background:linear-gradient(135deg,#f59e0b,#fbbf24); }
.tt-sky     .ic{ background:linear-gradient(135deg,#0ea5e9,#38bdf8); }

/* Card contenedor (EFECTIVO / TOTAL DE CAPITAL) */
.tt-card{
  border:1px solid var(--card-br); border-radius:16px; background:var(--card-bg);
  padding:16px; box-shadow:0 6px 16px rgba(0,0,0,.05); margin-top:10px;
}
.tt-card h4{ margin:0 0 10px 0; font-size:18px; font-weight:800; color:var(--text-1); }
.tt-callout{
  border:1px dashed rgba(99,102,241,.35); background:rgba(99,102,241,.06);
  padding:16px; border-radius:16px; font-weight:800; font-size:26px; margin-top:12px;
}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<style>
:root{
  /* Paleta de la app */
  --pri:#6366f1;          /* indigo */
  --accent:#f97316;       /* naranja */
  --text:#111827; --muted:#6b7280; --border:rgba(120,120,135,.18); --card:#ffffff;
}
@media (prefers-color-scheme: dark){
  :root{
    --text:#e5e7eb; --muted:#9ca3af; --border:#1f2937; --card:#0b0f19;
  }
}

/* Grid responsivo, limpio */
.mm-grid{ display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:12px; }
@media (max-width:1024px){ .mm-grid{ grid-template-columns:repeat(2,minmax(0,1fr)); } }
@media (max-width:640px){  .mm-grid{ grid-template-columns:1fr; } }

/* Tarjeta minimal (sin sombras, sin negrita) */
.mm-stat{
  background:var(--card); border:1px solid var(--border); border-radius:12px;
  padding:12px 14px; display:flex; flex-direction:column; gap:4px;
  border-left:4px solid var(--tone, var(--border));
}
.mm-stat .lbl{
  font-size:12px; letter-spacing:.04em; text-transform:uppercase;
  color:var(--muted); font-weight:400; line-height:1.2;
}
.mm-stat .val{
  font-size:24px; font-weight:400; color:var(--text); line-height:1.15;
}

/* Contenedor simple tipo “card” para secciones */
.mm-card{
  background:var(--card); border:1px solid var(--border); border-radius:12px;
  padding:14px; margin-top:10px;
}
.mm-card h4{ margin:0 0 8px 0; font-size:16px; font-weight:400; color:var(--muted); }

/* Números “callout” discretos (sin bold) */
.mm-total{ font-size:26px; font-weight:400; color:var(--text); }

/* Botones mantienen tus estilos; inputs quedan igual */
</style>
""", unsafe_allow_html=True)

st.markdown("""
<style>
/* H1 y título pegajoso un poco más livianos (sin negrita fuerte) */
h1, .tt-titlebar .ttl{ font-weight:600 !important; }

/* Tarjeta minimal: un pelín más compacta y borde izquierdo más fino */
.mm-stat{
  padding:10px 12px;
  border-radius:10px;
  border-left-width:3px;        /* antes 4px */
}
.mm-stat .lbl{
  font-size:11px;               /* etiqueta más discreta */
  letter-spacing:.06em;
}
.mm-stat .val{
  font-size:22px;               /* número más sereno */
}

/* Cards contenedoras ligeramente más suaves */
.mm-card{ border-radius:12px; }

/* Inputs y botones con la misma altura y radios redondeados */
.stButton > button{ min-height:42px; border-radius:10px; }
[data-testid="stTextInput"] input,
[data-testid="stTextArea"] textarea,
[data-testid="stNumberInput"] input{
  border-radius:10px;
}

/* Ajuste fino de separaciones dentro del consolidado */
.mm-grid{ gap:10px; }           /* grid un poco más ceñido */
.mm-card + .mm-card{ margin-top:10px; }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<style>
/* 1) Quita relleno del contenedor principal */
[data-testid="stAppViewContainer"] > .main,
[data-testid="stAppViewContainer"] > .main .block-container{
  padding-top:0 !important;
  margin-top:0 !important;
}

/* 3) Asegura que los H1/H2 no agreguen margen arriba */
.block-container h1, .block-container h2{ margin-top:0 !important; }

/* 4) Colapsa wrappers de components.html invisibles (iframes de altura 0) */
.block-container > div:has(> iframe[height="0"]:only-child),
.block-container > div:has(> iframe[style*="height: 0px"]:only-child){
  margin:0 !important; padding:0 !important; min-height:0 !important; line-height:0 !important;
}

/* 5) Por si usas tu barra pegajosa personalizada */
</style>
""", unsafe_allow_html=True)


# ====== Imports básicos ======
from datetime import date, timedelta, datetime
import sqlite3
import pandas as pd
import numpy as np
import re
import gspread
from google.oauth2.service_account import Credentials
import os, json, hmac, base64, time
import extra_streamlit_components as stx
import math



# ---------------------------------------------------------
# Ajuste visual por defecto (se puede cambiar en Admin)
# ---------------------------------------------------------
DB_FILE = Path("finanzas.sqlite")

def _db_sig() -> tuple[int, int]:
    """Firma del archivo SQLite para invalidar la cache cuando cambie."""
    try:
        s = DB_FILE.stat()
        # Usamos mtime y tamaño para mayor entropía (Windows tiene gran. de 1s)
        return (int(s.st_mtime), int(s.st_size))
    except Exception:
        return (0, 0)

# ========== Sesiones persistentes (cookie) + login/roles ==========


# --- Config desde ENV o Secrets (ENV tiene prioridad) ---
def cfg(name: str, default=None):
    v = os.environ.get(name, None)
    if v is None:
        try:
            v = st.secrets.get(name)  # type: ignore[attr-defined]
        except Exception:
            v = None
    return default if v is None else v

APP_SECRET = cfg("APP_SECRET", "")
ALLOW_DEFAULT_SECRET = str(cfg("ALLOW_DEFAULT_SECRET", "0")).strip() == "1"
if not APP_SECRET:
    APP_SECRET = "cambia_esta_clave_larga_y_unica"

if APP_SECRET == "cambia_esta_clave_larga_y_unica" and not ALLOW_DEFAULT_SECRET:
    st.error("APP_SECRET no configurado. Define APP_SECRET en Secrets o variables de entorno.")
    st.stop()

SESSION_COOKIE = "finz_sess"

COOKIE_SECURE_FLAG = str(cfg("COOKIE_SECURE", "1")).strip() == "1"
DEV_DEMO = str(cfg("DEV_DEMO_USERS", "0")).strip() == "1"

# CookieManager como widget (evita CachedWidgetWarning)
_cookie_widget = stx.CookieManager()
def _cookie_mgr():
    return _cookie_widget

# --- Password hashing (bcrypt -> fallback PBKDF2) ---
# --- Password hashing/verify universal (bcrypt + pbkdf2) ---

def hash_password(pw: str) -> str:
    try:
        import bcrypt  # type: ignore
        return "bcrypt$" + bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    except Exception:
        salt = os.urandom(16)
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, 200_000)
        return "pbkdf2$" + base64.b64encode(salt + dk).decode("utf-8")

def _verify_pbkdf2(pw: str, token: str) -> bool:
    try:
        raw = base64.b64decode(token.split("$",1)[1].encode("utf-8"))
        salt, dk_old = raw[:16], raw[16:]
        dk_new = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, 200_000)
        return hmac.compare_digest(dk_new, dk_old)
    except Exception:
        return False

def verify_password(pw: str, token: str) -> bool:
    token = token or ""
    if token.startswith("pbkdf2$"):
        return _verify_pbkdf2(pw, token)
    if token.startswith("bcrypt$") or token.startswith("$2"):
        try:
            import bcrypt  # type: ignore
            raw = token.split("$",1)[1] if token.startswith("bcrypt$") else token
            return bcrypt.checkpw(pw.encode("utf-8"), raw.encode("utf-8"))
        except Exception:
            return False
    # Fallback: intenta pbkdf2 por si no tiene prefijo
    return _verify_pbkdf2(pw, token)

# --- Usuarios DEMO solo en desarrollo ---
USERS = {}
if DEV_DEMO:
    USERS = {
        # Pon contraseñas “random” si de verdad necesitas demo local:
        "admin": {"pw": hash_password(os.getenv("DEMO_ADMIN_PW", "cámbiame!")), "role": "admin"},
        "user1": {"pw": hash_password(os.getenv("DEMO_USER1_PW", "cámbiame!")), "role": "user"},
    }

def _sign(data: dict) -> str:
    payload = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    b64 = base64.urlsafe_b64encode(payload).rstrip(b"=")
    sig = hmac.new(APP_SECRET.encode("utf-8"), b64, hashlib.sha256).digest()
    b64sig = base64.urlsafe_b64encode(sig).rstrip(b"=")
    return (b64 + b"." + b64sig).decode("utf-8")

def _b64url_decode(s: str) -> bytes:
    b = s.encode("utf-8")
    pad = (-len(b)) % 4
    return base64.urlsafe_b64decode(b + b"=" * pad)

def _verify(token: str) -> dict | None:
    try:
        b64, b64sig = token.split(".", 1)  # solo la 1ª vez
        b = b64.encode("utf-8")
        sig = _b64url_decode(b64sig)
        expected = hmac.new(APP_SECRET.encode("utf-8"), b, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, sig):
            return None
        data = json.loads(_b64url_decode(b64).decode("utf-8"))
        if int(data.get("exp", 0)) < int(time.time()):
            return None
        return data
    except Exception:
        return None

def _issue_session(username: str, role: str):
    ttl = st.session_state.get("sess_ttl", 7*24*3600)
    data = {"sub": username, "role": role, "exp": int(time.time()) + int(ttl)}
    token = _sign(data)
    cm = _cookie_mgr(); cm.get_all()  # monta el widget
    expires_dt = datetime.now() + timedelta(seconds=int(ttl))
    cm.set(
        SESSION_COOKIE,
        token,
        expires_at=expires_dt,
        key="set_"+SESSION_COOKIE,
        path="/",
        secure=COOKIE_SECURE_FLAG,  # en local http puro puedes poner 0
        same_site="Lax"
    )
    st.session_state["auth_user"] = username
    st.session_state["auth_role"] = role

def _clear_session():
    cm = _cookie_mgr()
    try:
        cm.get_all()  # monta el widget en el DOM
    except Exception:
        pass

    # 1) intenta borrar si existe (clave única para forzar render del componente)
    try:
        if cm.get(SESSION_COOKIE) is not None:
            cm.delete(SESSION_COOKIE, key=f"del_{int(time.time())}")
    except Exception:
        pass

    # 2) fuerza expiración por si el delete no llegó a tiempo
    try:
        cm.set(
            SESSION_COOKIE,
            "",
            expires_at=datetime.utcnow() - timedelta(days=1),
            key=f"exp_{int(time.time())}",
        )
    except Exception:
        pass

    # limpia el estado de la app
    st.session_state.pop("auth_user", None)
    st.session_state.pop("auth_role", None)

def current_user() -> tuple[str | None, str | None]:
    """Devuelve (usuario, rol). Si la cookie vieja no trae rol, aplica fallback por nombre."""
    u = st.session_state.get("auth_user")
    r = st.session_state.get("auth_role")
    if u:
        if not r:
            r = "admin" if u == "admin" else "user"
            st.session_state["auth_role"] = r
        return u, r

    cm = _cookie_mgr()
    token = cm.get(SESSION_COOKIE)
    if not token:
        return None, None
    data = _verify(token)
    if not data:
        return None, None
    u = data.get("sub")
    r = data.get("role") or ("admin" if u == "admin" else "user")
    st.session_state["auth_user"] = u
    st.session_state["auth_role"] = r
    return u, r

# =========================================================
# Base de datos (sqlite3)
# =========================================================
SCHEMA = """
CREATE TABLE IF NOT EXISTS transacciones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fecha TEXT,
    cliente_nombre TEXT,
    costo REAL DEFAULT 0,
    venta REAL DEFAULT 0,
    ganancia REAL DEFAULT 0,
    debe_flag INTEGER DEFAULT 0,
    paga TEXT,
    abono1 REAL DEFAULT 0,
    abono2 REAL DEFAULT 0,
    observacion TEXT
);
CREATE TABLE IF NOT EXISTS consolidado_diario (
    fecha TEXT PRIMARY KEY,
    efectivo REAL DEFAULT 0,
    notas TEXT
);
CREATE TABLE IF NOT EXISTS gastos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fecha TEXT,
    concepto TEXT,
    valor REAL DEFAULT 0,
    notas TEXT
);
CREATE TABLE IF NOT EXISTS prestamos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT,
    valor REAL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS inventario (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    producto TEXT,
    valor_costo REAL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS deudores_ini (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT,
    valor REAL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    pw_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT DEFAULT (datetime('now')),
    user TEXT,
    action TEXT,
    table_name TEXT,
    row_id INTEGER,
    details TEXT
);
"""

def get_conn():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn

def _col_exists(conn: sqlite3.Connection, table: str, col: str) -> bool:
    cur = conn.execute(f"PRAGMA table_info({table})")
    return any(r[1] == col for r in cur.fetchall())

def migrate_add_owner_columns():
    """
    Asegura columna 'owner' en tablas clave y rellena lo existente como 'admin'.
    Se puede ejecutar múltiples veces sin romper nada.
    """
    tables = ["transacciones", "gastos", "prestamos", "inventario", "deudores_ini", "consolidado_diario"]
    with get_conn() as conn:
        for t in tables:
            if not _col_exists(conn, t, "owner"):
                conn.execute(f"ALTER TABLE {t} ADD COLUMN owner TEXT")
                # Backfill: todo lo que ya estaba pasa a ser del admin
                conn.execute(f"UPDATE {t} SET owner='admin' WHERE owner IS NULL OR owner=''")

def audit(action: str,
          table_name: str | None = None,
          row_id: int | None = None,
          before: dict | None = None,
          after: dict | None = None,
          extra: dict | None = None):
    """Guarda un registro de auditoría en audit_log."""
    try:
        u = st.session_state.get("auth_user") or "(anon)"
    except Exception:
        u = "(anon)"

    payload = {
        "user": u,
        "action": action,
        "table": table_name,
        "row_id": row_id,
    }
    if extra:  payload["extra"]  = extra
    if before: payload["before"] = before
    if after:  payload["after"]  = after

    try:
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO audit_log(user, action, table_name, row_id, details) VALUES (?, ?, ?, ?, ?)",
                (u, action, table_name, row_id, json.dumps(payload, ensure_ascii=False, default=str))
            )
    except Exception as e:
        # No romper la app por fallos de auditoría
        print("AUDIT ERROR:", e)

def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)


def ensure_indexes():
    with get_conn() as conn:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_trans_fecha   ON transacciones(fecha)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_trans_cliente ON transacciones(cliente_nombre)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_gastos_fecha  ON gastos(fecha)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts      ON audit_log(ts)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_action  ON audit_log(action)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_table   ON audit_log(table_name)")

        # Índices por 'owner' solo si la columna existe (evita el error)
        for t in ["transacciones","gastos","prestamos","inventario","deudores_ini","consolidado_diario"]:
            if _col_exists(conn, t, "owner"):
                conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{t}_owner ON {t}(owner)")
                if t == "transacciones":
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_trans_owner_id ON transacciones(owner, id)")

init_db()
migrate_add_owner_columns()
ensure_indexes()

def _table_cols(conn, table):
    cur = conn.execute(f"PRAGMA table_info({table})")
    return {row[1] for row in cur.fetchall()}

def _add_col_if_missing(conn, table, col_def):
    name = col_def.split()[0]
    if name not in _table_cols(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {col_def}")

def migrate_to_per_user_data():
    try:
        with get_conn() as conn:
            # 1) Dueño de datos en tablas operativas
            for t in ["transacciones","gastos","prestamos","inventario","deudores_ini"]:
                _add_col_if_missing(conn, t, "owner TEXT")
                conn.execute(f"UPDATE {t} SET owner=COALESCE(NULLIF(owner,''),'admin') WHERE owner IS NULL OR owner=''")
                conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{t}_owner ON {t}(owner)")

            # 2) consolidado_diario → vuelve único por (fecha, owner)
            cols = _table_cols(conn, "consolidado_diario")
            if "owner" not in cols:
                # crear nueva tabla con PK auto y UNIQUE(fecha,owner)
                conn.execute("""
                CREATE TABLE IF NOT EXISTS consolidado_diario_v2 (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  fecha TEXT,
                  efectivo REAL DEFAULT 0,
                  notas TEXT,
                  owner TEXT,
                  UNIQUE(fecha, owner)
                )
                """)
                # mover datos viejos con owner='admin'
                cur = conn.execute("SELECT fecha, efectivo, notas FROM consolidado_diario")
                rows = cur.fetchall()
                for fecha, efectivo, notas in rows:
                    conn.execute("""
                      INSERT OR IGNORE INTO consolidado_diario_v2 (fecha, efectivo, notas, owner)
                      VALUES (?, ?, ?, 'admin')
                    """, (fecha, efectivo, notas))
                # reemplazar tabla
                conn.execute("DROP TABLE consolidado_diario")
                conn.execute("ALTER TABLE consolidado_diario_v2 RENAME TO consolidado_diario")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_consolidado_owner ON consolidado_diario(owner)")
    except Exception as e:
        st.warning(f"⚠️ Migración per-user falló: {e}")

migrate_to_per_user_data()

# ========= Gestión de usuarios (SQLite) =========
def db_get_user(username: str):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT username, pw_hash, role, is_active FROM users WHERE username=?",
            (username,)
        ).fetchone()
    if not row:
        return None
    return {"username": row[0], "pw": row[1], "role": row[2], "active": bool(row[3])}

def db_list_users() -> pd.DataFrame:
    with get_conn() as conn:
        df = pd.read_sql_query(
            "SELECT username, role, is_active AS activo, created_at FROM users ORDER BY username",
            conn
        )
    return df

def db_create_user(username: str, password: str, role: str = "user"):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO users (username, pw_hash, role) VALUES (?, ?, ?)",
            (username.strip(), hash_password(password), role)
        )
    audit("user.create", table_name="users", after={"username": username.strip(), "role": role})

def db_set_password(username: str, new_password: str):
    with get_conn() as conn:
        conn.execute(
            "UPDATE users SET pw_hash=? WHERE username=?",
            (hash_password(new_password), username.strip())
        )
    audit("user.password.change", table_name="users", after={"username": username.strip()})

def db_set_role(username: str, role: str):
    old = db_get_user(username)
    with get_conn() as conn:
        conn.execute("UPDATE users SET role=? WHERE username=?", (role, username.strip()))
    audit("user.role.change", table_name="users",
          before={"username": username.strip(), "role": old["role"] if old else None},
          after={"username": username.strip(), "role": role})

def db_delete_user(username: str):
    old = db_get_user(username)
    with get_conn() as conn:
        conn.execute("DELETE FROM users WHERE username=?", (username.strip(),))
    audit("user.delete", table_name="users", before={"username": username.strip(), "role": old["role"] if old else None})

def ensure_admin_seed():
    try:
        with get_conn() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO users (username, pw_hash, role)
                VALUES (?, ?, ?)
                """,
                ("admin", hash_password("admin123"), "admin"),
            )
            # Garantiza rol/activo sin tocar password si ya existía
            conn.execute("UPDATE users SET role='admin', is_active=1 WHERE username='admin'")
    except Exception as e:
        print("ensure_admin_seed error:", e)  

ensure_admin_seed() 

# ========== Login form ==========
def login_form() -> None:
    # Tarjeta bonita para el login (también en dark mode)
    st.markdown("""
    <style>
    .login-card{
      max-width: 520px; margin: 6vh auto; padding: 20px 22px;
      border:1px solid rgba(120,120,135,.18); border-radius:14px; background:#fff;
      box-shadow:0 6px 18px rgba(0,0,0,.06);
    }
    @media (prefers-color-scheme: dark){
      .login-card{ background:#0b0f19; border-color:#1f2937; }
    }
    </style>
    """, unsafe_allow_html=True)

    st.markdown('<div class="login-card">', unsafe_allow_html=True)
    st.title("Iniciar sesión")

    with st.form("login_form"):
        col1, col2 = st.columns(2, gap="small")
        username = col1.text_input("Usuario")
        password = col2.text_input("Contraseña", type="password")
        remember = st.checkbox("Recordarme por 7 días", value=True)
        ok = st.form_submit_button("Entrar", type="primary")

    if ok:
        uname = username.strip()

        # 1) Busca en SQLite
        urec = db_get_user(uname)
        if urec and urec["active"] and verify_password(password, urec["pw"]):
            st.session_state["sess_ttl"] = 7*24*3600 if remember else 12*3600
            _issue_session(uname, urec["role"])
            audit("login.success", extra={
                "remember": bool(remember),
                "role": urec["role"],
                "src": "sqlite",
                "user_try": uname
            })
            st.success("Bienvenido 👋")
            st.rerun()
        else:
            # Si el usuario existe pero está inactivo, no intentes DEMO
            if urec and not urec["active"]:
                audit("login.disabled", extra={"user_try": uname})
                st.error("Cuenta deshabilitada")
                st.stop()

            # 2) Fallback DEMO solo si está habilitado **y NO existe en SQLite**
            if DEV_DEMO and urec is None:
                u_demo = USERS.get(uname)
                if u_demo and verify_password(password, u_demo["pw"]):
                    st.session_state["sess_ttl"] = 7*24*3600 if remember else 12*3600
                    _issue_session(uname, u_demo.get("role", "user"))
                    audit("login.success", extra={
                        "remember": bool(remember),
                        "role": u_demo.get("role", "user"),
                        "src": "demo",
                        "user_try": uname
                    })
                    st.success("Bienvenido 👋")
                    st.rerun()
                    return

            audit("login.failed", extra={"user_try": uname})
            st.error("Usuario o contraseña inválidos")

    st.markdown('</div>', unsafe_allow_html=True)
    st.stop()

def require_user() -> tuple[str, str]:
    u, r = current_user()
    if not u:
        login_form()  # stop
    return u, r

def is_admin() -> bool:
    return st.session_state.get("auth_role") == "admin"

def _row_owner() -> str:
    # Quién es el dueño de la fila que se inserta
    return (st.session_state.get("auth_user") or "admin").strip()

def _owner_filter_sql(table: str) -> tuple[str, tuple]:
    # Admin ve todo; usuario normal ve solo lo suyo
    u = st.session_state.get("auth_user")
    if is_admin():
        return f"SELECT * FROM {table}", ()
    else:
        return f"SELECT * FROM {table} WHERE owner = ?", (u or "",)

def _current_owner() -> str:
    # dueño = usuario logueado; si no hay sesión (casos raros), "admin" para seeds/restore
    return st.session_state.get("auth_user") or "admin"

def _view_all_enabled() -> bool:
    # Admin puede activar "ver todo" desde la sidebar
    return bool(st.session_state.get("admin_view_all", False) and is_admin())

# =========================================================
# Utilidades meta
# =========================================================
def set_meta(key: str, value: str):
    old_value = None
    try:
        with get_conn() as conn:
            row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
            old_value = row[0] if row else None
    except Exception:
        pass

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO meta(key,value) VALUES(?,?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value
            """,
            (key, str(value))
        )

    audit("meta.set", table_name="meta",
          before={"key": key, "value": old_value},
          after={"key": key, "value": value})

def get_meta(key: str, default: float|str|None=None):
    with get_conn() as conn:
        row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    if row and row[0] is not None:
        try:
            return float(row[0])
        except Exception:
            return row[0]
    return default

def set_corte_deudores(d: date):
    set_meta("CORTE_DEUDORES", d.isoformat())

# Ajuste visual eliminado: no se usa más
ADJ_VENTAS_EFECTIVO = 0.0

# =========================================================
# Lectores cacheados (invalidados por mtime/size del .sqlite)
# =========================================================
@st.cache_data(show_spinner=False)
def _read_ventas(_sig: tuple[int, int], owner: str, view_all: bool) -> pd.DataFrame:
    q = "SELECT * FROM transacciones" + ("" if view_all else " WHERE owner=?")
    params = () if view_all else (owner,)
    with get_conn() as conn:
        df = pd.read_sql_query(q, conn, params=params)
    if df.empty:
        cols = ['id','fecha','cliente_nombre','costo','venta','ganancia','debe_flag','paga','abono1','abono2','observacion','owner']
        return pd.DataFrame(columns=cols)
    df['fecha'] = pd.to_datetime(df['fecha'], errors='coerce', dayfirst=True).dt.date
    for c in ['costo','venta','ganancia','abono1','abono2']:
        df[c] = pd.to_numeric(df[c], errors='coerce').fillna(0.0)
    df['debe_flag'] = df['debe_flag'].fillna(0).astype(int)
    df['observacion'] = (
        df['observacion'].astype(str).str.strip().str.upper()
        .replace({'NAN':'', 'NULL':'', 'NONE':'', 'NA':'', '<NA>':''})
    )
    return df

def read_ventas() -> pd.DataFrame:
    return _read_ventas(_db_sig(), _current_owner(), _view_all_enabled())


@st.cache_data(show_spinner=False)
def _read_gastos(_sig: tuple[int, int], owner: str, view_all: bool) -> pd.DataFrame:
    q = "SELECT * FROM gastos" + ("" if view_all else " WHERE owner=?")
    params = () if view_all else (owner,)
    with get_conn() as conn:
        df = pd.read_sql_query(q, conn, params=params)
    if df.empty:
        return pd.DataFrame(columns=['id','fecha','concepto','valor','notas','owner'])
    df['fecha'] = pd.to_datetime(df['fecha'], errors='coerce', dayfirst=True).dt.date
    df['valor'] = pd.to_numeric(df['valor'], errors='coerce').fillna(0.0)
    return df

def read_gastos() -> pd.DataFrame:
    return _read_gastos(_db_sig(), _current_owner(), _view_all_enabled())


@st.cache_data(show_spinner=False)
def _read_prestamos(_sig: tuple[int, int], owner: str, view_all: bool) -> pd.DataFrame:
    q = "SELECT * FROM prestamos" + ("" if view_all else " WHERE owner=?")
    params = () if view_all else (owner,)
    with get_conn() as conn:
        df = pd.read_sql_query(q, conn, params=params)
    if df.empty:
        return pd.DataFrame(columns=['id','nombre','valor','owner'])
    df['valor'] = pd.to_numeric(df['valor'], errors='coerce').fillna(0.0)
    return df

def read_prestamos() -> pd.DataFrame:
    return _read_prestamos(_db_sig(), _current_owner(), _view_all_enabled())


@st.cache_data(show_spinner=False)
def _read_inventario(_sig: tuple[int, int], owner: str, view_all: bool) -> pd.DataFrame:
    q = "SELECT * FROM inventario" + ("" if view_all else " WHERE owner=?")
    params = () if view_all else (owner,)
    with get_conn() as conn:
        df = pd.read_sql_query(q, conn, params=params)
    if df.empty:
        return pd.DataFrame(columns=['id','producto','valor_costo','owner'])
    df['valor_costo'] = pd.to_numeric(df['valor_costo'], errors='coerce').fillna(0.0)
    return df

def read_inventario() -> pd.DataFrame:
    return _read_inventario(_db_sig(), _current_owner(), _view_all_enabled())


@st.cache_data(show_spinner=False)
def _read_consolidado(_sig: tuple[int, int], owner: str, view_all: bool) -> pd.DataFrame:
    q = "SELECT * FROM consolidado_diario" + ("" if view_all else " WHERE owner=?")
    params = () if view_all else (owner,)
    with get_conn() as conn:
        df = pd.read_sql_query(q, conn, params=params)
    if df.empty:
        return pd.DataFrame(columns=['fecha','efectivo','notas','owner'])
    df['fecha_raw'] = df['fecha'].astype(str)
    df['fecha'] = pd.to_datetime(df['fecha'], errors='coerce', dayfirst=True).dt.date
    df['efectivo'] = pd.to_numeric(df['efectivo'], errors='coerce').fillna(0.0)
    return df

def read_consolidado() -> pd.DataFrame:
    return _read_consolidado(_db_sig(), _current_owner(), _view_all_enabled())


@st.cache_data(show_spinner=False)
def _read_deudores_ini(_sig: tuple[int, int], owner: str, view_all: bool) -> pd.DataFrame:
    q = "SELECT * FROM deudores_ini" + ("" if view_all else " WHERE owner=?")
    params = () if view_all else (owner,)
    with get_conn() as conn:
        df = pd.read_sql_query(q, conn, params=params)
    if df.empty:
        return pd.DataFrame(columns=['id','nombre','valor','owner'])
    df['nombre'] = df['nombre'].astype(str).str.strip()
    df['valor']  = pd.to_numeric(df['valor'], errors='coerce').fillna(0.0)
    return df[['id','nombre','valor','owner']]

def read_deudores_ini() -> pd.DataFrame:
    return _read_deudores_ini(_db_sig(), _current_owner(), _view_all_enabled())

# ========= Corte y unificación de deudores =========
def get_corte_deudores() -> date:
    v = get_meta("CORTE_DEUDORES", "")
    if not v:
        return date.today()
    s = str(v).strip()
    try:
        return date.fromisoformat(s)
    except Exception:
        pass
    try:
        return pd.to_datetime(s, errors="coerce", dayfirst=True).date()
    except Exception:
        return date.today()

def deudores_unificados(corte: date | None = None) -> tuple[pd.DataFrame, float]:
    """
    Devuelve SOLO deudores generados desde 'corte' (ventas a crédito - abonos),
    agregados por CLIENTE. Ignora totalmente la tabla de saldos iniciales.
    """
    if corte is None:
        corte = get_corte_deudores()

    v = read_ventas()
    if v.empty:
        return pd.DataFrame(columns=["CLIENTE", "NUEVO", "TOTAL"]), 0.0

    mov = v[["fecha", "cliente_nombre", "venta", "abono1", "abono2", "debe_flag"]].copy()
    mov["CLIENTE"] = mov["cliente_nombre"].astype(str).str.strip().str.upper()
    for c in ["venta", "abono1", "abono2", "debe_flag"]:
        mov[c] = pd.to_numeric(mov[c], errors="coerce").fillna(0.0)

    # Solo desde el corte y solo ventas a crédito
    mov = mov[(mov["fecha"] >= corte) & (mov["debe_flag"] == 1)]
    if mov.empty:
        return pd.DataFrame(columns=["CLIENTE", "NUEVO", "TOTAL"]), 0.0

    ventas_credito = mov.groupby("CLIENTE")["venta"].sum(min_count=1)
    abonos_total   = (mov["abono1"] + mov["abono2"]).groupby(mov["CLIENTE"]).sum(min_count=1)

    nuevo = (ventas_credito.fillna(0.0) - abonos_total.fillna(0.0)).clip(lower=0.0)

    out = nuevo.rename("NUEVO").reset_index()
    out["TOTAL"] = out["NUEVO"]  # alias para mantener interfaz previa
    out = out[out["NUEVO"] > 0].sort_values(["TOTAL"], ascending=False)

    total_visual = float(out["TOTAL"].sum()) if not out.empty else 0.0
    return out[["CLIENTE", "NUEVO", "TOTAL"]], total_visual

def deudores_sin_corte() -> tuple[pd.DataFrame, float]:
    """
    Deudores totales (toda la historia): ventas a crédito - abonos,
    agregados por CLIENTE. Sin fecha de corte ni saldos iniciales.
    """
    v = read_ventas()
    if v.empty:
        return pd.DataFrame(columns=["CLIENTE", "NUEVO"]), 0.0

    mov = v[["cliente_nombre", "venta", "abono1", "abono2", "debe_flag"]].copy()
    mov["CLIENTE"] = mov["cliente_nombre"].astype(str).str.strip().str.upper()
    for c in ["venta", "abono1", "abono2", "debe_flag"]:
        mov[c] = pd.to_numeric(mov[c], errors="coerce").fillna(0.0)

    mov = mov[mov["debe_flag"] == 1]
    if mov.empty:
        return pd.DataFrame(columns=["CLIENTE", "NUEVO"]), 0.0

    ventas_credito = mov.groupby("CLIENTE")["venta"].sum(min_count=1)
    abonos_total   = (mov["abono1"] + mov["abono2"]).groupby(mov["CLIENTE"]).sum(min_count=1)
    nuevo = (ventas_credito.fillna(0.0) - abonos_total.fillna(0.0)).clip(lower=0.0)

    out = nuevo.rename("NUEVO").reset_index()
    out = out[out["NUEVO"] > 0].sort_values("NUEVO", ascending=False)

    total = float(out["NUEVO"].sum()) if not out.empty else 0.0
    return out[["CLIENTE", "NUEVO"]], total

# =========================================================
# Normalizadores y helpers
# =========================================================
SHEET_COLUMNS_MAP_VENTAS = {
    'FECHA':'fecha','CLIENTE':'cliente_nombre','COSTO':'costo','VENTA':'venta',
    'GANANCIA':'ganancia','DEBE':'debe_flag','PAGA':'paga',
    'ABONO 1':'abono1','ABONO1':'abono1','ABONO 2':'abono2','ABONO2':'abono2',
    'OBSERVACIÓN':'observacion','OBSERVACION':'observacion','OBS':'observacion'
}
RECO_BOOL = {"x":1,"X":1,"si":1,"sí":1,"true":1,True:1,1:1}

def _parse_pesos(cell) -> float:
    """Convierte texto con miles/decimales (., ,) a float. Soporta (1.234,56), 1,234.56, 1234, 1234.5, etc."""
    if pd.isna(cell):
        return 0.0
    if isinstance(cell, (int, float, np.integer, np.floating)):
        try:
            x = float(cell)
            return 0.0 if np.isnan(x) else x
        except Exception:
            return 0.0

    s = str(cell).strip()
    if not s:
        return 0.0

    # signo
    neg = False
    if s.startswith("(") and s.endswith(")"):
        neg, s = True, s[1:-1]
    if s.startswith("−") or s.startswith("-"):
        neg, s = True, s[1:]

    s = s.replace(" ", "")

    # Posición del último separador decimal potencial
    last_comma = s.rfind(",")
    last_dot   = s.rfind(".")
    dec_pos = max(last_comma, last_dot)

    def only_digits(x): return re.sub(r"\D", "", x or "")

    if dec_pos > -1 and dec_pos < len(s) - 1:
        dec_sep = s[dec_pos]
        int_part = only_digits(s[:dec_pos])
        dec_part = only_digits(s[dec_pos+1:])

        # Heurística: si solo hay un tipo de separador, aparece varias veces y la cola es de 3 dígitos,
        # probablemente eran separadores de miles -> sin decimales.
        only_one_kind = (("," in s) ^ ("." in s))
        sep_count = s.count(dec_sep)
        tail_len = len(dec_part)
        if only_one_kind and (sep_count > 1 or tail_len >= 3):
            int_part = only_digits(s)
            dec_part = ""

        if dec_part:
            # máximo 2 decimales
            val = float(f"{int_part}.{dec_part[:2]}") if int_part else float(f"0.{dec_part[:2]}")
        else:
            val = float(int_part) if int_part else 0.0
    else:
        # sin separador decimal: quita todo lo que no sea dígito
        int_part = only_digits(s)
        val = float(int_part) if int_part else 0.0

    return -val if neg else val

def to_pesos_series(series: pd.Series) -> pd.Series:
    return series.apply(_parse_pesos).astype(float)

def normalize_ventas(df_raw: pd.DataFrame) -> pd.DataFrame:
    df = df_raw.copy()
    df.columns = [str(c).strip().upper() for c in df.columns]
    keep = [c for c in df.columns if c in SHEET_COLUMNS_MAP_VENTAS]
    df = df[keep].rename(columns=SHEET_COLUMNS_MAP_VENTAS)
    if 'fecha' in df:
        df['fecha'] = pd.to_datetime(df['fecha'], errors='coerce', dayfirst=True).dt.date
    for c in ['costo','venta','ganancia','abono1','abono2']:
        if c in df: df[c] = to_pesos_series(df[c])
    if 'debe_flag' in df:
        df['debe_flag'] = df['debe_flag'].map(lambda v: RECO_BOOL.get(v,0)).fillna(0).astype(int)
    if 'observacion' in df:
        df['observacion'] = df['observacion'].astype(str).str.strip().str.upper()
    for c in ['fecha','cliente_nombre','costo','venta','ganancia','debe_flag','paga','abono1','abono2','observacion']:
        if c not in df:
            df[c] = 0 if c in ['costo','venta','ganancia','abono1','abono2'] else (0 if c=='debe_flag' else '')
    return df[['fecha','cliente_nombre','costo','venta','ganancia','debe_flag','paga','abono1','abono2','observacion']]

def normalize_gastos(df_raw: pd.DataFrame) -> pd.DataFrame:
    df = df_raw.copy(); df.columns = [str(c).strip().upper() for c in df.columns]
    fecha_col = next((c for c in df.columns if c in ('FECHA','K','DIA','DÍA')), None)
    concepto_col = next((c for c in df.columns if c in ('CONCEPTO','DETALLE','DESCRIPCION','DESCRIPCIÓN')), None)
    valor_col = next((c for c in df.columns if c in ('VALOR','MONTO','IMPORTE')), None)
    notas_col = next((c for c in df.columns if 'OBS' in c or 'NOTA' in c or 'DESCRIP' in c), None)
    out = pd.DataFrame()
    out['fecha'] = pd.to_datetime(df[fecha_col], errors='coerce', dayfirst=True).dt.date if fecha_col else pd.NaT
    out['concepto'] = df[concepto_col].astype(str) if concepto_col else ''
    out['valor'] = to_pesos_series(df[valor_col]) if valor_col else 0.0
    out['notas'] = df[notas_col].astype(str) if notas_col else ''
    out = out.dropna(how='all')
    out['valor'] = out['valor'].fillna(0.0); out['notas'] = out['notas'].fillna('')
    if 'fecha' in out:
        out['fecha'] = pd.to_datetime(out['fecha'], errors='coerce', dayfirst=True).dt.date
    out = out[(out['concepto'].astype(str).str.strip()!='') | (out['valor'].ne(0))]
    return out[['fecha','concepto','valor','notas']]

def normalize_prestamos(df_raw: pd.DataFrame) -> pd.DataFrame:
    df = df_raw.copy(); df.columns = [str(c).strip().upper() for c in df.columns]
    nombre_col = 'NOMBRE' if 'NOMBRE' in df.columns else None
    valor_col = 'VALOR' if 'VALOR' in df.columns else None
    out = pd.DataFrame()
    out['nombre'] = df[nombre_col].astype(str) if nombre_col else ''
    out['valor'] = to_pesos_series(df[valor_col]) if valor_col else 0.0
    out = out[(out['nombre'].astype(str).str.strip()!='') & out['valor'].notna()]
    out['valor'] = out['valor'].fillna(0.0)
    return out[['nombre','valor']]

def normalize_inventario(df_raw: pd.DataFrame) -> pd.DataFrame:
    df = df_raw.copy(); df.columns = [str(c).strip().upper() for c in df.columns]
    prod_col = 'PRODUCTO' if 'PRODUCTO' in df.columns else None
    costo_col = next((c for c in df.columns if ('VALOR' in c and 'COSTO' in c) or c=='VALOR COSTO' or c=='COSTO'), None)
    out = pd.DataFrame()
    out['producto'] = df[prod_col].astype(str) if prod_col else ''
    out['valor_costo'] = to_pesos_series(df[costo_col]) if costo_col else 0.0
    out = out[out['producto'].astype(str).str.strip()!='']
    out['valor_costo'] = out['valor_costo'].fillna(0.0)
    return out[['producto','valor_costo']]

def extract_deudores_ini_from_xls(xls: pd.ExcelFile, sheet_name: str) -> pd.DataFrame:
    df = pd.read_excel(xls, sheet_name=sheet_name, header=None)
    if df.shape[1] < 6:
        return pd.DataFrame(columns=['nombre','valor'])
    nombres = df.iloc[:, 4].astype(str).fillna("").str.strip()
    valores = to_pesos_series(df.iloc[:, 5])
    out = pd.DataFrame({"nombre": nombres, "valor": valores})
    out = out[(out['nombre'] != "") & (out['valor'] > 0)]
    out = out.groupby('nombre', as_index=False)['valor'].sum()
    return out[['nombre','valor']]

# --- Helpers seguros para DB / casting ---
def _to_date_str(v):
    """Convierte cualquier cosa a 'YYYY-MM-DD' o None. Evita NaT/NaN."""
    try:
        if v is None:
            return None
        if isinstance(v, pd.Timestamp):
            if pd.isna(v):
                return None
            return v.date().isoformat()
        if isinstance(v, datetime):
            return v.date().isoformat()
        if isinstance(v, date):
            return v.isoformat()
        s = str(v).strip()
        if not s or s.lower() in ("nat", "nan", "none"):
            return None
        dt = pd.to_datetime(s, errors="coerce", dayfirst=True)
        if pd.isna(dt):
            return None
        return dt.date().isoformat()
    except Exception:
        return None

def _to_float(v) -> float:
    try:
        x = float(v)
        if np.isnan(x):
            return 0.0
        return x
    except Exception:
        return 0.0

def _to_int(v) -> int:
    try:
        if v is None:
            return 0
        if isinstance(v, (int, np.integer)):
            return int(v)
        x = float(v)
        if np.isnan(x):
            return 0
        return int(x)
    except Exception:
        return 0

# =========================================================
# Inserciones / Upserts
# =========================================================
def delete_consolidado(fecha_str: str):
    owner = _current_owner()
    with get_conn() as conn:
        cur = conn.execute("SELECT * FROM consolidado_diario WHERE fecha=? AND owner=?", (fecha_str, owner))
        row = cur.fetchone()
        cols = [d[0] for d in cur.description] if cur.description else []
        before = dict(zip(cols, row)) if row else None
        conn.execute("DELETE FROM consolidado_diario WHERE fecha=? AND owner=?", (fecha_str, owner))
    audit("delete", table_name="consolidado_diario", extra={"fecha": fecha_str, "owner": owner}, before=before)

def upsert_consolidado(fecha_str: str, efectivo: float, notas: str=""):
    owner = _current_owner()
    before = None
    with get_conn() as conn:
        cur = conn.execute("SELECT * FROM consolidado_diario WHERE fecha=? AND owner=?", (fecha_str, owner))
        row = cur.fetchone()
        cols = [d[0] for d in cur.description] if cur.description else []
        before = dict(zip(cols, row)) if row else None

    with get_conn() as conn:
        conn.execute("""
            INSERT INTO consolidado_diario(fecha,efectivo,notas,owner)
            VALUES(?,?,?,?)
            ON CONFLICT(fecha, owner) DO UPDATE SET
                efectivo=excluded.efectivo,
                notas=excluded.notas
        """, (fecha_str, _to_float(efectivo), str(notas or '').strip(), owner))
    audit("upsert", table_name="consolidado_diario",
          extra={"fecha": fecha_str, "owner": owner},
          before=before,
          after={"fecha": fecha_str, "efectivo": float(efectivo), "notas": str(notas or '').strip(), "owner": owner})

def get_efectivo_global_now() -> tuple[float, str]:
    owner = _current_owner()
    with get_conn() as conn:
        row = conn.execute(
            "SELECT efectivo, notas FROM consolidado_diario WHERE UPPER(TRIM(fecha))='GLOBAL' AND owner=?",
            (owner,)
        ).fetchone()
    if row:
        return float(row[0] or 0.0), str(row[1] or "")
    return 0.0, ""

def insert_venta(r: dict, owner_override: str | None = None) -> int:
    payload = {
        'fecha': _to_date_str(r.get('fecha')),
        'cliente_nombre': str(r.get('cliente_nombre') or '').strip(),
        'costo': _to_float(r.get('costo')),
        'venta': _to_float(r.get('venta')),
        'ganancia': _to_float(r.get('ganancia')),
        'debe_flag': _to_int(r.get('debe_flag')),
        'paga': str(r.get('paga') or '').strip(),
        'abono1': _to_float(r.get('abono1')),
        'abono2': _to_float(r.get('abono2')),
        'observacion': str(r.get('observacion') or '').strip(),
        'owner': (owner_override.strip() if owner_override else _row_owner()),
    }
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO transacciones
            (fecha, cliente_nombre, costo, venta, ganancia, debe_flag, paga, abono1, abono2, observacion, owner)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (payload['fecha'], payload['cliente_nombre'], payload['costo'], payload['venta'],
             payload['ganancia'], payload['debe_flag'], payload['paga'], payload['abono1'],
             payload['abono2'], payload['observacion'], payload['owner'])
        )
        row_id = cur.lastrowid
    audit("insert", table_name="transacciones", row_id=row_id, after=payload)
    return row_id

def insert_gasto(r: dict, owner_override: str | None = None) -> int:
    payload = {
        'fecha': _to_date_str(r.get('fecha')),
        'concepto': str(r.get('concepto') or '').strip(),
        'valor': _to_float(r.get('valor')),
        'notas': str(r.get('notas') or '').strip(),
        'owner': (owner_override.strip() if owner_override else _row_owner()),
    }
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO gastos (fecha, concepto, valor, notas, owner) VALUES (?, ?, ?, ?, ?)",
            (payload['fecha'], payload['concepto'], payload['valor'], payload['notas'], payload['owner'])
        )
        row_id = cur.lastrowid
    audit("insert", table_name="gastos", row_id=row_id, after=payload)
    return row_id

def insert_prestamo(r: dict, owner_override: str | None = None) -> int:
    payload = {
        'nombre': str(r.get('nombre') or '').strip(),
        'valor': _to_float(r.get('valor')),
        'owner': (owner_override.strip() if owner_override else _row_owner()),
    }
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO prestamos (nombre, valor, owner) VALUES (?, ?, ?)",
            (payload['nombre'], payload['valor'], payload['owner'])
        )
        row_id = cur.lastrowid
    audit("insert", table_name="prestamos", row_id=row_id, after=payload)
    return row_id

def insert_inventario(r: dict, owner_override: str | None = None) -> int:
    payload = {
        'producto': str(r.get('producto') or '').strip(),
        'valor_costo': _to_float(r.get('valor_costo')),
        'owner': (owner_override.strip() if owner_override else _row_owner()),
    }
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO inventario (producto, valor_costo, owner) VALUES (?, ?, ?)",
            (payload['producto'], payload['valor_costo'], payload['owner'])
        )
        row_id = cur.lastrowid
    audit("insert", table_name="inventario", row_id=row_id, after=payload)
    return row_id

def insert_deudor_ini(r: dict, owner_override: str | None = None) -> int:
    payload = {
        'nombre': str(r.get('nombre') or '').strip(),
        'valor': _to_float(r.get('valor')),
        'owner': (owner_override.strip() if owner_override else _row_owner()),
    }
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO deudores_ini (nombre, valor, owner) VALUES (?, ?, ?)",
            (payload['nombre'], payload['valor'], payload['owner'])
        )
        row_id = cur.lastrowid
    audit("insert", table_name="deudores_ini", row_id=row_id, after=payload)
    return row_id

def _fetch_row_as_dict(conn: sqlite3.Connection, table: str, row_id: int) -> dict | None:
    cur = conn.execute(f"SELECT * FROM {table} WHERE id=?", (int(row_id),))
    r = cur.fetchone()
    if not r:
        return None
    cols = [d[0] for d in cur.description]
    return dict(zip(cols, r))

def delete_venta_id(row_id: int):
    where = "id=?"
    params = [int(row_id)]
    if not _view_all_enabled():
        where += " AND owner=?"
        params.append(_current_owner())

    with get_conn() as conn:
        cur = conn.execute(f"SELECT * FROM transacciones WHERE {where}", tuple(params))
        row = cur.fetchone()
        cols = [d[0] for d in cur.description] if cur.description else []
        before = dict(zip(cols, row)) if row else None

        conn.execute(f"DELETE FROM transacciones WHERE {where}", tuple(params))

    audit("delete", table_name="transacciones", row_id=int(row_id), before=before)


def delete_gasto_id(row_id: int):
    where = "id=?"
    params = [int(row_id)]
    if not _view_all_enabled():
        where += " AND owner=?"
        params.append(_current_owner())

    with get_conn() as conn:
        cur = conn.execute(f"SELECT * FROM gastos WHERE {where}", tuple(params))
        row = cur.fetchone()
        cols = [d[0] for d in cur.description] if cur.description else []
        before = dict(zip(cols, row)) if row else None

        conn.execute(f"DELETE FROM gastos WHERE {where}", tuple(params))

    audit("delete", table_name="gastos", row_id=int(row_id), before=before)


def delete_prestamo_id(row_id: int):
    where = "id=?"
    params = [int(row_id)]
    if not _view_all_enabled():
        where += " AND owner=?"
        params.append(_current_owner())

    with get_conn() as conn:
        cur = conn.execute(f"SELECT * FROM prestamos WHERE {where}", tuple(params))
        row = cur.fetchone()
        cols = [d[0] for d in cur.description] if cur.description else []
        before = dict(zip(cols, row)) if row else None

        conn.execute(f"DELETE FROM prestamos WHERE {where}", tuple(params))

    audit("delete", table_name="prestamos", row_id=int(row_id), before=before)


def delete_inventario_id(row_id: int):
    where = "id=?"
    params = [int(row_id)]
    if not _view_all_enabled():
        where += " AND owner=?"
        params.append(_current_owner())

    with get_conn() as conn:
        cur = conn.execute(f"SELECT * FROM inventario WHERE {where}", tuple(params))
        row = cur.fetchone()
        cols = [d[0] for d in cur.description] if cur.description else []
        before = dict(zip(cols, row)) if row else None

        conn.execute(f"DELETE FROM inventario WHERE {where}", tuple(params))

    audit("delete", table_name="inventario", row_id=int(row_id), before=before)

def update_venta_fields(row_id: int, **changes) -> bool:
    allowed = {"fecha","cliente_nombre","costo","venta","ganancia","debe_flag","paga","abono1","abono2","observacion"}
    if not changes:
        return False

    payload = {}
    for k, v in changes.items():
        if k not in allowed:
            continue
        if k in {"costo","venta","ganancia","abono1","abono2"}: payload[k] = _to_float(v)
        elif k == "debe_flag": payload[k] = _to_int(v)
        elif k == "fecha": payload[k] = _to_date_str(v)
        else: payload[k] = str(v or "").strip()
    if not payload:
        return False

    where = "id=?"
    params_where = [int(row_id)]
    if not _view_all_enabled():
        where += " AND owner=?"
        params_where.append(_current_owner())

    with get_conn() as conn:
        cur = conn.execute(f"SELECT * FROM transacciones WHERE {where}", tuple(params_where))
        before_row = cur.fetchone()
        if not before_row:
            audit("update.denied", table_name="transacciones", row_id=int(row_id),
                  extra={"reason":"row not found or not owned", "owner":_current_owner()})
            return False

        cols = [d[0] for d in cur.description]
        before = dict(zip(cols, before_row))

        sets = ", ".join([f"{k}=?" for k in payload.keys()])
        vals = list(payload.values()) + params_where
        conn.execute(f"UPDATE transacciones SET {sets} WHERE {where}", vals)

        after = before.copy(); after.update(payload)

    audit("update", table_name="transacciones", row_id=int(row_id), before=before, after=after)
    return True


def update_gasto_fields(row_id: int, **changes) -> bool:
    allowed = {"fecha","concepto","valor","notas"}
    if not changes:
        return False

    payload = {}
    for k, v in changes.items():
        if k not in allowed: continue
        if k == "valor": payload[k] = _to_float(v)
        elif k == "fecha": payload[k] = _to_date_str(v)
        else: payload[k] = str(v or "").strip()
    if not payload:
        return False

    where = "id=?"
    params_where = [int(row_id)]
    if not _view_all_enabled():
        where += " AND owner=?"
        params_where.append(_current_owner())

    with get_conn() as conn:
        cur = conn.execute(f"SELECT * FROM gastos WHERE {where}", tuple(params_where))
        before_row = cur.fetchone()
        if not before_row:
            audit("update.denied", table_name="gastos", row_id=int(row_id),
                  extra={"reason":"row not found or not owned", "owner":_current_owner()})
            return False

        cols = [d[0] for d in cur.description]
        before = dict(zip(cols, before_row))

        sets = ", ".join([f"{k}=?" for k in payload.keys()])
        vals = list(payload.values()) + params_where
        conn.execute(f"UPDATE gastos SET {sets} WHERE {where}", vals)

        after = before.copy(); after.update(payload)

    audit("update", table_name="gastos", row_id=int(row_id), before=before, after=after)
    return True


def update_prestamo_fields(row_id: int, **changes) -> bool:
    allowed = {"nombre","valor"}
    if not changes:
        return False

    payload = {}
    for k, v in changes.items():
        if k not in allowed: continue
        if k == "valor": payload[k] = _to_float(v)
        else: payload[k] = str(v or "").strip()
    if not payload:
        return False

    where = "id=?"
    params_where = [int(row_id)]
    if not _view_all_enabled():
        where += " AND owner=?"
        params_where.append(_current_owner())

    with get_conn() as conn:
        cur = conn.execute(f"SELECT * FROM prestamos WHERE {where}", tuple(params_where))
        before_row = cur.fetchone()
        if not before_row:
            audit("update.denied", table_name="prestamos", row_id=int(row_id),
                  extra={"reason":"row not found or not owned", "owner":_current_owner()})
            return False

        cols = [d[0] for d in cur.description]
        before = dict(zip(cols, before_row))

        sets = ", ".join([f"{k}=?" for k in payload.keys()])
        vals = list(payload.values()) + params_where
        conn.execute(f"UPDATE prestamos SET {sets} WHERE {where}", vals)

        after = before.copy(); after.update(payload)

    audit("update", table_name="prestamos", row_id=int(row_id), before=before, after=after)
    return True


def update_inventario_fields(row_id: int, **changes) -> bool:
    allowed = {"producto","valor_costo"}
    if not changes:
        return False

    payload = {}
    for k, v in changes.items():
        if k not in allowed: continue
        if k == "valor_costo": payload[k] = _to_float(v)
        else: payload[k] = str(v or "").strip()
    if not payload:
        return False

    where = "id=?"
    params_where = [int(row_id)]
    if not _view_all_enabled():
        where += " AND owner=?"
        params_where.append(_current_owner())

    with get_conn() as conn:
        cur = conn.execute(f"SELECT * FROM inventario WHERE {where}", tuple(params_where))
        before_row = cur.fetchone()
        if not before_row:
            audit("update.denied", table_name="inventario", row_id=int(row_id),
                  extra={"reason":"row not found or not owned", "owner":_current_owner()})
            return False

        cols = [d[0] for d in cur.description]
        before = dict(zip(cols, before_row))

        sets = ", ".join([f"{k}=?" for k in payload.keys()])
        vals = list(payload.values()) + params_where
        conn.execute(f"UPDATE inventario SET {sets} WHERE {where}", vals)

        after = before.copy(); after.update(payload)

    audit("update", table_name="inventario", row_id=int(row_id), before=before, after=after)
    return True

# =========================================================
# Helpers UI
# =========================================================
def money(x: float) -> str:
    try:
        return f"($ {abs(x):,.0f})" if x < 0 else f"$ {x:,.0f}"
    except Exception:
        return "$ 0"

def notify_ok(msg: str):
    st.success(msg)
    try:
        st.toast(msg, icon="✅")
    except Exception:
        pass

def flash_next_run(msg: str, icon: str = "✅"):
    """Guarda un mensaje para mostrarlo tras el próximo rerun."""
    st.session_state["_flash_msg"] = (msg, icon)

def show_flash_if_any():
    """Muestra y limpia el mensaje pendiente (si existe)."""
    data = st.session_state.pop("_flash_msg", None)
    if not data:
        return
    msg, icon = (data if isinstance(data, tuple) else (str(data), "✅"))
    try:
        st.toast(msg, icon=icon)
    except Exception:
        pass
    st.success(msg)

def currency_input(label: str, key: str, value: float = 0.0,
                   help: str | None = None, in_form: bool = False, live: bool = True) -> float:
    """
    Campo de moneda con formato en vivo (miles '.' y decimales ',').
    Máximo 2 decimales. Si no hay decimales, no los muestra.
    """
    state_key = f"{key}_txt"

    # ---- helpers ----
    def _group_dots(digits: str) -> str:
        digits = (digits or "").lstrip("0") or "0"
        out = []
        for i, ch in enumerate(reversed(digits), 1):
            out.append(ch)
            if i % 3 == 0 and i < len(digits):
                out.append(".")
        return "".join(reversed(out))

    def _normalize_text(s: str) -> str:
        if not isinstance(s, str):
            s = str(s or "")
        s = s.strip().replace(" ", "")
        neg = s.startswith("-") or s.startswith("−") or (s.startswith("(") and s.endswith(")"))
        s2 = s.strip("()").lstrip("-−")
        dots, commas = s2.count("."), s2.count(",")
        ld, lc = s2.rfind("."), s2.rfind(",")

        head, frac = "", ""
        if dots or commas:
            sep = "." if (ld > lc) else ","
            parts = s2.split(sep)
            tail_digits = re.sub(r"\D", "", parts[-1] if parts else "")
            sep_count = dots if sep == "." else commas
            if sep_count > 1 and len(tail_digits) == 3:
                head = re.sub(r"\D", "", s2)
            elif 1 <= len(tail_digits) <= 2:
                head = re.sub(r"\D", "", "".join(parts[:-1]))
                frac = tail_digits[:2]
            else:
                head = re.sub(r"\D", "", s2)
        else:
            head = re.sub(r"\D", "", s2)

        txt = _group_dots(head) + ("," + frac if frac else "")
        if neg and txt != "0":
            txt = "-" + txt
        return txt

    # ---- preparar valor en session_state ANTES de crear el widget ----
    if state_key not in st.session_state:
        try:
            init = int(round(float(value or 0.0)))
        except Exception:
            init = 0
        st.session_state[state_key] = f"{init:,}".replace(",", ".")
    else:
        raw0 = st.session_state.get(state_key, "")
        norm0 = _normalize_text(str(raw0))
        if norm0 != raw0:
            st.session_state[state_key] = norm0  # OK: aún no hemos creado el widget

    # ---- widget (no escribas en session_state después de esto) ----
    st.text_input(label, key=state_key, help=help)

    # ---- JS opcional para formateo en vivo mientras se teclea ----
    if live:
        import json
        components.html(f"""
        <script>
        (function(){{
        try{{
            const doc=(window.parent||window).document;
            const LABEL={json.dumps(label)};
            const STATE={json.dumps(state_key)};
            function groupDots(d){{ d=(d||'').replace(/\\D/g,'').replace(/^0+(?=\\d)/,'')||'0';
            let out='', c=0; for(let i=d.length-1;i>=0;--i){{ out=d[i]+out; if(++c%3===0&&i>0) out='.'+out; }} return out; }}
            function normalize(s){{
            s=(s||'').replace(/\\s+/g,'');
            const neg=/^[-−(]/.test(s); s=s.replace(/[()−-]/g,'');
            const dots=(s.match(/\\./g)||[]).length, commas=(s.match(/,/g)||[]).length;
            const ld=s.lastIndexOf('.'), lc=s.lastIndexOf(',');
            let head='', frac='';
            if(dots || commas){{
                const sep   = (ld > lc) ? '.' : ',';
                const parts = s.split(sep);
                const tail  = (parts[parts.length-1]||'').replace(/\\D/g,'');
                const sc    = (sep === '.') ? dots : commas;
                const oneKind = ((dots > 0 && commas === 0) || (commas > 0 && dots === 0));

                // Solo un tipo de separador y: aparece >1 vez o la "cola" tiene ≥3 dígitos
                // => tratar como separadores de miles (sin decimales)
                if(oneKind && (sc > 1 || tail.length >= 3)){{
                head = s.replace(/\\D/g,'');
                frac = '';
                }} else if(tail.length >= 1 && tail.length <= 2){{
                head = parts.slice(0,-1).join('').replace(/\\D/g,'');
                frac = tail.slice(0,2);
                }} else {{
                head = s.replace(/\\D/g,'');
                frac = '';
                }}
            }} else {{
                head = s.replace(/\\D/g,'');
            }}
            let out = groupDots(head) + (frac ? (','+frac) : '');
            if(neg && out!=='0') out='-'+out;
            return out;
            }}
            function install(el){{
            if(!el || el.dataset.ttMoneyInstalled===STATE) return;
            el.dataset.ttMoneyInstalled=STATE; el.setAttribute('inputmode','decimal'); el.autocomplete='off';
            const fmt=()=>{{ const v=normalize(el.value); if(v!==el.value){{ const a=(doc.activeElement===el); el.value=v; if(a) el.setSelectionRange(el.value.length, el.value.length); }} }};
            el.addEventListener('input', ()=>setTimeout(fmt,0)); setTimeout(fmt,0);
            }}
            let tries=0, t=setInterval(()=>{{
            const el=[...doc.querySelectorAll('input[aria-label="'+LABEL+'"]')].find(n=>n && n.dataset.ttMoneyInstalled!==STATE);
            if(el){{ clearInterval(t); install(el); }} else if(++tries>40) clearInterval(t);
            }},80);
        }}catch(e){{}}
        }})();
        </script>
        """, height=0, width=0)

    # ---- devuelve el float robusto usando tu parser ----
    return float(_parse_pesos(st.session_state[state_key]))

def df_format_money(df: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
    d = df.copy()
    for c in cols:
        if c in d.columns:
            d[c] = pd.to_numeric(d[c], errors='coerce').fillna(0.0).map(money)
    return d

def _reset_keys(keys: list[str]):
    """Elimina claves del session_state para que los widgets vuelvan al valor por defecto en el próximo rerun."""
    for k in keys:
        st.session_state.pop(k, None)

def clear_venta_form_rt():
    # cubre desktop (keys *_txt) y móvil (keys sin _txt)
    _reset_keys([
        "VTA_fecha_rt", "VTA_cliente_rt", "VTA_debe_rt", "VTA_paga_rt", "VTA_obs_rt",
        "VTA_costo_rt_txt", "VTA_costo_rt",
        "VTA_venta_rt_txt", "VTA_venta_rt",
        "VTA_ab1_rt_txt", "VTA_ab1_rt",
        "VTA_ab2_rt_txt", "VTA_ab2_rt",
        "VTA_ganancia_view_rt",
    ])
    # Fuerza vacío por si el navegador/autofill insiste
    st.session_state["VTA_cliente_rt"] = ""

def clear_gasto_form():
    _reset_keys([
        "GTO_fecha", "GTO_concepto", "GTO_notas",
        "GTO_valor_txt", "GTO_valor",   # desktop y móvil
    ])

def clear_inventario_form():
    _reset_keys([
        "INV_producto",
        "INV_valor_costo_txt", "INV_valor_costo",  # desktop y móvil
    ])

def filtro_busqueda(df: pd.DataFrame, cols: list[str], key: str):
    q1, q2 = st.columns([2,1], gap="small")
    texto = q1.text_input("🔎 Buscar", key=f"q_{key}")
    fecha_rango = q2.date_input(
        "Rango",
        value=(date.today().replace(day=1), date.today()),
        format="DD/MM/YYYY",
        key=f"rng_{key}"
    )
    df2 = df.copy()
    if texto:
        patt = texto.strip().upper()
        mask = False
        for c in cols:
            mask = mask | df2[c].astype(str).str.upper().str.contains(patt, na=False)
        df2 = df2[mask]
    if isinstance(fecha_rango, tuple) and len(fecha_rango)==2 and "fecha" in df2:
        f0, f1 = fecha_rango
        df2 = df2[(df2["fecha"]>=f0) & (df2["fecha"]<=f1)]
    return df2


# --- User badge (logo + nombre arriba a la derecha) ---
def _guess_logo_path(candidates: list[str] | None = None) -> str | None:
    from pathlib import Path
    base = Path(__file__).parent
    defaults = [
        "logo.png", "logo.jpg", "logo.jpeg", "logo.webp", "logo.svg",
        "assets/logo.png", "assets/logo.jpg", "assets/logo.jpeg", "assets/logo.webp", "assets/logo.svg",
        "static/logo.png", "static/logo.jpg", "static/logo.jpeg", "static/logo.webp", "static/logo.svg",
        "images/logo.png", "images/logo.jpg", "images/logo.jpeg", "images/logo.webp", "images/logo.svg",
        "img/logo.png", "img/logo.jpg", "img/logo.jpeg", "img/logo.webp", "img/logo.svg",
    ]
    for rel in (candidates or defaults):
        p = (base / rel).resolve()
        if p.is_file():
            return str(p)
    return None

def _img_to_data_uri(path: str | None) -> str | None:
    try:
        from pathlib import Path
        if not path:
            return None
        p = Path(path)
        if not p.is_file():
            # último intento: relativo al archivo del app
            p = (Path(__file__).parent / path).resolve()
            if not p.is_file():
                return None
        ext = p.suffix.lower().lstrip(".")
        if ext == "jpg":
            ext = "jpeg"
        mime = "image/svg+xml" if ext == "svg" else f"image/{ext or 'png'}"
        data = base64.b64encode(p.read_bytes()).decode("utf-8")
        return f"data:{mime};base64,{data}"
    except Exception:
        return None

def _get_logo_uri(preferred: str | None = None) -> str | None:
    from pathlib import Path

    # si estaba cacheado como None, vuelve a intentar
    if st.session_state.get("logo_uri_cache", "##miss##") is None:
        st.session_state.pop("logo_uri_cache", None)
        st.session_state.pop("logo_uri_sig", None)

    cand = preferred or _guess_logo_path()
    if not cand:
        return None

    p = Path(cand)
    if not p.is_file():
        p = (Path(__file__).parent / cand).resolve()

    sig = f"{str(p)}::{p.stat().st_mtime if p.exists() else 0}"
    if st.session_state.get("logo_uri_sig") == sig:
        return st.session_state.get("logo_uri_cache")

    uri = _img_to_data_uri(str(p)) if p.exists() else None
    st.session_state["logo_uri_cache"] = uri
    st.session_state["logo_uri_sig"] = sig
    return uri

def show_logo_over_title(username: str, logo_path: str | None = None):
    """Pequeño logo + usuario sobre el título de la página (no flotante)."""
    uri = _img_to_data_uri(logo_path or _guess_logo_path())
    st.markdown("""
    <style>
      .brand-top{
        display:flex; align-items:center; gap:10px;
        margin:4px 0 2px 0;
      }
      .brand-top img{ height:100px; width:auto; display:block; }
      .brand-top .u{ font-weight:600; color:#374151; letter-spacing:.2px; }
    </style>
    """, unsafe_allow_html=True)

    if uri:
        st.markdown(
            f'<div class="brand-top"><img src="{uri}" alt="logo"><span class="u">{username}</span></div>',
            unsafe_allow_html=True
        )
    else:
        st.markdown(f'<div class="brand-top"><span class="u">{username}</span></div>',
                    unsafe_allow_html=True)
        
def show_sticky_header(title_text: str,
                       logo_path: str | None = None,
                       show_brand_text: bool = False,
                       fixed: bool = False,
                       warn_if_missing: bool = True):
    st.markdown(
        f'''
        <div class="tt-titlebar" role="banner">
          <div class="l"></div>
          <div class="ttl">{_clean_title(title_text)}</div>
          <div class="r"></div>
        </div>
        ''',
        unsafe_allow_html=True
    )

def show_user_badge(username: str, logo_path: str | None = None, warn_if_missing: bool = False):
    # intenta resolver logo si no te pasan ruta
    resolved = logo_path or _guess_logo_path()

    uri = _img_to_data_uri(resolved)

    # Estilos del badge fijo
    st.markdown("""
<style>
.app-user-badge{
  position: fixed;
  top: 10px;
  right: 16px;
  z-index: 999999;
  display: inline-flex;
  align-items: center;
  gap: 10px;
  background: rgba(255,255,255,.92);
  padding: 6px 10px;
  border-radius: 999px;
  box-shadow: 0 2px 6px rgba(0,0,0,.08);
  backdrop-filter: saturate(180%) blur(6px);
  -webkit-backdrop-filter: saturate(180%) blur(6px);
  border: 1px solid rgba(120,120,135,.18);
}
.app-user-badge img{ height:22px; width:auto; display:block; }
.app-user-badge .name{
  font-weight:600; color:#374151; letter-spacing:.2px; white-space:nowrap;
}
</style>
""", unsafe_allow_html=True)

    img_html = f'<img src="{uri}" alt="logo">' if uri else ""
    st.markdown(
        f'<div class="app-user-badge">{img_html}<span class="name">{username}</span></div>',
        unsafe_allow_html=True
    )

    if warn_if_missing and not uri:
        st.sidebar.info(
            "⚠️ No encontré el logo. Coloca el archivo como **logo.png** en la carpeta del app, "
            "o pásame otra ruta al llamar a `show_user_badge(user, logo_path=\"ruta/a/tu_logo.png\")`."
        )

def show_sidebar_logo(logo_path: str | None = None, height: int = 64):
    """Muestra el logo en la sidebar (centrado). Usa auto–detección si no pasas ruta."""
    uri = _img_to_data_uri(logo_path or _guess_logo_path())
    if not uri:
        return
    st.sidebar.markdown(
        f"""
        <div style="display:flex;align-items:center;justify-content:center;
                    padding:8px 0 12px;border-bottom:1px solid rgba(120,120,135,.15);">
          <img src="{uri}" alt="logo" style="height:{height}px;width:auto;"/>
        </div>
        """,
        unsafe_allow_html=True
    )

# Compat: _nz usado en editores (convierte None/NaN/strings a float seguro)
def _nz(x) -> float:
    return _to_float(x)

def stat_card(label: str, value: str, icon: str, tone: str = "tt-indigo"):
    st.markdown(
        f"""
        <div class="tt-stat {tone}">
          <div class="ic">{icon}</div>
          <div class="meta">
            <div class="lbl">{label}</div>
            <div class="val">{value}</div>
          </div>
        </div>
        """,
        unsafe_allow_html=True
    )

def stat_min(label: str, value: str, tone: str = "var(--pri)"):
    """Tarjeta minimal con borde izquierdo en el color 'tone'."""
    st.markdown(
        f"""
        <div class="mm-stat" style="--tone:{tone}">
          <div class="lbl">{label}</div>
          <div class="val">{value}</div>
        </div>
        """,
        unsafe_allow_html=True
    )


# =========================
# Google Sheets Sync
# =========================
GOOGLE_SHEETS_ENABLED = bool(int(get_meta("GSHEETS_ENABLED", 1)))  # 1=on, 0=off

# 1) RUTA DEL JSON — puedes:
#    a) poner el archivo "service_account.json" en la carpeta del proyecto, o
#    b) definir la variable de entorno GSERVICE_ACCOUNT_FILE con la ruta absoluta, o
#    c) guardar el JSON en st.secrets["gcp_service_account"] (dict)
GSERVICE_ACCOUNT_FILE = os.getenv("GSERVICE_ACCOUNT_FILE", "service_account.json")

# Permite sobreescribir el ID desde Admin (meta)
GSPREADSHEET_ID = str(get_meta("GSHEET_ID", ""))  # vacío por defecto
try:
    if not GSPREADSHEET_ID:
        GSPREADSHEET_ID = st.secrets.get("GSHEET_ID", "") or os.getenv("GSHEET_ID", "")
except Exception:
    GSPREADSHEET_ID = os.getenv("GSHEET_ID", "")

GS_SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive"
]

# Mapa de tabla SQLite -> nombre de hoja en el Spreadsheet
GSHEET_MAP = {
    "transacciones":      "Ventas",
    "gastos":             "Gastos",
    "prestamos":          "Prestamos",
    "inventario":         "Inventario",
    "consolidado_diario": "Consolidado",
    "deudores_ini":       "DeudoresIniciales",
}

@st.cache_resource(show_spinner=False)
def _gs_client():
    # 1º: secrets como dict (Streamlit Cloud / .streamlit/secrets.toml)
    sa_info = None
    try:
        # si existe secrets["gcp_service_account"] (dict), úsalo
        sa_info = st.secrets.get("gcp_service_account", None)
    except Exception:
        pass

    if sa_info:
        creds = Credentials.from_service_account_info(dict(sa_info), scopes=GS_SCOPES)
    else:
        # 2º: archivo (ENV o por defecto)
        path = GSERVICE_ACCOUNT_FILE
        if not os.path.isfile(path):
            raise FileNotFoundError(
                f"No encuentro el archivo de credenciales: {path}. "
                "Ponlo en la carpeta del proyecto o define GSERVICE_ACCOUNT_FILE."
            )
        creds = Credentials.from_service_account_file(path, scopes=GS_SCOPES)
    try:
        sa_email = getattr(creds, "service_account_email", None)
        if not sa_email:
            sa_email = json.loads(creds.to_json()).get("client_email")
        st.session_state["_gs_sa_email"] = sa_email
    except Exception:
        pass

    return gspread.authorize(creds)

def _gs_open_ws(title: str):
    client = _gs_client()
    sh = client.open_by_key(GSPREADSHEET_ID)
    try:
        return sh.worksheet(title)
    except gspread.WorksheetNotFound:
        return sh.add_worksheet(title=title, rows=1000, cols=30)

def _read_table_direct(table: str) -> pd.DataFrame:
    with get_conn() as conn:
        try:
            df = pd.read_sql_query(f"SELECT * FROM {table}", conn)
        except Exception:
            df = pd.DataFrame()
    if not df.empty:
        for c in df.columns:
            if pd.api.types.is_datetime64_any_dtype(df[c]) or pd.api.types.is_datetime64tz_dtype(df[c]):
                df[c] = pd.to_datetime(df[c], errors="coerce").dt.strftime("%Y-%m-%d")
            elif pd.api.types.is_object_dtype(df[c]):
                df[c] = df[c].astype(str)
    return df

def sync_tables_to_gsheet(tables: list[str]):
    if not GOOGLE_SHEETS_ENABLED:
        return
    if not GSPREADSHEET_ID:
        st.warning("Configura el Google Sheet ID en Administración antes de sincronizar.")
        return
    for t in tables:
        try:
            ws_name = GSHEET_MAP.get(t)   # <- usa la constante global
            if not ws_name:
                continue
            df = _read_table_direct(t)
            ws = _gs_open_ws(ws_name)
            ws.clear()
            if df.empty:
                ws.update([["(vacío)"]])
            else:
                values = [df.columns.tolist()] + df.astype(object).where(pd.notnull(df), "").values.tolist()
                ws.update(values, value_input_option="USER_ENTERED")
        except Exception as e:
            st.warning(f"No se pudo sincronizar '{t}' a Google Sheets: {e}")

# --- Restaurar SQLite desde Google Sheets si la BD está vacía ---
def _gs_read_df(ws_title: str) -> pd.DataFrame:
    if not GOOGLE_SHEETS_ENABLED or not GSPREADSHEET_ID:
        return pd.DataFrame()
    try:
        ws = _gs_open_ws(ws_title)
        values = ws.get_all_values()
        if not values or len(values) <= 1 or (values and values[0] and values[0][0] == "(vacío)"):
            return pd.DataFrame()
        df = pd.DataFrame(values[1:], columns=values[0])
        return df
    except Exception:
        return pd.DataFrame()

def _db_is_completely_empty() -> bool:
    tables = ["transacciones","gastos","prestamos","inventario","deudores_ini","consolidado_diario"]
    total = 0
    with get_conn() as conn:
        for t in tables:
            try:
                total += int(conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0])
            except Exception:
                pass
    return total == 0

def restore_from_gsheets_if_empty():
    if not GOOGLE_SHEETS_ENABLED or not GSPREADSHEET_ID:
        return
    # Evita repetir en el mismo run
    if st.session_state.get("_restored_from_gsheets"): 
        return
    if not _db_is_completely_empty():
        return

    try:
        # Transacciones
        df = _gs_read_df(GSHEET_MAP["transacciones"])
        if not df.empty:
            df = df.drop(columns=[c for c in df.columns if c.lower()=="id"], errors="ignore")
            for _, r in df.iterrows():
                insert_venta(r.to_dict(), owner_override='admin')

        # Gastos
        df = _gs_read_df(GSHEET_MAP["gastos"])
        if not df.empty:
            df = df.drop(columns=[c for c in df.columns if c.lower()=="id"], errors="ignore")
            for _, r in df.iterrows():
                insert_gasto(r.to_dict(), owner_override='admin')

        # Prestamos
        df = _gs_read_df(GSHEET_MAP["prestamos"])
        if not df.empty:
            df = df.drop(columns=[c for c in df.columns if c.lower()=="id"], errors="ignore")
            for _, r in df.iterrows():
                insert_prestamo(r.to_dict(), owner_override='admin')

        # Inventario
        df = _gs_read_df(GSHEET_MAP["inventario"])
        if not df.empty:
            df = df.drop(columns=[c for c in df.columns if c.lower()=="id"], errors="ignore")
            for _, r in df.iterrows():
                insert_inventario(r.to_dict(), owner_override='admin')

        # Consolidado (incluye "GLOBAL")
        df = _gs_read_df(GSHEET_MAP["consolidado_diario"])
        if not df.empty:
            for _, r in df.iterrows():
                upsert_consolidado(str(r.get("fecha") or r.get("FECHA")), 
                                   _to_float(r.get("efectivo") or r.get("EFECTIVO")), 
                                   str(r.get("notas") or r.get("NOTAS") or ""))

        # Deudores iniciales
        df = _gs_read_df(GSHEET_MAP["deudores_ini"])
        if not df.empty:
            df = df.drop(columns=[c for c in df.columns if c.lower()=="id"], errors="ignore")
            for _, r in df.iterrows():
                insert_deudor_ini(r.to_dict(), owner_override='admin')

        st.session_state["_restored_from_gsheets"] = True
        notify_ok("Base restaurada automáticamente desde Google Sheets.")
        st.cache_data.clear()

    except Exception as e:
        st.warning(f"No se pudo restaurar desde Google Sheets: {e}")

# ========= Refresco estandarizado =========
def finish_and_refresh(msg: str | None = "Listo ✅", tables_to_sync: list[str] | None = None):
    try:
        if tables_to_sync:
            sync_tables_to_gsheet(tables_to_sync)
        if msg:
            flash_next_run(msg)   # <- en vez de notify_ok aquí
        u = st.session_state.get("auth_user")
        if u:
            try: backup_user_flush_audit(u)
            except Exception as _e: pass
    finally:
        st.cache_data.clear()
        st.rerun()

restore_from_gsheets_if_empty()
# =========================
# Backups automáticos (SQLite)
# =========================
BACKUP_DIR = Path("backups")
BACKUP_EVERY_HOURS = 8
KEEP_BACKUPS = 40

def make_db_backup() -> Path:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    backup_path = BACKUP_DIR / f"finanzas_{ts}.sqlite"
    with sqlite3.connect(DB_FILE) as src, sqlite3.connect(backup_path) as dst:
        src.backup(dst)
    try:
        files = sorted(BACKUP_DIR.glob("finanzas_*.sqlite"),
                       key=lambda p: p.stat().st_mtime,
                       reverse=True)
        for p in files[KEEP_BACKUPS:]:
            p.unlink(missing_ok=True)
    except Exception:
        pass
    audit("backup.create", extra={"path": str(backup_path), "keep": KEEP_BACKUPS})
    return backup_path

def auto_backup_if_due():
    try:
        last_iso = get_meta("LAST_BACKUP_ISO", "")
        now = datetime.now()
        due = True
        if last_iso:
            try:
                last_dt = datetime.fromisoformat(str(last_iso))
                due = (now - last_dt) >= timedelta(hours=BACKUP_EVERY_HOURS)
            except Exception:
                due = True
        if due:
            path = make_db_backup()
            set_meta("LAST_BACKUP_ISO", now.isoformat(timespec="seconds"))
            notify_ok(f"Copia de seguridad creada: {path}")
    except Exception as e:
        st.warning(f"No se pudo crear la copia de seguridad: {e}")

# =========================================================
# Importación TODO-EN-UNO desde Excel
# =========================================================
def _truncate_tables(tables: list[str]):
    with get_conn() as conn:
        for t in tables:
            conn.execute(f"DELETE FROM {t}")

def _insert_many(table: str, df: pd.DataFrame) -> int:
    n = 0
    if df is None or df.empty:
        return 0
    for _, row in df.iterrows():
        r = row.to_dict()
        if table == "transacciones":
            insert_venta(r)
        elif table == "gastos":
            insert_gasto(r)
        elif table == "prestamos":
            insert_prestamo(r)
        elif table == "inventario":
            insert_inventario(r)
        elif table == "deudores_ini":
            insert_deudor_ini(r)
        n += 1
    return n

def import_excel_all(xls_file, replace: bool = False) -> dict:
    """
    Carga HOJAS conocidas de un .xlsx:
      - Ventas, Gastos, Prestamos, Inventario
      - DeudoresIniciales desde hoja 'Consolidado' (cols E/F)
    """
    xls = pd.ExcelFile(xls_file)
    if replace:
        _truncate_tables(["transacciones","gastos","prestamos","inventario","deudores_ini"])

    stats = {}

    # Ventas
    try:
        v_raw = pd.read_excel(xls, sheet_name="Ventas")
        v = normalize_ventas(v_raw)
        stats["ventas"] = _insert_many("transacciones", v)
    except Exception:
        stats["ventas"] = 0

    # Gastos
    try:
        g_raw = pd.read_excel(xls, sheet_name="Gastos")
        g = normalize_gastos(g_raw)
        stats["gastos"] = _insert_many("gastos", g)
    except Exception:
        stats["gastos"] = 0

    # Prestamos
    try:
        p_raw = pd.read_excel(xls, sheet_name="Prestamos")
        p = normalize_prestamos(p_raw)
        stats["prestamos"] = _insert_many("prestamos", p)
    except Exception:
        stats["prestamos"] = 0

    # Inventario
    try:
        i_raw = pd.read_excel(xls, sheet_name="Inventario")
        i = normalize_inventario(i_raw)
        stats["inventario"] = _insert_many("inventario", i)
    except Exception:
        stats["inventario"] = 0

    # DeudoresIniciales desde 'Consolidado' (col E = nombre, col F = valor)
    try:
        ddf = extract_deudores_ini_from_xls(xls, "Consolidado")
        stats["deudores_ini"] = _insert_many("deudores_ini", ddf)
    except Exception:
        stats["deudores_ini"] = 0

    try:
        fname = getattr(xls_file, "name", None)
    except Exception:
        fname = None
    audit("import.xlsx", table_name="*", extra={"filename": fname, "replace": bool(replace), "stats": stats})
    return stats

import unicodedata

def _slug_user(u: str) -> str:
    s = unicodedata.normalize("NFKD", str(u)).encode("ascii","ignore").decode("ascii")
    s = re.sub(r"[^A-Za-z0-9 _-]+", " ", s).strip().upper()
    s = re.sub(r"\s+", " ", s)
    return s[:60] or "USER"

def _meta_key_user_sheet(slug: str) -> str:
    return f"GSHEET_USER::{slug}"

def _meta_key_last_audit(slug: str) -> str:
    return f"GSHEET_USER_LASTAUDIT::{slug}"

def _open_sheet_by_ref(gc, ref: str):
    ref = (ref or "").strip()
    if not ref:
        raise ValueError("Referencia vacía para Google Sheet.")
    return gc.open_by_url(ref) if ref.startswith("http") else gc.open_by_key(ref)

def _gs_open_or_create_user_book(username: str, prefix: str = "BK-"):
    """Devuelve (sh, slug). Crea la hoja del usuario; si no puede, usa fallback (ID o URL)."""
    gc = _gs_client()
    slug = _slug_user(username)
    key  = _meta_key_user_sheet(slug)
    sheet_ref = str(get_meta(key, "")) or ""

    try:
        if sheet_ref:
            try:
                sh = _open_sheet_by_ref(gc, sheet_ref)
            except Exception:
                # El ID/URL guardado ya no sirve → crea una nueva y guarda el nuevo ID
                sh = gc.create(f"{prefix}{slug}")
                set_meta(key, sh.id)
        else:
            # Primera vez → crea y guarda ID
            sh = gc.create(f"{prefix}{slug}")
            set_meta(key, sh.id)

    except Exception as e:
        # Cuota llena o sin permiso para crear → usa fallback
        fallback_ref = str(get_meta("GSHEET_BACKUP_ID", "")) or str(GSPREADSHEET_ID or "")
        fallback_ref = fallback_ref.strip()

        if not fallback_ref:
            raise PermissionError(
                "No hay hoja de respaldo configurada (GSHEET_BACKUP_ID ni GSPREADSHEET_ID)."
            ) from e

        try:
            sh = _open_sheet_by_ref(gc, fallback_ref)
        except Exception as ex:
            sa = st.session_state.get("_gs_sa_email", "(service-account)") or "(service-account)"
            raise PermissionError(
                "No tengo permisos para abrir la hoja de respaldo configurada.\n\n"
                f"Comparte esa hoja (ID/URL: {fallback_ref}) con el correo del Service Account "
                f"**{sa}** como **Editor**."
            ) from ex

    return sh, slug

def _ws(sh, name: str, rows=1000, cols=30):
    import gspread
    try:
        return sh.worksheet(name)
    except gspread.WorksheetNotFound:
        return sh.add_worksheet(title=name, rows=rows, cols=cols)

def _ws_write(ws, df: pd.DataFrame):
    ws.clear()
    if df is None or df.empty:
        ws.update([["(vacío)"]], value_input_option="RAW")
        return
    values = [df.columns.tolist()] + df.astype(object).where(pd.notnull(df), "").values.tolist()
    ws.update(values, value_input_option="USER_ENTERED")

def backup_user_snapshot(username: str):
    if not GOOGLE_SHEETS_ENABLED:
        st.warning("Google Sheets está deshabilitado en Administración."); return

    sh, slug = _gs_open_or_create_user_book(username)   # ← FALTABA

    tablas = {
        "Ventas":              _read_table_direct("transacciones"),
        "Gastos":              _read_table_direct("gastos"),
        "Prestamos":           _read_table_direct("prestamos"),
        "Inventario":          _read_table_direct("inventario"),
        "DeudoresIniciales":   _read_table_direct("deudores_ini"),
        "Consolidado":         _read_table_direct("consolidado_diario"),
    }

    for nombre, df in tablas.items():
        _ws_write(_ws(sh, nombre), df)

    with get_conn() as conn:
        df_a = pd.read_sql_query(
            "SELECT id, ts, action, table_name AS tabla, row_id FROM audit_log WHERE user=? ORDER BY id DESC LIMIT 200",
            conn, params=(username,)
        )
    _ws_write(_ws(sh, "Estado", rows=200, cols=10), df_a)

    audit("user.backup.snapshot", extra={"user": username})

def backup_user_flush_audit(username: str) -> int:
    if not GOOGLE_SHEETS_ENABLED:
        return 0

    sh, slug = _gs_open_or_create_user_book(username)   # ← 2 valores
    sheet_name = f"{slug}::Cambios"                     # ← usa prefijo siempre (evita choques en fallback)
    ws = _ws(sh, sheet_name, rows=1000, cols=6)

    last_id = int(get_meta(_meta_key_last_audit(slug), 0) or 0)
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, ts, user, action, table_name, row_id, details "
            "FROM audit_log WHERE user=? AND id>? ORDER BY id ASC",
            (username, last_id)
        ).fetchall()
    if not rows:
        return 0

    try:
        size = len(ws.get_all_values() or [])
    except Exception:
        size = 0

    payload = []
    if size == 0:
        payload.append(["id","ts","user","action","table","row_id","details"])
    for r in rows:
        payload.append([r[0], r[1], r[2], r[3], r[4], r[5], str(r[6] or "")])

    ws.append_rows(payload, value_input_option="RAW")
    set_meta(_meta_key_last_audit(slug), int(rows[-1][0]))
    audit("user.backup.flush_audit", extra={"user": username, "pushed": len(rows)})
    return len(rows)

# =========================================================
# Sidebar (login primero)
# =========================================================
user, role = require_user()

with st.sidebar:
        # Ejecuta el backup automático sólo cuando ya hay sesión iniciada
    try:
        auto_backup_if_due()
    except Exception as e:
        st.warning(f"No se pudo crear la copia de seguridad: {e}")

    # --- LOGO arriba de "Mi Cuenta"
    _logo_uri = _img_to_data_uri(_guess_logo_path() or "logo.png")
    if _logo_uri:
        st.markdown("""
        <style>
          .sb-logo{
            display:flex; justify-content:center; align-items:center;
            padding: 6px 0 14px;
          }
          .sb-logo img{ height:52px; width:auto; display:block; }
        </style>
        """, unsafe_allow_html=True)
        st.markdown(f'<div class="sb-logo"><img src="{_logo_uri}" alt="logo"></div>', unsafe_allow_html=True)

                
# Muestra badge (logo + usuario). Si tu archivo se llama distinto, pásalo:
# show_user_badge(user, logo_path="assets/ticketo.png", warn_if_missing=True)
# show_user_badge(user, logo_path="logo.png", warn_if_missing=True)

# =========================================================
# Menú en la sidebar (reemplaza tabs)
# =========================================================

# ===================== NAV + HEADER =====================
# (Estilo del menú en la sidebar)
with st.sidebar:
    st.markdown("""
<style>
/* Contenedor del grupo */
section[data-testid="stSidebar"] div[role="radiogroup"]{
  display:flex; flex-direction:column; gap:10px; align-items:stretch;
}

/* Cada opción */
section[data-testid="stSidebar"] div[role="radiogroup"] > label{
  width:100%; display:flex; align-items:center; cursor:pointer;
  padding:0 !important; border:none !important; background:transparent !important;
}

/* Oculta el circulito del radio (primer hijo) */
section[data-testid="stSidebar"] div[role="radiogroup"] > label > div:first-child{ display:none; }

/* “Píldora” visible (segundo hijo) */
section[data-testid="stSidebar"] div[role="radiogroup"] > label > div:last-child{
  flex:1 1 auto;
  border:1px solid rgba(120,120,135,.25);
  border-radius:12px;
  padding:10px 12px;
  background:#ffffff;
  box-shadow:0 1px 1px rgba(0,0,0,.03);
  transition:background .15s ease, border-color .15s ease, box-shadow .15s ease;
}

/* Hover */
section[data-testid="stSidebar"] div[role="radiogroup"] > label:hover > div:last-child{
  background:#f8fafc; border-color:rgba(120,120,135,.45);
}

/* === SELECCIONADO (robusto, sin JS) === */
section[data-testid="stSidebar"] div[role="radiogroup"] > label[aria-checked="true"] > div:last-child,
section[data-testid="stSidebar"] div[role="radiogroup"] > label > *[role="radio"][aria-checked="true"] + div,
section[data-testid="stSidebar"] div[role="radiogroup"] > label > input[type="radio"]:checked + div{
  background:#eef2ff !important;
  border-color:#4f46e5 !important;
  box-shadow:0 0 0 2px rgba(79,70,229,.18) inset;
}
                
/* Oculta el control nativo si aparece */
section[data-testid="stSidebar"] div[role="radiogroup"] > label > input[type="radio"]{ display:none !important; }
                
</style>
""", unsafe_allow_html=True)
    
# ÚNICO radio de navegación (key única y persistente)
# Construye la lista de tabs (agrega Admin si aplica)
tabs = [
    
    "🧮 Diario Consolidado", "📊 Panel de control", "🧾 Ventas",
    "💸 Gastos", "🤝 Préstamos", "📦 Inventario", "⬆️ Importar/Exportar", "👤 Deudores","⚙️ Mi Cuenta"
] + (["🛠️ Administración"] if is_admin() else [])

# === Auto-compact y flag móvil por parámetros de URL ===
qp = st.query_params
if qp.get("compact") == "1":
    st.session_state["ui_compact"] = True
if qp.get("m") == "1":
    st.session_state["is_mobile"] = True

with st.sidebar:
    # valor inicial SOLO la primera vez
    if "nav_left" not in st.session_state:
        st.session_state["nav_left"] = tabs[0]

    _prev_nav = st.session_state["nav_left"]   # ← NUEVO: guardo valor previo

    # ⬇️⬇️ NUEVO: switch de modo compacto en la sidebar
    compact = st.toggle("🧩 Modo compacto", value=st.session_state.get("ui_compact", False), key="ui_compact")
    st.divider()  # opcional, solo para separar visualmente

    if is_admin():
        st.session_state.setdefault("admin_view_all", False)
        st.session_state["admin_view_all"] = st.toggle("👁️ Ver todo (admin)", value=st.session_state["admin_view_all"])

    # Navegación
    st.radio(
        "Secciones",
        tabs,
        label_visibility="collapsed",
        key="nav_left",
    )

current = st.session_state["nav_left"]

SHOW_QUICK_ACTIONS = False 

# st.markdown("""
# <style>
# @media (max-width: 900px){
#   /* Sidebar más angosta y oculta por defecto (se abre con data-tt-open="1") */
#   section[data-testid='stSidebar']{
#     width: 68vw !important;
#     min-width: 260px !important;
#     max-width: 420px !important;
#     transition: transform .25s ease, visibility .25s ease !important;
#     transform: translateX(-110%);
#     visibility: hidden;
#     z-index: 2000 !important;
#   }
#   section[data-testid='stSidebar'][data-tt-open='1']{
#     transform: translateX(0) !important;
#     visibility: visible !important;
#   }

#   /* Oculta el control nativo en móvil (dejamos solo nuestro burger) */
#   [data-testid='stSidebarCollapseControl'],
#   [data-testid='collapsedControl']{
#     display:none !important;
#   }

#   /* Botón hamburguesa naranja (fuera de la sidebar) */
#   #tt-burger{
#     position: fixed;
#     top: 14px; left: 14px;
#     width: 52px; height: 52px;
#     border: 0; border-radius: 999px;
#     background: linear-gradient(135deg,#f97316,#f59e0b);
#     box-shadow: 0 10px 24px rgba(0,0,0,.18);
#     cursor: pointer; z-index: 2100;
#   }
#   #tt-burger span{
#     display:block; width:22px; height:3px; background:#fff; border-radius:2px;
#     margin:4px auto;
#     box-shadow: 0 1px 0 rgba(0,0,0,.08);
#   }

#   /* Overlay cuando la sidebar está abierta */
#   #tt-ov{ position:fixed; inset:0; background:rgba(0,0,0,.25); z-index:1999; }
# }
# </style>
# """, unsafe_allow_html=True)

# ⬇️⬇️ NUEVO: CSS si está activo el modo compacto
if st.session_state.get("ui_compact", False):
    st.markdown("""
    <style>
      html, body, [data-testid="stSidebar"]{ font-size: 14px; }
      [data-testid="stMetric"] small{ display:none; }  /* oculta subtexto de métricas */
      .tt-titlebar .ttl{ font-size:22px !important; } /* reduce título fijo */
      /* Opcional: achica pastillas del menú lateral un poquito */
      section[data-testid="stSidebar"] div[role="radiogroup"] > label > div:last-child{
        padding:8px 10px;
      }
    </style>
    """, unsafe_allow_html=True)

if st.session_state.get("ui_compact", False):
    st.markdown("""
    <style>
      @media (max-width: 900px){
        .stButton > button{ min-height: 40px; font-size: 15px; }
        [data-testid="stMetric"]{ padding:12px 12px; }
        /* Reduce el gap entre controles en columnas pequeñas */
        .stColumn > div{ padding-top: 2px; padding-bottom: 2px; }
      }
    </style>
    """, unsafe_allow_html=True)

if st.session_state.get("ui_compact", False):
    st.markdown("""
    <style>
      /* En móvil: permitir wrap en celdas para evitar scroll lateral infinito */
      @media (max-width: 900px){
        [data-testid="stDataFrame"] table td,
        [data-testid="stDataFrame"] table th{
          white-space: normal !important;
          word-break: break-word !important;
        }
        [data-testid="stDataFrame"] { height: 420px !important; }
      }
    </style>
    """, unsafe_allow_html=True)

def _clean_title(raw: str) -> str:
    return raw.split(" ", 1)[1] if " " in raw else raw

# (lo demás igual)
st.session_state.pop("logo_uri_cache", None)
st.session_state.pop("logo_uri_sig", None)

_show_logo_path = str(Path(__file__).parent / "logo.png")

st.markdown("""
<style>
/* ===== DARK MODE OVERRIDES (debe ir DESPUÉS del CSS claro) ===== */
@media (prefers-color-scheme: dark){

  :root{
    --card-bg: #0b0f19;
    --card-border: #1f2937;
    --pill-bg: #111827;
    --pill-hover: #0f172a;
    --text: #e5e7eb;
  }

  /* Tarjetas: métricas + expanders */
  [data-testid="stMetric"],
  details[data-testid="stExpander"]{
    background: var(--card-bg) !important;
    border-color: var(--card-border) !important;
  }
  details[data-testid="stExpander"] > summary{
    color: var(--text) !important;
  }

  /* Pastillas del menú lateral (radio de la sidebar) */
  section[data-testid="stSidebar"] div[role="radiogroup"] > label > div:last-child{
    background: var(--pill-bg) !important;
    border-color: var(--card-border) !important;
  }
  section[data-testid="stSidebar"] div[role="radiogroup"] > label:hover > div:last-child{
    background: var(--pill-hover) !important;
    border-color: #334155 !important;
  }
  section[data-testid="stSidebar"] div[role="radiogroup"] > label[aria-checked="true"] > div:last-child,
  section[data-testid="stSidebar"] div[role="radiogroup"] > label > *[role="radio"][aria-checked="true"] + div,
  section[data-testid="stSidebar"] div[role="radiogroup"] > label > input[type="radio"]:checked + div{
    background: #111827 !important;
    border-color: #6366f1 !important;
    box-shadow: 0 0 0 2px rgba(99,102,241,.25) inset !important;
  }

  /* Tablas (dataframe) */
  [data-testid="stDataFrame"] table thead th{
    background: var(--card-bg) !important;
    color: var(--text) !important;
  }
  [data-testid="stDataFrame"] table tbody tr:nth-child(odd){
    background: #0f172a !important;
  }
  [data-testid="stDataFrame"] table td, 
  [data-testid="stDataFrame"] table th{
    border-color: var(--card-border) !important;
  }

  /* Botón primario */
  .stButton > button[kind="primary"]{
    background:#6366f1 !important;
    border-color:#6366f1 !important;
    color:#fff !important;
  }

  /* Textos dentro de tarjetas/badge */
  [data-testid="stMetric"] small,
  [data-testid="stMetric"] label,
  .app-user-badge .name,
  .brand-top .u{
    color: var(--text) !important;
  }
}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<style>
@media (prefers-color-scheme: dark){

  /* DataFrame: zebra par + color de texto en celdas */
  [data-testid="stDataFrame"] table tbody tr:nth-child(even){
    background:#0b1220 !important;
  }
  [data-testid="stDataFrame"] table td{
    color: var(--text) !important;
  }

  /* Métricas: valor grande y delta legibles */
  [data-testid="stMetric"] [data-testid="stMetricValue"],
  [data-testid="stMetric"] [data-testid="stMetricDelta"]{
    color: var(--text) !important;
  }

  /* Pastillas de la sidebar: asegura color del texto */
  section[data-testid="stSidebar"] div[role="radiogroup"] > label > div:last-child{
    color: var(--text) !important;
  }

  /* Popover/Expander: texto consistente */
  [data-testid="stExpander"] *,
  [data-testid="stPopoverBody"] *{
    color: var(--text) !important;
  }

  /* Badge de usuario (arriba derecha) en tono oscuro */
  .app-user-badge{
    background: rgba(17,24,39,.88) !important;  /* similar a --card-bg con blur */
    border-color: var(--card-border) !important;
  }

  /* Línea bajo el logo de la sidebar en oscuro */
  .sb-logo{
    border-bottom:1px solid var(--card-border) !important;
  }
}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<style>
# /* ========= BOTÓN HAMBURGUESA — NARANJA ========= */
# [data-testid="stSidebarCollapseControl"] button,
# [data-testid="collapsedControl"]{
#   width: 46px !important;
#   height: 46px !important;
#   border-radius: 999px !important;
#   background: linear-gradient(135deg,#f97316,#fb923c) !important; /* 🟧 naranja → naranja claro */
#   border: 0 !important;
#   padding: 0 !important;
#   display: flex !important;
#   align-items: center !important;
#   justify-content: center !important;
#   position: relative !important;
#   box-shadow: 0 6px 16px rgba(249,115,22,.35), 0 2px 4px rgba(0,0,0,.16) !important; /* sombras naranjas */
#   transition: transform .12s ease, box-shadow .12s ease, filter .12s ease;
#   z-index: 2000 !important;
#   cursor: pointer;
# }

/* 3 barras blancas centradas */
[data-testid="stSidebarCollapseControl"] button::before,
[data-testid="collapsedControl"]::before{
  content:"";
  position: absolute;
  top: 50%; left: 50%;
  transform: translate(-50%, -50%);
  width: 22px; height: 2px;
  background:#fff; border-radius: 2px;
  box-shadow: 0 -6px 0 0 #fff, 0  6px 0 0 #fff;
}

[data-testid="stSidebarCollapseControl"] button:hover,
[data-testid="collapsedControl"]:hover{
  transform: translateY(-1px) scale(1.04);
}

/* Efecto pulse cuando está colapsado — tono naranja */
@keyframes tt-pulse {
  0%   { box-shadow: 0 0 0 0 rgba(249,115,22,.55); }
  70%  { box-shadow: 0 0 0 14px rgba(249,115,22,0); }
  100% { box-shadow: 0 0 0 0 rgba(249,115,22,0); }
}
[data-testid="collapsedControl"]{
  animation: tt-pulse 2.2s ease-out infinite;
}

/* ========= SIDEBAR MÁS ANGOSTA EN MÓVIL ========= */
@media (max-width: 900px){
  section[data-testid="stSidebar"]{
    width: 232px !important;
    min-width: 232px !important;
  }
  [data-testid="stSidebarCollapseControl"]{
    top: 8px !important;
    left: 8px !important;
  }
}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<style>
/* === FIX FINAL: fuerza que el toggle de la sidebar exista y sea visible === */

/* Móvil: NO lo ocultes (anula cualquier regla previa que lo esconda) */
@media (max-width:900px){
  [data-testid*="SidebarCollapse"],
  [data-testid*="SidebarCollapse"] *,
  [data-testid="stSidebarCollapseControl"],
  [data-testid="stSidebarCollapseControl"] *,
  [data-testid="collapsedControl"]{
    display:flex !important;
    visibility:visible !important;
    pointer-events:auto !important;
    opacity:1 !important;
  }
}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<style>
/* FIX: colapsar wrappers vacíos que deja components.html cuando height=0 */
/* Cubre varios contenedores de Streamlit y distintas formas en que se pinta el height */
.block-container > div:has(> iframe[height="0"]:only-child),
.block-container > div:has(> iframe[style*="height:0"]:only-child),
[data-testid="stElementContainer"]:has(> iframe[height="0"]:only-child),
div[data-testid="stIFrame"]:has(> iframe[height="0"]:only-child){
  margin:0 !important;
  padding:0 !important;
  min-height:0 !important;
  line-height:0 !important;
}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<style>
/* ——— Anti-espacio arriba (versión que mantiene el toolbar) ——— */

/* 0) Quita la banda de color */
div[data-testid="stDecoration"]{ height:0 !important; }

/* 1) Sin padding/margen arriba en el contenedor principal */
[data-testid="stAppViewContainer"] > .main,
[data-testid="stAppViewContainer"] > .main .block-container{
  padding-top:0 !important;
  margin-top:0 !important;
}

/* 3) H1/H2 al ras cuando son lo primero */
.block-container h1:first-child,
.block-container h2:first-child{ margin-top:0 !important; }

/* 4) Si usas barra de título propia, que no agregue margen extra */
.tt-titlebar{ margin-top:0 !important; top:0 !important; }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<style>
/* Colapsa cualquier wrapper que contenga solo utilidades invisibles */
.block-container > div:has(> style),
.block-container > div:has(> iframe[height="0"]),
.block-container > div:has(> iframe[style*="height:0"]),
[data-testid="stElementContainer"]:has(> iframe[height="0"]),
div[data-testid="stIFrame"]:has(> iframe[height="0"]){
  margin:0 !important; padding:0 !important; min-height:0 !important; line-height:0 !important;
}

</style>
""", unsafe_allow_html=True)


st.markdown("""
<style>
# /* EXCEPCIÓN: el botón de abrir/cerrar sidebar SÍ recibe clics */
# div[data-testid="stToolbar"] [data-testid*="SidebarCollapse"],
# div[data-testid="stToolbar"] [data-testid="stSidebarCollapseControl"]{
#   pointer-events: auto !important;
# }

/* 2) Forzar visibilidad/posición de la hamburguesa en todas las vistas */
@media (min-width:901px){
  [data-testid="stSidebarCollapseControl"],
  [data-testid="collapsedControl"]{
    position: fixed !important;
    top: 12px !important; left: 12px !important;
    display: flex !important; visibility: visible !important;
    opacity: 1 !important; pointer-events: auto !important;
    z-index: 4000 !important;
  }
  /* Deja espacio en el título para la hamburguesa */
  .tt-titlebar{ padding-left:74px !important; }
}
@media (max-width:900px){
  [data-testid="stSidebarCollapseControl"],
  [data-testid="collapsedControl"]{
    position: fixed !important;
    top: 8px !important; left: 8px !important;
    display: flex !important; visibility: visible !important;
    opacity: 1 !important; pointer-events: auto !important;
    z-index: 4000 !important;
  }
}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<style>

# /* El toolbar NO bloquea clics, salvo excepción para el toggle */
# div[data-testid="stToolbar"]{
#   position:fixed !important; top:6px !important; right:8px !important;
#   left:auto !important; bottom:auto !important;
#   display:inline-flex !important; width:auto !important; height:auto !important;
#   background:transparent !important; box-shadow:none !important;
#   transform:none !important; z-index:1 !important; pointer-events:none !important;
# }
# div[data-testid="stToolbar"] [data-testid*="SidebarCollapse"]{
#   pointer-events:auto !important;
# }

/* Fuerza visibilidad y saca el control del header para TODAS las variantes */
[data-testid="stSidebarCollapseControl"],
[data-testid="stSidebarCollapseControl"] > button,
[data-testid="collapsedControl"]{
  position:fixed !important;
  top:12px !important; left:12px !important;
  display:flex !important; visibility:visible !important; opacity:1 !important;
  pointer-events:auto !important; z-index:4000 !important;
}

/* Estilo opcional (puedes quitarlo si quieres el look nativo) */
[data-testid="stSidebarCollapseControl"],
[data-testid="stSidebarCollapseControl"] > button,
[data-testid="collapsedControl"]{
  width:46px; height:46px; border-radius:999px; border:0;
  background:linear-gradient(135deg,#f97316,#fb923c);
  box-shadow:0 6px 16px rgba(249,115,22,.35), 0 2px 4px rgba(0,0,0,.16);
}
[data-testid="stSidebarCollapseControl"] svg,
[data-testid="stSidebarCollapseControl"] > button svg,
[data-testid="collapsedControl"] svg{
  width:22px; height:22px; display:block !important;   /* NO ocultes el SVG */
}

@media (max-width:900px){
  [data-testid="stSidebarCollapseControl"],
  [data-testid="stSidebarCollapseControl"] > button,
  [data-testid="collapsedControl"]{ top:8px !important; left:8px !important; }
  section[data-testid="stSidebar"]{ width:232px !important; min-width:232px !important; }
}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<style id="tt-restore-burger">
/* 1) No ocultes el header: vuelve a su altura normal */
header[data-testid="stHeader"]{
  height:auto !important; min-height:unset !important;
  padding:0 !important; border:0 !important; background:transparent !important;
}

# /* 2) El toolbar vuelve a ser clicable y sin forzado de posición */
# div[data-testid="stToolbar"]{
#   position:static !important; width:auto !important; height:auto !important;
#   transform:none !important; box-shadow:none !important;
#   pointer-events:auto !important;
# }

# /* 3) Muestra y coloca SIEMPRE el toggle de la sidebar (hamburguesa) */
# [data-testid="stSidebarCollapseControl"],
# [data-testid="collapsedControl"],
# [data-testid="stSidebarCollapseControl"] > button{
#   display:flex !important; visibility:visible !important; opacity:1 !important;
#   pointer-events:auto !important;
#   position:fixed !important; top:12px !important; left:12px !important;
#   z-index:5000 !important;
# }

</style>
""", unsafe_allow_html=True)

st.markdown("""
<style>
/* ===== TÍTULO CENTRADO + ESTILO ELEGANTE ===== */

/* La barra ocupa 3 columnas simétricas:
   [espacio izq] [título] [espacio dcha] → el título queda centrado
   aunque esté la hamburguesa a la izquierda. */
.tt-titlebar{
  position: sticky; top: 0; z-index: 1000;
  margin: 6px 0 14px;
  padding: 8px 12px;
  display: grid; align-items: center;
  grid-template-columns: 52px 1fr 52px;           /* móvil */
  background: rgba(255,255,255,.86);
  border-bottom: 1px solid rgba(120,120,135,.14);
  backdrop-filter: saturate(160%) blur(6px);
  -webkit-backdrop-filter: saturate(160%) blur(6px);
}

/* Escritorio: reserva ~ancho del botón/hamburguesa */
@media (min-width: 901px){
  .tt-titlebar{ grid-template-columns: 74px 1fr 74px; }
}

/* Pastilla del título */
.tt-titlebar .ttl{
  justify-self: center;                      /* centrado real */
  display: inline-block;
  padding: 8px 16px;
  font-size: 18px; font-weight: 700; letter-spacing: .2px;
  color: #111827;
  background: linear-gradient(180deg, rgba(255,255,255,.92), rgba(255,255,255,.72));
  border: 1px solid rgba(120,120,135,.18);
  border-radius: 999px;
  box-shadow: 0 6px 16px rgba(0,0,0,.06);
  line-height: 1.15 !important;
}

/* Subrayado sutil con degradado */
.tt-titlebar .ttl::after{
  content:"";
  display:block;
  height:2px; width:46px;
  margin:6px auto 0;
  background: linear-gradient(90deg,#6366f1,#f97316);
  border-radius: 999px;
  opacity: .9;
}

/* ——— Dark mode ——— */
@media (prefers-color-scheme: dark){
  .tt-titlebar{
    background: rgba(11,15,25,.82);
    border-bottom: 1px solid #1f2937;
  }
  .tt-titlebar .ttl{
    color: #e5e7eb;
    background: linear-gradient(180deg, rgba(17,24,39,.95), rgba(17,24,39,.78));
    border-color: #1f2937;
    box-shadow: 0 6px 18px rgba(0,0,0,.35);
  }
}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<style>
.tt-sticky-cta{
  position: sticky;
  bottom: 0;
  z-index: 1200;
  background: rgba(255,255,255,.95);
  border-top: 1px solid rgba(120,120,135,.18);
  backdrop-filter: saturate(160%) blur(6px);
  -webkit-backdrop-filter: saturate(160%) blur(6px);
  padding: 10px 12px;
  margin-top: 8px;
  /* sombra sutil */
  box-shadow: 0 -6px 16px rgba(0,0,0,.06);
}
@media (prefers-color-scheme: dark){
  .tt-sticky-cta{
    background: rgba(11,15,25,.86);
    border-top: 1px solid #1f2937;
  }
}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<style>
/* ====== ULTRA COMPACT ====== */

/* Menos espacio vertical global entre bloques y columnas */
[data-testid="stVerticalBlock"]{ gap:4px !important; row-gap:4px !important; }
[data-testid="stHorizontalBlock"]{ column-gap:8px !important; row-gap:4px !important; }

/* Inputs y selects más bajos y con menos padding */
[data-testid="stTextInput"] input,
[data-testid="stNumberInput"] input,
[data-testid="stTextArea"] textarea,
[data-testid="stDateInput"] input,
[data-baseweb="select"] > div{
  min-height: 36px !important;
  padding: 6px 10px !important;
  border-radius: 8px !important;
}

/* Etiquetas de widgets más pegadas y un pelín más chicas */
[data-testid="stWidgetLabel"]{
  margin-bottom: 2px !important;
  font-size: 12px !important;
}

/* Botones un poco más bajos y compactos */
.stButton > button{
  min-height: 36px !important;
  padding: 8px 12px !important;
  border-radius: 10px !important;
}

/* Métricas con menos relleno */
[data-testid="stMetric"]{
  padding:10px 12px !important;
}

/* Tablas/DataFrames: filas con menos alto */
[data-testid="stDataFrame"] table td,
[data-testid="stDataFrame"] table th{
  padding-top:6px !important;
  padding-bottom:6px !important;
}

/* Grids y tarjetas propias más ceñidas */
.mm-grid{ gap:8px !important; }
.mm-card{ margin-top:8px !important; padding:12px !important; }
.tt-grid{ gap:10px !important; }
.tt-stat{ padding:12px !important; }

/* Título: menos margen y padding */
.tt-titlebar{ margin:4px 0 8px !important; padding:6px 10px !important; }
.tt-titlebar .ttl{ padding:6px 12px !important; font-size:16px !important; }

/* Menú lateral (pestañas) aún más angosto y con menos padding */
section[data-testid="stSidebar"] div[role="radiogroup"]{ gap:6px !important; }
section[data-testid="stSidebar"] div[role="radiogroup"] > label > div:last-child{
  padding:8px 9px !important;
  border-radius:10px !important;
}

/* Checkbox y radio un poco más pegados a su etiqueta */
[data-testid="stCheckbox"] label, [role="radiogroup"] label{
  gap:6px !important;
}

/* Formularios: quita aire arriba/abajo */
form [data-testid="stVerticalBlock"]{ gap:4px !important; }
</style>
""", unsafe_allow_html=True)


# Título siempre actualizado
show_sticky_header(current, logo_path=_show_logo_path, show_brand_text=False)

st.markdown("""
<style id="typography-hierarchy-reset">
/* ===== Variables para jerarquía de texto ===== */
:root{
  --h1: 24px;      /* desktop */
  --h2: 20px;
  --label: 12px;
  --label-tracking: .06em;
  --card-bg: var(--card);
  --card-br: var(--border);
}
@media (max-width: 900px){
  :root{
    --h1: 22px;    /* móvil */
    --h2: 18px;
    --label: 11px;
  }
}

/* ===== Titulares (una sola jerarquía) ===== */
h1, .tt-titlebar .ttl{
  font-size: var(--h1) !important;
  font-weight: 600 !important;  /* semi-bold */
  letter-spacing: .01em;
  text-transform: none;
}
h2{
  font-size: var(--h2) !important;
  font-weight: 600 !important;
  letter-spacing: .005em;
}

/* ===== Labels de widgets (inputs, selects, etc.) ===== */
div[data-testid="stWidgetLabel"] label{
  font-size: var(--label) !important;
  letter-spacing: var(--label-tracking) !important;
  font-weight: 500 !important;
  color: var(--muted) !important;
}

/* ===== Unificar estilo de “card” (una sola estética, sin sombras fuertes) ===== */
[data-testid="stMetric"],
details[data-testid="stExpander"],
.mm-card, .tt-card{
  background: var(--card-bg) !important;
  border: 1px solid var(--card-br) !important;
  border-radius: 12px !important;
  box-shadow: none !important;               /* sin sombras pesadas */
}

/* Quitar gradientes/relieves de icon pills y stats “tt-” */
.tt-stat{
  background: var(--card-bg) !important;
  border: 1px solid var(--card-br) !important;
  box-shadow: none !important;
}
.tt-stat .ic{
  background: var(--pri) !important;        /* color liso */
  box-shadow: none !important;
}

/* Titlebar más sobria y coherente con el resto */
.tt-titlebar{
  background: rgba(255,255,255,.92) !important;
  border-bottom: 1px solid var(--card-br) !important;
  box-shadow: none !important;
}
@media (prefers-color-scheme: dark){
  .tt-titlebar{ background: rgba(11,15,25,.88) !important; }
}

/* Números “callout” sin negrita innecesaria */
.mm-total{ font-weight: 400 !important; }

/* Zebra más suave en tablas (o quítala del todo) */
[data-testid="stDataFrame"] table tbody tr:nth-child(odd){
  background: transparent !important;
}
</style>
""", unsafe_allow_html=True)



# --- POPUP DE MENÚ PARA MÓVIL (reemplaza la sidebar en pantallas chicas) ---
# if st.session_state.get("is_mobile", False):
#     lcol, rcol = st.columns([1,6])
#     with lcol:  # botón al lado del título
#         pop = st.popover("☰ Menú", use_container_width=False)
#     with pop:
#         choice = st.radio(
#             "Ir a",
#             tabs,
#             index=tabs.index(st.session_state["nav_left"]),
#             label_visibility="collapsed",
#             key="nav_pop"
#         )
#         if choice != st.session_state["nav_left"]:
#             st.session_state["nav_left"] = choice
#             st.rerun()

#     # Oculta sidebar en móvil cuando usamos el popover
#     st.markdown("""
#     <style>
#     @media (max-width: 900px){
#       section[data-testid="stSidebar"]{ display:none !important; }
#       [data-testid="stSidebarCollapseControl"],
#       [data-testid="collapsedControl"]{ display:none !important; }
#     }
#     </style>
#     """, unsafe_allow_html=True)

show_flash_if_any()

# def quick_nav_mobile():
#     if not st.session_state.get("is_mobile", False):
#         return
#     st.markdown("### ")
#     map_short = {
#         "Consolidado":"🧮 Diario Consolidado",
#         "Ventas":"🧾 Ventas",
#         "Gastos":"💸 Gastos",
#         "Deudores":"👤 Deudores"
#     }
#     choice = st.radio("Ir a", list(map_short.keys()), horizontal=True, key="quick_nav_mob")
#     target = map_short[choice]
#     if st.session_state.get("nav_left") != target:
#         st.session_state["nav_left"] = target
#         st.rerun()

# # Llamado (una sola vez tras el header)
# quick_nav_mobile()

def show(section: str) -> bool:
    return current == section



# ---------------------------------------------------------
# Diario consolidado
# ---------------------------------------------------------
if show("🧮 Diario Consolidado"):
    v_df = read_ventas(); g_df = read_gastos(); p_df = read_prestamos(); i_df = read_inventario()

    total_cuenta    = float(v_df.loc[v_df['observacion'].eq('CUENTA'),   'venta'].sum()) if not v_df.empty else 0.0
    total_efectivo  = float(v_df.loc[v_df['observacion'].eq('EFECTIVO'), 'venta'].sum()) if not v_df.empty else 0.0
    total_gastos    = float(g_df['valor'].sum()) if not g_df.empty else 0.0
    total_costos    = float(v_df['costo'].sum()) if not v_df.empty else 0.0
    total_prestamos = float(p_df['valor'].sum()) if not p_df.empty else 0.0
    total_inventario= float(i_df['valor_costo'].sum()) if not i_df.empty else 0.0

    d_ini = read_deudores_ini()
    total_deudores_ini = float(d_ini['valor'].sum()) if not d_ini.empty else 0.0

    total_ventas  = float(total_cuenta + total_efectivo)
    total_ganancia= float(v_df['ganancia'].sum()) if not v_df.empty else 0.0

    # ===== Fila 1 =====
    st.markdown('<div class="mm-grid">', unsafe_allow_html=True)
    c1, c2, c3 = st.columns(3, gap="small")
    with c1: stat_min("Total ventas",   money(total_ventas),   "var(--pri)")
    with c2: stat_min("Ganancia total", money(total_ganancia), "var(--accent)")
    with c3: stat_min("Gastos totales", money(total_gastos),   "var(--border)")
    st.markdown('</div>', unsafe_allow_html=True)

    # ===== Fila 2 =====
    st.markdown('<div class="mm-grid">', unsafe_allow_html=True)
    c4, c5, c6 = st.columns(3, gap="small"  )
    with c4: stat_min("Costos totales",   money(total_costos),    "var(--border)")
    with c5: stat_min("Total préstamos",  money(total_prestamos), "var(--pri)")
    with c6: stat_min("Inventario total", money(total_inventario),"var(--border)")
    st.markdown('</div>', unsafe_allow_html=True)

    # ===== Deudores =====
    corte_actual = get_corte_deudores()
    _, nuevo_total = deudores_unificados(corte_actual)
    st.markdown('<div class="mm-grid">', unsafe_allow_html=True)
    d1, d2, _ = st.columns([1,1,1], gap="small")
    with d1: stat_min("Total deudores (histórico)", money(total_deudores_ini), "var(--accent)")
    with d2: stat_min(f"Deudores desde {corte_actual.strftime('%d/%m/%Y')}", money(nuevo_total), "var(--pri)")
    st.markdown('</div>', unsafe_allow_html=True)

    # ===== Efectivo global (minimal) =====
    st.markdown('<div class="mm-card">', unsafe_allow_html=True)
    st.markdown("### Efectivo (manual)")

    efectivo_ini, _ = get_efectivo_global_now()
    metric_box = st.empty()
    metric_box.metric("EFECTIVO", money(efectivo_ini))

    # Layout 2:1 — izquierda: monto + guardar / derecha: confirmar + eliminar
    colL, colR = st.columns([2, 1], gap="small")

    with colL:
        CONS_efectivo = currency_input("Efectivo en caja", key="CONS_efectivo_input",
                                    value=float(efectivo_ini))
        if st.button("💾 Guardar / Reemplazar (global)", use_container_width=True,
                    key="CONS_efectivo_save"):
            # Guardamos sin notas
            upsert_consolidado("GLOBAL", float(CONS_efectivo), "")
            nuevo_ef, _ = get_efectivo_global_now()
            metric_box.metric("EFECTIVO", money(nuevo_ef))
            components.html("<script>try{document.activeElement && document.activeElement.blur();}catch(e){}</script>", height=0, width=0)
            finish_and_refresh("Efectivo (GLOBAL) reemplazado.", ["consolidado_diario"])

    with colR:
        st.markdown("&nbsp;", unsafe_allow_html=True)  # pequeño espacio vertical
        confirm_del = st.checkbox("Confirmar eliminación", key="CONS_del_confirm")
        if st.button("🗑️ Eliminar efectivo (global)", use_container_width=True,
                    disabled=not confirm_del, key="CONS_efectivo_delete"):
            delete_consolidado("GLOBAL")
            metric_box.metric("EFECTIVO", money(0.0))
            finish_and_refresh("Efectivo (GLOBAL) eliminado.", ["consolidado_diario"])
    st.markdown('</div>', unsafe_allow_html=True)

    # ===== Total de capital (minimal) =====
    total_capital = float(nuevo_total + efectivo_ini + total_prestamos + total_inventario)
    st.markdown(
        f'''
        <div class="mm-card">
          <h4>Total de capital</h4>
          <div class="mm-total">{money(total_capital)}</div>
        </div>
        ''',
        unsafe_allow_html=True
    )
# ---------------------------------------------------------
# Dashboard
# ---------------------------------------------------------
elif show("📊 Panel de control"):
    v = read_ventas(); g = read_gastos()

    c1, c2, c3 = st.columns(3, gap="small")
    c1.metric("Ventas registradas", len(v))
    c2.metric("Gastos registrados", len(g))
    c3.metric("Total VENTA", money(float(v['venta'].sum()) if not v.empty else 0.0))

    st.markdown("### Ventas por día")

    if v.empty:
        st.info("No hay ventas registradas.")
    else:
        # Selector de rango
        rango = st.selectbox(
            "Rango",
            ["Últimos 30 días", "Últimos 90 días", "Año actual", "Todo"],
            index=0,
            key="DASH_rng"
        )

        dv = v.copy()
        dv["fecha"] = pd.to_datetime(dv["fecha"], errors="coerce")
        dv = dv.dropna(subset=["fecha"])
        today = pd.Timestamp(date.today())

        if rango == "Últimos 30 días":
            start = today - pd.Timedelta(days=30)
            dv = dv[dv["fecha"] >= start]
        elif rango == "Últimos 90 días":
            start = today - pd.Timedelta(days=90)
            dv = dv[dv["fecha"] >= start]
        elif rango == "Año actual":
            start = pd.Timestamp(today.year, 1, 1)
            dv = dv[(dv["fecha"] >= start) & (dv["fecha"] <= today)]
        # "Todo" no filtra

        # Serie diaria + media móvil 7d
        serie = (
            dv.groupby("fecha", as_index=False)["venta"]
              .sum()
              .sort_values("fecha")
              .rename(columns={"venta": "Ventas"})
        )
        serie["Media 7d"] = serie["Ventas"].rolling(7, min_periods=1).mean()

        st.line_chart(
            serie.set_index("fecha")[["Ventas", "Media 7d"]],
            use_container_width=True
        )

        # (Opcional) Breakdown por observación
        with st.expander("Ver totales por observación"):
            obs = (
                dv.groupby("observacion", as_index=False)["venta"]
                  .sum()
                  .sort_values("venta", ascending=False)
                  .rename(columns={"observacion": "Observación", "venta": "Ventas"})
            )
            if not obs.empty:
                st.bar_chart(obs.set_index("Observación"), use_container_width=True)
            else:
                st.caption("Sin datos para este rango.")

# ---------------------------------------------------------
# Ventas
# ---------------------------------------------------------
elif show("🧾 Ventas"):
    f1c1, f1c2 = st.columns(2, gap="small")
    VTA_fecha = f1c1.date_input("Fecha", value=date.today(), max_value=date.today(), key="VTA_fecha_rt", format="DD/MM/YYYY")
    VTA_cliente = f1c2.text_input("Cliente", key="VTA_cliente_rt")

    f2c1, f2c2, f2c3 = st.columns(3, gap="small")
    with f2c1:
        VTA_costo = currency_input("Costo", key="VTA_costo_rt", value=0.0)
    with f2c2:
        VTA_venta = currency_input("Venta", key="VTA_venta_rt", value=0.0)
    with f2c3:
        VTA_gan_calc = max(0.0, float(VTA_venta - VTA_costo))
        st.text_input("Ganancia", value=money(VTA_gan_calc), disabled=True, key="VTA_ganancia_view_rt")

    f3c1, f3c2 = st.columns(2, gap="small")
    VTA_debe = f3c1.checkbox("DEBE", key="VTA_debe_rt")
    VTA_paga = f3c2.checkbox("PAGA (pagó hoy)", key="VTA_paga_rt")

    f4c1, f4c2 = st.columns(2, gap="small")
    with f4c1:
        VTA_ab1 = currency_input("Abono 1", key="VTA_ab1_rt", value=0.0)
    with f4c2:
        VTA_ab2 = currency_input("Abono 2", key="VTA_ab2_rt", value=0.0)

    # Validaciones previas
    invalid_paga = bool(VTA_debe and VTA_paga and (float(VTA_ab1) + float(VTA_ab2) <= 0))
    if invalid_paga:
        st.warning("Marcaste PAGA, pero no registraste abonos. Agrega Abono 1 y/o Abono 2.")
    if float(VTA_venta) < float(VTA_costo):
        st.warning("La venta es menor que el costo. ¿Seguro?")

    obs_val = "CUENTA" if VTA_debe else "EFECTIVO"

    # Guardar
    if st.button("💾 Guardar venta", type="primary", key="VTA_submit_rt", disabled=invalid_paga):
        insert_venta({
            'fecha': str(VTA_fecha),
            'cliente_nombre': VTA_cliente,
            'costo': float(VTA_costo),
            'venta': float(VTA_venta),
            'ganancia': float(VTA_gan_calc),
            'debe_flag': 1 if VTA_debe else 0,
            'paga': 'X' if VTA_paga else '',
            'abono1': float(VTA_ab1),
            'abono2': float(VTA_ab2),
            'observacion': obs_val,
        })

        # 🔄 Limpiar widgets del formulario de Ventas
        _reset_keys([
            "VTA_fecha_rt", "VTA_cliente_rt", "VTA_debe_rt", "VTA_paga_rt", "VTA_obs_rt",
            "VTA_costo_rt_txt", "VTA_venta_rt_txt", "VTA_ab1_rt_txt", "VTA_ab2_rt_txt",
            "VTA_ganancia_view_rt"
        ])
        components.html("<script>try{document.activeElement && document.activeElement.blur();}catch(e){}</script>", height=0, width=0)
        clear_venta_form_rt()
        finish_and_refresh("Venta guardada", ["transacciones"])

    st.divider()

    # ===== A PARTIR DE AQUÍ TODO QUEDA DENTRO DEL ELIF =====
    v = read_ventas()
    if not v.empty:
        # Precargar último estado de filtros (opcional)
        if "q_ventas" not in st.session_state and "ventas_last_text" in st.session_state:
            st.session_state["q_ventas"] = st.session_state["ventas_last_text"]
        if "rng_ventas" not in st.session_state and "ventas_last_rango" in st.session_state:
            st.session_state["rng_ventas"] = st.session_state["ventas_last_rango"]

        # Filtro de búsqueda y rango
        flt_key = "ventas"
        v = filtro_busqueda(v, ["cliente_nombre","observacion"], key=flt_key)
        st.session_state["ventas_last_text"]  = st.session_state.get(f"q_{flt_key}", "")
        st.session_state["ventas_last_rango"] = st.session_state.get(f"rng_{flt_key}", None)

        # === NUEVO: Filtro por cliente (multi-select con búsqueda) ===
        clientes = (
            v["cliente_nombre"]
            .astype(str).str.strip()
            .replace({"nan":"", "None":"", "": None})
            .dropna()
            .unique()
            .tolist()
        )
        clientes = sorted(clientes)
        cli_sel = st.multiselect("Filtrar por cliente(s)", options=clientes, key="ventas_cli")
        if cli_sel:
            patt = {c.strip().upper() for c in cli_sel}
            v = v[v["cliente_nombre"].astype(str).str.strip().str.upper().isin(patt)]
        # === FIN NUEVO ===

        # Export CSV del resultado filtrado
        st.download_button(
            "⬇️ Exportar CSV (ventas filtradas)",
            v.to_csv(index=False).encode("utf-8"),
            file_name="ventas_filtradas.csv",
            mime="text/csv",
            use_container_width=True
        )

        # Métricas y tablas
        v_num = v.copy()
        for col in ['costo','venta','ganancia']:
            v_num[col] = pd.to_numeric(v_num[col], errors='coerce').fillna(0.0)

        mask_obs = v_num['observacion'].fillna('').str.strip().ne('')
        v_valid = v_num[mask_obs]

        tot_costos   = float(v_valid['costo'].sum())
        tot_ventas   = float(v_valid['venta'].sum())
        tot_ganancia = float(v_valid['ganancia'].sum())
        tot_ventas_mostrar = tot_ventas + ADJ_VENTAS_EFECTIVO

        m1, m2, m3 = st.columns(3, gap="small")
        m1.metric("Costos totales",  money(tot_costos))
        m2.metric("Ventas totales", money(tot_ventas))
        m3.metric("Ganancia total",  money(tot_ganancia))

        with st.expander("🔍 Detalle de ventas por observación", expanded=False):
            det = (v_valid.groupby("observacion", dropna=False)["venta"]
                   .sum().rename("VENTA").reset_index()
                   .sort_values("VENTA", ascending=False))
            det = df_format_money(det, ["VENTA"])
            st.dataframe(det, use_container_width=True)
            st.caption(
                f"Con ajuste: {money(float(v_valid['venta'].sum()) + ADJ_VENTAS_EFECTIVO)}"
            )

        cols = ['fecha','cliente_nombre','observacion','costo','venta','ganancia','debe_flag','paga','abono1','abono2']
        v_show = v.sort_values('fecha', ascending=False)[cols]
        v_show = df_format_money(v_show, ['costo','venta','ganancia','abono1','abono2'])
        st.dataframe(v_show, use_container_width=True)

        # --- EDITOR: solo Abonos y PAGA editables, con formato ---
        vv = v.sort_values('fecha', ascending=False).copy()

        for c in ('abono1', 'abono2', 'venta'):
            vv[c] = pd.to_numeric(vv[c], errors='coerce').fillna(0).astype(float)

        # === ACCIONES POR FILA (popover por fila) ============================
        st.markdown("### Acciones por fila")

        # Toma las columnas completas para edición
        vv_full = vv.sort_values('fecha', ascending=False).copy()

        # (opcional) limita cuántas filas mostrar con acciones para no recargar la página
        lim = st.number_input("Máx. filas a listar con acciones", 5, 200, value=50, step=5, key="ventas_row_actions_lim")
        vv_act = vv_full.head(int(lim))

        # Tabla solo para ver (sin edición)
        v_show_actions = vv_act[['id','fecha','cliente_nombre','observacion','costo','venta','ganancia','debe_flag','abono1','abono2']].copy()
        v_show_actions = df_format_money(v_show_actions, ['costo','venta','ganancia','abono1','abono2'])
        st.dataframe(v_show_actions, use_container_width=True, hide_index=True)

        st.divider()
        st.markdown("#### Operar por fila (popover)")

        for _, r in vv_act.iterrows():
            rid = int(r['id'])
            c1, c2 = st.columns([7,1], gap="small")
            with c1:
                tipo = 'DEBE' if int(r['debe_flag'])==1 else 'EFECTIVO'
                st.caption(f"**#{rid}** {r['fecha']} · {r['cliente_nombre']} · {money(float(r['venta']))} · {tipo}")

            # Botón que abre popover con edición rápida
            with c2:
                with st.popover(f"⋯  #{rid}", use_container_width=True):
                    st.markdown(f"**Venta #{rid}** — edición rápida")
                    # Edición rápida (campos más usados)
                    e_ab1 = st.number_input("Abono 1", min_value=0.0, value=float(_nz(r['abono1'])), step=100.0, key=f"pop_ab1_{rid}")
                    e_ab2 = st.number_input("Abono 2", min_value=0.0, value=float(_nz(r['abono2'])), step=100.0, key=f"pop_ab2_{rid}")
                    e_paga = st.checkbox("PAGA (pagó hoy)", value=str(r.get('paga','')).strip().upper()=='X', key=f"pop_paga_{rid}")

                    # Acciones
                    bcol1, bcol2, bcol3 = st.columns([1,1,2],gap="small")
                    if bcol1.button("Guardar", key=f"pop_save_{rid}"):
                        payload = {}
                        if float(e_ab1) != float(_nz(r['abono1'])): payload['abono1'] = float(e_ab1)
                        if float(e_ab2) != float(_nz(r['abono2'])): payload['abono2'] = float(e_ab2)
                        if ('X' if e_paga else '') != str(r.get('paga','')).strip(): payload['paga'] = 'X' if e_paga else ''
                        if payload:
                            update_venta_fields(rid, **payload)
                        finish_and_refresh(f"Venta #{rid} actualizada.", ["transacciones"])

                    # Borrado con confirmación en el propio popover
                    conf = bcol2.checkbox("Confirmar 🗑️", key=f"pop_conf_{rid}")
                    if bcol2.button("Eliminar", disabled=not conf, key=f"pop_del_{rid}"):
                        delete_venta_id(rid)
                        finish_and_refresh(f"Venta #{rid} eliminada.", ["transacciones"])

        # === FIN ACCIONES POR FILA (popover) =================================



# ====== Editor en bloque (abonos / PAGA) ======
# Base para edición masiva: solo columnas necesarias + bandera PAGA booleana
        vv_editor = vv_full[['id','fecha','cliente_nombre','venta','abono1','abono2','paga']].copy()
        vv_editor['PAGA'] = vv_editor['paga'].astype(str).str.strip().str.upper().eq('X')
        vv_editor.drop(columns=['paga'], inplace=True)
        vv_editor['🗑️ Eliminar'] = False

        # Alinear índices con lo que devuelve data_editor (posición 0..n-1)
        vv_editor = vv_editor.reset_index(drop=True)

        edited = st.data_editor(
            vv_editor,
            key='ventas_editor',
            use_container_width=True,
            hide_index=True,
            num_rows="fixed",
            column_order=["fecha","cliente_nombre","venta","abono1","abono2","PAGA","🗑️ Eliminar"],
            column_config={
                "fecha": st.column_config.DateColumn("Fecha", format="DD/MM/YYYY", disabled=True),
                "cliente_nombre": st.column_config.TextColumn("Cliente", disabled=True),
                "venta": st.column_config.NumberColumn("Venta", format="$ %,d", disabled=True),
                "abono1": st.column_config.NumberColumn("Abono 1", format="$ %,d", step=100, min_value=0),
                "abono2": st.column_config.NumberColumn("Abono 2", format="$ %,d", step=100, min_value=0),
                "PAGA": st.column_config.CheckboxColumn("PAGA"),
                "🗑️ Eliminar": st.column_config.CheckboxColumn("Eliminar"),
            }
        )

        # --- Barra CTA pegajosa cuando hay cambios en el editor ---
        state_ventas_editor = st.session_state.get("ventas_editor", {})
        edited_rows = (getattr(state_ventas_editor, "edited_rows", None) 
                    or state_ventas_editor.get("edited_rows", {}))

        # Marcados para eliminar (si usas la columna "🗑️ Eliminar")
        to_delete_positions = edited.index[edited.get('🗑️ Eliminar', False) == True].tolist() if '🗑️ Eliminar' in edited.columns else []

        # ¿Hay algo que guardar?
        hay_cambios = bool(edited_rows or to_delete_positions)

        if hay_cambios:
            with st.container():
                st.markdown('<div class="tt-sticky-cta">', unsafe_allow_html=True)
                bL, bR = st.columns([1,1],gap="small")
                # Guardar (usa la misma lógica que tu botón existente)
                if bL.button("💾 Guardar cambios (arriba)", type="primary", key="VENTAS_save_sticky"):
                    n_upd = 0
                    for pos, changes in (edited_rows or {}).items():
                        row_id = int(vv_editor.iloc[int(pos)]['id'])
                        payload = {}
                        if 'abono1' in changes: payload['abono1'] = _nz(changes['abono1'])
                        if 'abono2' in changes: payload['abono2'] = _nz(changes['abono2'])
                        if 'PAGA'   in changes: payload['paga']   = 'X' if bool(changes['PAGA']) else ''
                        if payload:
                            update_venta_fields(row_id, **payload); n_upd += 1
                    for pos in to_delete_positions:
                        rid = int(vv_editor.iloc[int(pos)]['id'])
                        delete_venta_id(rid)
                    finish_and_refresh(f"Ventas actualizadas: {n_upd}", ["transacciones"])

                # Cancelar → limpia los edits del data_editor y recarga
                if bR.button("Cancelar edición", key="VENTAS_cancel_sticky"):
                    # vacía los cambios del editor
                    st.session_state['ventas_editor'] = {}
                    st.rerun()

                st.markdown('</div>', unsafe_allow_html=True)

        cE, cD = st.columns(2, gap="small")

        # if cE.button("💾 Guardar cambios", type="primary", key="VENTAS_save"):
        #     n_upd = 0
        #     st_state = st.session_state.get("ventas_editor", {})
        #     edited_rows = getattr(st_state, "edited_rows", None) or st_state.get("edited_rows", {})

        #     for pos, changes in (edited_rows or {}).items():
        #         row_id = int(vv_editor.iloc[int(pos)]['id'])
        #         payload = {}
        #         if 'abono1' in changes: payload['abono1'] = _nz(changes['abono1'])
        #         if 'abono2' in changes: payload['abono2'] = _nz(changes['abono2'])
        #         if 'PAGA'   in changes: payload['paga']   = 'X' if bool(changes['PAGA']) else ''
        #         if payload:
        #             update_venta_fields(row_id, **payload); n_upd += 1

        #     to_del = edited.index[edited['🗑️ Eliminar'] == True].tolist()
        #     for pos in to_del:
        #         rid = int(vv_editor.iloc[int(pos)]['id'])
        #         delete_venta_id(rid)

        #     finish_and_refresh(f"Ventas actualizadas: {n_upd}", ["transacciones"])

# ---------------------------------------------------------
# Gastos
# ---------------------------------------------------------
elif show("💸 Gastos"):
    # --- Predeclaraciones para Pylance (evita reportUndefinedVariable) ---
    GTO_fecha: date | None = date.today()
    GTO_conc: str = ""
    GTO_valor: float = 0.0
    GTO_notas: str = ""

    with st.form(key="GTO_form", clear_on_submit=True):
        c1, c2 = st.columns(2, gap="small")
        GTO_fecha = c1.date_input(
            "Fecha",
            value=date.today(),
            max_value=date.today(),              # bloquea fechas futuras
            key="GTO_fecha",
            format="DD/MM/YYYY"
        )
        GTO_conc  = c2.text_input("Concepto", key="GTO_concepto")

        c3, c4 = st.columns(2, gap="small")
        with c3:
            GTO_valor = currency_input("Valor", key="GTO_valor", value=0.0, in_form=True)
        with c4:
            GTO_notas = st.text_input("Notas", value="", key="GTO_notas")

        GTO_submit = st.form_submit_button("💾 Guardar gasto")

    if GTO_submit and GTO_fecha is not None:
        insert_gasto({
            'fecha': str(GTO_fecha),
            'concepto': GTO_conc,
            'valor': float(GTO_valor),
            'notas': GTO_notas
        })
        components.html("<script>try{document.activeElement && document.activeElement.blur();}catch(e){}</script>", height=0, width=0)
        clear_gasto_form()
        finish_and_refresh("Gasto guardado", ["gastos"])

    st.divider()

    # ===== A PARTIR DE AQUÍ TODO QUEDA DENTRO DEL ELIF =====
    g = read_gastos()
    if not g.empty:
        # Precargar último estado de filtros (opcional)
        if "q_gastos" not in st.session_state and "gastos_last_text" in st.session_state:
            st.session_state["q_gastos"] = st.session_state["gastos_last_text"]
        if "rng_gastos" not in st.session_state and "gastos_last_rango" in st.session_state:
            st.session_state["rng_gastos"] = st.session_state["gastos_last_rango"]

        # Filtro de búsqueda y rango (concepto/notas)
        g = filtro_busqueda(g, ["concepto","notas"], key="gastos")
        st.session_state["gastos_last_text"]  = st.session_state.get("q_gastos", "")
        st.session_state["gastos_last_rango"] = st.session_state.get("rng_gastos", None)

        # Export CSV del resultado filtrado
        st.download_button(
            "⬇️ Exportar CSV (gastos filtrados)",
            g.to_csv(index=False).encode("utf-8"),
            file_name="gastos_filtrados.csv",
            mime="text/csv",
            use_container_width=True
        )

        # Métrica + tabla
        st.metric("TOTAL GASTOS", money(float(g['valor'].sum())))
        g_show = g.sort_values('fecha', ascending=False).copy()
        g_show = df_format_money(g_show, ['valor'])
        st.dataframe(g_show, use_container_width=True)

        # === GASTOS: edición/borrado en línea ===
        gg = g.sort_values('fecha', ascending=False).copy()
        g_editor = gg[['id','fecha','concepto','valor','notas']].copy()
        g_editor['🗑️ Eliminar'] = False

        edited_g = st.data_editor(
            g_editor,
            key='gastos_editor',
            use_container_width=True,
            hide_index=True,
            num_rows="fixed",
            column_order=["fecha","concepto","valor","notas","🗑️ Eliminar"],
            column_config={
                "fecha": st.column_config.DateColumn("Fecha", format="DD/MM/YYYY", disabled=True),
                "concepto": st.column_config.TextColumn("Concepto"),
                "valor": st.column_config.NumberColumn("Valor", format="$ %,d", step=100),
                "notas": st.column_config.TextColumn("Notas"),
                "🗑️ Eliminar": st.column_config.CheckboxColumn("Eliminar"),
            }
        )

        cg1, cg2 = st.columns(2, gap="small")

        if cg1.button("💾 Guardar cambios", type="primary", key="GTO_inline_save"):
            n_upd = 0
            for i, row in edited_g.iterrows():
                row_id = int(g_editor.loc[i, 'id'])
                changes = {}
                if str(row['concepto']).strip() != str(g_editor.loc[i,'concepto']).strip():
                    changes['concepto'] = row['concepto']
                if float(row['valor']) != float(g_editor.loc[i,'valor']):
                    changes['valor'] = float(row['valor'])
                if str(row['notas']).strip() != str(g_editor.loc[i,'notas']).strip():
                    changes['notas'] = row['notas']
                if changes:
                    update_gasto_fields(row_id, **changes)
                    n_upd += 1
            finish_and_refresh(f"Gastos actualizados: {n_upd}", ["gastos"])

        if cg2.button("🗑️ Eliminar seleccionados", type="primary", key="GTO_inline_del"):
            idxs = edited_g.index[edited_g['🗑️ Eliminar'] == True].tolist()
            ids = [int(g_editor.loc[i,'id']) for i in idxs]
            if ids:
                for rid in ids:
                    delete_gasto_id(rid)
                finish_and_refresh(f"Eliminados {len(ids)} gastos.", ["gastos"])
            else:
                st.info("Marca al menos una fila en ‘Eliminar’.")

# ---------------------------------------------------------
# Préstamos
# ---------------------------------------------------------
elif show("🤝 Préstamos"):
    # ---- Alta con form (igual que el tuyo) ----
    with st.form(key="PRE_form", clear_on_submit=True):
        c1, c2 = st.columns(2, gap="small")
        PRE_nombre = c1.text_input("Nombre", key="PRE_nombre")
        with c2:
            PRE_valor = currency_input("Valor", key="PRE_valor", value=0.0, in_form=True)
        PRE_submit = st.form_submit_button("💾 Guardar préstamo")

    if PRE_submit:
        insert_prestamo({'nombre': PRE_nombre, 'valor': float(PRE_valor)})
        finish_and_refresh("Préstamo guardado", ["prestamos"])

    st.divider()
    p = read_prestamos()
    if not p.empty:
        # ---- Totales + tabla de vista ----
        st.metric("TOTAL PRÉSTAMOS", money(float(p['valor'].sum())))
        p_show = p.sort_values('id', ascending=False).copy()
        p_show = df_format_money(p_show, ['valor'])
        st.dataframe(p_show, use_container_width=True)

        # =========================================================
        # === PRÉSTAMOS: edición/borrado en línea (tu bloque) ===
        # =========================================================
        pp = p.sort_values('id', ascending=False).copy()
        p_editor = pp[['id','nombre','valor']].copy()
        p_editor['🗑️ Eliminar'] = False

        edited_p = st.data_editor(
            p_editor,
            key='prestamos_editor',
            use_container_width=True,
            hide_index=True,
            num_rows="fixed",
            column_order=["nombre","valor","🗑️ Eliminar"],
            column_config={
                "nombre": st.column_config.TextColumn("Nombre"),
                "valor": st.column_config.NumberColumn("Valor", format="$ %,d", step=100),
                "🗑️ Eliminar": st.column_config.CheckboxColumn("Eliminar"),
            }
        )

        cp1, cp2 = st.columns(2, gap="small")

        if cp1.button("💾 Guardar cambios", type="primary", key="PRE_inline_save"):
            n_upd = 0
            for i, row in edited_p.iterrows():
                row_id = int(p_editor.loc[i, 'id'])
                changes = {}
                if str(row['nombre']).strip() != str(p_editor.loc[i,'nombre']).strip():
                    changes['nombre'] = row['nombre']
                if float(row['valor']) != float(p_editor.loc[i,'valor']):
                    changes['valor'] = float(row['valor'])
                if changes:
                    update_prestamo_fields(row_id, **changes)
                    n_upd += 1
            finish_and_refresh(f"Préstamos actualizados: {n_upd}", ["prestamos"])

        if cp2.button("🗑️ Eliminar seleccionados", type="primary", key="PRE_inline_del"):
            idxs = edited_p.index[edited_p['🗑️ Eliminar'] == True].tolist()
            ids = [int(p_editor.loc[i,'id']) for i in idxs]
            if ids:
                for rid in ids:
                    delete_prestamo_id(rid)
                finish_and_refresh(f"Eliminados {len(ids)} préstamos.", ["prestamos"])
            else:
                st.info("Marca al menos una fila en ‘Eliminar’.")

        st.divider()

        # ===============================================
        # === NUEVO: Acciones por fila → Eliminar rápido
        # ===============================================
        st.markdown("#### Acciones por fila (eliminar uno)")

        # Para no saturar el DOM, limita cuántas filas muestran acciones
        lim = st.number_input("Máx. filas con acciones", 5, 200, value=50, step=5, key="pre_row_actions_lim")
        p_act = p.sort_values("id", ascending=False).head(int(lim))

        for _, r in p_act.iterrows():
            rid = int(r["id"])
            nombre = str(r["nombre"])
            val = float(_nz(r["valor"]))

            cL, cR = st.columns([7, 1], gap="small")
            with cL:
                st.caption(f"**#{rid}** · {nombre} · {money(val)}")

            with cR:
                with st.popover(f"⋯  #{rid}", use_container_width=True):
                    st.markdown(f"**Préstamo #{rid}**")
                    st.caption("Cuando el préstamo esté pagado, puedes eliminar el registro.")
                    conf = st.checkbox("Confirmar eliminación", key=f"pre_conf_{rid}")
                    if st.button("🗑️ Eliminar", disabled=not conf, key=f"pre_del_{rid}"):
                        delete_prestamo_id(rid)  # respeta owner/admin
                        finish_and_refresh(f"Préstamo #{rid} eliminado.", ["prestamos"])

    else:
        st.info("No hay préstamos registrados.")

# ---------------------------------------------------------
# Inventario
# ---------------------------------------------------------
elif show("📦 Inventario"):
    with st.form(key="INV_form",clear_on_submit=True):
        c1, c2 = st.columns(2, gap="small")
        INV_prod  = c1.text_input("Producto", key="INV_producto")
        with c2:
            INV_costo = currency_input("Valor costo", key="INV_valor_costo", value=0.0, in_form=True)
        INV_submit = st.form_submit_button("💾 Guardar ítem")
    if INV_submit:
        insert_inventario({'producto': INV_prod, 'valor_costo': float(INV_costo)})
        clear_inventario_form()
        finish_and_refresh("Ítem guardado", ["inventario"])

    st.divider()
    i = read_inventario()
    if not i.empty:
        st.metric("TOTAL INVENTARIO", money(float(i['valor_costo'].sum())))
        i_show = i.sort_values('id', ascending=False).copy()
        i_show = df_format_money(i_show, ['valor_costo'])
        st.dataframe(i_show, use_container_width=True)

    # === INVENTARIO: edición/borrado en línea ===
        ii = i.sort_values('id', ascending=False).copy()
        i_editor = ii[['id','producto','valor_costo']].copy()
        i_editor['🗑️ Eliminar'] = False

        edited_i = st.data_editor(
            i_editor,
            key='inventario_editor',
            use_container_width=True,
            hide_index=True,
            num_rows="fixed",
            column_order=["producto","valor_costo","🗑️ Eliminar"],
            column_config={
                "producto": st.column_config.TextColumn("Producto"),
                "valor_costo": st.column_config.NumberColumn("Valor costo", format="$ %,d", step=100),
                "🗑️ Eliminar": st.column_config.CheckboxColumn("Eliminar"),
            }
        )

        ci1, ci2 = st.columns(2, gap="small")

        if ci1.button("💾 Guardar cambios", type="primary", key="INV_inline_save"):
            n_upd = 0
            for irow, row in edited_i.iterrows():
                row_id = int(i_editor.loc[irow, 'id'])
                changes = {}
                if str(row['producto']).strip() != str(i_editor.loc[irow,'producto']).strip():
                    changes['producto'] = row['producto']
                if float(row['valor_costo']) != float(i_editor.loc[irow,'valor_costo']):
                    changes['valor_costo'] = float(row['valor_costo'])
                if changes:
                    update_inventario_fields(row_id, **changes)
                    n_upd += 1
            finish_and_refresh(f"Inventario actualizado: {n_upd}", ["inventario"])

        if ci2.button("🗑️ Eliminar seleccionados", type="primary", key="INV_inline_del"):
            idxs = edited_i.index[edited_i['🗑️ Eliminar'] == True].tolist()
            ids = [int(i_editor.loc[i,'id']) for i in idxs]
            if ids:
                for rid in ids:
                    delete_inventario_id(rid)
                finish_and_refresh(f"Eliminados {len(ids)} ítems.", ["inventario"])
            else:
                st.info("Marca al menos una fila en ‘Eliminar’.")

# ---------------------------------------------------------
# Deudores
# ---------------------------------------------------------
elif show("👤 Deudores"):
    st.markdown("### Deudores")

    df_deu, total_deu = deudores_sin_corte()
    st.metric("Total por cobrar", money(total_deu))

    if not df_deu.empty:
        st.dataframe(
            df_format_money(df_deu.copy(), ["NUEVO"]),
            use_container_width=True,
            hide_index=True  # si tu versión lo soporta
        )
    else:
        st.info("No hay deudores pendientes.")

# ---------------------------------------------------------
# Importar/Exportar (Nuevo: todo en uno)
# ---------------------------------------------------------
elif show("⬆️ Importar/Exportar"):
    up = st.file_uploader("Selecciona tu archivo .xlsx", type=["xlsx"])
    replace = st.checkbox("Reemplazar (vaciar tablas antes de importar)", value=False)
    btn = st.button("Importar ahora", type="primary", disabled=(up is None))
    if btn and up is not None:
        try:
            stats = import_excel_all(up, replace=replace)
            msg = (f"Importado ✔️ — Ventas:{stats.get('ventas',0)} · Gastos:{stats.get('gastos',0)} · "
                f"Préstamos:{stats.get('prestamos',0)} · Inventario:{stats.get('inventario',0)} · "
                f"DeudoresIniciales:{stats.get('deudores_ini',0)}")
            finish_and_refresh(msg, ["transacciones","gastos","prestamos","inventario","deudores_ini"])
        except Exception as e:
            st.error(f"Error importando: {e}")

    st.divider()
    st.markdown("### Exportar a Google Sheets (global)")

    tablas_disponibles = list(GSHEET_MAP.keys())
    sel = st.multiselect(
        "Tablas a exportar",
        options=tablas_disponibles,
        default=tablas_disponibles,
        help="Se crean/actualizan hojas con estos nombres en tu Spreadsheet."
    )

    col_a, col_b = st.columns([1,1], gap="small")
    with col_a:
        if st.button("⬆️ Sincronizar ahora", type="primary", disabled=not sel, key="sync_gs"):
            sync_tables_to_gsheet(sel)
            finish_and_refresh(f"Sincronizadas: {', '.join(sel)}")

    with col_b:
        sa = st.session_state.get("_gs_sa_email", None) or "—"
        st.caption(f"Service Account: {sa}")
        st.caption(f"Sheet ID/URL: {GSPREADSHEET_ID or '—'}")

elif show("⚙️ Mi Cuenta"):
    st.subheader("Mi Cuenta")
    st.caption(f"Sesión: **{user}** · rol **{role}**")

    c1, c2, c3 = st.columns(3, gap="small")
    if c1.button("🚪 Cerrar sesión", use_container_width=True):
        audit("logout", extra={"user": user}); _clear_session(); st.success("Sesión cerrada"); st.stop()
    if c2.button("🔄 Reiniciar estado y caché", use_container_width=True):
        st.session_state.clear(); st.rerun()
    if c3.button("💾 Copia de seguridad local (sqlite)", use_container_width=True):
        p = make_db_backup(); set_meta("LAST_BACKUP_ISO", datetime.now().isoformat(timespec="seconds"))
        finish_and_refresh(f"Backup creado: {p}")

    st.markdown("---")
    with st.form("SELF_pw_form2", clear_on_submit=True):
        newp = st.text_input("Nueva contraseña", type="password")
        ok = st.form_submit_button("Cambiar mi contraseña")
    if ok:
        db_set_password(user, newp); notify_ok("Tu contraseña fue actualizada.")
    
    st.markdown("### Respaldo personal en Google Sheets")
    cA, cB = st.columns(2, gap="small")

    with cA:
        if st.button("🔄 Actualizar CAMBIOS (incremental)", use_container_width=True, key="BK_u_flush"):
            n = backup_user_flush_audit(user)
            notify_ok(f"Respaldo actualizado. Cambios nuevos: {n}")

    with cB:
        if st.button("📦 Generar SNAPSHOT completo", use_container_width=True, key="BK_u_snap"):
            backup_user_snapshot(user)
            notify_ok("Snapshot completo escrito en tu hoja de respaldo.")

    # Enlace a la hoja
    try:
        sh, _ = _gs_open_or_create_user_book(user)   # ahora la función ya no revienta
        st.link_button("Abrir mi hoja en Google Sheets", sh.url, use_container_width=True)
    except Exception as e:
        st.warning(f"No se pudo abrir el enlace del respaldo: {e}")

# ---------------------------------------------------------
# Administración (solo admin) — Google Sheets en una columna
# ---------------------------------------------------------
if is_admin() and show("🛠️ Administración"):

    # -------- Google Sheets (una columna) --------
    st.subheader("Google Sheets")

    gs_id_val = st.text_input("Google Sheet ID", value=GSPREADSHEET_ID, key="CFG_GSHEET_ID")
    if st.button("Guardar Sheets ID", use_container_width=True, key="BTN_SAVE_GSID"):
        set_meta("GSHEET_ID", gs_id_val.strip())
        finish_and_refresh("Google Sheet ID actualizado.")

    gs_enabled_ui = st.toggle(
        "Habilitar Google Sheets",
        value=GOOGLE_SHEETS_ENABLED,
        key="CFG_GSHEETS_ENABLED"
    )
    if st.button("Guardar estado Sheets", use_container_width=True, key="BTN_SAVE_GSSTATE"):
        set_meta("GSHEETS_ENABLED", 1 if gs_enabled_ui else 0)
        finish_and_refresh("Estado de Google Sheets actualizado.")

    st.divider()

    # -------- Acciones rápidas --------
    c3, c4, c5 = st.columns(3, gap="small")
    if c3.button("Sincronizar TODAS las tablas a Google Sheets", use_container_width=True):
        if not GOOGLE_SHEETS_ENABLED:
            st.info("Sincronización deshabilitada en Admin → “Habilitar Google Sheets”.")
        else:
            sync_tables_to_gsheet(list(GSHEET_MAP.keys()))
            notify_ok("Sincronización enviada.")
    if c4.button("Limpiar caché y recargar ahora", use_container_width=True):
        st.cache_data.clear(); st.rerun()
    if c5.button("Cerrar sesión (admin)", use_container_width=True):
        _clear_session(); st.rerun()

    st.divider()

    # -------- Gestión de usuarios --------
    with st.expander("➕ Crear usuario", expanded=False):
        cu1, cu2, cu3 = st.columns(3, gap="small")
        new_user = cu1.text_input("Usuario nuevo", key="USR_newname")
        new_pass = cu2.text_input("Contraseña", type="password", key="USR_newpass")
        new_role = cu3.selectbox("Rol", ["user", "admin"], key="USR_newrole")
        if st.button("Crear usuario", key="USR_create_btn"):
            if not new_user or not new_pass:
                st.error("Usuario y contraseña son obligatorios.")
            else:
                try:
                    db_create_user(new_user, new_pass, new_role)
                    notify_ok(f"Usuario '{new_user}' creado.")
                    st.cache_data.clear()
                except Exception as e:
                    st.error(f"No se pudo crear: {e}")

    with st.expander("🔑 Cambiar contraseña / rol", expanded=False):
        dfu = db_list_users()
        if dfu.empty:
            st.info("No hay usuarios.")
        else:
            sel_user = st.selectbox("Usuario", dfu["username"].tolist(), key="USR_sel_change")
            np1, np2 = st.columns(2, gap="small")
            new_pass2 = np1.text_input("Nueva contraseña", type="password", key="USR_newpass2")
            if np1.button("Actualizar contraseña", key="USR_update_pwd"):
                if not new_pass2:
                    st.error("Escribe la nueva contraseña.")
                else:
                    db_set_password(sel_user, new_pass2)
                    notify_ok("Contraseña actualizada.")

            current_role = dfu.loc[dfu["username"]==sel_user,"role"].iloc[0]
            new_role2 = np2.selectbox("Rol", ["user","admin"],
                                      index=0 if current_role=="user" else 1,
                                      key="USR_newrole2")
            if np2.button("Actualizar rol", key="USR_update_role"):
                if sel_user == user and new_role2 != "admin":
                    st.error("No puedes quitarte el rol admin a ti mismo.")
                else:
                    db_set_role(sel_user, new_role2)
                    notify_ok("Rol actualizado.")

    with st.expander("🗂️ Lista de usuarios / eliminar", expanded=False):
        dfu = db_list_users()
        if dfu.empty:
            st.info("No hay usuarios.")
        else:
            st.dataframe(dfu, use_container_width=True)
            del_user = st.selectbox("Usuario a eliminar", dfu["username"].tolist(), key="USR_del_sel")
            confirm_del_user = st.checkbox("Confirmo eliminar este usuario", key="USR_del_ok")
            if st.button("Eliminar usuario", type="primary", disabled=not confirm_del_user, key="USR_del_btn"):
                if del_user == user:
                    st.error("No puedes eliminar tu propia cuenta.")
                else:
                    db_delete_user(del_user)
                    notify_ok(f"Usuario '{del_user}' eliminado.")
                    st.cache_data.clear()

    with st.expander("📜 Auditoría", expanded=False):
        # filtros
        colf1, colf2, colf3 = st.columns([1,1,2], gap="small")
        rango = colf1.date_input(
            "Rango",
            value=(date.today() - timedelta(days=30), date.today()),
            format="DD/MM/YYYY",
            key="AUD_rng"
        )
        usuario = colf2.text_input("Usuario contiene", key="AUD_user")
        acc = colf3.text_input("Acción contiene (p.ej. insert, delete, login)", key="AUD_act")
        tabla = st.text_input("Tabla contiene (p.ej. transacciones, gastos)", key="AUD_tbl")

        limit = st.number_input("Máx. registros", min_value=100, max_value=10000, value=1000, step=100)

        # consulta
        q = "SELECT id, ts, user, action, table_name AS tabla, row_id, details FROM audit_log WHERE 1=1"
        params = []
        if isinstance(rango, tuple) and len(rango) == 2:
            q += " AND date(ts) BETWEEN ? AND ?"
            params += [str(rango[0]), str(rango[1])]
        if usuario:
            q += " AND user LIKE ?"
            params.append(f"%{usuario.strip()}%")
        if acc:
            q += " AND action LIKE ?"
            params.append(f"%{acc.strip()}%")
        if tabla:
            q += " AND table_name LIKE ?"
            params.append(f"%{tabla.strip()}%")
        q += " ORDER BY id DESC LIMIT ?"
        params.append(int(limit))

        with get_conn() as conn:
            df_aud = pd.read_sql_query(q, conn, params=params)

        # vista amigable (columna details truncada)
        def _shorten(s, n=140):
            try:
                s = str(s or "")
                return s if len(s) <= n else s[:n] + "…"
            except Exception:
                return s

        if not df_aud.empty:
            df_aud_view = df_aud.copy()
            df_aud_view["details"] = df_aud_view["details"].map(lambda x: _shorten(x, 200))
            st.dataframe(df_aud_view, use_container_width=True, height=400)
            # descarga
            csv = df_aud.to_csv(index=False).encode("utf-8-sig")
            st.download_button("⬇️ Exportar auditoría CSV", csv,
                               file_name=f"audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")

            # purga opcional
            colp1, colp2 = st.columns([1,3], gap="small")
            dias = colp1.number_input("Purgar > días", min_value=7, max_value=3650, value=180, step=30)
            if colp2.button("🧹 Purgar registros anteriores a ese umbral"):
                with get_conn() as conn:
                    conn.execute("DELETE FROM audit_log WHERE ts < datetime('now', ?)", (f"-{int(dias)} days",))
                audit("audit.purge", extra={"older_than_days": int(dias)})
                st.success(f"Auditoría purgada (> {int(dias)} días).")
                st.cache_data.clear(); st.rerun()
        else:
            st.info("Sin registros con los filtros actuales.")

    with st.expander("🧹 Arrancar de cero (borrar TODOS los datos)", expanded=False):
        st.warning(
            "Esto vacía todas las tablas de negocio (ventas, gastos, préstamos, inventario, deudores, "
            "consolidado y auditoría). Puedes conservar los usuarios si quieres."
        )

        keep_users = st.checkbox("Conservar usuarios (tabla users)", value=True)
        disable_gs = st.checkbox("Desactivar Google Sheets antes de borrar (evita auto-restauración)", value=True)

        conf = st.text_input("Escribe: BORRAR TODO", placeholder="BORRAR TODO")
        ok = st.button("🧨 Borrar TODO", type="primary", disabled=(conf.strip().upper() != "BORRAR TODO"))

        if ok:
            try:
                # 1) Desactiva Sheets para que no se restaure solo al estar vacía la BD
                if disable_gs:
                    set_meta("GSHEETS_ENABLED", 0)

                # 2) Backup por si acaso
                try:
                    make_db_backup()
                except Exception as _e:
                    pass  # si falla el backup no bloqueamos el borrado

                # 3) Vaciar tablas
                with get_conn() as conn:
                    tablas = [
                        "transacciones","gastos","prestamos","inventario",
                        "deudores_ini","consolidado_diario","audit_log"
                    ]
                    if not keep_users:
                        tablas.append("users")
                    for t in tablas:
                        conn.execute(f"DELETE FROM {t}")
                    conn.execute("DELETE FROM meta")  # limpia metadatos (incluye cortes/ajustes)

                audit("db.wipe", extra={"keep_users": bool(keep_users)})

                # 4) Limpia caché/estado y reinicia
                st.session_state.clear()
                finish_and_refresh("Base borrada. Empezamos de cero ✅")
            except Exception as e:
                st.error(f"No pude vaciar los datos: {e}")
# ---------------------------------------------------------