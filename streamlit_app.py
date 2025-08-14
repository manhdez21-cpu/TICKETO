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

def _close_sidebar_on_mobile():
    components.html("""
    <script>
    (function () {
      try{
        if (!window.matchMedia("(max-width: 900px)").matches) return;
        const doc = window.parent?.document || document;

        // 1) Tocar el overlay (Drawer abierto)
        const ov = doc.querySelector('[data-testid="stSidebarOverlay"]');
        if (ov && ov.offsetParent !== null){ ov.click(); return; }

        // 2) Botón de colapso (por si no hay overlay visible)
        const btn =
          doc.querySelector('[data-testid="stSidebarCollapseControl"] button') ||
          doc.querySelector('[data-testid="collapsedControl"]') ||
          doc.querySelector('[data-testid="stSidebarCollapseControl"]');
        if (btn){ btn.click(); return; }

        // 3) Fallback: fuerza oculto
        const sb = doc.querySelector('section[data-testid="stSidebar"]');
        if (sb){
          sb.style.transform = 'translateX(-110%)';
          sb.style.visibility = 'hidden';
        }
      }catch(e){}
    })();
    </script>
    """, height=0, width=0)

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

with st.sidebar:
    p = Path(__file__).resolve()
    st.caption(f"🧩 Build: {APP_BUILD}")

st.markdown('<meta name="google" content="notranslate">', unsafe_allow_html=True)

# with st.sidebar:
#     p = pathlib.Path(__file__).resolve()
#     st.caption(f"🧩 Build: {APP_BUILD}")
#     st.caption(f"📄 Script: {p.name}")
#     st.caption(f"📁 Carpeta: {p.parent}")
#     st.caption(f"🔑 App sig: {_app_sig()}")

# --- Layout top limpio (quitamos header nativo de Streamlit) ---
st.markdown("""
<style>
/* Mostrar el header nativo (antes estaba display:none) */
header[data-testid="stHeader"]{
  display:flex !important;
  height: 36px; min-height: 36px;
  background: transparent !important;
  border-bottom: none !important;
}

/* Evita que el contenido del header tape cosas */
header[data-testid="stHeader"] > div { background: transparent !important; box-shadow: none !important; }

/* Nuestro header pegajoso queda por debajo del control de sidebar */
.tt-sticky{ z-index: 1000 !important; }

/* El control de colapso/expandir sidebar siempre por encima y clickeable */
[data-testid="stSidebarCollapseControl"],
[data-testid="collapsedControl"]{
  z-index: 2000 !important;
  pointer-events: auto !important;
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
import streamlit.components.v1 as components



# ---------------------------------------------------------
# Ajuste visual por defecto (se puede cambiar en Admin)
# ---------------------------------------------------------
ADJ_VENTAS_EFECTIVO = 455_500.0
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
init_db()

def ensure_indexes():
    with get_conn() as conn:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_trans_fecha   ON transacciones(fecha)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_trans_cliente ON transacciones(cliente_nombre)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_gastos_fecha  ON gastos(fecha)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts      ON audit_log(ts)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_action  ON audit_log(action)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_table   ON audit_log(table_name)")

ensure_indexes()

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
        col1, col2 = st.columns(2)
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

# >>> Ajustes administrables cargados desde meta <<<
ADJ_VENTAS_EFECTIVO = float(get_meta("ADJ_VENTAS_EFECTIVO", ADJ_VENTAS_EFECTIVO))

# =========================================================
# Lectores cacheados (invalidados por mtime/size del .sqlite)
# =========================================================
@st.cache_data(show_spinner=False)
def _read_ventas(_sig: tuple[int, int]) -> pd.DataFrame:
    with get_conn() as conn:
        df = pd.read_sql_query("SELECT * FROM transacciones", conn)
    if df.empty:
        cols = ['id','fecha','cliente_nombre','costo','venta','ganancia','debe_flag','paga','abono1','abono2','observacion']
        return pd.DataFrame(columns=cols)
    df['fecha'] = pd.to_datetime(df['fecha'], errors='coerce', dayfirst=True).dt.date
    for c in ['costo','venta','ganancia','abono1','abono2']:
        df[c] = pd.to_numeric(df[c], errors='coerce').fillna(0.0)
    df['debe_flag'] = df['debe_flag'].fillna(0).astype(int)
    df['observacion'] = (
        df['observacion']
          .astype(str)
          .str.strip()
          .str.upper()
          .replace({'NAN':'', 'NULL':'', 'NONE':'', 'NA':'', '<NA>':''})
    )
    return df

def read_ventas() -> pd.DataFrame:
    return _read_ventas(_db_sig())


@st.cache_data(show_spinner=False)
def _read_gastos(_sig: tuple[int, int]) -> pd.DataFrame:
    with get_conn() as conn:
        df = pd.read_sql_query("SELECT * FROM gastos", conn)
    if df.empty:
        return pd.DataFrame(columns=['id','fecha','concepto','valor','notas'])
    df['fecha'] = pd.to_datetime(df['fecha'], errors='coerce', dayfirst=True).dt.date
    df['valor'] = pd.to_numeric(df['valor'], errors='coerce').fillna(0.0)
    return df

def read_gastos() -> pd.DataFrame:
    return _read_gastos(_db_sig())


@st.cache_data(show_spinner=False)
def _read_prestamos(_sig: tuple[int, int]) -> pd.DataFrame:
    with get_conn() as conn:
        df = pd.read_sql_query("SELECT * FROM prestamos", conn)
    if df.empty:
        return pd.DataFrame(columns=['id','nombre','valor'])
    df['valor'] = pd.to_numeric(df['valor'], errors='coerce').fillna(0.0)
    return df

def read_prestamos() -> pd.DataFrame:
    return _read_prestamos(_db_sig())


@st.cache_data(show_spinner=False)
def _read_inventario(_sig: tuple[int, int]) -> pd.DataFrame:
    with get_conn() as conn:
        df = pd.read_sql_query("SELECT * FROM inventario", conn)
    if df.empty:
        return pd.DataFrame(columns=['id','producto','valor_costo'])
    df['valor_costo'] = pd.to_numeric(df['valor_costo'], errors='coerce').fillna(0.0)
    return df

def read_inventario() -> pd.DataFrame:
    return _read_inventario(_db_sig())


@st.cache_data(show_spinner=False)
def _read_consolidado(_sig: tuple[int, int]) -> pd.DataFrame:
    with get_conn() as conn:
        df = pd.read_sql_query("SELECT * FROM consolidado_diario", conn)
    if df.empty:
        return pd.DataFrame(columns=['fecha','efectivo','notas'])
    df['fecha_raw'] = df['fecha'].astype(str)
    df['fecha'] = pd.to_datetime(df['fecha'], errors='coerce', dayfirst=True).dt.date
    df['efectivo'] = pd.to_numeric(df['efectivo'], errors='coerce').fillna(0.0)
    return df

def read_consolidado() -> pd.DataFrame:
    return _read_consolidado(_db_sig())


@st.cache_data(show_spinner=False)
def _read_deudores_ini(_sig: tuple[int, int]) -> pd.DataFrame:
    with get_conn() as conn:
        df = pd.read_sql_query("SELECT * FROM deudores_ini", conn)
    if df.empty:
        return pd.DataFrame(columns=['id','nombre','valor'])

    cols = {c.lower(): c for c in df.columns}
    if 'nombre' not in df.columns and cols.get('cliente'):
        df = df.rename(columns={cols['cliente']: 'nombre'})
    elif 'nombre' in df.columns and cols.get('cliente'):
        mask = df['nombre'].astype(str).str.strip().eq("")
        df.loc[mask, 'nombre'] = df.loc[mask, cols['cliente']].astype(str)

    if 'valor' not in df.columns and cols.get('saldo'):
        df = df.rename(columns={cols['saldo']: 'valor'})
    elif 'valor' in df.columns and cols.get('saldo'):
        v = pd.to_numeric(df['valor'], errors='coerce').fillna(0.0)
        s = pd.to_numeric(df[cols['saldo']], errors='coerce').fillna(0.0)
        if v.abs().sum() == 0 and s.abs().sum() > 0:
            df['valor'] = s

    if 'id' not in df.columns:
        df.insert(0, 'id', range(1, len(df) + 1))

    df['nombre'] = df['nombre'].astype(str).str.strip()
    df['valor']  = pd.to_numeric(df['valor'], errors='coerce').fillna(0.0)
    return df[['id','nombre','valor']]

def read_deudores_ini() -> pd.DataFrame:
    return _read_deudores_ini(_db_sig())

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
    if corte is None:
        corte = get_corte_deudores()

    ini = read_deudores_ini()
    ini_df = ini.copy()
    ini_df["CLIENTE"] = ini_df["nombre"].astype(str).str.strip().str.upper()
    ini_df = (ini_df.groupby("CLIENTE", as_index=False)["valor"].sum()
              .rename(columns={"valor": "INICIAL"}))

    v = read_ventas()
    if v.empty:
        return pd.DataFrame(columns=["CLIENTE", "NUEVO", "INICIAL", "TOTAL"]), 0.0

    mov = v[["fecha", "cliente_nombre", "venta", "abono1", "abono2", "debe_flag"]].copy()
    mov["CLIENTE"] = mov["cliente_nombre"].astype(str).str.strip().str.upper()
    for c in ["venta", "abono1", "abono2", "debe_flag"]:
        mov[c] = pd.to_numeric(mov[c], errors="coerce").fillna(0.0)

    mov = mov[mov["fecha"] >= corte]
    if mov.empty:
        return pd.DataFrame(columns=["CLIENTE", "NUEVO", "INICIAL", "TOTAL"]), 0.0

    ventas_credito = mov.loc[mov["debe_flag"] == 1].groupby("CLIENTE")["venta"].sum(min_count=1)
    abonos_total   = (mov["abono1"] + mov["abono2"]).groupby(mov["CLIENTE"]).sum(min_count=1)
    nuevo = (ventas_credito.fillna(0.0) - abonos_total.fillna(0.0)).clip(lower=0.0)

    out = ini_df.merge(nuevo.rename("NUEVO").reset_index(), on="CLIENTE", how="outer")
    out["INICIAL"] = pd.to_numeric(out["INICIAL"], errors="coerce").fillna(0.0)
    out["NUEVO"]   = pd.to_numeric(out["NUEVO"],   errors="coerce").fillna(0.0)
    out["TOTAL"]   = out["INICIAL"] + out["NUEVO"]

    out_pos = out[out["NUEVO"] > 0].copy().sort_values(["TOTAL", "INICIAL"], ascending=False)
    total_visual = float(out_pos["TOTAL"].sum()) if not out_pos.empty else 0.0
    return out_pos[["CLIENTE", "NUEVO", "INICIAL", "TOTAL"]], total_visual

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
    if pd.isna(cell): return 0.0
    if isinstance(cell, (int, float, np.integer, np.floating)):
        try:
            x = float(cell)
            return 0.0 if np.isnan(x) else float(round(x))
        except Exception:
            return 0.0
    s = str(cell).strip()
    if s == "": return 0.0
    # Soporta (1.000), -1.000, 1.000,00
    neg = False
    if s.startswith("(") and s.endswith(")"):
        neg = True
        s = s[1:-1]
    if s.startswith("−"):  # signo unicode
        neg = True
        s = s[1:]
    if s.startswith("-"):
        neg = True
        s = s[1:]
    s = s.replace(" ", "")
    # Ignora decimales; conserva miles
    if "," in s and "." in s:
        s = s.replace(".", "").split(",")[0]
    elif "," in s and "." not in s:
        parts = s.split(",")
        s = "".join(parts) if len(parts) > 1 and all(len(p) == 3 for p in parts[1:]) else parts[0]
    elif "." in s and "," not in s:
        parts = s.split(".")
        s = "".join(parts) if len(parts) > 1 and all(len(p) == 3 for p in parts[1:]) else parts[0]
    else:
        s = re.sub(r"\D", "", s)
    s = re.sub(r"[^\d]", "", s)
    val = float(s) if s else 0.0
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
    with get_conn() as conn:
        cur = conn.execute("SELECT * FROM consolidado_diario WHERE fecha=?", (fecha_str,))
        row = cur.fetchone()
        cols = [d[0] for d in cur.description] if cur.description else []
        before = dict(zip(cols, row)) if row else None
        conn.execute("DELETE FROM consolidado_diario WHERE fecha=?", (fecha_str,))
    audit("delete", table_name="consolidado_diario", extra={"fecha": fecha_str}, before=before)

def upsert_consolidado(fecha_str: str, efectivo: float, notas: str=""):
    before = None
    with get_conn() as conn:
        cur = conn.execute("SELECT * FROM consolidado_diario WHERE fecha=?", (fecha_str,))
        row = cur.fetchone()
        cols = [d[0] for d in cur.description] if cur.description else []
        before = dict(zip(cols, row)) if row else None

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO consolidado_diario(fecha,efectivo,notas)
            VALUES(?,?,?)
            ON CONFLICT(fecha) DO UPDATE SET
                efectivo=excluded.efectivo,
                notas=excluded.notas
            """,
            (fecha_str, _to_float(efectivo), str(notas or '').strip())
        )
    audit("upsert", table_name="consolidado_diario",
          extra={"fecha": fecha_str},
          before=before,
          after={"fecha": fecha_str, "efectivo": float(efectivo), "notas": str(notas or '').strip()})

def get_efectivo_global_now() -> tuple[float, str]:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT efectivo, notas FROM consolidado_diario WHERE UPPER(TRIM(fecha))='GLOBAL'"
        ).fetchone()
    if row:
        ef = float(row[0] or 0.0); nt = str(row[1] or ""); return ef, nt
    return 0.0, ""

def insert_venta(r: dict) -> int:
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
    }
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO transacciones
            (fecha, cliente_nombre, costo, venta, ganancia, debe_flag, paga, abono1, abono2, observacion)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (payload['fecha'], payload['cliente_nombre'], payload['costo'], payload['venta'],
             payload['ganancia'], payload['debe_flag'], payload['paga'], payload['abono1'],
             payload['abono2'], payload['observacion'])
        )
        row_id = cur.lastrowid
    audit("insert", table_name="transacciones", row_id=row_id, after=payload)
    return row_id

def insert_gasto(r: dict) -> int:
    payload = {
        'fecha': _to_date_str(r.get('fecha')),
        'concepto': str(r.get('concepto') or '').strip(),
        'valor': _to_float(r.get('valor')),
        'notas': str(r.get('notas') or '').strip(),
    }
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO gastos (fecha, concepto, valor, notas) VALUES (?, ?, ?, ?)",
            (payload['fecha'], payload['concepto'], payload['valor'], payload['notas'])
        )
        row_id = cur.lastrowid
    audit("insert", table_name="gastos", row_id=row_id, after=payload)
    return row_id

def insert_prestamo(r: dict) -> int:
    payload = {
        'nombre': str(r.get('nombre') or '').strip(),
        'valor': _to_float(r.get('valor')),
    }
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO prestamos (nombre, valor) VALUES (?, ?)",
            (payload['nombre'], payload['valor'])
        )
        row_id = cur.lastrowid
    audit("insert", table_name="prestamos", row_id=row_id, after=payload)
    return row_id

def insert_inventario(r: dict) -> int:
    payload = {
        'producto': str(r.get('producto') or '').strip(),
        'valor_costo': _to_float(r.get('valor_costo')),
    }
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO inventario (producto, valor_costo) VALUES (?, ?)",
            (payload['producto'], payload['valor_costo'])
        )
        row_id = cur.lastrowid
    audit("insert", table_name="inventario", row_id=row_id, after=payload)
    return row_id

def insert_deudor_ini(r: dict) -> int:
    payload = {
        'nombre': str(r.get('nombre') or '').strip(),
        'valor': _to_float(r.get('valor')),
    }
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO deudores_ini (nombre, valor) VALUES (?, ?)",
            (payload['nombre'], payload['valor'])
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
    with get_conn() as conn:
        before = _fetch_row_as_dict(conn, "transacciones", row_id)
        conn.execute("DELETE FROM transacciones WHERE id=?", (int(row_id),))
    audit("delete", table_name="transacciones", row_id=int(row_id), before=before)

def delete_gasto_id(row_id: int):
    with get_conn() as conn:
        before = _fetch_row_as_dict(conn, "gastos", row_id)
        conn.execute("DELETE FROM gastos WHERE id=?", (int(row_id),))
    audit("delete", table_name="gastos", row_id=int(row_id), before=before)

def delete_prestamo_id(row_id: int):
    with get_conn() as conn:
        before = _fetch_row_as_dict(conn, "prestamos", row_id)
        conn.execute("DELETE FROM prestamos WHERE id=?", (int(row_id),))
    audit("delete", table_name="prestamos", row_id=int(row_id), before=before)

def delete_inventario_id(row_id: int):
    with get_conn() as conn:
        before = _fetch_row_as_dict(conn, "inventario", row_id)
        conn.execute("DELETE FROM inventario WHERE id=?", (int(row_id),))
    audit("delete", table_name="inventario", row_id=int(row_id), before=before)

def update_venta_fields(row_id: int, **changes) -> bool:
    """
    Actualiza campos de una venta (fila de transacciones) de forma parcial.
    Uso típico: update_venta_fields(123, abono2=50000)  # solo cambia abono2
    También puedes pasar abono1, paga, etc.
    """
    allowed = {
        "fecha", "cliente_nombre", "costo", "venta", "ganancia",
        "debe_flag", "paga", "abono1", "abono2", "observacion"
    }
    if not changes:
        return False

    # Sanitiza tipos
    payload = {}
    for k, v in changes.items():
        if k not in allowed:
            continue
        if k in {"costo", "venta", "ganancia", "abono1", "abono2"}:
            payload[k] = _to_float(v)
        elif k == "debe_flag":
            payload[k] = _to_int(v)
        elif k == "fecha":
            payload[k] = _to_date_str(v)
        else:
            payload[k] = str(v or "").strip()

    if not payload:
        return False

    with get_conn() as conn:
        before = _fetch_row_as_dict(conn, "transacciones", int(row_id))
        if before is None:
            return False

        sets = ", ".join([f"{k}=?" for k in payload.keys()])
        vals = list(payload.values()) + [int(row_id)]
        conn.execute(f"UPDATE transacciones SET {sets} WHERE id=?", vals)

        after = before.copy()
        after.update(payload)

    audit("update", table_name="transacciones", row_id=int(row_id), before=before, after=after)
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

def currency_input(label: str, key: str, value: float = 0.0, help: str | None = None, in_form: bool = False) -> float:
    # En móvil usamos number_input para teclado numérico nativo
    if st.session_state.get("is_mobile", False):
        return float(st.number_input(label, key=key, value=float(value), step=100.0, help=help))
    # Desktop: tu implementación actual con formato
    state_key = f"{key}_txt"
    if state_key not in st.session_state:
        st.session_state[state_key] = f"{int(round(float(value))):,.0f}"
    if in_form:
        st.text_input(label, value=st.session_state[state_key], key=state_key, help=help)
    else:
        def _fmt():
            raw = st.session_state[state_key]
            val = _parse_pesos(raw)
            st.session_state[state_key] = f"{int(round(val)):,.0f}"
        st.text_input(label, value=st.session_state[state_key], key=state_key, help=help, on_change=_fmt)
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
    q1, q2 = st.columns([2,1])
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

components.html("""
<script>
(function () {
  try{
    if (!window.matchMedia("(max-width: 900px)").matches) return;
    const topWin = window.parent || window;
    const doc = topWin.document;

    function closeDrawer(){
      const ov = doc.querySelector('[data-testid="stSidebarOverlay"]');
      if (ov && ov.offsetParent !== null){ ov.click(); return true; }
      const btn = doc.querySelector('[data-testid="stSidebarCollapseControl"] button, [data-testid="collapsedControl"]');
      if (btn){ btn.click(); return true; }
      const sb = doc.querySelector('section[data-testid="stSidebar"]');
      if (sb){
        sb.style.transform = 'translateX(-110%)';
        sb.style.visibility = 'hidden';
        sb.setAttribute('data-tt-closed','1');
        return true;
      }
      return false;
    }

    let tries = 0;
    const t = setInterval(function(){
      if (closeDrawer() || tries++ > 30) clearInterval(t);
    }, 100);
    topWin.setTimeout(closeDrawer, 50);
    topWin.setTimeout(closeDrawer, 250);
    topWin.setTimeout(closeDrawer, 600);
  }catch(e){}
})();
</script>
""", height=0, width=0)

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
    st.markdown("""
    <style>
      .tt-titlebar{
        position: sticky;
        top: 0;
        z-index: 1000;
        display:flex; align-items:center; gap:12px;
        padding: 10px 16px 12px 16px;
        background: rgba(255,255,255,.97);
        border-bottom: 1px solid rgba(120,120,135,.15);
      }
      .tt-titlebar .ttl{
        font-size:28px; font-weight:800; color:#111827; white-space:nowrap;
        overflow:hidden; text-overflow:ellipsis;
      }
    </style>
    """, unsafe_allow_html=True)

    st.markdown(
        f'<div class="tt-titlebar"><div class="ttl">{_clean_title(title_text)}</div></div>',
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
                insert_venta(r.to_dict())

        # Gastos
        df = _gs_read_df(GSHEET_MAP["gastos"])
        if not df.empty:
            df = df.drop(columns=[c for c in df.columns if c.lower()=="id"], errors="ignore")
            for _, r in df.iterrows():
                insert_gasto(r.to_dict())

        # Prestamos
        df = _gs_read_df(GSHEET_MAP["prestamos"])
        if not df.empty:
            df = df.drop(columns=[c for c in df.columns if c.lower()=="id"], errors="ignore")
            for _, r in df.iterrows():
                insert_prestamo(r.to_dict())

        # Inventario
        df = _gs_read_df(GSHEET_MAP["inventario"])
        if not df.empty:
            df = df.drop(columns=[c for c in df.columns if c.lower()=="id"], errors="ignore")
            for _, r in df.iterrows():
                insert_inventario(r.to_dict())

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
                insert_deudor_ini(r.to_dict())

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

    # --- Botón de menú compacto (debajo del logo)
    # --- Menú "Mi Cuenta" (popover con fallback a expander) ---
    if st.session_state.get("is_mobile", False):
        mi_cuenta = st.expander("Mi cuenta", expanded=False)
    else:
        try:
            mi_cuenta = st.popover("Mi Cuenta", use_container_width=True)
        except Exception:
            mi_cuenta = st.expander("Mi cuenta", expanded=False)

    with mi_cuenta:
        st.caption(f"Sesión: **{user}** · rol **{role}**")

        if st.button("🚪 Cerrar sesión", use_container_width=True, key="btn_logout"):
            audit("logout", extra={"user": user})
            _clear_session()
            st.success("Sesión cerrada. Volviendo al login…")
            # da ~500ms para que el navegador actualice cookies y luego recarga
            components.html(
                "<script>setTimeout(()=>window.parent.location.reload(), 600)</script>",
                height=0, width=0
            )
            st.stop()

        if st.button("🔄 Reiniciar estado y caché"):
            st.session_state.clear(); st.rerun()

        if st.button("💾 Haz una copia de seguridad ahora"):
            try:
                p = make_db_backup()
                set_meta("LAST_BACKUP_ISO", datetime.now().isoformat(timespec="seconds"))
                finish_and_refresh(f"Backup creado: {p}")
            except Exception as e:
                st.error(f"No se pudo crear el backup: {e}")
        
        from pathlib import Path

        st.markdown("---")
        last_bkp = None
        try:
            BACKUP_DIR.mkdir(exist_ok=True, parents=True)
            files = list(BACKUP_DIR.glob("finanzas_*.sqlite"))
            if files:
                last_bkp = max(files, key=lambda p: p.stat().st_mtime)
        except Exception:
            pass

        if last_bkp:
            with open(last_bkp, "rb") as f:
                st.download_button(
                    "⬇️ Descargar último backup",
                    f.read(),
                    file_name=last_bkp.name,
                    mime="application/octet-stream",
                    use_container_width=True
                )

        st.markdown("---")
        st.markdown("**Mi cuenta**")

        with st.form("SELF_pw_form", clear_on_submit=True):
            newp = st.text_input("Nueva contraseña", type="password")
            ok = st.form_submit_button("Cambiar mi contraseña")

        if ok:
            if not newp:
                st.error("Escribe la nueva contraseña.")
            else:
                db_set_password(user, newp)
                notify_ok("Tu contraseña fue actualizada.")
                
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
    "💸 Gastos", "🤝 Préstamos", "📦 Inventario", "⬆️ Importar/Exportar", "👤 Deudores"
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

    # Navegación
    st.radio(
        "Secciones",
        tabs,
        label_visibility="collapsed",
        key="nav_left",
    )

current = st.session_state["nav_left"]

# Si cambió la pestaña, cierra la sidebar en móvil
if _prev_nav != current:
    _close_sidebar_on_mobile()

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

from pathlib import Path
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

  /* Header pegajoso */
  .tt-titlebar{
    background: var(--card-bg) !important;
    border-bottom: 1px solid var(--card-border) !important;
  }
  .tt-titlebar .ttl{ color: var(--text) !important; }

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
/* ========= BOTÓN HAMBURGUESA LLAMATIVO (centrado de verdad) ========= */
[data-testid="stSidebarCollapseControl"] button,
[data-testid="collapsedControl"]{
  width: 46px !important;
  height: 46px !important;
  border-radius: 999px !important;
  background: linear-gradient(135deg,#6366f1,#22d3ee) !important;
  border: 0 !important;
  padding: 0 !important;
  display: flex !important;
  align-items: center !important;
  justify-content: center !important;
  position: relative !important;              /* <— clave para centrar el ::before */
  box-shadow: 0 6px 16px rgba(99,102,241,.35), 0 2px 4px rgba(0,0,0,.16) !important;
  transition: transform .12s ease, box-shadow .12s ease, filter .12s ease;
  z-index: 2000 !important;
  cursor: pointer;
}

/* Oculta el icono SVG original */
[data-testid="stSidebarCollapseControl"] button svg,
[data-testid="collapsedControl"] svg{ display:none !important; }

/* 3 barras centradas */
[data-testid="stSidebarCollapseControl"] button::before,
[data-testid="collapsedControl"]::before{
  content:"";
  position: absolute;
  top: 50%; left: 50%;
  transform: translate(-50%, -50%);
  width: 22px; height: 2px;                   /* barra central */
  background:#fff; border-radius: 2px;
  box-shadow:
    0 -6px 0 0 #fff,                           /* barra superior */
    0  6px 0 0 #fff;                           /* barra inferior */
}

[data-testid="stSidebarCollapseControl"] button:hover,
[data-testid="collapsedControl"]:hover{
  transform: translateY(-1px) scale(1.04);
}

/* Efecto pulse cuando está colapsado */
@keyframes tt-pulse {
  0%   { box-shadow: 0 0 0 0 rgba(99,102,241,.55); }
  70%  { box-shadow: 0 0 0 14px rgba(99,102,241,0); }
  100% { box-shadow: 0 0 0 0 rgba(99,102,241,0); }
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

# Título siempre actualizado
show_sticky_header(current, logo_path=_show_logo_path, show_brand_text=False)
show_flash_if_any()

def quick_nav_mobile():
    if not st.session_state.get("is_mobile", False):
        return
    st.markdown("### ")
    map_short = {
        "Consolidado":"🧮 Diario Consolidado",
        "Ventas":"🧾 Ventas",
        "Gastos":"💸 Gastos",
        "Deudores":"👤 Deudores"
    }
    choice = st.radio("Ir a", list(map_short.keys()), horizontal=True, key="quick_nav_mob")
    target = map_short[choice]
    if st.session_state.get("nav_left") != target:
        st.session_state["nav_left"] = target
        st.rerun()

# Llamado (una sola vez tras el header)
quick_nav_mobile()

with st.container():
    a1, a2, a3 = st.columns([1,1,6])
    with a1.popover("➕ Venta", use_container_width=True):
        fv1, fv2 = st.columns(2)
        q_fecha = fv1.date_input("Fecha", value=date.today(), max_value=date.today(), format="DD/MM/YYYY", key="QA_VTA_F")
        q_cliente = fv2.text_input("Cliente", key="QA_VTA_C")
        q_costo = currency_input("Costo", key="QA_VTA_COSTO")
        q_venta = currency_input("Venta", key="QA_VTA_VENTA")
        q_debe  = st.checkbox("DEBE", key="QA_VTA_DEBE")
        q_obs   = st.selectbox("Observación", ["EFECTIVO","CUENTA",""], index=0, key="QA_VTA_OBS")
        if st.button("Guardar venta rápida", type="primary", key="QA_VTA_SAVE"):
            insert_venta({
                'fecha': str(q_fecha), 'cliente_nombre': q_cliente,
                'costo': float(q_costo), 'venta': float(q_venta),
                'ganancia': max(0.0, float(q_venta - q_costo)),
                'debe_flag': 1 if q_debe else 0, 'paga': '',
                'abono1': 0.0, 'abono2': 0.0, 'observacion': q_obs
            })

            # 🔄 Limpiar widgets de venta rápida (incluye los *_txt de currency_input)
            _reset_keys([
                "QA_VTA_F", "QA_VTA_C", "QA_VTA_DEBE", "QA_VTA_OBS",
                "QA_VTA_COSTO_txt", "QA_VTA_VENTA_txt"
            ])
            components.html("<script>try{document.activeElement && document.activeElement.blur();}catch(e){}</script>", height=0, width=0)
            finish_and_refresh("Venta guardada ✅", ["transacciones"])

    with a2.popover("➕ Gasto", use_container_width=True):
        gg1, gg2 = st.columns(2)
        qg_fecha = gg1.date_input("Fecha", value=date.today(), max_value=date.today(), format="DD/MM/YYYY", key="QA_GTO_F")
        qg_conc  = gg2.text_input("Concepto", key="QA_GTO_C")
        qg_val   = currency_input("Valor", key="QA_GTO_V", value=0.0)
        qg_notas = st.text_input("Notas", key="QA_GTO_N")
        if st.button("Guardar gasto rápido", type="primary", key="QA_GTO_SAVE"):
            insert_gasto({'fecha': str(qg_fecha), 'concepto': qg_conc, 'valor': float(qg_val), 'notas': qg_notas})

            # 🔄 Limpiar widgets de gasto rápido
            _reset_keys([
                "QA_GTO_F", "QA_GTO_C", "QA_GTO_N",
                "QA_GTO_V_txt"
            ])
            components.html("<script>try{document.activeElement && document.activeElement.blur();}catch(e){}</script>", height=0, width=0)
            finish_and_refresh("Gasto guardado ✅", ["gastos"])

def show(section: str) -> bool:
    return current == section



# ---------------------------------------------------------
# Diario consolidado
# ---------------------------------------------------------
if show("🧮 Diario Consolidado"):
    v_df = read_ventas(); g_df = read_gastos(); p_df = read_prestamos(); i_df = read_inventario(); c_df = read_consolidado()

    total_cuenta    = float(v_df.loc[v_df['observacion'].eq('CUENTA'),   'venta'].sum()) if not v_df.empty else 0.0
    total_efectivo  = float(v_df.loc[v_df['observacion'].eq('EFECTIVO'), 'venta'].sum()) if not v_df.empty else 0.0
    total_gastos    = float(g_df['valor'].sum()) if not g_df.empty else 0.0
    total_costos    = float(v_df['costo'].sum()) if not v_df.empty else 0.0
    total_prestamos = float(p_df['valor'].sum()) if not p_df.empty else 0.0
    total_inventario= float(i_df['valor_costo'].sum()) if not i_df.empty else 0.0

    d_ini = read_deudores_ini()
    total_deudores_ini = float(d_ini['valor'].sum()) if not d_ini.empty else 0.0

    # Ajuste visual para ventas efectivas
    total_efectivo_mostrar = total_efectivo + ADJ_VENTAS_EFECTIVO

    c1, c2, c3 = st.columns(3)
    c1.metric("TOTAL DE VENTAS CUENTA",   money(total_cuenta))
    c2.metric("TOTAL DE VENTAS EFECTIVAS", money(total_efectivo_mostrar))
    c3.metric("GASTOS TOTALES",           money(total_gastos))

    c4, c5, c6 = st.columns(3)
    c4.metric("COSTOS TOTALES (desde C3)", money(total_costos))
    c5.metric("TOTAL PRÉSTAMOS",           money(total_prestamos))
    c6.metric("INVENTARIO TOTAL",          money(total_inventario))

    st.metric("TOTAL DEUDORES", money(total_deudores_ini))

    corte_actual = get_corte_deudores()
    _, uni_total = deudores_unificados(corte_actual)

    c7, c8 = st.columns(2)
    c7.metric("DEUDORES NUEVOS (desde corte)", money(uni_total))
    c8.metric("DEUDORES TOTAL (inicial + nuevos)", money(total_deudores_ini + uni_total))

    st.markdown("### EFECTIVO (manual)")
    efectivo_ini, notas_ini = get_efectivo_global_now()
    metric_box = st.empty()
    metric_box.metric("EFECTIVO", money(efectivo_ini))

    colA, colB = st.columns([1, 2])
    with colA:
        CONS_efectivo = currency_input("Efectivo en caja", key="CONS_efectivo_input", value=float(efectivo_ini))
    with colB:
        CONS_notas = st.text_input("Notas", value=notas_ini, key="CONS_efectivo_notas")

    colS, colD = st.columns([1, 1])
    if colS.button("💾 Guardar / Reemplazar (global)", key="CONS_efectivo_save"):
        upsert_consolidado("GLOBAL", float(CONS_efectivo), CONS_notas)
        nuevo_ef, _ = get_efectivo_global_now()
        metric_box.metric("EFECTIVO", money(nuevo_ef))
        components.html("<script>try{document.activeElement && document.activeElement.blur();}catch(e){}</script>", height=0, width=0)
        finish_and_refresh("Efectivo (GLOBAL) reemplazado.", ["consolidado_diario"])

    confirm_del = colD.checkbox("Confirmar eliminación", key="CONS_del_confirm")
    if colD.button("🗑️ Eliminar efectivo (global)", disabled=not confirm_del, key="CONS_efectivo_delete"):
        delete_consolidado("GLOBAL")
        metric_box.metric("EFECTIVO", money(0.0))
        finish_and_refresh("Efectivo (GLOBAL) eliminado.", ["consolidado_diario"])

    total_capital = (
        total_cuenta
        + total_efectivo_mostrar
        + total_prestamos
        + total_inventario
        + (total_deudores_ini + uni_total)
        + efectivo_ini
        - (total_gastos + total_costos)
    )
    st.metric("TOTAL DE CAPITAL", money(total_capital))

# ---------------------------------------------------------
# Dashboard
# ---------------------------------------------------------
elif show("📊 Panel de control"):
    v = read_ventas(); g = read_gastos()
    st.metric("Ventas registradas", len(v))
    st.metric("Gastos registrados", len(g))
    st.metric("Total VENTA", money(float(v['venta'].sum()) if not v.empty else 0.0))

# ---------------------------------------------------------
# Ventas
# ---------------------------------------------------------
elif show("🧾 Ventas"):
    f1c1, f1c2 = st.columns(2)
    VTA_fecha = f1c1.date_input("Fecha", value=date.today(), max_value=date.today(), key="VTA_fecha_rt", format="DD/MM/YYYY")
    VTA_cliente = f1c2.text_input("Cliente", key="VTA_cliente_rt")

    f2c1, f2c2, f2c3 = st.columns(3)
    with f2c1:
        VTA_costo = currency_input("Costo", key="VTA_costo_rt", value=0.0)
    with f2c2:
        VTA_venta = currency_input("Venta", key="VTA_venta_rt", value=0.0)
    with f2c3:
        VTA_gan_calc = max(0.0, float(VTA_venta - VTA_costo))
        st.text_input("Ganancia", value=money(VTA_gan_calc), disabled=True, key="VTA_ganancia_view_rt")

    f3c1, f3c2 = st.columns(2)
    VTA_debe = f3c1.checkbox("DEBE", key="VTA_debe_rt")
    VTA_paga = f3c2.checkbox("PAGA (pagó hoy)", key="VTA_paga_rt")

    f4c1, f4c2 = st.columns(2)
    with f4c1:
        VTA_ab1 = currency_input("Abono 1", key="VTA_ab1_rt", value=0.0)
    with f4c2:
        VTA_ab2 = currency_input("Abono 2", key="VTA_ab2_rt", value=0.0)

    VTA_obs = st.selectbox("Observación", ["EFECTIVO","CUENTA",""], index=0, key="VTA_obs_rt")

    # Validaciones previas
    invalid_paga = bool(VTA_debe and VTA_paga and (float(VTA_ab1) + float(VTA_ab2) <= 0))
    if invalid_paga:
        st.warning("Marcaste PAGA, pero no registraste abonos. Agrega Abono 1 y/o Abono 2.")
    if float(VTA_venta) < float(VTA_costo):
        st.warning("La venta es menor que el costo. ¿Seguro?")

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
            'observacion': VTA_obs,
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
        v = filtro_busqueda(v, ["cliente_nombre","observacion"], key="ventas")
        st.session_state["ventas_last_text"]  = st.session_state.get("q_ventas", "")
        st.session_state["ventas_last_rango"] = st.session_state.get("rng_ventas", None)

        # Chips por observación
        obs_sel = st.radio("Filtrar por observación", ["(todas)", "EFECTIVO", "CUENTA"],
                           horizontal=True, key="ventas_obs")
        if obs_sel != "(todas)":
            v = v[v["observacion"] == obs_sel]

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

        m1, m2, m3 = st.columns(3)
        m1.metric("Costos totales",  money(tot_costos))
        m2.metric("Ventas totales",  money(tot_ventas_mostrar))
        m3.metric("Ganancia total",  money(tot_ganancia))

        with st.expander("🔍 Detalle de ventas por observación", expanded=False):
            det = (v_valid.groupby("observacion", dropna=False)["venta"]
                   .sum().rename("VENTA").reset_index()
                   .sort_values("VENTA", ascending=False))
            det = df_format_money(det, ["VENTA"])
            st.dataframe(det, use_container_width=True)
            st.caption(
                f"Total sin ajuste: {money(float(v_valid['venta'].sum()))} | "
                f"Con ajuste: {money(float(v_valid['venta'].sum()) + ADJ_VENTAS_EFECTIVO)}"
            )

        cols = ['fecha','cliente_nombre','observacion','costo','venta','ganancia','debe_flag','paga','abono1','abono2']
        v_show = v.sort_values('fecha', ascending=False)[cols]
        v_show = df_format_money(v_show, ['costo','venta','ganancia','abono1','abono2'])
        st.dataframe(v_show, use_container_width=True)

        with st.expander("✏️ Editar venta (abonos)", expanded=False):
            vv = read_ventas()
            if vv.empty:
                st.info("No hay ventas para editar.")
            else:
                opts = vv.sort_values('fecha', ascending=False).copy()
                opts['label'] = opts.apply(
                    lambda r: (
                        f"#{int(r['id'])} • {r['fecha']} • {str(r['cliente_nombre'])[:25]} • "
                        f"{money(float(r['venta']))} • Ab1 {money(float(r['abono1']))} • Ab2 {money(float(r['abono2']))}"
                    ),
                    axis=1
                )
                choice = st.selectbox("Selecciona la venta a editar", opts['label'].tolist(), key="ED_VTA_sel")

                sel_id = int(choice.split("•")[0].strip().lstrip("#"))
                row = vv.loc[vv["id"] == sel_id].iloc[0]

                st.caption(f"Cliente: **{row['cliente_nombre']}** · Fecha: **{row['fecha']}** · Venta: **{money(float(row['venta']))}**")

                kpref = f"ED_VTA_{sel_id}"
                c1, c2 = st.columns(2)
                with c1:
                    new_ab1 = currency_input("Abono 1", key=f"{kpref}_ab1", value=float(row["abono1"]))
                with c2:
                    new_ab2 = currency_input("Abono 2", key=f"{kpref}_ab2", value=float(row["abono2"]))

                total_abonos = float(new_ab1) + float(new_ab2)
                st.write(f"**Abonos totales:** {money(total_abonos)}  / Venta: {money(float(row['venta']))}")

                auto_paga = st.checkbox("Marcar PAGA automáticamente si Abono1+Abono2 ≥ Venta", value=True, key=f"{kpref}_auto_paga")
                excede = total_abonos > float(row["venta"])
                if excede:
                    st.warning("Los abonos superan el valor de la venta. Verifica si es correcto.")
                # Si quieres bloquear el guardado cuando excede, descomenta la siguiente línea:
                # save_disabled = excede
                save_disabled = False

                if st.button("💾 Guardar cambios", type="primary", disabled=save_disabled, key=f"{kpref}_save"):
                    changes = {}
                    if float(new_ab1) != float(row["abono1"]):
                        changes["abono1"] = float(new_ab1)
                    if float(new_ab2) != float(row["abono2"]):
                        changes["abono2"] = float(new_ab2)
                    if auto_paga and total_abonos >= float(row["venta"]):
                        changes["paga"] = "X"  # mantiene tu convención de PAGA

                    if not changes:
                        st.info("No hay cambios para guardar.")
                    else:
                        ok = update_venta_fields(sel_id, **changes)
                        if ok:
                            finish_and_refresh(f"Venta #{sel_id} actualizada ✅", ["transacciones"])
                        else:
                            st.error("No se pudo actualizar la venta.")

        with st.expander("🗑️ Eliminar venta", expanded=False):
            vv = read_ventas()
            if vv.empty:
                st.info("No hay ventas para eliminar.")
            else:
                opts = vv.sort_values('fecha', ascending=False).copy()
                opts['label'] = opts.apply(
                    lambda r: f"#{int(r['id'])} • {r['fecha']} • {str(r['cliente_nombre'])[:25]} • "
                              f"{money(float(r['venta']))} • {'DEBE' if int(r['debe_flag'])==1 else ''}",
                    axis=1
                )
                choice = st.selectbox("Selecciona la venta a eliminar", opts['label'].tolist())
                sel_id = int(choice.split("•")[0].strip().lstrip("#"))
                confirm = st.checkbox("Confirmo eliminar esta venta")
                if st.button("Eliminar venta", type="primary", disabled=not confirm):
                    # ⚠️ Todo lo del modal DEBE ir dentro del with
                    with st.modal("¿Eliminar definitivamente esta venta?"):
                        st.write(choice)
                        c1, c2 = st.columns(2)
                        if c1.button("Sí, eliminar", type="primary", key="del_v_ok"):
                            delete_venta_id(sel_id)
                            finish_and_refresh(f"Venta #{sel_id} eliminada.", ["transacciones"])
                        if c2.button("Cancelar", key="del_v_cancel"):
                            st.rerun()
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
        c1, c2 = st.columns(2)
        GTO_fecha = c1.date_input(
            "Fecha",
            value=date.today(),
            max_value=date.today(),              # bloquea fechas futuras
            key="GTO_fecha",
            format="DD/MM/YYYY"
        )
        GTO_conc  = c2.text_input("Concepto", key="GTO_concepto")

        c3, c4 = st.columns(2)
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

        with st.expander("🗑️ Eliminar gasto", expanded=False):
            gg = read_gastos()
            if gg.empty:
                st.info("No hay gastos para eliminar.")
            else:
                opts = gg.sort_values('fecha', ascending=False).copy()
                opts['label'] = opts.apply(
                    lambda r: f"#{int(r['id'])} • {r['fecha']} • {str(r['concepto'])[:40]} • "
                              f"{money(float(r['valor']))}",
                    axis=1
                )
                choice = st.selectbox("Selecciona el gasto a eliminar", opts['label'].tolist(), key="DEL_GTO_sel")
                sel_id = int(choice.split("•")[0].strip().lstrip("#"))
                confirm = st.checkbox("Confirmo eliminar este gasto", key="DEL_GTO_ok")
                if st.button("Eliminar gasto", type="primary", disabled=not confirm, key="DEL_GTO_btn"):
                    # ⚠️ Todo lo del modal DEBE ir dentro del with
                    with st.modal("¿Eliminar definitivamente este gasto?"):
                        st.write(choice)
                        c1, c2 = st.columns(2)
                        if c1.button("Sí, eliminar", type="primary", key="del_g_ok"):
                            delete_gasto_id(sel_id)
                            finish_and_refresh(f"Gasto #{sel_id} eliminado.", ["gastos"])
                        if c2.button("Cancelar", key="del_g_cancel"):
                            st.rerun()

# ---------------------------------------------------------
# Préstamos
# ---------------------------------------------------------
elif show("🤝 Préstamos"):
    with st.form(key="PRE_form",clear_on_submit=True):
        c1, c2 = st.columns(2)
        PRE_nombre = c1.text_input("Nombre", key="PRE_nombre")
        with c2:
            PRE_valor  = currency_input("Valor", key="PRE_valor", value=0.0, in_form=True)
        PRE_submit = st.form_submit_button("💾 Guardar préstamo")
    if PRE_submit:
        insert_prestamo({'nombre': PRE_nombre, 'valor': float(PRE_valor)})
        finish_and_refresh("Préstamo guardado", ["prestamos"])

    st.divider()
    p = read_prestamos()
    if not p.empty:
        st.metric("TOTAL PRÉSTAMOS", money(float(p['valor'].sum())))
        p_show = p.sort_values('id', ascending=False).copy()
        p_show = df_format_money(p_show, ['valor'])
        st.dataframe(p_show, use_container_width=True)

    with st.expander("🗑️ Eliminar préstamo", expanded=False):
        pp = read_prestamos()
        if pp.empty:
            st.info("No hay préstamos para eliminar.")
        else:
            opts = pp.sort_values('id', ascending=False).copy()
            opts['label'] = opts.apply(
                lambda r: f"#{int(r['id'])} • {str(r['nombre'])[:30]} • {money(float(r['valor']))}",
                axis=1
            )
            choice = st.selectbox("Selecciona el préstamo a eliminar", opts['label'].tolist(), key="DEL_PRE_sel")
            sel_id = int(choice.split("•")[0].strip().lstrip("#"))
            confirm = st.checkbox("Confirmo eliminar este préstamo", key="DEL_PRE_ok")
            if st.button("Eliminar préstamo", type="primary", disabled=not confirm, key="DEL_PRE_btn"):
                delete_prestamo_id(sel_id)
                finish_and_refresh(f"Préstamo #{sel_id} eliminado.", ["prestamos"])

# ---------------------------------------------------------
# Inventario
# ---------------------------------------------------------
elif show("📦 Inventario"):
    with st.form(key="INV_form",clear_on_submit=True):
        c1, c2 = st.columns(2)
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

    with st.expander("🗑️ Eliminar ítem de inventario", expanded=False):
        ii = read_inventario()
        if ii.empty:
            st.info("No hay ítems de inventario para eliminar.")
        else:
            opts = ii.sort_values('id', ascending=False).copy()
            opts['label'] = opts.apply(
                lambda r: f"#{int(r['id'])} • {str(r['producto'])[:40]} • {money(float(r['valor_costo']))}",
                axis=1
            )
            choice = st.selectbox("Selecciona el ítem a eliminar", opts['label'].tolist(), key="DEL_INV_sel")
            sel_id = int(choice.split("•")[0].strip().lstrip("#"))
            confirm = st.checkbox("Confirmo eliminar este ítem", key="DEL_INV_ok")
            if st.button("Eliminar ítem", type="primary", disabled=not confirm, key="DEL_INV_btn"):
                delete_inventario_id(sel_id)
                finish_and_refresh(f"Ítem #{sel_id} eliminado.", ["inventario"])

# ---------------------------------------------------------
# Deudores
# ---------------------------------------------------------
elif show("👤 Deudores"):
    d_ini = read_deudores_ini()
    if d_ini.empty:
        st.info("No hay saldos iniciales de deudores cargados. Importa tu Excel (Consolidado: columnas E/F).")
    else:
        st.metric("Total por cobrar (Iniciales)", money(float(d_ini['valor'].sum())))
        base = d_ini[['nombre','valor']].rename(columns={'nombre':'CLIENTE','valor':'SALDO'})
        base_show = df_format_money(base, ['SALDO'])
        st.dataframe(base_show.sort_values('SALDO', ascending=False), use_container_width=True)
        st.caption("Tabla principal = saldos iniciales importados; no se modifican.")

    corte_actual = get_corte_deudores()
    with st.expander("⚙️ Fecha de corte para nuevos deudores (desde esta fecha se suman ventas a crédito)", expanded=False):
        nueva_corte = st.date_input("Fecha de corte", value=corte_actual, max_value=date.today(), key="CFG_CORTE_DEUDORES", format="DD/MM/YYYY")
        c1, c2 = st.columns(2)
        if c1.button("Guardar corte", type="primary"):
            set_corte_deudores(nueva_corte)
            set_meta("CORTE_DEUDORES", str(nueva_corte))
            finish_and_refresh(f"Corte guardado: {nueva_corte}")
        c2.caption("Deja la fecha en HOY para empezar a sumar desde ahora.")

    with st.expander("📊 Ver unificado (Iniciales + Ventas desde corte)", expanded=False):
        uni_df, _ = deudores_unificados(corte_actual)
        if not uni_df.empty:
            for c in ["NUEVO","INICIAL","TOTAL"]:
                uni_df[c] = pd.to_numeric(uni_df[c], errors="coerce").fillna(0.0)
            total_unificado = float(uni_df["TOTAL"].sum())
            total_nuevo = float(uni_df["NUEVO"].sum())
        else:
            total_unificado = 0.0; total_nuevo = 0.0

        cA, cB = st.columns(2)
        cA.metric("Total por cobrar (Unificado – solo NUEVO>0)", money(total_unificado))
        cB.metric("NUEVO acumulado (desde el corte)", money(total_nuevo))

        if not uni_df.empty:
            uni_show = df_format_money(uni_df, ['NUEVO','INICIAL','TOTAL'])
            st.dataframe(uni_show, use_container_width=True)
        else:
            st.write("Aún no hay nuevos saldos provenientes de Ventas desde la fecha de corte.")

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
            resumen = ", ".join([f"{k}: {v}" for k, v in stats.items()])
            finish_and_refresh(f"Importación completa ➜ {resumen}",
                               tables_to_sync=["transacciones","gastos","prestamos","inventario","deudores_ini"])
        except Exception as e:
            st.error(f"Error importando: {e}")

# ---------------------------------------------------------
# Administración (solo admin)
# ---------------------------------------------------------
if is_admin() and show("🛠️ Administración"):
        c1, c2 = st.columns(2)

        # Ajuste visual de ventas efectivas
        adj_val = c1.number_input("Ajuste visual a Ventas Efectivas (+/-)", value=float(ADJ_VENTAS_EFECTIVO), step=100.0)
        if c1.button("Guardar ajuste"):
            set_meta("ADJ_VENTAS_EFECTIVO", float(adj_val))
            finish_and_refresh("Ajuste visual actualizado.")

        # Google Sheets ID editable
        gs_id_val = c2.text_input("Google Sheet ID", value=GSPREADSHEET_ID)
        if c2.button("Guardar Sheets ID"):
            set_meta("GSHEET_ID", gs_id_val.strip())
            finish_and_refresh("Google Sheet ID actualizado.")

        gs_enabled_ui = c2.toggle("Habilitar Google Sheets", value=GOOGLE_SHEETS_ENABLED, key="CFG_GSHEETS_ENABLED")
        if c2.button("Guardar estado Sheets"):
            set_meta("GSHEETS_ENABLED", 1 if gs_enabled_ui else 0)
            finish_and_refresh("Estado de Google Sheets actualizado.")

        st.divider()
        c3, c4, c5 = st.columns(3)
        if c3.button("Sincronizar TODAS las tablas a Google Sheets"):
            if not GOOGLE_SHEETS_ENABLED:
                st.info("Sincronización deshabilitada en Admin → “Habilitar Google Sheets”.")
            else:
                sync_tables_to_gsheet(list(GSHEET_MAP.keys()))
                notify_ok("Sincronización enviada.")
        if c4.button("Limpiar caché y recargar ahora"):
            st.cache_data.clear(); st.rerun()
        if c5.button("Cerrar sesión (admin)"):
            _clear_session(); st.rerun()

        st.divider()
        # --- Gestión de usuarios ---
        with st.expander("➕ Crear usuario", expanded=False):
            cu1, cu2, cu3 = st.columns(3)
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
                np1, np2 = st.columns(2)
                new_pass2 = np1.text_input("Nueva contraseña", type="password", key="USR_newpass2")
                if np1.button("Actualizar contraseña", key="USR_update_pwd"):
                    if not new_pass2:
                        st.error("Escribe la nueva contraseña.")
                    else:
                        db_set_password(sel_user, new_pass2)
                        notify_ok("Contraseña actualizada.")

                current_role = dfu.loc[dfu["username"]==sel_user,"role"].iloc[0]
                new_role2 = np2.selectbox("Rol", ["user","admin"], index=0 if current_role=="user" else 1, key="USR_newrole2")
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
            colf1, colf2, colf3 = st.columns([1,1,2])
            rango = colf1.date_input("Rango", value=(date.today() - timedelta(days=30), date.today()), format="DD/MM/YYYY", key="AUD_rng")
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
                st.download_button("⬇️ Exportar auditoría CSV", csv, file_name=f"audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")

                # purga opcional
                colp1, colp2 = st.columns([1,3])
                dias = colp1.number_input("Purgar > días", min_value=7, max_value=3650, value=180, step=30)
                if colp2.button("🧹 Purgar registros anteriores a ese umbral"):
                    with get_conn() as conn:
                        conn.execute("DELETE FROM audit_log WHERE ts < datetime('now', ?)", (f"-{int(dias)} days",))
                    audit("audit.purge", extra={"older_than_days": int(dias)})
                    st.success(f"Auditoría purgada (> {int(dias)} días).")
                    st.cache_data.clear(); st.rerun()
            else:
                st.info("Sin registros con los filtros actuales.")

# ---------------------------------------------------------
