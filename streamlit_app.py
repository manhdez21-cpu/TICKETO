# streamlit_app.py — Control de Gastos y Ventas (login + roles + admin + refresco)
# Ejecuta:
#   pip install -r requirements.txt
#   pip install extra-streamlit-components bcrypt
#   streamlit run streamlit_app.py
#.\.venv\Scripts\Activate


import streamlit as st
from PIL import Image

import auth_db as AUTH
from io import BytesIO
from datetime import datetime
from sqlalchemy import text

import sqlite3
from contextlib import contextmanager
from pathlib import Path

# ÚNICA configuración de página (primera instrucción st.*)
try:
    _logo = Image.open("assets/ticketo.png")   # tu logo
except Exception:
    _logo = "💸"                                # fallback emoji si no existe el archivo

st.set_page_config(
    page_title="TickeTo",
    page_icon=_logo,
    layout="wide",
    initial_sidebar_state="collapsed",
)


st.markdown("""
<style>
.stat-grid { display:grid; grid-template-columns: repeat(3, minmax(0,1fr)); gap: 12px; }
@media (max-width: 1024px) {.stat-grid { grid-template-columns: repeat(2, minmax(0,1fr)); }}
@media (max-width: 640px)  {.stat-grid { grid-template-columns: repeat(1, minmax(0,1fr)); }}
.stat-card {
  border: 1px solid rgba(0,0,0,0.08);
  border-radius: 14px; padding: 14px 16px;
  background: white; min-height: 84px; display:flex; flex-direction:column; justify-content:center;
}
.stat-title { font-size:11px; letter-spacing:.06em; color:#6b7280; text-transform:uppercase; margin-bottom:6px; }
.stat-value { font-size:22px; font-weight:600; color:#111827; }
</style>
""", unsafe_allow_html=True)

def render_stat_cards(items, hide_empty=True, hide_zero=False):
    def _ok(v):
        if v is None or v == "": return False
        if hide_zero and (isinstance(v, (int, float)) and float(v) == 0.0): return False
        return True

    clean = []
    for it in items:
        title = str(it.get("title", "")).strip()
        val   = it.get("value", None)
        if hide_empty and (not title or not _ok(val)): 
            continue
        fmt = it.get("fmt")
        s = fmt(val) if callable(fmt) else (f"{val:,}" if isinstance(val, (int,float)) else str(val))
        clean.append((title, s))

    if not clean:
        return

    st.markdown('<div class="stat-grid">', unsafe_allow_html=True)
    for title, sval in clean:
        st.markdown(
            f'<div class="stat-card"><div class="stat-title">{title}</div>'
            f'<div class="stat-value">{sval}</div></div>',
            unsafe_allow_html=True
        )
    st.markdown('</div>', unsafe_allow_html=True)


# --- Compact modes ---------------------------------------------------------
def _get_compact_level() -> int:
    # Lee ?compact=... de la URL (Streamlit >=1.31 expone st.query_params como mapping)
    try:
        val = st.query_params.get("compact", "0")
        return int(val) if str(val).isdigit() else 0
    except Exception:
        return 0

def _apply_compact_css(level: int = 1):
    if level <= 0:
        return
    # Base: compacto (compact=1)
    css_base = """
    <style>
      /* quita bordes/márgenes globales */
      .block-container{padding:0.2rem 0.6rem 0.5rem 0.6rem;}
      /* oculta cromo */
      header, footer, #MainMenu{visibility:hidden;}
      [data-testid="stDecoration"], [data-testid="stToolbar"]{display:none;}
      /* inputs y botones más chicos */
      .stButton>button{padding:0.35rem 0.8rem; line-height:1.1; min-height:2rem; font-size:0.95rem;}
      .stTextInput input, .stPassword input{padding:0.25rem 0.5rem; min-height:2.1rem; font-size:0.95rem;}
      /* menos separación entre bloques/columnas/forms */
      [data-testid="stVerticalBlock"], [data-testid="stForm"]{gap:0.45rem;}
      [data-testid="stHorizontalBlock"]{gap:0.5rem;}
      /* sidebar también compacto */
      [data-testid="stSidebar"] .block-container{padding-top:0.5rem;}
    </style>
    """
    st.markdown(css_base, unsafe_allow_html=True)

    # Ultra: aún más compacto (compact=2)
    if level >= 2:
        css_ultra = """
        <style>
          .block-container{padding:0.1rem 0.4rem 0.25rem 0.4rem;}
          .stButton>button{padding:0.20rem 0.60rem; min-height:1.8rem; font-size:0.88rem;}
          .stTextInput input, .stPassword input{padding:0.15rem 0.40rem; min-height:1.85rem; font-size:0.9rem;}
          [data-testid="stVerticalBlock"], [data-testid="stForm"]{gap:0.30rem;}
          [data-testid="stHorizontalBlock"]{gap:0.35rem;}
          /* tablas un poco más apretadas */
          [data-testid="stDataFrame"] {margin-top:0.25rem;}
        </style>
        """
        st.markdown(css_ultra, unsafe_allow_html=True)

# LEE EL NIVEL Y APLICA CSS (hazlo temprano en el script)
_compact_level = _get_compact_level()
_apply_compact_css(_compact_level)


import os
import bcrypt  # needed for bcrypt hashes

# --- Arranque seguro (soporta BYPASS_BOOT y ausencia de AUTH) -----------------
def _try_safe_boot():
    # Si quieres saltarte el boot en dev: export BYPASS_BOOT=1
    if os.getenv("BYPASS_BOOT", "0") == "1":
        return True, "BYPASS_BOOT=1 (arranque omitido)"

    # Si hay un objeto AUTH con safe_boot, úsalo
    try:
        if 'AUTH' in globals() and hasattr(AUTH, "safe_boot") and callable(AUTH.safe_boot):
            return AUTH.safe_boot()
    except Exception as e:
        # Si AUTH existe pero safe_boot falla, detén la app en producción
        st.error(f"❌ Falló AUTH.safe_boot: {e}")
        st.stop()

    # Si no hay AUTH, permite continuar (modo sin auth)
    return True, "AUTH no disponible (continuando sin autenticación)"

def _is_admin(user: dict) -> bool:
    try:
        if 'AUTH' in globals() and hasattr(AUTH, "is_admin"):
            return bool(AUTH.is_admin(user))
    except Exception:
        pass
    # fallback por rol en el objeto de sesión
    role = (user.get("role") or "").strip().lower() if isinstance(user, dict) else ""
    return role == "admin"


def safe_boot():
    # 1) Prueba de vida muy rápida
    try:
        AUTH.ping()  # SELECT 1
    except Exception as e:
        st.session_state["AUTH_OFFLINE"] = True
        st.warning("No pude conectar con la BD de usuarios (Neon). La app arrancará en modo offline.")
        st.exception(e)  # opcional para ver el porqué
        return

    # 2) Si hay conexión, corre migraciones/seed
    try:
        AUTH.init_users_table()
        AUTH.ensure_admin_seed()
    except Exception as e:
        st.session_state["AUTH_OFFLINE"] = True
        st.warning("Fallo inicializando la tabla de usuarios; inicio en modo offline.")
        st.exception(e)  # opcional

BYPASS_BOOT = str(st.secrets.get("BYPASS_BOOT", os.environ.get("BYPASS_BOOT", "0"))).strip() == "1"

if not BYPASS_BOOT:
    ok, msg = _try_safe_boot()
    if not ok:
        st.error(f"Inicio falló: {msg}")
        st.stop()
else:
    st.session_state["_offline_auth"] = True
    

# === Conexión universal a BD (Postgres en prod, SQLite en local) ===
import os
from contextlib import contextmanager
from pathlib import Path
from sqlalchemy import create_engine, text

DB_FILE = (Path(__file__).parent / "data" / "finanzas.sqlite")

import os, streamlit as st
from sqlalchemy import create_engine

def _get_database_url():
    url = (os.getenv("DATABASE_URL") or "").strip()
    if not url:
        try:  # raíz de secrets (si existiera)
            url = str(st.secrets.get("DATABASE_URL","")).strip()
        except Exception:
            url = ""
    if not url:
        try:  # como lo tienes en secrets
            url = str(st.secrets["connections"]["auth_db"].get("DATABASE_URL","")).strip()
        except Exception:
            url = url or ""
    if not url:
        try:  # variante 'url' de st.connection
            url = str(st.secrets["connections"]["auth_db"].get("url","")).strip()
        except Exception:
            url = url or ""
    if not url:
        st.error("No encuentro DATABASE_URL en secrets/entorno.")
        st.stop()
    return url

DB_URL = _get_database_url()
engine = create_engine(DB_URL, pool_pre_ping=True)

try:
    with engine.connect() as c:
        c.execute(text("SELECT 1"))
    DB_ONLINE = True
except Exception as e:
    DB_ONLINE = False
    st.error("❌ No pude conectar a Neon. Revisa host/ssl/credenciales.")
    st.exception(e)
    st.stop()

DIALECT = "postgres"

USER_COL = '"user"' if DIALECT == "postgres" else "user"

IS_CLOUD = os.getenv("STREAMLIT_RUNTIME", "") != ""
if IS_CLOUD and DIALECT != "postgres":
    st.error("🚨 Producción sin DATABASE_URL: datos se perderán al reiniciar. "
             "Configura DATABASE_URL (Neon) en Settings → Secrets.")
    st.stop()

@contextmanager
def get_conn():
    with engine.begin() as conn:
        yield conn

import streamlit as st
import streamlit.components.v1 as components

def _update_row(table: str, row_id: int, payload: dict):
    """UPDATE genérico para cualquier tabla, compatible con SQLite/Postgres."""
    # 1) construye el SET con parámetros nombrados
    sets = ", ".join([f"{k} = :{k}" for k in payload.keys()])
    # 2) where con dueño si no está activado 'ver todo'
    view_all = _view_all_enabled()
    where = "id = :id" + ("" if view_all else " AND owner = :owner")
    # 3) parámetros
    params = {**payload, "id": int(row_id)}
    if not view_all:
        params["owner"] = _current_owner()
    # 4) ejecuta
    with get_conn() as conn:
        conn.execute(text(f"UPDATE {table} SET {sets} WHERE {where}"), params)

if os.getenv("DEBUG_UI") == "1":
    st.write("🟢 Arrancando interfaz… (modo mínimo)")



# --- Forzar compact por URL sin JS ni DOM hacks ---
def _ensure_compact_query_params():
    try:
        qp = st.query_params
        changed = False
        if qp.get("compact") != "2":
            qp["compact"] = "2"; changed = True
        if qp.get("m") != "1":
            qp["m"] = "1"; changed = True
        if changed and not st.session_state.get("_qp_once"):
            st.session_state["_qp_once"] = True
            st.experimental_set_query_params(**qp)  # escribe URL
            st.stop()  # ← evita el doble rerun
        else:
            st.session_state["_qp_once"] = True
    except Exception:
        pass

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

import hashlib
from pathlib import Path

APP_BUILD = "TickeTo · 2025-08-13 nav-left-fix"

def _app_sig() -> str:
    try:
        return hashlib.sha1(Path(__file__).read_bytes()).hexdigest()[:10]
    except Exception:
        return "nohash"

st.markdown('<meta name="google" content="notranslate">', unsafe_allow_html=True)

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
import pandas as pd
import numpy as np
import re
import gspread
import os, json, hmac, base64, time
try:
    import extra_streamlit_components as stx
except Exception:
    stx = None  # desactiva cookies persistentes si no está instalado
    st.warning("extra-streamlit-components no está instalado; usando sesión básica.")
import math

READ_XLSX_KW = dict(dtype=str, keep_default_na=False)  # siempre texto


def _db_sig() -> tuple[int, int]:
    """Firma del archivo SQLite para invalidar la cache cuando cambie."""
    try:
        s = DB_FILE.stat()
        # Usamos mtime y tamaño para mayor entropía (Windows tiene gran. de 1s)
        return (int(s.st_mtime), int(s.st_size))
    except Exception:
        return (0, 0)
    
def _db_sig_runtime() -> tuple[int, int, int, int, int]:
    with get_conn() as c:
        a = c.execute(text("SELECT COALESCE(MAX(id),0) FROM transacciones")).scalar() or 0
        b = c.execute(text("SELECT COALESCE(MAX(id),0) FROM gastos")).scalar() or 0
        c1 = c.execute(text("SELECT COALESCE(MAX(id),0) FROM prestamos")).scalar() or 0
        d = c.execute(text("SELECT COALESCE(MAX(id),0) FROM inventario")).scalar() or 0
        e = c.execute(text("SELECT COALESCE(COUNT(*),0) FROM consolidado_diario")).scalar() or 0
    return (int(a), int(b), int(c1), int(d), int(e))


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
    st.warning("APP_SECRET no configurado; define APP_SECRET o ALLOW_DEFAULT_SECRET=1 en desarrollo.")

SESSION_COOKIE = "finz_sess"
LOGOUT_SENTINEL = "__force_logout"
COOKIE_SECURE_FLAG = str(cfg("COOKIE_SECURE", "1")).strip() == "1"
DEV_DEMO = str(cfg("DEV_DEMO_USERS", "1")).strip() == "1"

# CookieManager como widget (evita CachedWidgetWarning)
_cookie_widget = stx.CookieManager()
def _cookie_mgr():
    return _cookie_widget

# --- Password hashing (bcrypt -> fallback PBKDF2) ---
# --- Password hashing/verify universal (bcrypt + pbkdf2) ---

def hash_password(pw: str) -> str:
    try:
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
        "admin": {"pw": hash_password(os.getenv("DEMO_ADMIN_PW", "admin123*")), "role": "admin"},
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
    cm = _cookie_mgr(); cm.get_all()
    expires_dt = datetime.now() + timedelta(seconds=int(ttl))
    cm.set(SESSION_COOKIE, token, expires_at=expires_dt, key="set_"+SESSION_COOKIE,
        path="/", secure=COOKIE_SECURE_FLAG, same_site="Lax")
    st.session_state["auth_user"] = username
    st.session_state["auth_role"] = role
    st.session_state["user"] = {"username": username, "role": role}
    st.session_state.pop(LOGOUT_SENTINEL, None)

def _clear_session():
    cm = _cookie_mgr()
    try: cm.get_all()
    except Exception: pass

    try:
        if cm.get(SESSION_COOKIE) is not None:
            cm.delete(SESSION_COOKIE, key=f"del_{int(time.time())}")
    except Exception:
        pass

    try:
        cm.set(
            SESSION_COOKIE, "",
            expires_at=datetime.utcnow() - timedelta(days=1),
            key=f"exp_{int(time.time())}",
        )
    except Exception:
        pass

    # limpia el estado de la app
    st.session_state.pop("auth_user", None)
    st.session_state.pop("auth_role", None)
    st.session_state[LOGOUT_SENTINEL] = True   # 👈👈 NUEVO: fuerza logout en el próximo rerun

def logout_and_refresh():
    _clear_session()            # borra cookie + session_state
    # (opcional) mensaje para el próximo run
    flash_next_run("Sesión cerrada 👋", "👋")
    st.cache_data.clear()
    st.rerun()                  # ← fuerza el rerun inmediato

def current_user() -> tuple[str | None, str | None]:
    """Devuelve (usuario, rol). Si la cookie vieja no trae rol, aplica fallback por nombre."""
    if st.session_state.get(LOGOUT_SENTINEL):
        return None, None
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

def _col_exists(conn, table: str, col: str) -> bool:
    table = table.strip()
    col = col.strip()
    if DIALECT == "sqlite":
        # PRAGMA va por exec_driver_sql en SQLAlchemy 2.x
        rows = conn.exec_driver_sql(f"PRAGMA table_info({table})").fetchall()
        # En PRAGMA table_info, la columna 2 (índice 1) es el nombre de la columna
        return any(r[1] == col for r in rows)
    else:
        # Postgres: consulta en information_schema
        q = text("""
            SELECT 1
            FROM information_schema.columns
            WHERE table_name = :t
              AND column_name = :c
            LIMIT 1
        """)
        return conn.execute(q, {"t": table, "c": col}).first() is not None

def migrate_add_owner_columns():
    tables = ["transacciones","gastos","prestamos","inventario","deudores_ini","consolidado_diario"]
    with get_conn() as conn:
        for t in tables:
            if DIALECT == "postgres":
                # Postgres permite IF NOT EXISTS
                conn.execute(text(f'ALTER TABLE {t} ADD COLUMN IF NOT EXISTS owner TEXT'))
            else:
                # SQLite: sólo si no existe la columna
                if not _col_exists(conn, t, "owner"):
                    conn.execute(text(f'ALTER TABLE {t} ADD COLUMN owner TEXT'))
        # Backfill simple (evita NULL/''), tabla por tabla
        for t in tables:
            conn.execute(text(f"UPDATE {t} SET owner='admin' WHERE owner IS NULL OR owner=''"))

def migrate_add_deleted_at():
    tables = ["transacciones","gastos","prestamos","inventario","deudores_ini","consolidado_diario"]
    with get_conn() as conn:
        for t in tables:
            if DIALECT == "postgres":
                conn.execute(text(f'ALTER TABLE {t} ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP NULL'))
            else:
                # SQLite no soporta IF NOT EXISTS en ADD COLUMN
                rows = conn.exec_driver_sql(f"PRAGMA table_info({t})").fetchall()
                cols = {r[1] for r in rows}
                if "deleted_at" not in cols:
                    conn.execute(text(f'ALTER TABLE {t} ADD COLUMN deleted_at TEXT NULL'))

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
                text(f"INSERT INTO audit_log({USER_COL}, action, table_name, row_id, details) "
                    "VALUES (:u, :a, :t, :rid, :d)"),
                {
                    "u": u,
                    "a": action,
                    "t": table_name,
                    "rid": row_id,
                    "d": json.dumps(payload, ensure_ascii=False, default=str),
                },
            )
    except Exception as e:
        pass  # added to keep except block non-empty
        # No romper la app por fallos de auditoría
# REMOVED (debug print):         print("AUDIT ERROR:", e)

def init_db():
    schema = """
    CREATE TABLE IF NOT EXISTS transacciones (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fecha TEXT,
        cliente_nombre TEXT,
        costo DOUBLE PRECISION DEFAULT 0,
        venta DOUBLE PRECISION DEFAULT 0,
        ganancia DOUBLE PRECISION DEFAULT 0,
        debe_flag INTEGER DEFAULT 0,
        paga TEXT,
        abono1 DOUBLE PRECISION DEFAULT 0,
        abono2 DOUBLE PRECISION DEFAULT 0,
        observacion TEXT,
        owner TEXT
    );

    CREATE TABLE IF NOT EXISTS consolidado_diario (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fecha TEXT,
        efectivo DOUBLE PRECISION DEFAULT 0,
        notas TEXT,
        owner TEXT,
        UNIQUE(fecha, owner)
    );

    CREATE TABLE IF NOT EXISTS gastos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fecha TEXT,
        concepto TEXT,
        valor DOUBLE PRECISION DEFAULT 0,
        notas TEXT,
        owner TEXT
    );

    CREATE TABLE IF NOT EXISTS prestamos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT,
        valor DOUBLE PRECISION DEFAULT 0,
        owner TEXT
    );

    CREATE TABLE IF NOT EXISTS inventario (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        producto TEXT,
        valor_costo DOUBLE PRECISION DEFAULT 0,
        owner TEXT
    );

    CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT
    );

    CREATE TABLE IF NOT EXISTS deudores_ini (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT,
        valor DOUBLE PRECISION DEFAULT 0,
        owner TEXT
    );

    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT,
        user TEXT,
        action TEXT,
        table_name TEXT,
        row_id INTEGER,
        details TEXT
    );
    """
    if DIALECT == "postgres":
        schema = (
            schema
            .replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
            .replace("DOUBLE PRECISION", "DOUBLE PRECISION")
            .replace("\n        user TEXT,", '\n        "user" TEXT,')  # ← añade esta línea
        )

    with get_conn() as c:
        for stmt in [s.strip() for s in schema.split(";") if s.strip()]:
            c.execute(text(stmt))

def ensure_indexes():
    stmts = [
        "CREATE INDEX IF NOT EXISTS idx_trans_fecha   ON transacciones(fecha)",
        "CREATE INDEX IF NOT EXISTS idx_trans_cliente ON transacciones(cliente_nombre)",
        "CREATE INDEX IF NOT EXISTS idx_gastos_fecha  ON gastos(fecha)",
    ]

    # Índices por owner si la columna existe
    for t in ["transacciones","gastos","prestamos","inventario","deudores_ini","consolidado_diario"]:
        stmts.append(f"CREATE INDEX IF NOT EXISTS idx_{t}_owner ON {t}(owner)")

    # Único (fecha,owner) ya está en el CREATE, pero refuerza por si la tabla existía
    stmts.append("CREATE UNIQUE INDEX IF NOT EXISTS ux_consolidado_fecha_owner ON consolidado_diario(fecha, owner)")

    with get_conn() as c:
        for s in stmts:
            c.execute(text(s))

from sqlalchemy import text

def migrate_to_per_user_data():
    """
    Migra a datos por usuario si hiciera falta.
    Corre de forma idempotente (IF NOT EXISTS).
    """
    url = _get_database_url()  # usa el helper que añadimos
    from sqlalchemy import create_engine
    eng = create_engine(url, pool_pre_ping=True)
    with eng.begin() as conn:
        conn.execute(text("ALTER TABLE IF EXISTS transacciones      ADD COLUMN IF NOT EXISTS owner TEXT"))
        conn.execute(text("ALTER TABLE IF EXISTS gastos             ADD COLUMN IF NOT EXISTS owner TEXT"))
        conn.execute(text("ALTER TABLE IF EXISTS prestamos          ADD COLUMN IF NOT EXISTS owner TEXT"))
        conn.execute(text("ALTER TABLE IF EXISTS inventario         ADD COLUMN IF NOT EXISTS owner TEXT"))
        conn.execute(text("ALTER TABLE IF EXISTS consolidado_diario ADD COLUMN IF NOT EXISTS owner TEXT"))
        # índices opcionales (se crean solo si faltan)
        conn.execute(text("DO $$ BEGIN IF to_regclass('public.idx_trans_owner') IS NULL THEN CREATE INDEX idx_trans_owner ON transacciones(owner); END IF; END $$;"))
        conn.execute(text("DO $$ BEGIN IF to_regclass('public.idx_gastos_owner') IS NULL THEN CREATE INDEX idx_gastos_owner ON gastos(owner); END IF; END $$;"))
        conn.execute(text("DO $$ BEGIN IF to_regclass('public.idx_prest_owner')  IS NULL THEN CREATE INDEX idx_prest_owner  ON prestamos(owner); END IF; END $$;"))
        conn.execute(text("DO $$ BEGIN IF to_regclass('public.idx_inv_owner')    IS NULL THEN CREATE INDEX idx_inv_owner    ON inventario(owner); END IF; END $$;"))
    return True


@st.cache_resource
def _boot_db_once():
    init_db()
    migrate_add_owner_columns()
    ensure_indexes()
    migrate_to_per_user_data()
    migrate_add_deleted_at()   # 👈 nuevo
    return True

_BOOT = _boot_db_once()

def _table_cols(conn, table: str) -> set[str]:
    if DIALECT == "sqlite":
        rows = conn.exec_driver_sql(f"PRAGMA table_info({table})").fetchall()
        return {r[1] for r in rows}
    else:
        rows = conn.execute(text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name   = :t
        """), {"t": table}).fetchall()
        return {r[0] for r in rows}

def _add_col_if_missing(conn, table: str, col_def: str):
    col_name = col_def.split()[0]
    if DIALECT == "postgres":
        conn.execute(text(f'ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {col_def}'))
    else:
        if not has_column(conn, table, col_name):
            conn.execute(text(f'ALTER TABLE {table} ADD COLUMN {col_def}'))


def migrate_to_per_user_data():
    tables = ["transacciones","gastos","prestamos","inventario","deudores_ini","consolidado_diario"]
    try:
        with get_conn() as conn:
            # 1) Asegurar columna owner
            for t in tables:
                if DIALECT == "postgres":
                    conn.execute(text(f'ALTER TABLE {t} ADD COLUMN IF NOT EXISTS owner TEXT'))
                else:
                    if not has_column(conn, t, "owner"):
                        conn.execute(text(f'ALTER TABLE {t} ADD COLUMN owner TEXT'))

            # 2) Backfill por defecto
            for t in tables:
                conn.execute(text(f"""
                    UPDATE {t}
                       SET owner = COALESCE(NULLIF(owner,''), :def_owner)
                     WHERE owner IS NULL OR owner = ''
                """), {"def_owner": "admin"})

            # 3) Índices por owner (opcionales, útiles para filtros)
            for t in tables:
                conn.execute(text(f'CREATE INDEX IF NOT EXISTS idx_{t}_owner ON {t}(owner)'))

    except Exception as e:
        st.warning(f"⚠️ Migración per-user falló: {e}")
        
migrate_to_per_user_data()

import os, streamlit as st, urllib.parse as _u
_dbu = os.getenv("DATABASE_URL", "")
_host = ""
try:
    _host = _u.urlsplit(_dbu.replace("+psycopg2","")).hostname or ""
except Exception:
    pass


# ========== Login form ==========

def login_form() -> None:
    # Tarjeta bonita para el login
    st.markdown("""
    <style>
    .login-card{
      max-width:520px;margin:6vh auto;padding:20px 22px;
      border:1px solid rgba(120,120,135,.18);border-radius:14px;background:#fff;
      box-shadow:0 6px 18px rgba(0,0,0,.06);
    }
    @media (prefers-color-scheme: dark){
      .login-card{ background:#0b0f19;border-color:#1f2937; }
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
        src = "neon"
        auth = None
        try:
            # 1) Intento normal contra Neon
            auth = AUTH.authenticate(uname, password)
        except Exception as e:
            # 2) Si Neon falla, marca offline y avisa
            st.session_state["AUTH_OFFLINE"] = True
            st.info("No se pudo validar en Neon. Probando usuarios DEMO (si están habilitados).")
            st.exception(e)

        # 3) Fallback DEMO (solo si activas DEV_DEMO_USERS=1)
        if (not auth) and DEV_DEMO and uname in USERS and verify_password(password, USERS[uname]["pw"]):
            auth = {"username": uname, "role": USERS[uname]["role"]}
            src = "demo"

        if auth:
            st.session_state["sess_ttl"] = 7*24*3600 if remember else 12*3600
            _issue_session(auth["username"], auth["role"])
            audit("login.success", extra={"remember": bool(remember), "role": auth["role"], "src": src, "user_try": uname})
            st.success("Bienvenido 👋"); st.rerun()
        else:
            audit("login.failed", extra={"user_try": uname, "src": src})
            st.error("Usuario o contraseña inválidos (o autenticación offline sin DEMO).")    

    st.markdown('</div>', unsafe_allow_html=True)
    st.stop()


def require_user():
    # si ya hay sesión, retorna
    if "user" in st.session_state and st.session_state["user"]:
        u = st.session_state["user"]
        return u["username"], u["role"]

    # 👉 mostrar formulario de login en el cuerpo y cortar el render aquí
    login_form()   # tu login central ya dibuja y al final hace st.stop()
    st.stop()
    
    # si no hay sesión, muestra login en la sidebar mínima y bloquea el resto
    with st.sidebar:
        st.subheader("Iniciar sesión")
        u = st.text_input("Usuario", key="login_user")
        p = st.text_input("Contraseña", type="password", key="login_pass")
        go = st.button("Ingresar", type="primary", key="login_btn")

        if go:
            src = "neon"
            auth = None
            try:
                # 1) Intento Neon
                auth = AUTH.authenticate(u, p)
            except Exception as e:
                st.session_state["AUTH_OFFLINE"] = True
                st.info("Auth Neon caída; probando usuarios DEMO (si están habilitados).")
                st.exception(e)

            # 2) Fallback DEMO
            if (not auth) and DEV_DEMO and u in USERS and verify_password(p, USERS[u]["pw"]):
                auth = {"username": u, "role": USERS[u]["role"]}
                src = "demo"

            if auth:
                st.session_state["user"] = auth
                st.session_state.pop("nav_left", None)
                st.rerun()
            else:
                st.error("No fue posible validarte.")

    st.stop()  # evita que se renderice el resto sin login

def is_admin() -> bool:
    u = st.session_state.get("user") or {}
    return str(u.get("role", "")).strip().lower() == "admin"

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
            row = conn.execute(text("SELECT value FROM meta WHERE key=:key"), {"key": key}).fetchone()
            old_value = row[0] if row else None
    except Exception:
        pass

    with get_conn() as conn:
        conn.execute(
            text("""
                INSERT INTO meta(key,value) VALUES(:key,:value)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
            """),
            {"key": key, "value": str(value)}
        )

    audit("meta.set", table_name="meta",
        before={"key": key, "value": old_value},
        after={"key": key, "value": value})

def get_meta(key: str, default=None):
    with get_conn() as conn:
        row = conn.execute(
            text("SELECT value FROM meta WHERE key = :key"),
            {"key": key}
        ).fetchone()
        return row[0] if row and row[0] is not None else default

def set_corte_deudores(d: date):
    set_meta("CORTE_DEUDORES", d.isoformat())

# Ajuste visual eliminado: no se usa más
ADJ_VENTAS_EFECTIVO = 0.0

# =========================================================
# Lectores cacheados (invalidados por mtime/size del .sqlite)
# =========================================================
@st.cache_data
def read_consolidado_diario():
    """Lee la tabla consolidado_diario para que finish_and_refresh pueda invalidarla selectivamente."""
    with get_conn() as conn:
        return pd.read_sql_query(text("SELECT * FROM consolidado_diario ORDER BY id DESC"), conn)

@st.cache_data(show_spinner=False)
def _read_ventas(_sig: tuple[int, int], owner: str, view_all: bool) -> pd.DataFrame:
    base = "SELECT * FROM transacciones WHERE (deleted_at IS NULL)"
    sql = text(base + ("" if view_all else " AND owner = :owner"))
    params = None if view_all else {"owner": owner}
    with get_conn() as conn:
        df = pd.read_sql_query(sql, conn, params=params)
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
    return _read_ventas(_db_sig_runtime(), _current_owner(), _view_all_enabled())


@st.cache_data(show_spinner=False)
def _read_gastos(_sig: tuple[int, int], owner: str, view_all: bool) -> pd.DataFrame:
    base = "SELECT * FROM gastos WHERE (deleted_at IS NULL)"
    stmt = text(base + ("" if view_all else " AND owner = :owner"))
    params = None if view_all else {"owner": owner}
    with get_conn() as conn:
        df = pd.read_sql_query(stmt, conn, params=params)
    if df.empty:
        return pd.DataFrame(columns=['id','fecha','concepto','valor','notas','owner'])
    df['fecha'] = pd.to_datetime(df['fecha'], errors='coerce', dayfirst=True).dt.date
    df['valor'] = pd.to_numeric(df['valor'], errors='coerce').fillna(0.0)
    return df

def read_gastos() -> pd.DataFrame:
    return _read_gastos(_db_sig_runtime(), _current_owner(), _view_all_enabled())


@st.cache_data(show_spinner=False)
def _read_prestamos(_sig: tuple[int, int], owner: str, view_all: bool) -> pd.DataFrame:
    base = "SELECT * FROM prestamos WHERE (deleted_at IS NULL)"
    stmt = text(base + ("" if view_all else " AND owner = :owner"))
    params = None if view_all else {"owner": owner}
    with get_conn() as conn:
        df = pd.read_sql_query(stmt, conn, params=params)
    if df.empty:
        return pd.DataFrame(columns=['id','nombre','valor','owner'])
    df['valor'] = pd.to_numeric(df['valor'], errors='coerce').fillna(0.0)
    return df

def read_prestamos() -> pd.DataFrame:
    return _read_prestamos(_db_sig_runtime(), _current_owner(), _view_all_enabled())


@st.cache_data(show_spinner=False)
def _read_inventario(_sig: tuple[int, int], owner: str, view_all: bool) -> pd.DataFrame:
    base = "SELECT * FROM inventario WHERE (deleted_at IS NULL)"
    stmt = text(base + ("" if view_all else " AND owner = :owner"))
    params = None if view_all else {"owner": owner}
    with get_conn() as conn:
        df = pd.read_sql_query(stmt, conn, params=params)
    if df.empty:
        return pd.DataFrame(columns=['id','producto','valor_costo','owner'])
    df['valor_costo'] = pd.to_numeric(df['valor_costo'], errors='coerce').fillna(0.0)
    return df

def read_inventario() -> pd.DataFrame:
    return _read_inventario(_db_sig_runtime(), _current_owner(), _view_all_enabled())


@st.cache_data(show_spinner=False)
def _read_consolidado(_sig: tuple[int, int], owner: str, view_all: bool) -> pd.DataFrame:
    base = "SELECT * FROM consolidado_diario WHERE (deleted_at IS NULL)"
    stmt = text(base + ("" if view_all else " AND owner = :owner"))
    params = None if view_all else {"owner": owner}
    with get_conn() as conn:
        df = pd.read_sql_query(stmt, conn, params=params)
    if df.empty:
        return pd.DataFrame(columns=['fecha','efectivo','notas','owner'])
    df['fecha_raw'] = df['fecha'].astype(str)
    df['fecha'] = pd.to_datetime(df['fecha'], errors='coerce', dayfirst=True).dt.date
    df['efectivo'] = pd.to_numeric(df['efectivo'], errors='coerce').fillna(0.0)
    return df

def read_consolidado() -> pd.DataFrame:
    return _read_consolidado(_db_sig_runtime(), _current_owner(), _view_all_enabled())


@st.cache_data(show_spinner=False)
def _read_deudores_ini(_sig: tuple[int, int], owner: str, view_all: bool) -> pd.DataFrame:
    base = "SELECT * FROM deudores_ini WHERE (deleted_at IS NULL)"
    stmt = text(base + ("" if view_all else " AND owner = :owner"))
    params = None if view_all else {"owner": owner}
    with get_conn() as conn:
        df = pd.read_sql_query(stmt, conn, params=params)
    if df.empty:
        return pd.DataFrame(columns=['id','nombre','valor','owner'])
    df['nombre'] = df['nombre'].astype(str).str.strip()
    df['valor']  = pd.to_numeric(df['valor'], errors='coerce').fillna(0.0)
    return df[['id','nombre','valor','owner']]

def read_deudores_ini() -> pd.DataFrame:
    return _read_deudores_ini(_db_sig_runtime(), _current_owner(), _view_all_enabled())

CACHE_READERS = {
    "transacciones": read_ventas,
    "gastos": read_gastos,
    "prestamos": read_prestamos,
    "inventario": read_inventario,
    # agrega los que ya usas en finish_and_refresh:
    "deudores_ini": read_deudores_ini,
    "consolidado_diario": read_consolidado_diario,  # usa aquí el nombre real de tu lector
}

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

def _df_to_csv_bytes(df):
    buf = BytesIO()
    # utf-8-sig para que Excel abra con acentos bien
    buf.write(df.to_csv(index=False, encoding="utf-8-sig").encode("utf-8-sig"))
    buf.seek(0)
    return buf

def _sync_users_to_google_sheets(df, sheet_id: str):
    """
    Envía el DF de usuarios a una hoja llamada 'users'.
    Requiere credenciales de Service Account en secrets:
      st.secrets['gcp_service_account']  (dict del JSON)
    """
    # 1) Credenciales
    sa_dict = st.secrets.get("gcp_service_account") or st.secrets.get("google_service_account")
    if not sa_dict:
        st.error("Faltan credenciales en secrets: `gcp_service_account` (JSON de Service Account).")
        return False

    gc = gspread.service_account_from_dict(sa_dict)
    # 2) Abre por ID
    sh = gc.open_by_key(sheet_id)
    # 3) Worksheet 'users' (crea si no existe)
    try:
        ws = sh.worksheet("users")
    except Exception:
        ws = sh.add_worksheet(title="users", rows=100, cols=10)
    # 4) Sobrescribe contenido
    values = [list(df.columns)] + df.astype(str).values.tolist()
    ws.clear()
    ws.update("A1", values)
    return True

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
    # Numéricos ya vienen OK
    try:
        import numpy as np
    except Exception:
        class np:  # fallback minúsculo
            floating = float
            integer = int
            def isnan(x): return False

    if v is None:
        return 0.0
    if isinstance(v, (int, float, np.integer, np.floating)):
        try:
            x = float(v)
            return 0.0 if (hasattr(np, "isnan") and np.isnan(x)) else x
        except Exception:
            return 0.0

    # Cadenas: usa el parser que entiende puntos de miles y coma decimal
    s = str(v).strip()
    if not s:
        return 0.0
    try:
        # 👇 tu parser robusto declarado arriba en el archivo
        return _parse_pesos(s)
    except Exception:
        # último intento: normaliza coma decimal
        try:
            return float(s.replace(",", "."))
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

# ===== Helpers DELETE unificado =====
from sqlalchemy import text  # asegúrate de tener este import

def _delete_where_params(row_id: int):
    view_all = _view_all_enabled()
    if view_all:
        where  = "id = :id"
        params = {"id": int(row_id)}
    else:
        # permite borrar si soy el dueño O si la fila no tiene owner (NULL/'')
        where  = "id = :id AND (owner = :owner OR owner IS NULL OR owner = '')"
        params = {"id": int(row_id), "owner": (_current_owner() or "")}
    return where, params

def soft_delete_row(table: str, row_id: int):
    where, params = _delete_where_params(row_id)
    before = None
    with get_conn() as conn:
        cur = conn.execute(text(f"SELECT * FROM {table} WHERE {where}"), params)
        # ------- FIX AQUÍ: no uses cur.description -------
        m = cur.mappings().first()   # regresa un dict-like o None
        before = dict(m) if m else None
        # --------------------------------------------------
        if DIALECT == "postgres":
            conn.execute(text(f"UPDATE {table} SET deleted_at = NOW() WHERE {where}"), params)
        else:
            conn.execute(text(f"UPDATE {table} SET deleted_at = datetime('now') WHERE {where}"), params)
    audit("delete.soft", table_name=table, row_id=int(row_id), before=before)

def restore_row(table: str, row_id: int):
    """Quita la marca de eliminado."""
    where, params = _delete_where_params(row_id)
    with get_conn() as conn:
        conn.execute(text(f"UPDATE {table} SET deleted_at = NULL WHERE {where}"), params)
    try:
        audit("delete.restore", table_name=table, row_id=int(row_id))
    except Exception:
        pass

def hard_delete_row(table: str, row_id: int):
    where, params = _delete_where_params(row_id)
    before = None
    with get_conn() as conn:
        cur = conn.execute(text(f"SELECT * FROM {table} WHERE {where}"), params)
        # ------- FIX AQUÍ -------
        m = cur.mappings().first()
        before = dict(m) if m else None
        # ------------------------
        conn.execute(text(f"DELETE FROM {table} WHERE {where}"), params)
    audit("delete.hard", table_name=table, row_id=int(row_id), before=before)

def _delete_row(table: str, row_id: int):
    where, params = _delete_where_params(row_id)
    before = None
    with get_conn() as conn:
        cur = conn.execute(text(f"SELECT * FROM {table} WHERE {where}"), params)
        r = cur.fetchone()
        if r is not None and cur.description:
            cols = [d[0] for d in cur.description]
            before = dict(zip(cols, r))
        conn.execute(text(f"DELETE FROM {table} WHERE {where}"), params)
    try:
        audit("delete", table_name=table, row_id=int(row_id), before=before)
    except Exception:
        pass


def delete_consolidado(fecha_str: str):
    """Borrado lógico del consolidado por fecha/clave y owner actual."""
    owner = (_current_owner() or "")
    params = {"f": fecha_str, "o": owner}

    before = []
    with get_conn() as conn:
        # Obtener filas antes de borrar (para auditoría)
        cur = conn.execute(text(
            "SELECT * FROM consolidado_diario WHERE fecha=:f AND owner=:o"
        ), params)
        before = [dict(m) for m in cur.mappings().all()]

        # Borrado lógico
        if DIALECT == "postgres":
            conn.execute(text(
                "UPDATE consolidado_diario SET deleted_at = NOW() WHERE fecha=:f AND owner=:o"
            ), params)
        else:
            conn.execute(text(
                "UPDATE consolidado_diario SET deleted_at = datetime('now') WHERE fecha=:f AND owner=:o"
            ), params)

    # Auditoría (si tenías audit ya llamada adentro, puedes dejar solo esta)
    try:
        for b in before:
            audit("delete.soft", table_name="consolidado_diario", row_id=b.get("id"), before=b)
    except Exception:
        pass

def upsert_consolidado(fecha_str: str, efectivo, notas: str = ""):
    owner = _current_owner()
    # normaliza el efectivo por si viene "3.000.000" o "3,000,000"
    ef = _to_float(efectivo)
    no = str(notas or "").strip()

    with get_conn() as conn:
        # 1) ¿ya existe la fila?
        row = conn.execute(
            text("SELECT id FROM consolidado_diario WHERE fecha = :f AND owner = :o"),
            {"f": fecha_str, "o": owner}
        ).fetchone()

        if row:
            # 2) UPDATE
            conn.execute(
                text("UPDATE consolidado_diario SET efectivo = :e, notas = :n WHERE fecha = :f AND owner = :o"),
                {"e": ef, "n": no, "f": fecha_str, "o": owner}
            )
            rid = row[0]
            audit("update", table_name="consolidado_diario", row_id=rid,
                  after={"fecha": fecha_str, "efectivo": ef, "notas": no, "owner": owner})
        else:
            # 3) INSERT con upsert idempotente si tu dialecto lo soporta
            conn.execute(
                text("""
                    INSERT INTO consolidado_diario (fecha, efectivo, notas, owner)
                    VALUES (:f, :e, :n, :o)
                    ON CONFLICT (fecha, owner) DO UPDATE SET
                        efectivo = EXCLUDED.efectivo,
                        notas = EXCLUDED.notas
                """),
                {"f": fecha_str, "e": ef, "n": no, "o": owner}
            )
            audit("insert", table_name="consolidado_diario", row_id=None,
                  after={"fecha": fecha_str, "efectivo": ef, "notas": no, "owner": owner})

def get_efectivo_global_now() -> tuple[float, str]:
    owner = _current_owner()
    with get_conn() as conn:
        row = conn.execute(
            text("SELECT efectivo, notas FROM consolidado_diario "
                "WHERE UPPER(TRIM(fecha))='GLOBAL' AND owner=:o"),
            {"o": owner}
        ).fetchone()
    if row:
        return float(row[0] or 0.0), str(row[1] or "")
    return 0.0, ""

def insert_venta(r: dict, owner_override: str | None = None) -> int:
    data = {**data, "owner": (_current_owner() or "")}
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
    sql = text("""
        INSERT INTO transacciones
        (fecha, cliente_nombre, costo, venta, ganancia, debe_flag, paga, abono1, abono2, observacion, owner)
        VALUES (:fecha, :cliente_nombre, :costo, :venta, :ganancia, :debe_flag, :paga, :abono1, :abono2, :observacion, :owner)
    """)
    with get_conn() as conn:
        cur = conn.execute(sql, payload)
        row_id = cur.lastrowid
    audit("insert", table_name="transacciones", row_id=row_id, after=payload)
    return row_id

def insert_gasto(r: dict, owner_override: str | None = None) -> int:
    data = {**data, "owner": (_current_owner() or "")}
    payload = {
        'fecha': _to_date_str(r.get('fecha')),
        'concepto': str(r.get('concepto') or '').strip(),
        'valor': _to_float(r.get('valor')),
        'notas': str(r.get('notas') or '').strip(),
        'owner': (owner_override.strip() if owner_override else _row_owner()),
    }
    sql = text("INSERT INTO gastos (fecha, concepto, valor, notas, owner) "
               "VALUES (:fecha, :concepto, :valor, :notas, :owner)")
    with get_conn() as conn:
        cur = conn.execute(sql, payload)
        row_id = cur.lastrowid
    audit("insert", table_name="gastos", row_id=row_id, after=payload)
    return row_id

def insert_prestamo(r: dict, owner_override: str | None = None) -> int:
    data = {**data, "owner": (_current_owner() or "")}
    payload = {
        'nombre': str(r.get('nombre') or '').strip(),
        'valor': _to_float(r.get('valor')),
        'owner': (owner_override.strip() if owner_override else _row_owner()),
    }
    sql = text("INSERT INTO prestamos (nombre, valor, owner) "
               "VALUES (:nombre, :valor, :owner)")
    with get_conn() as conn:
        cur = conn.execute(sql, payload)
        row_id = cur.lastrowid
    audit("insert", table_name="prestamos", row_id=row_id, after=payload)
    return row_id

def insert_inventario(r: dict, owner_override: str | None = None) -> int:
    data = {**data, "owner": (_current_owner() or "")}
    payload = {
        "producto": str(r.get("producto") or "").strip(),
        "valor_costo": _to_float(r.get("valor_costo")),
        "owner": (owner_override.strip() if owner_override else _row_owner()),
    }

    sql = text("""
        INSERT INTO inventario (producto, valor_costo, owner)
        VALUES (:producto, :valor_costo, :owner)
    """)

    with get_conn() as conn:
        cur = conn.execute(sql, payload)
        row_id = cur.lastrowid
    audit("insert", table_name="inventario", row_id=row_id, after=payload)
    return row_id

def insert_deudor_ini(r: dict, owner_override: str | None = None) -> int:
    data = {**data, "owner": (_current_owner() or "")}
    payload = {
        'nombre': str(r.get('nombre') or '').strip(),
        'valor': _to_float(r.get('valor')),
        'owner': (owner_override.strip() if owner_override else _row_owner()),
    }
    sql = text("INSERT INTO deudores_ini (nombre, valor, owner) "
               "VALUES (:nombre, :valor, :owner)")
    with get_conn() as conn:
        cur = conn.execute(sql, payload)
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
    view_all = _view_all_enabled()
    where = "id = :id" + ("" if view_all else " AND owner = :owner")
    params = {"id": int(row_id)}
    if not view_all: params["owner"] = _current_owner()

    with get_conn() as conn:
        cur = conn.execute(text(f"SELECT * FROM transacciones WHERE {where}"), params)
        m = cur.mappings().first()
        before = dict(m) if m else None
        conn.execute(text(f"DELETE FROM transacciones WHERE {where}"), params)

    try: audit("delete", table_name="transacciones", row_id=int(row_id), before=before)
    except Exception: pass


def delete_gasto_id(row_id: int):
    soft_delete_row("gastos", int(row_id))


def delete_prestamo_id(row_id: int):
    soft_delete_row("prestamos", int(row_id))


def delete_inventario_id(row_id: int):
    soft_delete_row("inventario", int(row_id))

def update_venta_fields(row_id: int, payload: dict):
    # Normaliza numéricos si llegan como "3.000,00"
    if "venta" in payload:    payload["venta"]    = _to_float(payload["venta"])
    if "costo" in payload:    payload["costo"]    = _to_float(payload["costo"])
    if "ganancia" in payload: payload["ganancia"] = _to_float(payload["ganancia"])
    if "abono1" in payload:   payload["abono1"]   = _to_float(payload["abono1"])
    if "abono2" in payload:   payload["abono2"]   = _to_float(payload["abono2"])
    if "debe_flag" in payload: payload["debe_flag"] = _to_int(payload["debe_flag"])

    _update_row("transacciones", row_id, payload)
    audit("update", table_name="transacciones", row_id=row_id, after=payload)


def update_gasto_fields(row_id: int, payload: dict):
    if "valor" in payload:
        payload["valor"] = _to_float(payload["valor"])

    _update_row("gastos", row_id, payload)
    audit("update", table_name="gastos", row_id=row_id, after=payload)


def update_prestamo_fields(row_id: int, payload: dict):
    if "valor" in payload:
        payload["valor"] = _to_float(payload["valor"])

    _update_row("prestamos", row_id, payload)
    audit("update", table_name="prestamos", row_id=row_id, after=payload)



def update_inventario_fields(row_id: int, payload: dict):
    if "valor_costo" in payload:
        payload["valor_costo"] = _to_float(payload["valor_costo"])

    _update_row("inventario", row_id, payload)
    audit("update", table_name="inventario", row_id=row_id, after=payload)


# =========================================================
# Helpers UI
# =========================================================

# --- Compat: popover o expander según versión ---
def open_action_panel(label: str, key: str | None = None):
    """
    Devuelve un contenedor tipo popover si existe; si no, cae a expander.
    Evita kwargs no soportados (p.ej. use_container_width).
    """
    try:
        if hasattr(st, "popover"):
            # algunas versiones no aceptan use_container_width
            return st.popover(label, key=key)
    except TypeError:
        # firma distinta: vuelve a intentar sin key
        try:
            return st.popover(label)
        except Exception:
            pass
    # Fallback universal
    return st.expander(label)

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
    Campo moneda: miles '.' y decimales ',' (0–2).
    En formularios (`in_form=True`) NO escribe en session_state (solo lee).
    """
    state_key = f"{key}_txt"

    # --- helpers ---
    import re, json
    def _group_dots(d: str) -> str:
        d = re.sub(r"\D", "", d or "")
        d = d.lstrip("0") or "0"
        out = []
        while d:
            out.insert(0, d[-3:]); d = d[:-3]
        return ".".join(out)

    def _fmt_from_number(n: float) -> str:
        n = float(n or 0)
        neg = n < 0; n = abs(n)
        ent = int(n); dec = int(round((n - ent) * 100))
        txt = _group_dots(str(ent))
        if dec: txt += "," + f"{dec:02d}"
        if neg and txt != "0": txt = "-" + txt
        return txt

    def _normalize_text(s: str) -> str:
        s = str(s or "").strip().replace(" ", "")
        neg = s.startswith("-") or s.startswith("−") or (s.startswith("(") and s.endswith(")"))
        s = s.strip("()").lstrip("-−").replace(".", "")
        if s.count(",") > 1:
            i = s.find(","); s = s[:i+1] + s[i+1:].replace(",", "")
        if "," in s:
            ent, dec = s.split(",", 1)
            ent = re.sub(r"\D", "", ent)
            dec = re.sub(r"\D", "", dec)[:2]
            txt = (_group_dots(ent) if ent else "0") + ("," + dec if dec else "")
        else:
            ent = re.sub(r"\D", "", s)
            txt = _group_dots(ent) if ent else "0"
        if neg and txt != "0": txt = "-" + txt
        return txt

    # ---- RENDER ----
    if in_form:
        # ❗ En formularios: no tocar session_state.
        seed = st.session_state.get(state_key, _fmt_from_number(value))
        txt = st.text_input(label, value=seed, key=state_key, help=help)
    else:
        # Fuera de forms sí podemos normalizar y escribir en session_state
        if state_key not in st.session_state:
            st.session_state[state_key] = _fmt_from_number(value)
        else:
            norm0 = _normalize_text(st.session_state.get(state_key, ""))
            if norm0 != st.session_state[state_key]:
                st.session_state[state_key] = norm0

        def _cb_norm():
            st.session_state[state_key] = _normalize_text(st.session_state.get(state_key, ""))

        st.text_input(label, key=state_key, help=help, on_change=_cb_norm)

    # JS de formateo en vivo (no escribe directamente en session_state)
    if live:
        components.html(f"""
        <script>(function(){{
        try{{
            const doc=(window.parent||window).document;
            const LABEL={json.dumps(label)}; const STATE={json.dumps(state_key)};
            function groupDots(d){{ d=(d||'').replace(/\\D/g,'').replace(/^0+(?=\\d)/,'')||'0';
            let out='',c=0; for(let i=d.length-1;i>=0;--i){{ out=d[i]+out; if(++c%3===0&&i>0) out='.'+out; }} return out;}}
            function normalize(s){{
            s=(s||'').replace(/\\s+/g,'');
            const neg=/^[-−(]/.test(s); s=s.replace(/[()−-]/g,'').replace(/\\./g,'');
            const i=s.indexOf(','); if(i!==-1) s=s.slice(0,i+1)+s.slice(i+1).replace(/,/g,'');
            let ent=s,dec=''; if(i!==-1){{ ent=s.slice(0,i); dec=s.slice(i+1).replace(/\\D/g,'').slice(0,2); }}
            ent=ent.replace(/\\D/g,''); let out=(ent?groupDots(ent):'0')+(dec?(','+dec):''); if(neg&&out!=='0') out='-'+out; return out;
            }}
            function install(el){{
            if(!el||el.dataset.ttMoneyInstalled===STATE) return;
            el.dataset.ttMoneyInstalled=STATE; el.setAttribute('inputmode','decimal'); el.autocomplete='off';
            const fmt=()=>{{ const v=normalize(el.value); if(v!==el.value) el.value=v; }};
            el.addEventListener('input', ()=>setTimeout(fmt,0));
            el.addEventListener('keydown',(e)=>{{ if(e.key==='Enter'){{ const v=normalize(el.value);
                if(v!==el.value){{ el.value=v; el.dispatchEvent(new Event('input',{{bubbles:true}})); }} }} }});
            setTimeout(fmt,0);
            }}
            let tries=0,t=setInterval(()=>{{
            const nodes=[...doc.querySelectorAll('input[aria-label="'+LABEL+'"]')].filter(n=>n&&n.dataset.ttMoneyInstalled!==STATE);
            if(nodes.length){{ nodes.forEach(install); clearInterval(t); }} else if(++tries>40) clearInterval(t);
            }},80);
        }}catch(e){{}}
        }})()</script>""", height=0, width=0)

    # ---- Resultado numérico robusto ----
    def _parse_pesos(cell) -> float:
        import numpy as np
        if cell is None: return 0.0
        s = str(cell).strip()
        if not s: return 0.0
        neg = s.startswith("-") or s.startswith("−") or (s.startswith("(") and s.endswith(")"))
        s = s.strip("()").lstrip("-−").replace(".", "")
        if "," in s:
            ent, dec = s.split(",", 1)
            ent = re.sub(r"\\D", "", ent); dec = re.sub(r"\\D", "", dec)[:2]
            val = float(f"{ent or '0'}.{dec or '0'}")
        else:
            ent = re.sub(r"\\D", "", s)
            val = float(ent or 0)
        return -val if neg else val

    txt_now = st.session_state.get(state_key, _fmt_from_number(value))
    return float(_parse_pesos(txt_now))

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

def aplicar_filtros_guardados(df: pd.DataFrame, cols: list[str], key: str) -> pd.DataFrame:
    """Aplica los filtros guardados en session_state sin renderizar widgets."""
    texto = st.session_state.get(f"q_{key}", "")
    fecha_rango = st.session_state.get(f"rng_{key}", None)

    out = df.copy()

    if texto:
        patt = str(texto).strip().upper()
        mask = False
        for c in cols:
            mask = mask | out[c].astype(str).str.upper().str.contains(patt, na=False)
        out = out[mask]

    if isinstance(fecha_rango, tuple) and len(fecha_rango) == 2 and "fecha" in out:
        f0, f1 = fecha_rango
        out = out[(out["fecha"] >= f0) & (out["fecha"] <= f1)]

    return out


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
                    warn_if_missing: bool = True,
                    username: str | None = None):
    user_html = f'<div class="r"><span class="tt-user">👤 {username}</span></div>' if username else '<div class="r"></div>'
    st.markdown(
        f'''
        <div class="tt-titlebar" role="banner">
        <div class="l"></div>
        <div class="ttl">{_clean_title(title_text)}</div>
        {user_html}
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

def _secret(name, default=""):
    try:
        return st.secrets.get(name, default)  # si el archivo está mal, lo atrapamos abajo
    except Exception:
        return default

def _auth_db_available() -> bool:
    try:
        st.connection("auth_db", type="sql")  # solo prueba que existe la config
        return True
    except Exception:
        return False

# =========================
# Google Sheets Sync
# =========================
GOOGLE_SHEETS_ENABLED = bool(int(get_meta("GSHEETS_ENABLED", 0)))  # 1=on, 0=off

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
    import gspread
    from google.oauth2.service_account import Credentials
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
    # Cuenta SOLO datos de negocio en SQLite (usuarios viven en Neon)
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
                raw_fecha = str(r.get("fecha") or r.get("FECHA") or "").strip()
                if not raw_fecha:
                    continue  # salta filas sin fecha
                fecha_str = raw_fecha.upper() if raw_fecha.strip().upper() == "GLOBAL" else raw_fecha
                upsert_consolidado(
                    fecha_str,
                    _to_float(r.get("efectivo") or r.get("EFECTIVO")),
                    str(r.get("notas") or r.get("NOTAS") or "")
                )

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
def finish_and_refresh(
    msg: str | None = "Listo ✅",
    tables_to_sync: list[str] | None = None,
    *,
    rerun: bool = True
):
    """
    Invalida SOLO las caches de las tablas indicadas y opcionalmente sincroniza a GSheet.
    Luego muestra un flash y (opcional) hace rerun.
    """
    try:
        # 1) invalidación selectiva de caché
        if tables_to_sync:
            for name in tables_to_sync:
                f = CACHE_READERS.get(name)
                if f:
                    try:
                        f.clear()
                    except Exception:
                        pass

            # 2) sincronización solo de esas tablas (si aplica en tu app)
            try:
                sync_tables_to_gsheet(tables_to_sync)
            except Exception:
                pass

        # 3) mensaje para el próximo run
        if msg:
            flash_next_run(msg)

        # 4) backup/auditoría de usuario (igual que antes)
        u = st.session_state.get("auth_user")
        if u:
            try:
                backup_user_flush_audit(u)
            except Exception:
                pass

    finally:
        # ❌ NO limpies toda la cache global aquí
        # ✅ Sólo rerun si lo pides
        if rerun:
            st.rerun()

restore_from_gsheets_if_empty()
# =========================
# Backups automáticos (SQLite)
# =========================
BACKUP_DIR = Path(__file__).parent / "backups"
BACKUP_EVERY_HOURS = 8
KEEP_BACKUPS = 40

def make_db_backup() -> Path | None:
    # En Postgres (Neon) no hay archivo local que respaldar
    if DIALECT != "sqlite":
        return None

    DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    # tu lógica de copia/zip si la tenías...
    return DB_FILE if DB_FILE.exists() else None

def has_column(conn, table: str, col: str) -> bool:
    """Devuelve True si la columna existe (SQLite o Postgres)."""
    table = table.strip()
    col = col.strip()
    if DIALECT == "sqlite":
        # PRAGMA es solo SQLite y debe ir por exec_driver_sql en SA 2.x
        rows = conn.exec_driver_sql(f"PRAGMA table_info({table})").fetchall()
        # índice 1 = nombre de columna
        return any(r[1] == col for r in rows)
    else:
        # Postgres
        q = text("""
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name   = :t
              AND column_name  = :c
            LIMIT 1
        """)
        return conn.execute(q, {"t": table, "c": col}).first() is not None

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
    # Seguridad: la tabla de usuarios jamás se toca aquí.
    assert "users" not in tables, "Seguridad: no se puede truncar la tabla 'users'."
    with get_conn() as conn:
        if DIALECT == "postgres":
            # Neon/Postgres: rápido y reinicia autoincrementos
            conn.execute(text(f"TRUNCATE TABLE {', '.join(tables)} RESTART IDENTITY CASCADE"))
        else:
            # SQLite fallback
            for t in tables:
                conn.execute(text(f"DELETE FROM {t}"))

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

    # with get_conn() as conn:
    #     df_a = pd.read_sql_query(
    #         "SELECT id, ts, action, table_name AS tabla, row_id FROM audit_log WHERE user=? ORDER BY id DESC LIMIT 200",
    #         conn, params=(username,)
    #     )
    #_ws_write(_ws(sh, "Estado", rows=200, cols=10), df_a)

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
    
    "🧮 Diario Consolidado", "🧾 Ventas",
    "💸 Gastos", "🤝 Préstamos", "📦 Inventario", "👤 Deudores", "⬆️ Importar/Exportar", "⚙️ Mi Cuenta"
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
show_sticky_header(current, logo_path=_show_logo_path, show_brand_text=False, username=user)

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

st.markdown("""
<style>
.tt-titlebar .tt-user{
display:inline-block; padding:6px 10px; border-radius:999px;
border:1px solid rgba(120,120,135,.18);
background:rgba(255,255,255,.85);
backdrop-filter:saturate(160%) blur(6px);
-webkit-backdrop-filter:saturate(160%) blur(6px);
font-weight:600; color:#374151; white-space:nowrap;
}
@media (prefers-color-scheme: dark){
.tt-titlebar .tt-user{
    background:rgba(11,15,25,.82); border-color:#1f2937; color:#e5e7eb;
}
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

    _, total_deu = deudores_sin_corte()
    total_ventas  = float(total_cuenta + total_efectivo)
    total_ganancia= float(v_df['ganancia'].sum()) if not v_df.empty else 0.0

    # ---- necesarios para este bloque ----
    # Deudores “totales” (se muestran aunque sea 0)
    _, total_deu = deudores_sin_corte()

    # Efectivo global actual y métrica superior
    efectivo_ini, _ = get_efectivo_global_now()
    metric_box = st.empty()
    metric_box.metric("EFECTIVO", money(efectivo_ini))
    # -------------------------------------

    # === Tarjetas alineadas (no ocultar ceros) ===
    items = [
        {"title": "Total ventas",     "value": total_ventas,     "fmt": money},
        {"title": "Gastos totales",   "value": total_gastos,     "fmt": money},
        {"title": "Costos totales",   "value": total_costos,     "fmt": money},
        {"title": "Total préstamos",  "value": total_prestamos,  "fmt": money},
        {"title": "Inventario total", "value": total_inventario, "fmt": money},  # 👈 ya lo tenías
        {"title": "Deudores totales", "value": total_deu,        "fmt": money},  # 👈 NUEVO
    ]
    render_stat_cards(items, hide_empty=True, hide_zero=False)  # 👈 no ocultes 0

    # Layout 2:1 (solo usamos la izquierda; derecha queda vacía)
    colL, _ = st.columns([2, 1], gap="small")

    with colL:
        CONS_efectivo = currency_input("Efectivo en caja", key="CONS_efectivo_input",
                                    value=float(efectivo_ini))
        if st.button("💾 Guardar / Reemplazar (global)", use_container_width=True,
                    key="CONS_efectivo_save"):
            # Reemplazo automático: primero borro, luego inserto/actualizo
            delete_consolidado("GLOBAL")
            upsert_consolidado("GLOBAL", float(CONS_efectivo), "")

            nuevo_ef, _ = get_efectivo_global_now()
            metric_box.metric("EFECTIVO", money(nuevo_ef))
            components.html("<script>try{document.activeElement && document.activeElement.blur();}catch(e){}</script>", height=0, width=0)
            finish_and_refresh("Efectivo (GLOBAL) reemplazado.", ["consolidado_diario"])

    # ===== Total de capital (minimal) =====
    total_capital = float(total_deu + efectivo_ini + total_prestamos + total_inventario + total_deudores_ini)
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
    # ✅ Validaciones anti-vacío
        if not str(VTA_cliente).strip():
            st.warning("Escribe el nombre del cliente.")
        elif float(VTA_venta) <= 0:
            st.warning("La venta debe ser mayor que 0.")
        else:
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
                'observacion': "CUENTA" if VTA_debe else "EFECTIVO",
            })

            # 🔄 limpiar y refrescar como ya lo hacías
            _reset_keys([
                "VTA_fecha_rt","VTA_cliente_rt","VTA_debe_rt","VTA_paga_rt","VTA_obs_rt",
                "VTA_costo_rt_txt","VTA_venta_rt_txt","VTA_ab1_rt_txt","VTA_ab2_rt_txt",
                "VTA_ganancia_view_rt"
            ])
            components.html("<script>try{document.activeElement && document.activeElement.blur();}catch(e){}</script>", height=0, width=0)
            clear_venta_form_rt()
            finish_and_refresh("Venta guardada", ["transacciones"])

    st.divider()

    # ===== Listado (CON acciones por fila) =====
    v = read_ventas()
    if not v.empty:
        # Precargar último estado de filtros (opcional)
        if "q_ventas" not in st.session_state and "ventas_last_text" in st.session_state:
            st.session_state["q_ventas"] = st.session_state["ventas_last_text"]
        if "rng_ventas" not in st.session_state and "ventas_last_rango" in st.session_state:
            st.session_state["rng_ventas"] = st.session_state["ventas_last_rango"]

        # Aplicar filtros guardados (sin mostrar los controles todavía)
        v = aplicar_filtros_guardados(v, ["cliente_nombre", "observacion"], key="ventas")

        # Filtro por cliente(s) desde session_state (si hubo selección antes)
        cli_sel = st.session_state.get("ventas_cli", [])
        if cli_sel:
            patt = {str(c).strip().upper() for c in cli_sel}
            v = v[v["cliente_nombre"].astype(str).str.strip().str.upper().isin(patt)]

        # Export CSV del resultado filtrado
        st.download_button(
            "⬇️ Exportar CSV (ventas filtradas)",
            v.to_csv(index=False).encode("utf-8"),
            file_name="ventas_filtradas.csv",
            mime="text/csv",
            use_container_width=True
        )

        # Métricas (solo registros con observación válida)
        v_num = v.copy()
        for col in ['costo','venta','ganancia','abono1','abono2']:
            v_num[col] = pd.to_numeric(v_num[col], errors='coerce').fillna(0.0)
        mask_obs = v_num['observacion'].fillna('').str.strip().ne('')
        v_valid = v_num[mask_obs]
        m1, m2, m3 = st.columns(3, gap="small")
        m1.metric("Costos totales",  money(float(v_valid['costo'].sum())))
        m2.metric("Ventas totales",  money(float(v_valid['venta'].sum())))
        m3.metric("Ganancia total",  money(float(v_valid['ganancia'].sum())))

        # Paginación
        v = v.sort_values(["fecha","id"], ascending=[False, False]).reset_index(drop=True)
        page_size = st.number_input("Filas por página", min_value=5, max_value=100, value=20, step=5, key="ventas_page_size")
        total = len(v)
        num_pages = max(1, math.ceil(total / page_size))
        page = st.number_input("Página", min_value=1, max_value=num_pages, value=min(1, num_pages), step=1, key="ventas_page")
        start = (page - 1) * page_size
        stop  = start + page_size
        v_page = v.iloc[start:stop].copy()

        # Tabla visual rápida (sin acciones) de la página actual
        cols_show = ['fecha','cliente_nombre','observacion','costo','venta','ganancia','debe_flag','paga','abono1','abono2']
        v_show = v_page[cols_show].copy()
        v_show['debe_flag'] = v_show['debe_flag'].fillna(0).astype(int).map({1: "SÍ", 0: "NO"})
        v_show = df_format_money(v_show, ['costo','venta','ganancia','abono1','abono2'])
        st.dataframe(v_show, use_container_width=True)

        st.markdown("#### Acciones por venta")
        st.caption("Usa ✏️ para editar (abre un popover) o 🗑️ para eliminar con confirmación.")

        # Cabecera compacta para las filas con acciones
        hc1, hc2, hc3, hc4, hc5 = st.columns([1.1, 2.5, 1.2, 1.2, 2], gap="small")
        with hc1: st.write("**Fecha**")
        with hc2: st.write("**Cliente**")
        with hc3: st.write("**Obs.**")
        with hc4: st.write("**Venta**")
        with hc5: st.write("**Acciones**")

        for _, r in v_page.iterrows():
            rid = int(r["id"])
            c1, c2, c3, c4, c5 = st.columns([1.2, 2.2, 1, 1, 1.8], gap="small")  # c5: Acciones

            with c1:
                try:
                    f = pd.to_datetime(r["fecha"], errors="coerce").date()
                    st.write(f.strftime("%d/%m/%Y") if pd.notna(f) else "")
                except Exception:
                    st.write(str(r["fecha"] or ""))
            with c2: st.write(str(r.get("cliente_nombre","")).strip())
            with c3: st.write(str(r.get("observacion","")).strip())
            with c4: st.write(money(_to_float(r.get("venta",0))))

            with c5:
                a1, a2 = st.columns([1,1], gap="small")  # ← un solo nivel de columnas

                # ========== EDITAR ==========
                with a1:
                    pop = open_action_panel("✏️ Editar", key=f"pop_edit_{rid}")
                    with pop:
                        # valores actuales
                        _fecha   = pd.to_datetime(r.get("fecha"), errors="coerce").date() if r.get("fecha") else date.today()
                        _cliente = str(r.get("cliente_nombre") or "").strip()
                        _costo   = _to_float(r.get("costo"))
                        _venta   = _to_float(r.get("venta"))
                        _ab1     = _to_float(r.get("abono1"))
                        _ab2     = _to_float(r.get("abono2"))
                        _pagaB   = (str(r.get("paga") or "").strip().upper() == "X")
                        _debeB   = int(r.get("debe_flag") or 0) == 1
                        _obs     = (str(r.get("observacion") or "").strip().upper()) or ("CUENTA" if _debeB else "EFECTIVO")

                        with st.form(key=f"edit_form_{rid}", clear_on_submit=False):
                            fecha_i   = st.date_input("Fecha", value=_fecha, format="DD/MM/YYYY", key=f"e_fecha_{rid}")
                            cliente_i = st.text_input("Cliente", value=_cliente, key=f"e_cliente_{rid}")
                            costo_i   = currency_input("Costo", key=f"e_costo_{rid}", value=_costo, in_form=True)
                            venta_i   = currency_input("Venta", key=f"e_venta_{rid}", value=_venta, in_form=True)
                            ab1_i     = currency_input("Abono 1", key=f"e_ab1_{rid}", value=_ab1, in_form=True)
                            ab2_i     = currency_input("Abono 2", key=f"e_ab2_{rid}", value=_ab2, in_form=True)
                            debe_i    = st.checkbox("DEBE", value=_debeB, key=f"e_debe_{rid}")
                            paga_i    = st.checkbox("PAGA (pagó hoy)", value=_pagaB, key=f"e_paga_{rid}")
                            obs_i     = st.selectbox("Observación", ["EFECTIVO","CUENTA"],
                                                    index=(1 if _obs=="CUENTA" else 0), key=f"e_obs_{rid}")

                            gan_calc  = max(0.0, float(venta_i) - float(costo_i))
                            st.caption(f"Ganancia sugerida: {money(gan_calc)}")

                            ok = st.form_submit_button("💾 Guardar cambios", type="primary")
                            if ok:
                                update_venta_fields(
                                    rid,
                                    fecha=fecha_i,
                                    cliente_nombre=cliente_i,
                                    costo=float(costo_i),
                                    venta=float(venta_i),
                                    ganancia=float(gan_calc),
                                    debe_flag=1 if bool(debe_i) else 0,
                                    paga="X" if bool(paga_i) else "",
                                    abono1=float(ab1_i),
                                    abono2=float(ab2_i),
                                    observacion=str(obs_i).strip().upper(),
                                )
                                finish_and_refresh("Venta actualizada", ["transacciones"])

                # ========== ELIMINAR ==========
                with a2:
                    popd = open_action_panel("🗑️ Eliminar", key=f"pop_del_{rid}")
                    with popd:
                        st.warning("Esta acción eliminará la venta definitivamente.")
                        conf = st.checkbox("Confirmar eliminación", key=f"del_conf_{rid}")
                        if st.button("Eliminar", type="primary", disabled=not conf, key=f"del_btn_{rid}"):
                            delete_venta_id(rid)
                            finish_and_refresh("Venta eliminada", ["transacciones"])

    else:
        st.info("No hay ventas registradas aún.")



# ====== Editor en bloque (abonos / PAGA) ======
# Base para edición masiva: solo columnas necesarias + bandera PAGA booleana
        vv_editor = v[['id','fecha','cliente_nombre','venta','abono1','abono2','paga']].copy()
        vv_editor['paga'] = vv_editor['paga'].fillna('')
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
            GTO_valor = st.number_input("Valor", min_value=0.0, value=0.0, step=100.0, key="GTO_valor")
        with c4:
            GTO_notas = st.text_input("Notas", value="", key="GTO_notas")

        GTO_submit = st.form_submit_button("💾 Guardar gasto")

    if GTO_submit and GTO_fecha is not None:
    # ✅ Validaciones anti-vacío
        if not str(GTO_conc).strip():
            st.warning("El concepto es obligatorio.")
        elif float(GTO_valor) <= 0:
            st.warning("El valor debe ser mayor que 0.")
        else:
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
                    soft_delete_row("gastos", rid)
                finish_and_refresh(f"Eliminados {len(ids)} gastos.", ["gastos"])
            else:
                st.info("Marca al menos una fila en ‘Eliminar’.")
        ver_eliminados_g = st.session_state.get("GTO_show_del", False)
        ver_eliminados_g = st.toggle("Mostrar eliminados (para restaurar)", value=False, key="GTO_show_del")            
        if ver_eliminados_g:
            with get_conn() as conn:
                base = "SELECT id, fecha, concepto, valor, notas FROM gastos WHERE deleted_at IS NOT NULL"
                if _view_all_enabled():
                    q = text(base + " ORDER BY id DESC")
                    params = {}
                else:
                    q = text(base + " AND owner=:o ORDER BY id DESC")
                    params = {"o": _current_owner()}
                g_del = pd.read_sql_query(q, conn, params=params or None)

                if g_del.empty:
                    st.info("No hay gastos eliminados.")
                else:
                    for _, row in g_del.iterrows():
                        c_info, c_restore, c_hard = st.columns([6,2,2], gap="small")
                        with c_info:
                            st.markdown(f"**{row['fecha']}** — {row['concepto']} • ${row['valor']:,.0f}")
                        if c_restore.button("↩️ Restaurar", key=f"restore_g_{int(row['id'])}"):
                            restore_row("gastos", int(row["id"]))
                            st.cache_data.clear(); st.rerun()
                        if is_admin() and c_hard.button("❌ Borrar", key=f"hard_g_{int(row['id'])}"):
                            hard_delete_row("gastos", int(row["id"]))
                            st.cache_data.clear(); st.rerun()

# ---------------------------------------------------------
# Préstamos
# ---------------------------------------------------------
elif show("🤝 Préstamos"):
    # ---- Alta con form (una sola vez) ----
    with st.form("PRE_form", clear_on_submit=True):
        c1, c2 = st.columns(2, gap="small")
        PRE_nombre = c1.text_input("Nombre", key="PRE_nombre")
        # IMPORTANTE: in_form=True y etiqueta única para evitar colisiones por aria-label
        with c2:
            PRE_valor = st.number_input("Valor", min_value=0.0, value=0.0, step=100.0, key="PRE_valor")

        PRE_submit = st.form_submit_button("💾 Guardar préstamo", use_container_width=True)

    if PRE_submit:
    # ✅ Validaciones anti-vacío
        if not str(PRE_nombre).strip():
            st.warning("El nombre es obligatorio.")
        elif float(PRE_valor) <= 0:
            st.warning("El valor del préstamo debe ser mayor que 0.")
        else:
            insert_prestamo({"nombre": PRE_nombre, "valor": float(PRE_valor)})
            _reset_keys(["PRE_nombre", "PRE_valor", "PRE_valor_txt"])
            finish_and_refresh("Préstamo guardado", ["prestamos"])

    st.divider()

    # ---- Listado / edición / borrado ----
    p = read_prestamos()
    if not p.empty:

        # =========================================================
        # === PRÉSTAMOS: edición/borrado en línea (editor)      ===
        # =========================================================
        pp = p.sort_values('id', ascending=False).copy()

        # Base para el editor (alineada al orden de 'pp')
        p_editor = pp[['id', 'nombre', 'valor']].copy().reset_index(drop=True)
        p_editor['🗑️ Eliminar'] = False

        edited_p = st.data_editor(
            p_editor,
            key='prestamos_editor',
            use_container_width=True,
            hide_index=True,
            num_rows="fixed",
            column_order=["nombre", "valor", "🗑️ Eliminar"],
            column_config={
                "nombre": st.column_config.TextColumn("Nombre"),
                "valor": st.column_config.NumberColumn("Valor", format="$ %,d", step=100),
                "🗑️ Eliminar": st.column_config.CheckboxColumn("Eliminar"),
            }
        )

        cp1, cp2 = st.columns(2, gap="small")

        if cp1.button("💾 Guardar cambios", type="primary", key="PRE_inline_save"):
            n_upd = 0
            # Usa 'pp.iloc[i]' (mismo orden) para comparar con el original
            for i, row in edited_p.iterrows():
                row_id = int(pp.iloc[i]['id'])
                changes = {}
                if str(row['nombre']).strip() != str(pp.iloc[i]['nombre']).strip():
                    changes['nombre'] = row['nombre']
                if float(row['valor']) != float(_nz(pp.iloc[i]['valor'])):
                    changes['valor'] = float(row['valor'])
                if changes:
                    update_prestamo_fields(row_id, **changes)
                    n_upd += 1
            finish_and_refresh(f"Préstamos actualizados: {n_upd}", ["prestamos"])

        if cp2.button("🗑️ Eliminar seleccionados", type="primary", key="PRE_inline_del"):
            idxs = edited_p.index[edited_p['🗑️ Eliminar'] == True].tolist()
            ids = [int(pp.iloc[i]['id']) for i in idxs]
            if ids:
                for rid in ids:
                    soft_delete_row("prestamos", rid)
                finish_and_refresh(f"Eliminados {len(ids)} préstamos.", ["prestamos"])
            else:
                st.info("Marca al menos una fila en ‘Eliminar’.")
            
        ver_eliminados_p = st.session_state.get("PRE_show_del", False)
        ver_eliminados_p = st.toggle("Mostrar eliminados (para restaurar)", value=False, key="PRE_show_del")

        if ver_eliminados_p:
            with get_conn() as conn:
                base = "SELECT id, nombre, valor FROM prestamos WHERE deleted_at IS NOT NULL"
                if _view_all_enabled():
                    q = text(base + " ORDER BY id DESC")
                    params = {}
                else:
                    q = text(base + " AND owner=:o ORDER BY id DESC")
                    params = {"o": _current_owner()}
                p_del = pd.read_sql_query(q, conn, params=params or None)

                if p_del.empty:
                    st.info("No hay préstamos eliminados.")
                else:
                    for _, row in p_del.iterrows():
                        c_info, c_restore, c_hard = st.columns([6,2,2], gap="small")
                        with c_info:
                            st.markdown(f"**{row['nombre']}** — ${row['valor']:,.0f}")
                        if c_restore.button("↩️ Restaurar", key=f"restore_p_{int(row['id'])}"):
                            restore_row("prestamos", int(row["id"]))
                            st.cache_data.clear(); st.rerun()
                        if is_admin() and c_hard.button("❌ Borrar", key=f"hard_p_{int(row['id'])}"):
                            hard_delete_row("prestamos", int(row["id"]))
                            st.cache_data.clear(); st.rerun()

        st.divider()

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
            INV_costo = st.number_input("Valor costo", min_value=0.0, value=0.0, step=100.0, key="INV_valor_costo")
        INV_submit = st.form_submit_button("💾 Guardar ítem")
    if INV_submit:
    # ✅ Validaciones anti-vacío
        if not str(INV_prod).strip():
            st.warning("El nombre del producto es obligatorio.")
        elif float(INV_costo) <= 0:
            st.warning("El valor costo debe ser mayor que 0.")
        else:
            insert_inventario({'producto': INV_prod, 'valor_costo': float(INV_costo), 'owner': None})
            clear_inventario_form()
            finish_and_refresh("Ítem guardado", ["inventario"])

    st.divider()
    i = read_inventario()
    if not i.empty:

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
                    soft_delete_row("inventario", rid)
                finish_and_refresh(f"Eliminados {len(ids)} ítems.", ["inventario"])
            else:
                st.info("Marca al menos una fila en ‘Eliminar’.")

        ver_eliminados_i = st.session_state.get("INV_show_del", False)
        ver_eliminados_i = st.toggle("Mostrar eliminados (para restaurar)", value=False, key="INV_show_del")

        if ver_eliminados_i:
            with get_conn() as conn:
                base = "SELECT id, producto, valor_costo FROM inventario WHERE deleted_at IS NOT NULL"
                if _view_all_enabled():
                    q = text(base + " ORDER BY id DESC")
                    params = {}
                else:
                    q = text(base + " AND owner=:o ORDER BY id DESC")
                    params = {"o": _current_owner()}
                i_del = pd.read_sql_query(q, conn, params=params or None)

                if i_del.empty:
                    st.info("No hay ítems eliminados.")
                else:
                    for _, row in i_del.iterrows():
                        c_info, c_restore, c_hard = st.columns([6,2,2], gap="small")
                        with c_info:
                            st.markdown(f"**{row['producto']}** — ${row['valor_costo']:,.0f}")
                        if c_restore.button("↩️ Restaurar", key=f"restore_i_{int(row['id'])}"):
                            restore_row("inventario", int(row["id"]))
                            st.cache_data.clear(); st.rerun()
                        if is_admin() and c_hard.button("❌ Borrar", key=f"hard_i_{int(row['id'])}"):
                            hard_delete_row("inventario", int(row["id"]))
                            st.cache_data.clear(); st.rerun()

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
        sa = st.session_state.get("_gs_sa_email", "—") if GOOGLE_SHEETS_ENABLED else "—"
        sid = (GSPREADSHEET_ID or "—") if GOOGLE_SHEETS_ENABLED else "—"
        st.caption(f"Service Account: {sa}")
        st.caption(f"Sheet ID/URL: {sid}")

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
        AUTH.db_set_password(user, newp); notify_ok("Tu contraseña fue actualizada.")
    
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
        st.markdown(f'[Abrir mi hoja en Google Sheets]({sh.url})')
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
        finish_and_refresh("Caché limpiada", list(CACHE_READERS.keys()))
    if c5.button("Cerrar sesión (admin)", use_container_width=True):
        _clear_session(); st.rerun()

    if st.button("🔌 Probar conexión Neon / correr migraciones", use_container_width=True):
        try:
            AUTH.init_users_table()
            AUTH.ensure_admin_seed()
            st.session_state["AUTH_OFFLINE"] = False
            st.success("OK: conectado a Neon y migraciones listas.")
        except Exception as e:
            st.session_state["AUTH_OFFLINE"] = True
            st.error("No se pudo conectar a Neon.")
            st.exception(e)

    st.divider()


    # === Backup de usuarios (CSV) + Enviar a Google Sheets ===
    with st.container():
        st.subheader("📦 Respaldo de usuarios")

        # 1) Trae usuarios desde Neon
        try:
            df_users = AUTH.db_list_users()
        except Exception as e:
            df_users = None
            if _auth_db_available() and not st.session_state.get("AUTH_OFFLINE"):
                try:
                    df_users = AUTH.db_list_users()
                except Exception as e:
                    df_users = None
                    st.info("No hay conexión a la BD; puedes descargar CSV vacío o probar luego.")
                    st.exception(e)

        c1, c2 = st.columns([1.2, 1], gap="small")

        with c1:
            st.caption("Descargar respaldo CSV")
            if df_users is not None and not df_users.empty:
                csv_buf = _df_to_csv_bytes(df_users)
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                st.download_button(
                    "⬇️ Descargar users.csv",
                    data=csv_buf,
                    file_name=f"users_backup_{ts}.csv",
                    mime="text/csv",
                    use_container_width=True,
                )
            else:
                st.info("Aún no hay usuarios para exportar.")

        with c2:
            st.caption("Enviar a Google Sheets (hoja 'users')")
            # ID de la hoja: prueba primero desde secrets y deja input manual
            default_id = st.secrets.get("USERS_SHEET_ID", "")
            sheet_id = st.text_input("Sheets ID", value=default_id, key="USERS_SHEET_ID_INPUT")

            do_sync = st.button("📤 Enviar a Google Sheets", use_container_width=True)
            if do_sync:
                if not sheet_id:
                    st.warning("Ingresa el ID de la hoja de cálculo.")
                elif df_users is None or df_users.empty:
                    st.warning("No hay datos para enviar.")
                else:
                    try:
                        ok = _sync_users_to_google_sheets(df_users, sheet_id)
                        if ok:
                            st.success("Usuarios enviados a Google Sheets (worksheet 'users').")
                        else:
                            st.error("No se pudo enviar a Google Sheets (revisa credenciales/ID).")
                    except Exception as e:
                        st.error("Fallo al enviar a Google Sheets.")
                        st.exception(e)

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
                    # 👇 escribe en Neon (wrappers apuntan a auth_db)
                    AUTH.db_create_user(new_user, new_pass, new_role)
                    st.success(f"Usuario '{new_user}' creado.")
                    # 👇 invalida cualquier cache/listado previo y fuerza rerun
                    st.session_state.pop("_users_debug_df", None)
                    st.rerun()
                except Exception as e:
                    st.error(f"No se pudo crear: {e}")

    with st.expander("🔑 Cambiar contraseña / rol", expanded=False):
        dfu = AUTH.db_list_users()
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
                    AUTH.db_set_password(sel_user, new_pass2)
                    notify_ok("Contraseña actualizada.")

            current_role = dfu.loc[dfu["username"]==sel_user,"role"].iloc[0]
            new_role2 = np2.selectbox("Rol", ["user","admin"],
                                    index=0 if current_role=="user" else 1,
                                    key="USR_newrole2")
            if np2.button("Actualizar rol", key="USR_update_role"):
                if sel_user == user and new_role2 != "admin":
                    st.error("No puedes quitarte el rol admin a ti mismo.")
                else:
                    AUTH.db_set_role(sel_user, new_role2)
                    notify_ok("Rol actualizado.")

    with st.expander("🗂️ Lista de usuarios / eliminar", expanded=False):
        dfu = AUTH.db_list_users()
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
                    AUTH.db_delete_user(del_user)
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
        conds = ["1=1"]
        p = {}

        if isinstance(rango, tuple) and len(rango) == 2:
            # En Postgres es mejor castear: ts::date
            conds.append("ts::date BETWEEN :d1 AND :d2")
            p["d1"] = str(rango[0])
            p["d2"] = str(rango[1])

        if usuario:
            # ILIKE para búsqueda case-insensitive en PG
            conds.append('"user" ILIKE :u')
            p["u"] = f"%{usuario.strip()}%"

        if acc:
            conds.append("action ILIKE :a")
            p["a"] = f"%{acc.strip()}%"

        if tabla:
            conds.append("table_name ILIKE :t")
            p["t"] = f"%{tabla.strip()}%"

        p["lim"] = int(limit)

        q = f"""
        SELECT id, ts, "user", action, table_name AS tabla, row_id, details
        FROM audit_log
        WHERE {' AND '.join(conds)}
        ORDER BY id DESC
        LIMIT :lim
        """

        with get_conn() as conn:
            df_aud = pd.read_sql_query(text(q), conn, params=p)

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
            "consolidado y auditoría). **Los usuarios no se tocan** (viven en Neon)."
        )

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
                except Exception:
                    pass  # si falla el backup no bloqueamos el borrado

                # 3) Vaciar tablas (¡sin users!)
                with get_conn() as conn:
                    # Borra rápido y reinicia autoincrementos; respeta FKs con CASCADE
                    conn.execute(text("""
                        TRUNCATE TABLE
                            transacciones,
                            gastos,
                            prestamos,
                            inventario,
                            deudores_ini,
                            consolidado_diario,
                            audit_log
                        RESTART IDENTITY CASCADE
                    """))
                    conn.execute(text("DELETE FROM meta"))

                audit("db.wipe", extra={})

                # 4) Limpia caché/estado y reinicia
                st.session_state.clear()
                finish_and_refresh("Base borrada. Empezamos de cero ✅")
            except Exception as e:
                st.error(f"No pude vaciar los datos: {e}")

# --- detectar admin de forma robusta ---
u = st.session_state.get("user") or st.session_state.get("auth_user") or {}
role = (u.get("role") or st.session_state.get("role") or "").strip().lower()

# si tienes helper del módulo AUTH, úsalo:
try:
    is_admin = AUTH.is_admin(u)  # devuelve True/False
except Exception:
    is_admin = (role == "admin")

# opcional: feature flag para ocultar en prod aunque seas admin
SHOW_DEBUG_ADMIN = os.getenv("SHOW_DEBUG_ADMIN", "1") == "1"

if is_admin and SHOW_DEBUG_ADMIN:
    ver_neon = st.checkbox("👀 Ver usuarios en Neon (debug)")
    if ver_neon:
        # ... tu código para listar usuarios en Neon ...
        pass
# ---------------------------------------------------------