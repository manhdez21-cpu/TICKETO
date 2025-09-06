# auth_db.py — estable para Neon + distintas versiones de Streamlit SQLConnection
from __future__ import annotations
import hashlib
import streamlit as st
from sqlalchemy import text

def _conn():
    return st.connection("auth_db", type="sql")

def _get_engine(c):
    for attr in ("engine", "_engine"):
        eng = getattr(c, attr, None)
        if eng is not None:
            return eng
    inst = getattr(c, "_instance", None)
    if inst is not None:
        for attr in ("engine", "_engine"):
            eng = getattr(inst, attr, None)
            if eng is not None:
                return eng
    return None

def _exec_write(sql: str, params: dict | None = None) -> None:
    c = _conn()
    params = params or {}
    sess = getattr(c, "session", None)
    if sess is not None:
        with sess as s:
            s.execute(text(sql), params)
            s.commit()
        return
    eng = _get_engine(c)
    if eng is None:
        raise RuntimeError("No se pudo obtener engine para ejecutar DDL/DML")
    with eng.begin() as s:
        s.execute(text(sql), params)

def _query_df(sql: str, params: dict | None = None):
    return _conn().query(sql, params=params or {}, ttl=0)

def ping() -> bool:
    """Conexión muy rápida: SELECT 1; lanza excepción si no hay BD."""
    _ = _query_df("SELECT 1")
    return True

def _hash(pwd: str) -> str:
    return hashlib.sha256((pwd or "").encode("utf-8")).hexdigest()

# ---------- migraciones seguras ----------
def _backfill_from_legacy_password() -> None:
    has_password = _query_df("""
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema='public' AND table_name='users' AND column_name='password'
        LIMIT 1
    """)
    if has_password.empty:
        return

    rows = _query_df("""
        SELECT username, CAST(password AS TEXT) AS legacy_pwd
        FROM public.users
        WHERE password_hash IS NULL
    """)
    if not rows.empty:
        for _, r in rows.iterrows():
            u = (r["username"] or "").strip()
            legacy = r.get("legacy_pwd")
            if u and legacy is not None:
                _exec_write(
                    "UPDATE public.users SET password_hash=:ph WHERE username=:u AND password_hash IS NULL",
                    {"ph": _hash(str(legacy)), "u": u}
                )
    _exec_write("ALTER TABLE public.users DROP COLUMN IF EXISTS password;")

def _migrate_legacy_hash_column() -> None:
    """
    Migra bases antiguas donde existía la columna `hash` (NOT NULL)
    a la columna nueva `password_hash`, y luego elimina `hash`.
    """
    has_hash = _query_df("""
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema='public'
          AND table_name='users'
          AND column_name='hash'
        LIMIT 1
    """)
    if has_hash.empty:
        return

    # Asegura que exista password_hash
    _exec_write("ALTER TABLE public.users ADD COLUMN IF NOT EXISTS password_hash TEXT;")

    # Copia valores si hace falta
    _exec_write("""
        UPDATE public.users
           SET password_hash = COALESCE(password_hash, CAST(hash AS TEXT))
    """)

    # Elimina la columna legacy
    _exec_write("ALTER TABLE public.users DROP COLUMN IF EXISTS hash;")


def _fill_missing_password_hashes() -> None:
    rows = _query_df("SELECT username FROM public.users WHERE password_hash IS NULL")
    if rows.empty:
        return
    for _, r in rows.iterrows():
        u = (r["username"] or "").strip()
        if not u:
            continue
        temp_hash = _hash(f"TEMP_RESET::{u}")
        _exec_write(
            "UPDATE public.users SET password_hash=:ph WHERE username=:u AND password_hash IS NULL",
            {"ph": temp_hash, "u": u}
        )

def _safe_set_not_null_password_hash() -> None:
    cnt = int(_query_df("SELECT COUNT(*) AS c FROM public.users WHERE password_hash IS NULL").iloc[0]["c"])
    if cnt == 0:
        _exec_write("ALTER TABLE public.users ALTER COLUMN password_hash SET NOT NULL;")

def init_users_table() -> None:
    _exec_write("""
        CREATE TABLE IF NOT EXISTS public.users(
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    """)
    _exec_write("""
        ALTER TABLE public.users
        ADD COLUMN IF NOT EXISTS password_hash TEXT,
        ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user',
        ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
    """)
    _backfill_from_legacy_password()   # ya migra la columna legacy `password`
    _migrate_legacy_hash_column()      # ← ★ NUEVO: migra/borra la vieja `hash`
    _fill_missing_password_hashes()
    _safe_set_not_null_password_hash()

def ensure_admin_seed(username: str = "admin", password: str = "AdminSeguro_2025", role: str = "admin") -> None:
    exists = _query_df("SELECT 1 FROM public.users WHERE username=:u LIMIT 1", {"u": username})
    if exists.empty:
        _exec_write("""
            INSERT INTO public.users (username, password_hash, role, created_at)
            VALUES (:u, :ph, :r, NOW())
            ON CONFLICT (username) DO NOTHING
        """, {"u": username.strip(), "ph": _hash(password), "r": role})

# ---------- CRUD + auth ----------
def db_create_user(username: str, password: str, role: str = "user") -> None:
    _exec_write("""
        INSERT INTO public.users (username, password_hash, role, created_at)
        VALUES (:u, :ph, :r, NOW())
        ON CONFLICT (username) DO UPDATE
        SET password_hash = EXCLUDED.password_hash,
            role = EXCLUDED.role
    """, {"u": username.strip(), "ph": _hash(password), "r": role})

def db_set_password(username: str, new_password: str) -> None:
    _exec_write("UPDATE public.users SET password_hash=:ph WHERE username=:u",
                {"ph": _hash(new_password), "u": username.strip()})

def db_set_role(username: str, new_role: str) -> None:
    _exec_write("UPDATE public.users SET role=:r WHERE username=:u",
                {"r": new_role, "u": username.strip()})

def db_delete_user(username: str) -> None:
    _exec_write("DELETE FROM public.users WHERE username=:u", {"u": username.strip()})

def db_list_users():
    return _query_df("""
        SELECT id, username, role, created_at
        FROM public.users
        ORDER BY id
    """)

def authenticate(username: str, password: str):
    try:
        df = _query_df("""
            SELECT username, password_hash, role
            FROM public.users
            WHERE username = :u
            LIMIT 1
        """, {"u": username.strip()})
    except Exception:
        # Marcar modo offline; no reventar el front
        try:
            st.session_state["AUTH_OFFLINE"] = True
        except Exception:
            pass
        return None

    if df.empty:
        return None
    row = df.iloc[0]
    if str(row["password_hash"]) != _hash(password):
        return None
    return {"username": username.strip(), "role": (row.get("role") or "user")}

# Aliases para tu UI
create_user = db_create_user
set_password = db_set_password
update_role_by_username = db_set_role
delete_user_by_username = db_delete_user
list_users = db_list_users
