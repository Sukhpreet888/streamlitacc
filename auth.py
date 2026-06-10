"""
AccountSync — Authentication Module
Handles login verification, session management, and user CRUD via Supabase.
"""

import bcrypt
import streamlit as st
from supabase_backend import get_client


# ── Core Auth Functions ───────────────────────────────────────────────────────

def _fetch_user(username: str) -> dict | None:
    """Fetch a user record from Supabase by username. Returns None if not found."""
    try:
        res = (
            get_client()
            .table("accountsync_users")
            .select("*")
            .eq("username", username.strip().lower())
            .single()
            .execute()
        )
        return res.data
    except Exception:
        return None


def verify_login(username: str, password: str) -> tuple[bool, str]:
    """
    Check username + password against Supabase.
    Returns (success: bool, message: str).
    """
    if not username or not password:
        return False, "Please enter both username and password."

    user = _fetch_user(username.strip().lower())

    if user is None:
        return False, "Invalid username or password."

    if not user.get("is_active", False):
        return False, "Your account has been deactivated. Contact your administrator."

    stored_hash = user["password_hash"].encode("utf-8")
    try:
        match = bcrypt.checkpw(password.encode("utf-8"), stored_hash)
    except Exception:
        return False, "Authentication error. Please try again."

    if not match:
        return False, "Invalid username or password."

    # Update last_login timestamp
    try:
        from datetime import datetime, timezone
        get_client().table("accountsync_users").update(
            {"last_login": datetime.now(timezone.utc).isoformat()}
        ).eq("username", username.strip().lower()).execute()
    except Exception:
        pass

    return True, user.get("full_name") or username


def is_logged_in() -> bool:
    return st.session_state.get("_auth_logged_in", False)


def get_current_user() -> str:
    return st.session_state.get("_auth_username", "")


def get_current_fullname() -> str:
    return st.session_state.get("_auth_fullname", "")


def do_login(username: str, full_name: str):
    st.session_state["_auth_logged_in"] = True
    st.session_state["_auth_username"]  = username.strip().lower()
    st.session_state["_auth_fullname"]  = full_name


def do_logout():
    for key in ["_auth_logged_in", "_auth_username", "_auth_fullname"]:
        st.session_state.pop(key, None)


# ── User Management (Admin) ───────────────────────────────────────────────────

def list_users() -> list[dict]:
    """Return all users (for admin panel)."""
    try:
        res = (
            get_client()
            .table("accountsync_users")
            .select("id, username, full_name, is_active, created_at, last_login")
            .order("created_at", desc=False)
            .execute()
        )
        return res.data or []
    except Exception as e:
        st.error(f"Could not load users: {e}")
        return []


def add_user(username: str, password: str, full_name: str) -> tuple[bool, str]:
    """Add a new user with a bcrypt-hashed password."""
    username = username.strip().lower()
    if not username or not password:
        return False, "Username and password are required."
    if len(password) < 6:
        return False, "Password must be at least 6 characters."
    try:
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(12)).decode("utf-8")
        get_client().table("accountsync_users").insert({
            "username":      username,
            "password_hash": hashed,
            "full_name":     full_name.strip(),
            "is_active":     True,
        }).execute()
        return True, f"User '{username}' created successfully."
    except Exception as e:
        if "unique" in str(e).lower():
            return False, f"Username '{username}' already exists."
        return False, str(e)


def set_user_active(username: str, active: bool) -> tuple[bool, str]:
    """Enable or disable a user account."""
    try:
        get_client().table("accountsync_users").update(
            {"is_active": active}
        ).eq("username", username).execute()
        status = "activated" if active else "deactivated"
        return True, f"User '{username}' {status}."
    except Exception as e:
        return False, str(e)


def delete_user(username: str) -> tuple[bool, str]:
    """Permanently delete a user."""
    try:
        get_client().table("accountsync_users").delete().eq("username", username).execute()
        return True, f"User '{username}' deleted."
    except Exception as e:
        return False, str(e)


def change_password(username: str, new_password: str) -> tuple[bool, str]:
    """Change a user's password."""
    if len(new_password) < 6:
        return False, "Password must be at least 6 characters."
    try:
        hashed = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt(12)).decode("utf-8")
        get_client().table("accountsync_users").update(
            {"password_hash": hashed}
        ).eq("username", username).execute()
        return True, "Password updated successfully."
    except Exception as e:
        return False, str(e)


# ── Login Page UI ─────────────────────────────────────────────────────────────

def show_login_page():
    """
    Login page — uses plain st.button (not st.form) so submit is 100% reliable.
    White card achieved via CSS on the centre column container.
    """

    # ── Handle pending login from previous click ──────────────────────────────
    if st.session_state.get("_do_login_now"):
        st.session_state.pop("_do_login_now")
        _u = st.session_state.pop("_pending_user", "").strip()
        _p = st.session_state.pop("_pending_pass", "")
        if not _u or not _p:
            st.session_state["_login_error"] = "Please enter both username and password."
        else:
            ok, result = verify_login(_u, _p)
            if ok:
                do_login(_u, result)
                st.rerun()          # rerun with _auth_logged_in=True → gate passes
            else:
                st.session_state["_login_error"] = result

    st.markdown("""
    <style>
    #MainMenu,footer,header,
    [data-testid="stToolbar"],
    [data-testid="stDecoration"],
    [data-testid="stStatusWidget"] {
        visibility:hidden !important; display:none !important;
    }
    .stApp {
        background: linear-gradient(135deg,#dbeafe 0%,#e0e7ff 55%,#ede9fe 100%) !important;
        min-height: 100vh;
    }
    .block-container { padding-top:60px !important; max-width:100% !important; }

    /* White card on centre column */
    div[data-testid="stVerticalBlockBorderWrapper"]:has(div.login-card-anchor) {
        background: white !important;
        border-radius: 24px !important;
        box-shadow: 0 8px 48px rgba(99,102,241,.14), 0 2px 16px rgba(0,0,0,.07) !important;
        padding: 0 !important;
    }

    /* Input wrapper */
    div.login-col div[data-testid="stTextInput"] > div {
        background: #f1f5f9 !important;
        border: 1.5px solid #e2e8f0 !important;
        border-radius: 14px !important;
        box-shadow: none !important;
    }
    div.login-col div[data-testid="stTextInput"] > div:focus-within {
        border-color: #4f46e5 !important;
        background: #fff !important;
        box-shadow: 0 0 0 3.5px rgba(79,70,229,.13) !important;
    }
    div.login-col div[data-testid="stTextInput"] input {
        background: transparent !important;
        font-size: 1rem !important;
        color: #1e293b !important;
        border: none !important;
        box-shadow: none !important;
        padding: 15px 14px !important;
    }
    div.login-col div[data-testid="stTextInput"] input::placeholder { color:#94a3b8 !important; }
    div.login-col div[data-testid="stTextInput"] label {
        font-size: .875rem !important; font-weight: 700 !important; color: #1e293b !important;
    }

    /* Sign In button */
    div.login-col div[data-testid="stButton"] > button {
        background: #3b5bdb !important;
        border: none !important;
        border-radius: 14px !important;
        font-size: 1.08rem !important;
        font-weight: 700 !important;
        padding: 17px 0 !important;
        color: #fff !important;
        width: 100% !important;
        letter-spacing: .02em !important;
        margin-top: 6px !important;
        transition: background .2s, transform .12s !important;
    }
    div.login-col div[data-testid="stButton"] > button:hover {
        background: #2f4bc4 !important;
        transform: translateY(-2px) !important;
    }
    div[data-testid="stAlert"] { border-radius: 10px !important; }
    </style>
    """, unsafe_allow_html=True)

    # Centre column
    _, mid, _ = st.columns([1, 1.3, 1])
    with mid:
        # Mark this column so CSS can target it
        st.markdown('<div class="login-col">', unsafe_allow_html=True)

        # White card wrapper
        st.markdown("""
        <div style="
            background:white;border-radius:24px;
            padding:52px 48px 44px;
            box-shadow:0 8px 48px rgba(99,102,241,.14),0 2px 16px rgba(0,0,0,.07);
        ">
            <div style="font-size:2.4rem;font-weight:800;color:#0f172a;
                        text-align:center;letter-spacing:-0.5px;
                        font-family:Segoe UI,Arial,sans-serif;margin-bottom:8px">
                Welcome back
            </div>
            <div style="font-size:1rem;color:#64748b;text-align:center;
                        font-family:Segoe UI,Arial,sans-serif;margin-bottom:36px">
                Sign in to access your dashboard
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Error message
        _err = st.session_state.pop("_login_error", "")
        if _err:
            st.error(_err)

        # Inputs — plain widgets, no form wrapper
        username = st.text_input(
            "Username",
            placeholder="Enter your username",
            key="lf_user",
        )
        password = st.text_input(
            "Password",
            placeholder="Enter your password",
            type="password",
            key="lf_pass",
        )

        # Sign In button
        if st.button("Sign In", use_container_width=True, type="primary", key="btn_sign_in"):
            # Store credentials and flag, then rerun so handler at top fires cleanly
            st.session_state["_pending_user"]   = username
            st.session_state["_pending_pass"]   = password
            st.session_state["_do_login_now"]   = True
            st.rerun()

        # Footer
        st.markdown("""
        <div style="display:flex;align-items:center;gap:10px;margin-top:24px;
                    color:#94a3b8;font-size:.82rem;font-family:Segoe UI,Arial,sans-serif">
            <span style="flex:1;height:1px;background:#e2e8f0;display:block"></span>
            🎧 Contact your administrator if you cannot log in.
            <span style="flex:1;height:1px;background:#e2e8f0;display:block"></span>
        </div>
        """, unsafe_allow_html=True)

        st.markdown('</div>', unsafe_allow_html=True)
