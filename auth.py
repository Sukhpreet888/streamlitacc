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
    """Centered card login using pure Streamlit widgets styled to match the design."""

    # ── Page + card CSS ───────────────────────────────────────────────────────
    st.markdown("""
    <style>
    #MainMenu, footer, header, [data-testid="stToolbar"],
    [data-testid="stDecoration"] { visibility:hidden !important; display:none !important; }

    /* Gradient background */
    .stApp {
        background: linear-gradient(135deg,#dbeafe 0%,#e0e7ff 55%,#ede9fe 100%) !important;
        min-height: 100vh;
    }
    .block-container {
        padding-top: 40px !important;
        padding-bottom: 0 !important;
        max-width: 100% !important;
    }

    /* White card around everything in the centre column */
    div[data-testid="stVerticalBlock"] > div.login-card-inner {
        background: white;
        border-radius: 24px;
        padding: 52px 48px 40px;
        box-shadow: 0 8px 48px rgba(99,102,241,.13), 0 2px 12px rgba(0,0,0,.06);
    }

    /* Headings */
    .login-title {
        font-size: 2.35rem; font-weight: 800; color: #0f172a;
        text-align: center; letter-spacing: -.5px;
        font-family: 'Segoe UI', Arial, sans-serif;
        margin-bottom: 8px;
    }
    .login-subtitle {
        font-size: .97rem; color: #64748b; text-align: center;
        font-family: 'Segoe UI', Arial, sans-serif;
        margin-bottom: 32px;
    }

    /* Input fields */
    div[data-testid="stTextInput"] label {
        font-size: .875rem !important; font-weight: 700 !important;
        color: #1e293b !important;
    }
    div[data-testid="stTextInput"] > div {
        background: #f1f5f9 !important;
        border: 1.5px solid #e2e8f0 !important;
        border-radius: 12px !important;
        transition: border-color .2s, box-shadow .2s;
    }
    div[data-testid="stTextInput"] > div:focus-within {
        border-color: #4f46e5 !important;
        background: white !important;
        box-shadow: 0 0 0 3px rgba(79,70,229,.12) !important;
    }
    div[data-testid="stTextInput"] input {
        background: transparent !important;
        font-size: .97rem !important;
        color: #1e293b !important;
        border: none !important;
        box-shadow: none !important;
        padding: 14px 12px !important;
    }

    /* Sign In button */
    div[data-testid="stFormSubmitButton"] > button,
    div[data-testid="stButton"] > button[kind="primary"] {
        background: #3b5bdb !important;
        border: none !important;
        border-radius: 12px !important;
        font-size: 1.05rem !important;
        font-weight: 700 !important;
        padding: 14px 0 !important;
        color: white !important;
        width: 100%;
        margin-top: 6px;
        transition: background .2s, transform .1s, box-shadow .2s;
        letter-spacing: .01em;
    }
    div[data-testid="stFormSubmitButton"] > button:hover,
    div[data-testid="stButton"] > button[kind="primary"]:hover {
        background: #2f4bc4 !important;
        transform: translateY(-1px);
        box-shadow: 0 6px 20px rgba(59,91,219,.30) !important;
    }

    /* Footer divider */
    .login-footer {
        display: flex; align-items: center; gap: 10px;
        margin-top: 24px; color: #94a3b8; font-size: .82rem;
        font-family: 'Segoe UI', Arial, sans-serif;
    }
    .login-footer::before, .login-footer::after {
        content: ''; flex: 1; height: 1px; background: #e2e8f0;
    }

    /* Error / warning */
    div[data-testid="stAlert"] {
        border-radius: 10px !important; margin-top: 10px !important;
    }
    </style>
    """, unsafe_allow_html=True)

    # ── Three-column layout: blank | card | blank ─────────────────────────────
    _, mid, _ = st.columns([1, 1.1, 1])

    with mid:
        # Card top HTML (title + subtitle)
        st.markdown("""
        <div style="background:white;border-radius:24px 24px 0 0;
                    padding:52px 48px 0;
                    box-shadow:0 8px 48px rgba(99,102,241,.13),0 2px 12px rgba(0,0,0,.06);">
            <div class="login-title">Welcome</div>
            <div class="login-subtitle">Sign in to access your dashboard</div>
        </div>
        """, unsafe_allow_html=True)

        # st.form keeps username + password + button as ONE submit action —
        # pressing Enter or clicking Sign In both work, and no rerun issues.
        with st.form(key="login_form", clear_on_submit=False):
            st.markdown("""
            <div style="background:white;padding:24px 48px 0;margin-top:-1px;">
            </div>""", unsafe_allow_html=True)

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

            submitted = st.form_submit_button(
                "Sign In",
                use_container_width=True,
            )

        # Card bottom HTML (footer)
        st.markdown("""
        <div style="background:white;border-radius:0 0 24px 24px;
                    padding:0 48px 36px;
                    box-shadow:0 8px 48px rgba(99,102,241,.13),0 2px 12px rgba(0,0,0,.06);
                    margin-top:-8px;">
            <div class="login-footer">🎧 Contact your administrator if you cannot log in.</div>
        </div>
        """, unsafe_allow_html=True)

        # ── Handle submit ─────────────────────────────────────────────────────
        if submitted:
            if username and password:
                with st.spinner("Verifying…"):
                    ok, result = verify_login(username, password)
                if ok:
                    do_login(username, result)
                    st.rerun()
                else:
                    st.error(result)
            else:
                st.warning("Please enter both username and password.")
