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
    Login page using st.form — 100% reliable submission.
    CSS makes the Streamlit form container look exactly like the white card mockup.
    """

    st.markdown("""
    <style>
    /* ── Hide all Streamlit chrome ──────────────────────── */
    #MainMenu, footer, header,
    [data-testid="stToolbar"],
    [data-testid="stDecoration"],
    [data-testid="stStatusWidget"]
        { visibility: hidden !important; display: none !important; }

    /* ── Full page gradient background ─────────────────── */
    .stApp {
        background: linear-gradient(135deg, #dbeafe 0%, #e0e7ff 55%, #ede9fe 100%) !important;
        min-height: 100vh;
    }

    /* ── Remove default page padding ───────────────────── */
    .block-container {
        padding-top: 60px !important;
        padding-bottom: 0 !important;
        max-width: 100% !important;
    }

    /* ── Centre everything ──────────────────────────────── */
    section[data-testid="stMain"] > div {
        display: flex;
        justify-content: center;
    }

    /* ── White card: target the form block ──────────────── */
    [data-testid="stForm"] {
        background: #ffffff !important;
        border-radius: 24px !important;
        padding: 52px 52px 44px !important;
        box-shadow: 0 8px 48px rgba(99,102,241,.14),
                    0 2px 16px rgba(0,0,0,.07) !important;
        width: 580px !important;
        max-width: 92vw !important;
        border: none !important;
    }

    /* ── Title and subtitle above the form ─────────────── */
    .login-title {
        font-size: 2.45rem;
        font-weight: 800;
        color: #0f172a;
        text-align: center;
        letter-spacing: -0.5px;
        font-family: 'Segoe UI', Arial, sans-serif;
        margin-bottom: 8px;
        display: block;
    }
    .login-sub {
        font-size: 1rem;
        color: #64748b;
        text-align: center;
        font-family: 'Segoe UI', Arial, sans-serif;
        margin-bottom: 32px;
        display: block;
    }

    /* ── Input labels ───────────────────────────────────── */
    [data-testid="stForm"] [data-testid="stTextInput"] label {
        font-size: 0.875rem !important;
        font-weight: 700 !important;
        color: #1e293b !important;
        font-family: 'Segoe UI', Arial, sans-serif !important;
        margin-bottom: 6px !important;
    }

    /* ── Input box wrapper ──────────────────────────────── */
    [data-testid="stForm"] [data-testid="stTextInput"] > div {
        background: #f1f5f9 !important;
        border: 1.5px solid #e2e8f0 !important;
        border-radius: 14px !important;
        box-shadow: none !important;
        transition: border-color .2s, box-shadow .2s, background .2s;
    }
    [data-testid="stForm"] [data-testid="stTextInput"] > div:focus-within {
        border-color: #4f46e5 !important;
        background: #fff !important;
        box-shadow: 0 0 0 3.5px rgba(79,70,229,.13) !important;
    }

    /* ── Input text ─────────────────────────────────────── */
    [data-testid="stForm"] [data-testid="stTextInput"] input {
        background: transparent !important;
        font-size: 1rem !important;
        color: #1e293b !important;
        border: none !important;
        box-shadow: none !important;
        padding: 15px 14px !important;
        font-family: 'Segoe UI', Arial, sans-serif !important;
    }
    [data-testid="stForm"] [data-testid="stTextInput"] input::placeholder {
        color: #94a3b8 !important;
    }

    /* ── Sign In button ─────────────────────────────────── */
    [data-testid="stForm"] [data-testid="stFormSubmitButton"] > button {
        background: #3b5bdb !important;
        border: none !important;
        border-radius: 14px !important;
        font-size: 1.08rem !important;
        font-weight: 700 !important;
        padding: 17px 0 !important;
        color: #ffffff !important;
        width: 100% !important;
        margin-top: 10px !important;
        letter-spacing: .02em !important;
        transition: background .2s, transform .12s, box-shadow .2s !important;
        font-family: 'Segoe UI', Arial, sans-serif !important;
    }
    [data-testid="stForm"] [data-testid="stFormSubmitButton"] > button:hover {
        background: #2f4bc4 !important;
        transform: translateY(-2px) !important;
        box-shadow: 0 8px 24px rgba(59,91,219,.32) !important;
    }
    [data-testid="stForm"] [data-testid="stFormSubmitButton"] > button:active {
        transform: translateY(0) !important;
    }

    /* ── Error / warning alert ──────────────────────────── */
    [data-testid="stForm"] [data-testid="stAlert"] {
        border-radius: 10px !important;
        margin-top: 8px !important;
    }

    /* ── Footer divider ─────────────────────────────────── */
    .login-footer {
        display: flex;
        align-items: center;
        gap: 10px;
        margin-top: 28px;
        color: #94a3b8;
        font-size: 0.82rem;
        font-family: 'Segoe UI', Arial, sans-serif;
    }
    .login-footer::before, .login-footer::after {
        content: '';
        flex: 1;
        height: 1px;
        background: #e2e8f0;
    }
    </style>
    """, unsafe_allow_html=True)

    # ── Three-col layout: push card to centre ────────────────────────────────
    _, mid, _ = st.columns([1, 1.6, 1])
    with mid:

        # Title + subtitle sit OUTSIDE the form but inside the same column
        st.markdown("""
        <div style="
            background:white;
            border-radius:24px 24px 0 0;
            padding:52px 52px 0 52px;
            box-shadow:0 8px 48px rgba(99,102,241,.14),0 2px 16px rgba(0,0,0,.07);
            margin-bottom:-2px;
            position:relative;
            z-index:1;
        ">
            <span class="login-title">Welcome back</span>
            <span class="login-sub">Sign in to access your dashboard</span>
        </div>
        """, unsafe_allow_html=True)

        # Show any pending error ABOVE the form (survives rerun)
        err_msg = st.session_state.pop("_login_error", "")
        if err_msg:
            st.error(err_msg)

        # The st.form
        with st.form("login_form", clear_on_submit=False, border=False):
            st.markdown("""
            <style>
            section[data-testid="stMain"] [data-testid="stForm"] {
                border-radius: 0 0 24px 24px !important;
                padding-top: 28px !important;
                margin-top: 0 !important;
            }
            </style>
            """, unsafe_allow_html=True)

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

            submitted = st.form_submit_button("Sign In", use_container_width=True)

            # Footer
            st.markdown(
                '<div class="login-footer">🔒 Contact your administrator if you cannot log in.</div>',
                unsafe_allow_html=True,
            )

        # ── Handle submit (outside form block, same column scope) ────────────
        if submitted:
            _user = username.strip() if username else ""
            _pass = password.strip() if password else ""
            if _user and _pass:
                with st.spinner("Verifying…"):
                    ok, result = verify_login(_user, _pass)
                if ok:
                    do_login(_user, result)
                    st.rerun()
                else:
                    st.session_state["_login_error"] = result
                    st.rerun()
            else:
                st.session_state["_login_error"] = "Please enter both username and password."
                st.rerun()
