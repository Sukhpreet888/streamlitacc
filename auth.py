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
    """Render the split-layout login page matching the AdPortal-style design."""

    st.markdown("""
    <style>
    /* ── Hide all Streamlit chrome ── */
    #MainMenu, footer, header { visibility: hidden; }
    [data-testid="stToolbar"] { display: none; }
    .block-container {
        padding: 0 !important;
        max-width: 100% !important;
    }
    section[data-testid="stMain"] > div:first-child {
        padding: 0 !important;
    }

    /* ── Full-page gradient background ── */
    .stApp {
        background: linear-gradient(135deg, #e8f0fe 0%, #dbeafe 40%, #ede9fe 100%);
        min-height: 100vh;
    }

    /* ── Outer wrapper: two columns side by side ── */
    .login-page {
        display: flex;
        align-items: center;
        justify-content: center;
        min-height: 100vh;
        padding: 40px 24px;
        gap: 80px;
    }

    /* ── Left branding panel ── */
    .login-brand {
        flex: 1;
        max-width: 480px;
    }
    .brand-logo {
        display: flex;
        align-items: center;
        gap: 14px;
        margin-bottom: 36px;
    }
    .brand-icon {
        width: 56px;
        height: 56px;
        background: #2563eb;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 1.6rem;
        color: white;
        font-weight: 800;
        flex-shrink: 0;
    }
    .brand-name {
        font-size: 2rem;
        font-weight: 800;
        color: #1e40af;
        font-family: 'Segoe UI', Arial, sans-serif;
        letter-spacing: -0.5px;
    }
    .brand-headline {
        font-size: 2.4rem;
        font-weight: 800;
        color: #0f172a;
        line-height: 1.25;
        margin-bottom: 18px;
        font-family: 'Segoe UI', Arial, sans-serif;
    }
    .brand-sub {
        font-size: 1rem;
        color: #475569;
        line-height: 1.6;
        font-family: 'Segoe UI', Arial, sans-serif;
    }

    /* ── Right card ── */
    .login-card {
        background: white;
        border-radius: 20px;
        padding: 52px 44px 44px;
        width: 100%;
        max-width: 460px;
        box-shadow: 0 8px 40px rgba(37,99,235,0.10), 0 2px 12px rgba(0,0,0,0.06);
        flex-shrink: 0;
    }
    .card-title {
        font-size: 1.85rem;
        font-weight: 800;
        color: #0f172a;
        margin: 0 0 6px;
        font-family: 'Segoe UI', Arial, sans-serif;
    }
    .card-sub {
        font-size: 0.95rem;
        color: #64748b;
        margin: 0 0 32px;
        font-family: 'Segoe UI', Arial, sans-serif;
    }
    .field-label {
        font-size: 0.875rem;
        font-weight: 600;
        color: #374151;
        margin-bottom: 6px;
        display: block;
        font-family: 'Segoe UI', Arial, sans-serif;
    }

    /* ── Style Streamlit inputs inside the card ── */
    div[data-testid="stTextInput"] input {
        border: 1.5px solid #e2e8f0 !important;
        border-radius: 10px !important;
        padding: 12px 14px 12px 40px !important;
        font-size: 0.95rem !important;
        color: #1e293b !important;
        background: #f8fafc !important;
        transition: border-color 0.2s;
    }
    div[data-testid="stTextInput"] input:focus {
        border-color: #2563eb !important;
        background: white !important;
        box-shadow: 0 0 0 3px rgba(37,99,235,0.12) !important;
    }
    div[data-testid="stTextInput"] label {
        font-size: 0.875rem !important;
        font-weight: 600 !important;
        color: #374151 !important;
    }

    /* ── Sign In button ── */
    div[data-testid="stButton"] > button[kind="primary"] {
        background: #2563eb !important;
        border: none !important;
        border-radius: 10px !important;
        font-size: 1rem !important;
        font-weight: 600 !important;
        padding: 14px !important;
        color: white !important;
        transition: background 0.2s, transform 0.1s;
        margin-top: 8px;
    }
    div[data-testid="stButton"] > button[kind="primary"]:hover {
        background: #1d4ed8 !important;
        transform: translateY(-1px);
    }

    /* ── Error / warning boxes ── */
    div[data-testid="stAlert"] {
        border-radius: 10px !important;
        margin-top: 12px !important;
    }

    /* ── Responsive: stack on small screens ── */
    @media (max-width: 768px) {
        .login-brand { display: none; }
        .login-page  { padding: 24px 16px; }
    }
    </style>

    <div class="login-page">

      <!-- LEFT: Branding -->
      <div class="login-brand">
        <div class="brand-logo">
          <div class="brand-icon">⇄</div>
          <span class="brand-name">AccountSync</span>
        </div>
        <div class="brand-headline">The Only Tool You Need for Financial Reconciliation</div>
        <div class="brand-sub">
          Upload once, reconcile everywhere. Let our smart engine match your
          debits and credits across Matched, Consecutive, Sum, and Cross match
          types — all from one unified dashboard.
        </div>
      </div>

      <!-- RIGHT: placeholder for card title (inputs rendered by Streamlit below) -->
      <div class="login-card">
        <div class="card-title">Welcome back</div>
        <div class="card-sub">Sign in to access your dashboard</div>
      </div>

    </div>
    """, unsafe_allow_html=True)

    # Streamlit inputs overlaid on the right card using columns
    # We push them into the right half with column sizing
    _, right = st.columns([1.05, 1])
    with right:
        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
        username = st.text_input(
            "Username",
            placeholder="👤  your username",
            key="login_user",
        )
        password = st.text_input(
            "Password",
            placeholder="🔒  ••••••••",
            type="password",
            key="login_pass",
        )

        # Error placeholder
        err_slot = st.empty()

        st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)
        if st.button("Sign In", use_container_width=True, type="primary", key="btn_signin"):
            if username and password:
                with st.spinner("Verifying…"):
                    ok, result = verify_login(username, password)
                if ok:
                    do_login(username, result)
                    st.rerun()
                else:
                    err_slot.error(result)
            else:
                err_slot.warning("Please enter both username and password.")

        st.markdown(
            "<p style='text-align:center;color:#94a3b8;font-size:0.82rem;"
            "margin-top:20px;font-family:Segoe UI,Arial,sans-serif'>"
            "Contact your administrator if you cannot log in.</p>",
            unsafe_allow_html=True,
        )
