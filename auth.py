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
    """Render the full-screen login page. Call at the top of your app."""
    st.markdown("""
    <style>
    /* Hide Streamlit chrome on login page */
    #MainMenu, footer, header { visibility: hidden; }
    .block-container { padding-top: 0 !important; }

    .login-wrapper {
        display: flex;
        justify-content: center;
        align-items: center;
        min-height: 100vh;
        background: linear-gradient(135deg, #1e3a5f 0%, #1e40af 50%, #1d4ed8 100%);
    }
    .login-card {
        background: white;
        border-radius: 16px;
        padding: 48px 40px 40px;
        width: 100%;
        max-width: 420px;
        box-shadow: 0 25px 60px rgba(0,0,0,0.3);
    }
    .login-logo {
        text-align: center;
        margin-bottom: 8px;
    }
    .login-logo h1 {
        font-size: 2rem;
        font-weight: 800;
        color: #1e40af;
        margin: 0;
        font-family: 'Segoe UI', Arial, sans-serif;
    }
    .login-logo p {
        color: #64748b;
        font-size: 0.9rem;
        margin: 4px 0 28px;
    }
    </style>

    <div class="login-wrapper">
      <div class="login-card">
        <div class="login-logo">
          <h1>AccountSync</h1>
          <p>Reconciliation Tool — Please sign in</p>
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    # Centre the form using columns
    _, mid, _ = st.columns([1, 2, 1])
    with mid:
        st.markdown("## 🔐 Sign In")
        username = st.text_input("Username", placeholder="Enter your username", key="login_user")
        password = st.text_input("Password", placeholder="Enter your password",
                                  type="password", key="login_pass")

        if st.button("Sign In →", use_container_width=True, type="primary"):
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

        st.markdown(
            "<p style='text-align:center;color:#94a3b8;font-size:0.8rem;margin-top:16px'>"
            "Contact your administrator if you cannot log in.</p>",
            unsafe_allow_html=True,
        )
