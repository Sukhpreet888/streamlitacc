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
    Centered single card login — Welcome, inputs, button all inside one white card.
    Uses st.components to render the full card as native HTML so inputs are
    truly inside the card, then reads the submitted value via st.query_params.
    """
    import streamlit.components.v1 as components

    # ── Check if form was submitted via query params ──────────────────────────
    qp = st.query_params
    if qp.get("__login_submitted") == "1":
        u = qp.get("__u", "").strip()
        p = qp.get("__p", "").strip()
        # Clear params immediately
        st.query_params.clear()
        if u and p:
            ok, result = verify_login(u, p)
            if ok:
                do_login(u, result)
                st.rerun()
            else:
                st.session_state["_login_error"] = result
                st.rerun()
        else:
            st.session_state["_login_error"] = "Please enter both username and password."
            st.rerun()

    err_msg = st.session_state.pop("_login_error", "")

    # ── Page CSS ──────────────────────────────────────────────────────────────
    st.markdown("""
    <style>
    #MainMenu, footer, header, [data-testid="stToolbar"],
    [data-testid="stDecoration"] { visibility: hidden !important; display:none !important; }
    .stApp {
        background: linear-gradient(135deg, #dbeafe 0%, #e0e7ff 55%, #ede9fe 100%) !important;
        min-height: 100vh;
    }
    .block-container {
        padding: 0 !important;
        max-width: 100% !important;
    }
    </style>
    """, unsafe_allow_html=True)

    # ── Error banner (outside iframe, above card area) ────────────────────────
    if err_msg:
        _, mid, _ = st.columns([1, 1.2, 1])
        with mid:
            st.error(err_msg)

    # ── Full card as a single HTML component ──────────────────────────────────
    card_html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    font-family: 'Segoe UI', Arial, sans-serif;
    background: transparent;
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    padding: 20px;
  }}

  .card {{
    background: white;
    border-radius: 24px;
    padding: 52px 52px 40px;
    width: 100%;
    max-width: 580px;
    box-shadow: 0 8px 48px rgba(99,102,241,0.13), 0 2px 12px rgba(0,0,0,0.06);
    text-align: center;
  }}

  h1 {{
    font-size: 2.4rem;
    font-weight: 800;
    color: #0f172a;
    margin-bottom: 10px;
    letter-spacing: -0.5px;
  }}

  .subtitle {{
    font-size: 1rem;
    color: #64748b;
    margin-bottom: 36px;
  }}

  .field {{
    text-align: left;
    margin-bottom: 20px;
  }}

  .field label {{
    display: block;
    font-size: 0.9rem;
    font-weight: 700;
    color: #1e293b;
    margin-bottom: 8px;
  }}

  .input-wrap {{
    display: flex;
    align-items: center;
    background: #f1f5f9;
    border: 1.5px solid #e2e8f0;
    border-radius: 12px;
    padding: 0 14px;
    transition: border-color 0.2s, box-shadow 0.2s, background 0.2s;
  }}

  .input-wrap:focus-within {{
    border-color: #4f46e5;
    background: white;
    box-shadow: 0 0 0 3px rgba(79,70,229,0.12);
  }}

  .input-wrap svg {{
    flex-shrink: 0;
    opacity: 0.45;
  }}

  .input-wrap input {{
    flex: 1;
    border: none;
    background: transparent;
    padding: 14px 10px;
    font-size: 1rem;
    color: #1e293b;
    outline: none;
    font-family: inherit;
  }}

  .input-wrap input::placeholder {{
    color: #94a3b8;
  }}

  .toggle-pw {{
    cursor: pointer;
    opacity: 0.45;
    background: none;
    border: none;
    padding: 0;
    display: flex;
    align-items: center;
    transition: opacity 0.2s;
  }}
  .toggle-pw:hover {{ opacity: 0.75; }}

  .btn-signin {{
    width: 100%;
    background: #3b5bdb;
    color: white;
    border: none;
    border-radius: 12px;
    padding: 16px;
    font-size: 1.05rem;
    font-weight: 700;
    cursor: pointer;
    margin-top: 8px;
    transition: background 0.2s, transform 0.1s, box-shadow 0.2s;
    letter-spacing: 0.01em;
  }}
  .btn-signin:hover {{
    background: #2f4bc4;
    transform: translateY(-1px);
    box-shadow: 0 6px 20px rgba(59,91,219,0.30);
  }}
  .btn-signin:active {{
    transform: translateY(0);
  }}

  .footer-line {{
    display: flex;
    align-items: center;
    gap: 12px;
    margin-top: 28px;
    color: #94a3b8;
    font-size: 0.82rem;
  }}
  .footer-line::before,
  .footer-line::after {{
    content: '';
    flex: 1;
    height: 1px;
    background: #e2e8f0;
  }}
</style>
</head>
<body>
<div class="card">
  <h1>Welcome</h1>
  <p class="subtitle">Sign in to access your dashboard</p>

  <form id="loginForm">
    <div class="field">
      <label for="uname">Username</label>
      <div class="input-wrap">
        <!-- person icon -->
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none"
             stroke="#6366f1" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
          <circle cx="12" cy="7" r="4"/>
        </svg>
        <input type="text" id="uname" name="uname"
               placeholder="Enter your username" autocomplete="username" required>
      </div>
    </div>

    <div class="field">
      <label for="pw">Password</label>
      <div class="input-wrap">
        <!-- lock icon -->
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none"
             stroke="#6366f1" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
        </svg>
        <input type="password" id="pw" name="pw"
               placeholder="Enter your password" autocomplete="current-password" required>
        <button type="button" class="toggle-pw" onclick="togglePw()" title="Show/hide password">
          <svg id="eye-icon" width="20" height="20" viewBox="0 0 24 24" fill="none"
               stroke="#475569" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
            <circle cx="12" cy="12" r="3"/>
          </svg>
        </button>
      </div>
    </div>

    <button type="submit" class="btn-signin">Sign In</button>
  </form>

  <div class="footer-line">
    <span>🎧 Contact your administrator if you cannot log in.</span>
  </div>
</div>

<script>
  function togglePw() {{
    var inp = document.getElementById('pw');
    inp.type = inp.type === 'password' ? 'text' : 'password';
  }}

  document.getElementById('loginForm').addEventListener('submit', function(e) {{
    e.preventDefault();
    var u = document.getElementById('uname').value.trim();
    var p = document.getElementById('pw').value;
    if (!u || !p) return;
    // Submit by redirecting with query params that Streamlit reads
    var params = new URLSearchParams(window.location.search);
    params.set('__login_submitted', '1');
    params.set('__u', u);
    params.set('__p', p);
    window.parent.location.search = params.toString();
  }});
</script>
</body>
</html>
"""

    components.html(card_html, height=620, scrolling=False)
