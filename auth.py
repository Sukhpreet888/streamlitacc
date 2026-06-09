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
    Pixel-perfect login card — everything (title, inputs, button, footer)
    lives inside one white card rendered via st.components.v1.html.
    The form posts to a tiny hidden Streamlit form via postMessage so the
    submit triggers a real Streamlit rerun with the credentials.
    """

    # ── Show error from previous attempt ─────────────────────────────────────
    err_msg = st.session_state.pop("_login_error", "")

    # ── Streamlit hidden form — receives values from the HTML card ────────────
    # We keep it invisible; the HTML card's JS fills the hidden inputs and
    # clicks the hidden submit button via DOM manipulation inside the iframe.
    # Better approach: use st.query_params to pass credentials from JS.
    qp = st.query_params
    if "lgu" in qp and "lgp" in qp:
        u = qp.get("lgu", "").strip()
        p = qp.get("lgp", "").strip()
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

    # ── Page CSS: gradient bg, hide chrome ───────────────────────────────────
    st.markdown("""
    <style>
    #MainMenu,footer,header,[data-testid="stToolbar"],[data-testid="stDecoration"]
        { visibility:hidden !important; display:none !important; }
    .stApp {
        background: linear-gradient(135deg,#dbeafe 0%,#e0e7ff 55%,#ede9fe 100%) !important;
    }
    .block-container { padding:0 !important; max-width:100% !important; }
    /* Hide the error/warning above the component */
    </style>
    """, unsafe_allow_html=True)

    # Show error banner if any
    if err_msg:
        _, mc, _ = st.columns([1,1.2,1])
        with mc:
            st.error(err_msg)

    # ── Full card as one HTML component ──────────────────────────────────────
    import streamlit.components.v1 as components

    # Pass error into the card so it shows inline too (belt-and-suspenders)
    err_html = f'<div class="err-box">{err_msg}</div>' if err_msg else ''

    card_html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  html, body {{
    width: 100%; height: 100%;
    font-family: 'Segoe UI', system-ui, Arial, sans-serif;
    background: transparent;
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 540px;
  }}

  .card {{
    background: #ffffff;
    border-radius: 24px;
    padding: 56px 52px 44px;
    width: 100%;
    max-width: 600px;
    box-shadow: 0 8px 48px rgba(99,102,241,.14), 0 2px 16px rgba(0,0,0,.07);
    text-align: center;
  }}

  .card h1 {{
    font-size: 2.5rem;
    font-weight: 800;
    color: #0f172a;
    letter-spacing: -0.5px;
    margin-bottom: 10px;
  }}

  .subtitle {{
    font-size: 1rem;
    color: #64748b;
    margin-bottom: 40px;
  }}

  .field {{
    text-align: left;
    margin-bottom: 20px;
  }}

  .field label {{
    display: block;
    font-size: 0.88rem;
    font-weight: 700;
    color: #1e293b;
    margin-bottom: 8px;
    letter-spacing: 0.01em;
  }}

  .input-row {{
    display: flex;
    align-items: center;
    background: #f1f5f9;
    border: 1.5px solid #e2e8f0;
    border-radius: 14px;
    padding: 0 16px;
    transition: border-color .2s, box-shadow .2s, background .2s;
  }}
  .input-row:focus-within {{
    border-color: #4f46e5;
    background: #fff;
    box-shadow: 0 0 0 3.5px rgba(79,70,229,.13);
  }}

  .input-row svg {{ flex-shrink: 0; opacity: 0.45; }}

  .input-row input {{
    flex: 1;
    border: none;
    background: transparent;
    padding: 15px 12px;
    font-size: 1rem;
    color: #1e293b;
    outline: none;
    font-family: inherit;
  }}
  .input-row input::placeholder {{ color: #94a3b8; }}

  .eye-btn {{
    background: none; border: none; cursor: pointer;
    opacity: 0.45; display: flex; align-items: center;
    padding: 0; transition: opacity .2s;
  }}
  .eye-btn:hover {{ opacity: 0.8; }}

  .btn-sign-in {{
    width: 100%;
    background: #3b5bdb;
    color: #fff;
    border: none;
    border-radius: 14px;
    padding: 17px;
    font-size: 1.08rem;
    font-weight: 700;
    cursor: pointer;
    margin-top: 10px;
    letter-spacing: .02em;
    transition: background .2s, transform .12s, box-shadow .2s;
  }}
  .btn-sign-in:hover {{
    background: #2f4bc4;
    transform: translateY(-2px);
    box-shadow: 0 8px 24px rgba(59,91,219,.32);
  }}
  .btn-sign-in:active {{ transform: translateY(0); }}

  .footer-row {{
    display: flex; align-items: center; gap: 10px;
    margin-top: 28px; color: #94a3b8; font-size: 0.82rem;
  }}
  .footer-row::before, .footer-row::after {{
    content: ''; flex: 1; height: 1px; background: #e2e8f0;
  }}

  .err-box {{
    background: #fef2f2; color: #b91c1c;
    border: 1px solid #fecaca; border-radius: 10px;
    padding: 10px 16px; margin-bottom: 20px;
    font-size: 0.9rem; text-align: left;
  }}
</style>
</head>
<body>
<div class="card">
  <h1>Welcome back</h1>
  <p class="subtitle">Sign in to access your dashboard</p>

  {err_html}

  <div class="field">
    <label for="u">Username</label>
    <div class="input-row">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none"
           stroke="#6366f1" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
        <circle cx="12" cy="7" r="4"/>
      </svg>
      <input type="text" id="u" placeholder="Enter your username"
             autocomplete="username" autofocus>
    </div>
  </div>

  <div class="field">
    <label for="p">Password</label>
    <div class="input-row">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none"
           stroke="#6366f1" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <rect x="3" y="11" width="18" height="11" rx="2"/>
        <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
      </svg>
      <input type="password" id="p" placeholder="Enter your password"
             autocomplete="current-password">
      <button class="eye-btn" type="button" onclick="togglePw()" title="Show / hide">
        <svg id="eye" width="20" height="20" viewBox="0 0 24 24" fill="none"
             stroke="#475569" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
          <circle cx="12" cy="12" r="3"/>
        </svg>
      </button>
    </div>
  </div>

  <button class="btn-sign-in" onclick="doLogin()">Sign In</button>

  <div class="footer-row">🎧 Contact your administrator if you cannot log in.</div>
</div>

<script>
  function togglePw() {{
    var inp = document.getElementById('p');
    inp.type = inp.type === 'password' ? 'text' : 'password';
  }}

  function doLogin() {{
    var u = document.getElementById('u').value.trim();
    var p = document.getElementById('p').value;
    if (!u || !p) {{
      alert('Please enter both username and password.');
      return;
    }}
    // Navigate the TOP window (Streamlit parent) with query params.
    // Streamlit picks these up on the next script run.
    var url = new URL(window.parent.location.href);
    url.searchParams.set('lgu', u);
    url.searchParams.set('lgp', p);
    window.parent.location.href = url.toString();
  }}

  // Allow Enter key to submit
  document.addEventListener('keydown', function(e) {{
    if (e.key === 'Enter') doLogin();
  }});
</script>
</body>
</html>"""

    components.html(card_html, height=600, scrolling=False)
