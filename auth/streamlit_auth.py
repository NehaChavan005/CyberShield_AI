import jwt
import streamlit as st

from auth.security import create_access_token, decode_access_token
from auth.store import authenticate_user, create_user, get_user


AUTH_BRAND_HTML = """
<div class="auth-title">
  <span class="auth-title-icon" aria-hidden="true">
    <svg viewBox="0 0 64 64" role="img" focusable="false">
      <defs>
        <linearGradient id="shieldOuter" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#00ffff"></stop>
          <stop offset="100%" stop-color="#00ff9f"></stop>
        </linearGradient>
        <linearGradient id="shieldInner" x1="20%" y1="10%" x2="80%" y2="90%">
          <stop offset="0%" stop-color="#0f4667"></stop>
          <stop offset="100%" stop-color="#09263a"></stop>
        </linearGradient>
      </defs>
      <path fill="url(#shieldOuter)" d="M32 4 9 13v17.2c0 15.5 8.9 24.8 23 29.8 14.1-5 23-14.3 23-29.8V13L32 4Z"/>
      <path fill="url(#shieldInner)" d="M32 10.5 14.5 17v12.9c0 11.8 6.5 19.6 17.5 23.9 11-4.3 17.5-12.1 17.5-23.9V17L32 10.5Z"/>
      <path fill="#9fffe7" d="m27.9 35.9-5.1-5.1-3.2 3.2 8.1 8.1L44.4 25.4l-3.2-3.2-13.3 13.7Z"/>
    </svg>
  </span>
  <span>CyberShield-AI</span>
</div>
"""


def _initialize_auth_state() -> None:
    st.session_state.setdefault("auth_token", None)
    st.session_state.setdefault("current_user", None)
    st.session_state.setdefault("auth_page", "Sign In")


def get_authenticated_user() -> dict | None:
    _initialize_auth_state()

    if st.session_state["auth_token"]:
        try:
            payload = decode_access_token(st.session_state["auth_token"])
            username = payload.get("sub")
            user = get_user(username)
            if user:
                st.session_state["current_user"] = {
                    "username": user.get("username"),
                    "full_name": user.get("full_name"),
                }
                return st.session_state["current_user"]
        except jwt.PyJWTError:
            pass

    st.session_state["auth_token"] = None
    st.session_state["current_user"] = None
    return None


def login_form() -> dict | None:
    user = get_authenticated_user()
    if user:
        return user

    st.markdown('<div class="auth-shell">', unsafe_allow_html=True)
    st.markdown(AUTH_BRAND_HTML, unsafe_allow_html=True)
    st.markdown('<div class="auth-card-title">Sign In</div>', unsafe_allow_html=True)
    st.caption("Access your SOC workspace with your existing analyst account.")
    with st.form("login_form", clear_on_submit=False):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login", use_container_width=True)

    if submitted:
        user = authenticate_user(username, password)
        if user is None:
            st.error("Invalid username or password.")
            st.markdown("</div>", unsafe_allow_html=True)
            return None

        st.session_state["auth_token"] = create_access_token(user["username"])
        st.session_state["current_user"] = user
        st.success("Login successful.")
        st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)
    return None


def signup_form() -> None:
    _initialize_auth_state()
    st.markdown('<div class="auth-shell">', unsafe_allow_html=True)
    st.markdown(AUTH_BRAND_HTML, unsafe_allow_html=True)
    st.markdown('<div class="auth-card-title">Create Account</div>', unsafe_allow_html=True)
    st.caption("Register a new CyberShield-AI analyst account.")
    with st.form("signup_form", clear_on_submit=True):
        full_name = st.text_input("Full Name")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")
        submitted = st.form_submit_button("Register", use_container_width=True)

    if submitted:
        if password != confirm_password:
            st.error("Passwords do not match.")
            st.markdown("</div>", unsafe_allow_html=True)
            return

        success, message = create_user(username, full_name, password)
        if success:
            st.success(message)
            st.session_state["auth_page"] = "Sign In"
        else:
            st.error(message)
    st.markdown("</div>", unsafe_allow_html=True)


def auth_page() -> dict | None:
    user = get_authenticated_user()
    if user:
        return user

    choice = st.sidebar.radio(
        "Access",
        ["Sign In", "Sign Up"],
        index=0 if st.session_state.get("auth_page") == "Sign In" else 1,
        label_visibility="collapsed",
    )
    st.session_state["auth_page"] = choice

    if choice == "Sign In":
        return login_form()

    signup_form()
    return None


def require_login() -> dict | None:
    user = auth_page()
    if user is None:
        st.stop()
    return user


def logout_button() -> None:
    if st.button("Log Out", use_container_width=True):
        st.session_state["auth_token"] = None
        st.session_state["current_user"] = None
        st.session_state["auth_page"] = "Sign In"
        st.rerun()


def open_signup_page() -> None:
    _initialize_auth_state()
    st.session_state["auth_page"] = "Sign Up"
