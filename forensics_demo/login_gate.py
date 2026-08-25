"""
Login/signup wall for the public demo, sitting in front of everything else.

This is intentionally separate from core/auth.py, which is the private
tool's single laptop password and machine lock gate and has nothing to do
with multiple people signing up. This one is an ordinary account system:
real accounts in core/accounts.py, and a 7 day trial clock per account.

How staying signed in works: the token lives in the page's own URL query
string (st.query_params), which Streamlit reads straight off the request.
That's what makes a login or signup show the dashboard immediately in the
same run, and it's also what a bookmarked link with that token in it would
skip straight past. A plain new visit to the bare URL asks for email and
password again, the same as any ordinary site without a "remember me"
cookie. Two browser-cookie based approaches for that convenience were
tried and dropped before landing here: injecting a bit of JS into a
components.html iframe to read a cookie back runs into Chromium's iframe
sandboxing (it blocks that iframe from moving the top-level page to a new
URL, which reading the cookie back that way depends on), and the
streamlit-cookies-manager package never got its "ready" component to
report back on this Streamlit version, its underlying st.cache usage is
out of date for it. Neither is worth the fragility for what's ultimately a
convenience, not the actual security boundary, that boundary is the
account and the trial clock, both fully server side either way.

Call require_login() once, right after st.set_page_config() and the CSS
injection. It either returns a dict describing who's signed in, or renders
the login/signup form (or the trial-expired screen) and stops the script
right there, so nothing below it runs for a visitor who isn't let in yet.
"""

import streamlit as st

from core import accounts, theme

QUERY_KEY = "vcf_s"
CONTACT_EMAIL = "sakthi.derbyuni.uk@gmail.com"

# Whoever signs in with one of these emails gets an extra "Signups" panel in
# the sidebar (see render_admin_panel below) on top of the ordinary demo,
# nobody else ever sees it or knows it exists. Sign up/log in with this same
# email through the normal form below to get in, there's no separate admin
# login.
ADMIN_EMAILS = {"sakthiwati@gmail.com"}


def _start_session(email):
    """Establish the session and hand back the now-logged-in user. Setting
    query_params is synchronous in Python, so the caller can carry
    straight on into the dashboard this same run, no rerun needed."""
    token, _expires = accounts.create_session(email)
    st.query_params[QUERY_KEY] = token
    user = accounts.get_user(email)
    st.session_state["_vcf_user"] = user
    return user


def _logout(email):
    accounts.clear_session(email)
    st.query_params.pop(QUERY_KEY, None)
    st.session_state.pop("_vcf_user", None)
    st.rerun()


def _header():
    st.markdown(
        f"""
        <div style="text-align:center;margin:40px 0 18px;">
          <div style="font-size:26px;font-weight:800;color:{theme.TEXT_PRIMARY};">
            Vehicle Cyber ForenX Tool
          </div>
          <div style="color:{theme.TEXT_SECONDARY};font-size:14.5px;margin-top:6px;">
            Sign in or create a free account to open the live demo.
            A new account gets a 7 day free trial, no card needed.
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_login_signup():
    """Renders the login/signup form and stops the script right after, so
    a visitor who isn't logged in never sees anything below this. On a
    successful submission it reruns immediately instead of rendering
    anything further, otherwise the freshly-drawn form widgets and
    whatever comes next (the dashboard, or the trial-expired screen) would
    both end up on the page at once."""
    _, mid, _ = st.columns([1, 1.3, 1])
    with mid:
        _header()
        login_tab, signup_tab = st.tabs(["Log in", "Sign up"])

        with login_tab:
            with st.form("vcf_login_form", clear_on_submit=False):
                email = st.text_input("Email")
                password = st.text_input("Password", type="password")
                submitted = st.form_submit_button("Log in", use_container_width=True, type="primary")
            if submitted:
                if not email or not password:
                    st.error("Enter both your email and password.")
                else:
                    try:
                        user = accounts.verify_login(email, password)
                    except accounts.InvalidLoginError as e:
                        st.error(str(e))
                    else:
                        _start_session(user["email"])
                        st.rerun()

        with signup_tab:
            with st.form("vcf_signup_form", clear_on_submit=False):
                name = st.text_input("Name", key="vcf_signup_name")
                email2 = st.text_input("Email", key="vcf_signup_email")
                password2 = st.text_input("Password", type="password", key="vcf_signup_password")
                st.caption("That's it, no card and no company details needed to try it out.")
                submitted2 = st.form_submit_button("Create free account", use_container_width=True, type="primary")
            if submitted2:
                try:
                    accounts.create_user(name, email2, password2)
                except (accounts.AccountExistsError, ValueError) as e:
                    st.error(str(e))
                else:
                    _start_session(email2)
                    st.rerun()

        st.markdown(
            f"""<div style="text-align:center;margin-top:22px;color:{theme.TEXT_MUTED};font-size:13px;">
            Questions first? <a href="mailto:{CONTACT_EMAIL}" style="color:{theme.BLUE};">{CONTACT_EMAIL}</a>
            </div>""",
            unsafe_allow_html=True,
        )
    st.stop()


def _trial_expired_screen(user):
    _, mid, _ = st.columns([1, 1.3, 1])
    with mid:
        st.markdown(
            f"""
            <div style="text-align:center;margin:60px 0 18px;">
              <div style="font-size:40px;">⏳</div>
              <div style="font-size:22px;font-weight:800;color:{theme.TEXT_PRIMARY};margin-top:10px;">
                Your 7 day free trial has ended
              </div>
              <div style="color:{theme.TEXT_SECONDARY};font-size:14.5px;margin-top:8px;">
                Thanks for trying out the demo, {user["name"]}. Reach out below and we'll help
                you keep going.
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.link_button(f"Email {CONTACT_EMAIL}", f"mailto:{CONTACT_EMAIL}", use_container_width=True, type="primary")
        if st.button("Log out", use_container_width=True):
            _logout(user["email"])
    st.stop()


def require_login():
    """Gate everything below this call behind a real account and a 7 day trial."""
    accounts.init_db()

    user = st.session_state.get("_vcf_user")

    if not user:
        token = st.query_params.get(QUERY_KEY)
        user = accounts.get_user_by_session_token(token) if token else None
        if user:
            st.session_state["_vcf_user"] = user

    if not user:
        _render_login_signup()  # stops the script here; a fresh login/signup reruns instead of returning

    days_left = accounts.days_remaining(user["signup_date"])
    if days_left <= 0:
        _trial_expired_screen(user)

    return {
        "email": user["email"],
        "name": user["name"],
        "days_left": days_left,
        "is_admin": user["email"] in ADMIN_EMAILS,
        "logout": lambda: _logout(user["email"]),
    }


def render_admin_panel():
    """A plain list of every signup: name, email, signup date, trial status.
    Call this from app.py only inside `if viewer["is_admin"]`, it has no
    gating of its own, it just renders. Meant to sit in the sidebar behind a
    collapsed expander so it stays out of the way on every ordinary visit."""
    users = accounts.list_users()
    st.caption(f"{len(users)} signup{'s' if len(users) != 1 else ''} total")
    for u in users:
        days_left = accounts.days_remaining(u["signup_date"])
        active = days_left > 0
        status_color = theme.GREEN if active else theme.TEXT_MUTED
        status_text = f"{days_left} day{'s' if days_left != 1 else ''} left" if active else "trial ended"
        st.markdown(
            f"""
            <div style="padding:8px 0;border-bottom:1px solid {theme.BORDER};">
              <div style="color:{theme.TEXT_PRIMARY};font-weight:700;font-size:13px;">{u['name']}</div>
              <div style="color:{theme.TEXT_SECONDARY};font-size:12px;">{u['email']}</div>
              <div style="color:{theme.TEXT_MUTED};font-size:11px;margin-top:2px;">
                signed up {u['signup_date'].strftime('%d %b %Y')} ·
                <span style="color:{status_color};">{status_text}</span>
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
