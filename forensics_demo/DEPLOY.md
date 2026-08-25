# Deploying this demo build

This is the **public demo** version of the Vehicle Cyber ForenX Tool: the
private tool's password gate, machine-lock, and vault encryption have all
been removed, and the app preloads two synthetic sample cases on first
start so a visitor lands on a populated dashboard immediately. It is
meant to let someone click through the real tool's workflow and output -
not to hold real case data.

In their place, this build has its own real login/signup wall (see
`login_gate.py` and `core/accounts.py`) with a 7 day free trial per
account. Nobody reaches the dashboard without an account, and an account
past day 7 sees a "trial's up" screen instead of the tool. See **Accounts
and the 7 day trial** below before deploying.

## Why not Vercel

Vercel runs Python code as short-lived serverless functions that take one HTTP
request and return one response - it looks for a top-level `app` / `application` /
`handler` object to call. That's the exact error you saw
(`Found app.py, main.py but none export a top-level "app"...`).

Streamlit doesn't fit that shape at all, with or without a password: it's a single
long-running process that holds a persistent WebSocket connection to the browser
for as long as the tab is open, and it reruns the whole script top-to-bottom on
every click. There's no `app` object to export - the "app" *is* the process.
Removing the password doesn't change that; the mismatch is architectural, not a
setting. Vercel simply isn't a host Streamlit apps can run on.

## Where this actually deploys - Streamlit Community Cloud (free)

This folder is already set up for it: `requirements.txt`, `packages.txt`
(installs `tesseract-ocr` for OCR on image evidence), and `.streamlit/config.toml`
(theme + fonts) are all in place, so no extra config is needed.

1. Push this folder to a GitHub repo you own (public or private both work).
2. Go to **share.streamlit.io** and sign in with GitHub.
3. Click **New app**, pick the repo/branch, set the main file path to `app.py`.
4. Click **Deploy**. First boot takes a minute or two (installing dependencies +
   `tesseract-ocr`); after that it's live at a `*.streamlit.app` URL you can share
   with anyone.

Alternative if you'd rather not use GitHub: **Hugging Face Spaces** also runs
Streamlit apps directly (choose the "Streamlit" Space type) and works the same way
using this same `requirements.txt`.

## Accounts and the 7 day trial

Signups and logins are stored in a small `users` table (email, a bcrypt
password hash, and the signup date the trial clock counts from), handled
by `core/accounts.py`. Where that table lives is controlled by one
setting:

- **Nothing set (default):** it falls back to a local SQLite file at
  `data/accounts.db`. This works with zero setup, but Streamlit Community
  Cloud's free tier can reset an app's local files on a redeploy, which
  would mean losing every signup along with it.
- **A `DATABASE_URL` secret pointing at a free hosted Postgres:** accounts
  survive redeploys. Both **Neon** and **Supabase** have a genuinely free
  tier (not a trial) that's more than enough for this. Create a project on
  either, copy the connection string they give you, and add it in
  Streamlit Cloud under your app's **Settings -> Secrets** as:

  ```toml
  DATABASE_URL = "postgresql://user:password@host/dbname"
  ```

  No code change needed either way, `core/accounts.py` picks up
  `DATABASE_URL` automatically if it's set and falls back to SQLite if
  it's not.

The trial itself is just a comparison of today's date against the
account's stored signup date, checked fresh on every login, so it can't be
reset by clearing a browser or trying a different one, it's tied to the
account, not the visitor's browser.

## Seeing who's signed up

Sign up (or log in) with an email listed in `ADMIN_EMAILS` at the top of
`login_gate.py`, already set to `sakthiwati@gmail.com`, and a collapsed
**Signups** panel appears in the sidebar below the trial status line.
Opening it lists every account: name, email, signup date, and whether their
trial is still active, newest first. Nobody who signs up with any other
email ever sees this panel or knows it's there. It reads straight from the
same `users` table described above, so it works whether that table is the
local SQLite fallback or a hosted Postgres. To add another admin, add their
email (lowercase) to that same `ADMIN_EMAILS` set and redeploy.

## Locking down Streamlit's own toolbar

Streamlit's own top-right "Deploy" button and the lower half of its hamburger
menu (Clear cache, Settings, and a link into a GitHub Codespace to edit and
redeploy the app's source) are meant only for whoever manages the app, never
a visitor. Streamlit's own default ("auto") tries to detect that and
normally gets it right on Community Cloud, but `.streamlit/config.toml` in
this project pins it explicitly with `[client] toolbarMode = "viewer"`, so
every visitor sees only the plain viewer menu (Rerun, Settings, Print,
record a screencast, About) no matter who they are or how they're signed
in, no detection involved. There's nothing to change here, it's already set;
this is just so it's clear why that section of the toolbar never appears.

## Resetting the demo

The sidebar has a **Reset demo data** button - it wipes anything a visitor added
and reseeds the two original sample cases. Nothing here is destructive to any real
data, since this build never touches the private tool at all. This only resets
the case data, not accounts, those live separately in the table described above.
