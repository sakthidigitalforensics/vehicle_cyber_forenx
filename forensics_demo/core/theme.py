"""
"Midnight Sparkle" visual system - built from the Claude Design mockup
handoff (turn 2, direction 2b): a playful, pill-everything take on a dark
plum surface with neon pink/mint/purple accents, replacing the earlier
"Lab Dark" instrument-panel look. This module is the single place that
owns the exact colors/typography and the small set of reusable HTML
snippets (badges, stat tiles, the CTA card, etc.) so every stage in app.py
draws from one consistent system instead of re-inventing styling inline.

Two layers of work happen here:
  1. `inject_global_css()` - one CSS block, injected once, that reskins
     Streamlit's own native widgets (buttons, metrics, radios, the file
     uploader dropzone, alerts, tabs, expanders, dataframes, the sidebar)
     via their stable `data-testid` hooks - so real, working widgets end up
     LOOKING like the mockup (rounded pills, bottom-shadow "pressed"
     buttons, springy hover lifts) rather than being replaced by static
     HTML that would lose functionality.
  2. Small HTML-snippet builders (badge/stat_tile/status_dot/cta_card/...)
     for the purely-decorative pieces the mockup has that Streamlit has no
     native widget for at all (colored severity pills, the stat tile, the
     gradient "next step" card).

Fonts: Nunito (body) + Fredoka (headings), bundled locally under
./static/fonts/ and wired up via [[theme.fontFaces]] in
.streamlit/config.toml - see that file's comments for why this stays
offline (no Google Fonts CDN call at runtime, unlike the original mockup's
own HTML). IBM Plex Mono stays bundled too, for `st.code()` / raw log line
display where a monospace face is genuinely useful.
"""

import html as _html

# ----------------------------------------------------------------------
# Palette - keep in sync with .streamlit/config.toml's [theme] section and
# the CATEGORICAL/STATUS_COLORS constants in app.py (those drive the
# Plotly charts; this file drives everything else). Names kept stable
# (BLUE/RED/AMBER/GREEN/TEAL) even though the hues themselves moved, so
# app.py's references didn't need to change when the visual direction did.
# ----------------------------------------------------------------------

BG = "#150f24"                # page background
SIDEBAR_BG = "#1d1533"        # sidebar background
CARD_BG = "#1d1533"           # tile / card background
ROW_ALT_BG = "#1a1330"        # alternating table row
PILL_BG = "#241a3d"           # input / pill / button / unselected-stepper background
TRACK_BG = "#2a1f45"          # progress-bar track
BORDER = "#2e2348"
BORDER_ALT = "#362a58"

TEXT_PRIMARY = "#f3ebff"
TEXT_SECONDARY = "#b7a5d8"
TEXT_MUTED = "#9b86c4"
TEXT_FAINT = "#9b86c4"

BLUE = "#ff86c8"       # primary brand accent (bright pink - was blue in "Lab Dark")
BLUE_TEXT = "#ff9ecf"  # slightly lighter pink for hover/text-on-dark use
PURPLE = "#b9a0ff"     # secondary accent (evidence-files stat, hover borders)
RED = "#ff5d8f"        # High severity
AMBER = "#ffc46b"      # Medium severity / pending
GREEN = "#7ef2c9"      # Low severity (mint)
TEAL = "#7ef2c9"        # system-status mint (vault unlocked / processed / verified) - same hue as GREEN

STATUS_COLORS = {"High": RED, "Medium": AMBER, "Low": GREEN}
STATUS_ICON = {"High": "🔴", "Medium": "🟠", "Low": "🟢"}


def esc(s):
    return _html.escape(str(s), quote=True)


_esc = esc  # internal alias used throughout this module


# ----------------------------------------------------------------------
# Global CSS - reskins native Streamlit widgets via their data-testid hooks.
# ----------------------------------------------------------------------

def inject_global_css():
    return f"""
<style>
:root {{
  --sf-bg: {BG}; --sf-sidebar-bg: {SIDEBAR_BG}; --sf-card-bg: {CARD_BG};
  --sf-border: {BORDER}; --sf-border-alt: {BORDER_ALT}; --sf-track: {TRACK_BG};
  --sf-text: {TEXT_PRIMARY}; --sf-text-2: {TEXT_SECONDARY}; --sf-muted: {TEXT_MUTED};
  --sf-pink: {BLUE}; --sf-purple: {PURPLE}; --sf-red: {RED}; --sf-amber: {AMBER}; --sf-mint: {GREEN};
}}

/* Heading font utility + mono utility for the raw/technical bits (hashes,
   log lines) that still benefit from a fixed-width face even in an
   otherwise playful, non-monospace visual system. */
.sf-heading {{ font-family:"Fredoka",system-ui,sans-serif; }}
.sf-mono {{ font-family:"IBM Plex Mono",ui-monospace,monospace; }}
.sf-label {{ font:800 10.5px "Nunito",sans-serif; color:{TEXT_MUTED};
             letter-spacing:.08em; text-transform:uppercase; }}

/* ---------------- Sidebar ---------------- */
[data-testid="stSidebar"] {{ border-right:1px solid {BORDER}; }}
[data-testid="stSidebar"] [data-testid="stBaseButton-secondary"] {{
  background:{PILL_BG}; border:1.5px solid {BORDER_ALT}; color:{TEXT_SECONDARY};
  border-radius:16px; font-weight:700;
}}
[data-testid="stSidebar"] [data-testid="stSelectbox"] > div > div {{
  background:{PILL_BG}; border-color:{BORDER_ALT}; border-radius:16px;
}}
[data-testid="stSidebar"] [data-testid="stCaptionContainer"] {{ color:{TEXT_MUTED}; }}

/* ---------------- Buttons - pill shape, bottom-shadow "pressed" 3D --- */
[data-testid="stBaseButton-primary"] {{
  background:{BLUE}; border:none; color:#2a1030; font-weight:800;
  border-radius:16px; box-shadow:0 4px 0 #d94f8b;
  transition:transform .12s ease, box-shadow .12s ease;
}}
[data-testid="stBaseButton-primary"]:hover {{ transform:translateY(-2px); box-shadow:0 6px 0 #d94f8b; }}
[data-testid="stBaseButton-primary"]:active {{ transform:translateY(3px); box-shadow:0 1px 0 #d94f8b; }}
[data-testid="stBaseButton-secondary"] {{
  background:{PILL_BG}; border:1.5px solid {BORDER_ALT}; color:{TEXT_SECONDARY};
  border-radius:16px; font-weight:700; transition:transform .12s ease, border-color .12s ease;
}}
[data-testid="stBaseButton-secondary"]:hover {{ transform:translateY(-2px); border-color:{BLUE}; color:{BLUE_TEXT}; }}

/* ---------------- Stat tiles (st.metric reskinned as a bordered tile) --- */
[data-testid="stMetric"] {{
  background:{CARD_BG}; border:1.5px solid {BORDER}; border-radius:20px;
  padding:16px 18px 14px; transition:transform .14s ease, border-color .14s ease;
}}
[data-testid="stMetric"]:hover {{ transform:translateY(-4px); border-color:{PURPLE}; }}
[data-testid="stMetricLabel"] p {{
  font:800 10.5px "Nunito",sans-serif !important; color:{TEXT_MUTED} !important;
  letter-spacing:.08em; text-transform:uppercase;
}}
[data-testid="stMetricValue"] {{
  font-family:"Fredoka",system-ui,sans-serif !important;
  font-size:32px !important; font-weight:600 !important;
}}
[data-testid="stMetricDelta"] svg {{ display:none; }}

/* ---------------- Radio-as-segmented-control (time-range filter etc.) -- */
[data-testid="stRadio"] [data-testid="stRadioGroup"] {{ gap:6px; }}
[data-testid="stRadio"] label {{
  font:700 12.5px "Nunito",sans-serif; color:{TEXT_SECONDARY};
}}

/* ---------------- File uploader dropzone -------------------------------- */
[data-testid="stFileUploaderDropzone"] {{
  background:linear-gradient(180deg, rgba(255,134,200,.08), rgba(185,160,255,.04));
  border:2.5px dashed #4a3a72 !important; border-radius:24px;
}}

/* ---------------- Alerts / expanders / tabs / dataframe ----------------- */
[data-testid="stAlert"] {{ border-radius:16px; }}
[data-testid="stExpander"] {{
  border:1.5px solid {BORDER}; border-radius:18px; background:{CARD_BG};
}}
[data-testid="stTabs"] button[role="tab"] {{
  font:700 12.5px "Nunito",sans-serif; color:{TEXT_MUTED};
}}
[data-testid="stTabs"] button[aria-selected="true"] {{ color:{BLUE_TEXT}; }}
[data-testid="stDataFrame"] {{ border:1.5px solid {BORDER}; border-radius:16px; overflow:hidden; }}

/* ---------------- Bordered containers (st.container(border=True)) ------ */
[data-testid="stVerticalBlockBorderWrapper"] {{ border-radius:20px !important; }}

/* ---------------- Custom badge pills (no native Streamlit equivalent) -- */
.sf-badge {{
  display:inline-flex; align-items:center; gap:5px; padding:4px 11px;
  border-radius:999px; font:800 10.5px "Nunito",sans-serif; letter-spacing:.02em;
  white-space:nowrap;
}}
.sf-badge-high    {{ background:rgba(255,93,143,.18); border:1.5px solid rgba(255,93,143,.5); color:{RED}; }}
.sf-badge-medium  {{ background:rgba(255,196,107,.16); border:1.5px solid rgba(255,196,107,.45); color:{AMBER}; }}
.sf-badge-low     {{ background:rgba(126,242,201,.14); border:1.5px solid rgba(126,242,201,.4);  color:{GREEN}; }}
.sf-badge-neutral {{ background:{PILL_BG}; border:1.5px solid {BORDER_ALT}; color:{TEXT_SECONDARY}; }}
.sf-badge-blue    {{ background:rgba(185,160,255,.16); border:1.5px solid rgba(185,160,255,.45); color:{PURPLE}; }}
.sf-badge-success {{ background:rgba(126,242,201,.14); border:1.5px solid rgba(126,242,201,.4); color:{GREEN}; }}

.sf-status-dot {{
  display:inline-flex; align-items:center; gap:6px; font:800 10.5px "Nunito",sans-serif;
  color:{TEAL}; letter-spacing:.04em;
}}
.sf-status-dot .dot {{
  width:8px; height:8px; border-radius:50%; background:{TEAL};
  box-shadow:0 0 0 4px rgba(126,242,201,.16);
}}

/* ---------------- Card / CTA / pattern-row building blocks -------------- */
.sf-card {{
  background:{CARD_BG}; border:1.5px solid {BORDER}; border-radius:20px; padding:17px 19px;
}}
.sf-cta {{
  padding:22px; border-radius:20px; display:flex; flex-direction:column; gap:9px;
  background:linear-gradient(150deg,{BLUE} 0%,{PURPLE} 100%);
  color:#2a1030;
}}
.sf-pattern-row {{
  display:flex; align-items:center; gap:12px; padding:13px 15px; border-radius:16px;
  background:{PILL_BG}; border:1.5px solid {BORDER_ALT}; font-size:13px; font-weight:700;
  transition:transform .12s ease, border-color .12s ease;
}}
.sf-pattern-row:hover {{ transform:translateX(4px); }}
.sf-pattern-row .dot {{ width:10px; height:10px; border-radius:50%; flex:none; }}
.sf-pattern-row .count {{ font:700 11px "Nunito",sans-serif; color:{TEXT_MUTED}; }}

/* ---------------- Custom evidence table --------------------------------- */
.sf-table {{ border:1.5px solid {BORDER}; border-radius:20px; overflow:hidden; }}
.sf-table-head, .sf-table-row {{
  display:grid; gap:12px; padding:12px 16px; font-size:12.5px; align-items:center;
}}
.sf-table-head {{
  background:#211937; font:800 10.5px "Nunito",sans-serif; color:{TEXT_MUTED};
  letter-spacing:.08em; text-transform:uppercase;
}}
.sf-table-row {{ border-top:1px solid {BORDER}; font-weight:700; transition:transform .12s ease; }}
.sf-table-row:hover {{ transform:translateX(4px); }}
.sf-table-row:nth-child(even) {{ background:{ROW_ALT_BG}; }}
.sf-table-row:nth-child(odd) {{ background:{CARD_BG}; }}
.sf-hash {{ font:400 11px "IBM Plex Mono",monospace; color:{TEXT_MUTED}; }}
</style>
"""


# ----------------------------------------------------------------------
# Reusable HTML snippet builders
# ----------------------------------------------------------------------

def badge(text, kind="neutral"):
    """kind: high | medium | low | neutral | blue | success"""
    return f'<span class="sf-badge sf-badge-{kind}">{_esc(text)}</span>'


def severity_badge(severity):
    kind = {"High": "high", "Medium": "medium", "Low": "low"}.get(severity, "neutral")
    return badge(severity.upper(), kind)


def status_dot(text):
    return f'<span class="sf-status-dot"><span class="dot"></span>{_esc(text)}</span>'


def stat_tile(label, value, delta_text=None, delta_color=None, progress_pct=None, accent=None):
    """
    A rounded stat tile matching the mockup - used on the Dashboard in
    place of a bare st.metric. `progress_pct` (0-100) renders a thin pill
    progress bar instead of/alongside the delta line. `accent` (a hex
    color, e.g. theme.RED) tints the border and label/value for a callout
    tile like "High-severity patterns".
    """
    delta_html = ""
    if delta_text:
        color = delta_color or TEXT_MUTED
        delta_html = f'<div style="font-size:12px;font-weight:700;color:{color};margin-top:2px">{_esc(delta_text)}</div>'
    bar_html = ""
    if progress_pct is not None:
        pct = max(0, min(100, progress_pct))
        bar_html = (
            f'<div style="height:9px;background:{TRACK_BG};border-radius:999px;margin-top:7px">'
            f'<div style="width:{pct}%;height:100%;background:linear-gradient(90deg,#7ef2c9,#41d3a3);border-radius:999px"></div></div>'
        )
    border = f"1.5px solid {accent}66" if accent else f"1.5px solid {BORDER}"
    label_color = accent or TEXT_MUTED
    value_color = accent or TEXT_PRIMARY
    return (
        f'<div class="sf-card" style="display:flex;flex-direction:column;gap:5px;border:{border}">'
        f'<div class="sf-label" style="color:{label_color}">{_esc(label)}</div>'
        f'<div class="sf-heading" style="font-size:34px;font-weight:600;line-height:1;color:{value_color}">{_esc(value)}</div>'
        f'{delta_html}{bar_html}</div>'
    )


def cta_card(kicker, headline, body, button_label):
    return (
        f'<div class="sf-cta">'
        f'<div class="sf-label" style="color:#2a1030;opacity:.75">{_esc(kicker)}</div>'
        f'<div class="sf-heading" style="font-size:23px;font-weight:600;line-height:1.2">{_esc(headline)}</div>'
        f'<div style="font-size:12px;color:#3d1f42;opacity:.85;line-height:1.55">{_esc(body)}</div>'
        f'</div>'
    )


def pattern_row(severity, text, count_label):
    color = STATUS_COLORS.get(severity, TEXT_MUTED)
    return (
        f'<div class="sf-pattern-row">'
        f'<span class="dot" style="background:{color}"></span>'
        f'<span style="flex:1">{_esc(text)}</span>'
        f'<span class="count">{_esc(count_label)}</span></div>'
    )


def evidence_table_html(columns, rows):
    """
    columns: list of header strings. rows: list of lists of already-escaped
    HTML cell strings (caller controls formatting/coloring per cell).
    """
    grid_style = f'grid-template-columns:{" ".join(["1fr"] * len(columns))};'
    head = "".join(f"<span>{_esc(c)}</span>" for c in columns)
    body = "".join(
        f'<div class="sf-table-row" style="{grid_style}">' + "".join(f"<span>{cell}</span>" for cell in row) + "</div>"
        for row in rows
    )
    return f'<div class="sf-table"><div class="sf-table-head" style="{grid_style}">{head}</div>{body}</div>'
