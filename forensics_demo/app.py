"""
Vehicle Cyber ForenX Tool - local-only Streamlit app.
Private, custom-built tool - not a third-party product.

Runs entirely on localhost. No network calls anywhere in this app or the
underlying extraction engine - all evidence, findings, and reports stay on
this machine, encrypted at rest under ./data/.

Run with:  streamlit run app.py
"""

import os
import json
from datetime import datetime, timedelta
import streamlit as st
import plotly.graph_objects as go

from streamlit_paste_button import paste_image_button

from core import db, auth, theme
from login_gate import require_login
from core.report_generator import generate_docx, generate_pdf, FONT_CHOICES
from extractors.pipeline import run_pipeline_on_files
from analyzers.pattern_detectors import run_all_detectors
from analyzers.narrative import build_story, burst_sentence, aggregate_events, find_bursts_for_value
from analyzers.artifact_extractor import extract_email_artifacts, extract_docx_metadata, extract_image_exif

# "Midnight Sparkle" palette (core/theme.py owns the full system - fonts,
# CSS, badges, stat tiles, the CTA card). These four stay here because the
# Plotly chart code below reads them directly; everything else pulls from
# `theme` so there is exactly one source of truth for each color. Only
# CATEGORICAL[0] (pink) is actually drawn today - both Dashboard charts are
# single-series - so the rest of the list is a passive, sensibly-ordered
# fallback for any future multi-series chart, not a validated multi-hue set.
CATEGORICAL = [theme.BLUE, theme.PURPLE, theme.GREEN, theme.AMBER, theme.RED, "#41d3a3", "#9085e9", "#e66767"]
STATUS_COLORS = theme.STATUS_COLORS
STATUS_ICON = theme.STATUS_ICON
CHART_SURFACE = theme.CARD_BG
CHART_INK = theme.TEXT_PRIMARY
CHART_GRID = theme.BORDER


def confidence_label(f):
    """Email findings don't get a meaningful automated confidence score (point 7) - every other type keeps its numeric score."""
    return "-" if f["type"] == "email" else f"{f['confidence']:.2f}"


def mark_dirty():
    """Flag that something changed this run, so the vault gets resealed at the end - see the resealing block at the bottom of this file."""
    st.session_state["vault_dirty"] = True


def _plotly_layout(fig, title=None, height=320, hovermode="closest", spikes=False):
    """
    Shared chart chrome so every Dashboard chart reads as one system: dark
    surface, consistent grid/ink, and a hover box styled to match rather than
    Plotly's default white tooltip. `hovermode="x unified"` + `spikes=True`
    is the closest Plotly equivalent of the dataviz skill's "crosshair finds
    the X" rule for time-series charts - a vertical hairline tracks the
    pointer and one tooltip lists every series at that X.
    """
    fig.update_layout(
        title=(title or ""), height=height,
        paper_bgcolor=CHART_SURFACE, plot_bgcolor=CHART_SURFACE,
        font=dict(color=CHART_INK, family="Nunito, system-ui, -apple-system, Segoe UI, sans-serif"),
        margin=dict(l=10, r=10, t=40 if title else 10, b=10),
        showlegend=False,
        hovermode=hovermode,
        hoverlabel=dict(bgcolor=CHART_SURFACE, font_size=13, font_color=CHART_INK,
                         bordercolor=CHART_GRID),
    )
    fig.update_xaxes(gridcolor=CHART_GRID, zerolinecolor=CHART_GRID)
    fig.update_yaxes(gridcolor=CHART_GRID, zerolinecolor=CHART_GRID)
    if spikes:
        fig.update_xaxes(showspikes=True, spikemode="across", spikesnap="cursor",
                          spikethickness=1, spikedash="dot", spikecolor=CHART_GRID)
    return fig


st.set_page_config(page_title="Vehicle Cyber ForenX Tool", layout="wide", page_icon="🚗")
st.markdown(theme.inject_global_css(), unsafe_allow_html=True)

# --------------------------------------------------------------------------
# PUBLIC DEMO BUILD - the real tool's password/machine-lock/encrypted-vault
# gate (core/auth.py + core/vault.py) is intentionally bypassed here. That
# gate exists to guarantee case data never leaves the analyst's laptop -
# meaningless (and actively misleading) once this is hosted on someone
# else's cloud infrastructure for a public demo. This file is a separate
# copy used ONLY for the hosted demo; the private production tool this was
# copied from still has its full auth/encryption gate intact and unedited.
#
# What this demo build has instead: a real account signup/login (see
# login_gate.py + core/accounts.py) and a 7 day trial per account. That is
# a normal multi-user access control, not the private tool's single-laptop
# vault, the two are unrelated on purpose.
# --------------------------------------------------------------------------

viewer = require_login()  # stops the script here for anyone not logged in, or past their trial

st.session_state["authenticated"] = True
st.session_state["vault_key"] = None

st.warning(
    "🎭 **Public demo build** - preloaded with synthetic sample cases. "
    "This is not the private, encrypted, machine-locked tool described in the README; it exists only "
    "to show what the real tool produces. Nothing you type here is confidential - avoid entering anything sensitive.",
    icon="🎭",
)

db.init_db()
try:
    from seed_demo_data import ensure_seeded
    ensure_seeded()
except Exception as _seed_err:
    st.error(f"Demo data seeding failed: {_seed_err}")

STAGES = ["Case Details", "Upload Evidence", "Investigation Story", "Findings", "Verification", "Artifacts", "Generate Report"]
STAGE_ICONS = ["🗂️", "📤", "📖", "🔎", "✅", "🔬", "📄"]
STATUS_OPTIONS = ["Unverified", "Verified", "False Positive", "Needs Further Investigation"]
ENTITY_TYPES = ["ipv4", "ipv6", "email", "url", "domain", "hash_sha256", "hash_sha1",
                "hash_md5", "mac_address", "crypto_eth", "crypto_btc", "phone", "file_path",
                "vin", "obd_dtc"]

# --------------------------------------------------------------------------
# Sidebar - case selection, lock/exit, branding
# --------------------------------------------------------------------------

st.sidebar.markdown(
    f"""<div style="display:flex;align-items:center;gap:9px;margin-bottom:2px">
    <div style="width:30px;height:30px;border-radius:11px;background:{theme.BLUE};display:flex;
    align-items:center;justify-content:center;font:700 13px 'Fredoka',sans-serif;color:#2a1030">VC</div>
    <div class="sf-heading" style="font-size:16px;font-weight:600;letter-spacing:-.01em">Vehicle Cyber<br>ForenX Tool</div>
    </div>""",
    unsafe_allow_html=True,
)
st.sidebar.markdown(theme.status_dot("DEMO MODE · SAMPLE DATA"), unsafe_allow_html=True)
st.sidebar.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

trial_word = "day" if viewer["days_left"] == 1 else "days"
st.sidebar.caption(f"Signed in as **{viewer['name']}** · {viewer['days_left']} {trial_word} left in your trial")
if st.sidebar.button("Log out", use_container_width=True):
    viewer["logout"]()

if viewer.get("is_admin"):
    with st.sidebar.expander("👤 Signups"):
        from login_gate import render_admin_panel
        render_admin_panel()

st.sidebar.divider()

if st.sidebar.button("🔁 Reset demo data", use_container_width=True):
    from seed_demo_data import reset_and_reseed
    reset_and_reseed()
    st.session_state["nav"] = "dashboard"
    st.rerun()
st.sidebar.caption("Wipes anything you've added and restores the two original sample cases.")
st.sidebar.divider()

cases = db.list_cases()
case_labels = {f"{c['case_id']} - {c['name']}": c["case_id"] for c in cases}
options = ["(none)"] + list(case_labels.keys())
# Keep the dropdown showing whichever case is actually active (e.g. right
# after creating one on Case Details) instead of always resetting to "(none)".
current_case_id = st.session_state.get("case_id")
default_label = next((label for label, cid in case_labels.items() if cid == current_case_id), "(none)")
st.sidebar.markdown('<div class="sf-label">Active case</div>', unsafe_allow_html=True)
choice = st.sidebar.selectbox("Active case", options, index=options.index(default_label), label_visibility="collapsed")
active_case_id = case_labels.get(choice)

if active_case_id:
    if st.session_state.get("case_id") != active_case_id:
        st.session_state["nav"] = "dashboard"  # switching cases always lands you on the dashboard
    st.session_state["case_id"] = active_case_id
elif "case_id" not in st.session_state:
    st.session_state["case_id"] = None

if "nav" not in st.session_state:
    st.session_state["nav"] = "dashboard"

on_dashboard = st.session_state.get("nav") == "dashboard"
if st.sidebar.button("🏠 Dashboard", use_container_width=True,
                      type="primary" if on_dashboard else "secondary"):
    st.session_state["nav"] = "dashboard"
    st.rerun()

if st.session_state.get("case_id"):
    st.sidebar.success(f"Active case: {st.session_state['case_id']}")
else:
    st.sidebar.info("Create or select a case to begin.")

st.sidebar.divider()
st.sidebar.caption("Built by **Sakthi**\nPublic demo build - synthetic sample data only.")


def require_case():
    if not st.session_state.get("case_id"):
        st.warning("Select or create a case first (see Case Details).")
        st.stop()
    return db.get_case(st.session_state["case_id"])


def goto(target):
    st.session_state["nav"] = target
    st.rerun()


def render_stepper(current_idx):
    """The guided 'flow' nav across the top of the main content - click any step to jump, current step highlighted."""
    cols = st.columns(len(STAGES))
    for i, (col, label, icon) in enumerate(zip(cols, STAGES, STAGE_ICONS)):
        with col:
            is_current = (st.session_state.get("nav") == i)
            if st.button(f"{i + 1:02d} · {icon} {label}", key=f"step_{i}",
                         type="primary" if is_current else "secondary",
                         use_container_width=True):
                goto(i)
    st.progress((current_idx + 1) / len(STAGES))
    st.markdown(
        f"""<div style="display:flex;justify-content:space-between;margin-top:-6px;padding-bottom:6px">
        <span class="sf-label">{STAGES[current_idx].upper()}</span>
        <span class="sf-label">{current_idx + 1} OF {len(STAGES)} STAGES</span>
        </div>""",
        unsafe_allow_html=True,
    )


def render_back_next(current_idx):
    st.divider()
    col1, col2, col3 = st.columns([1, 3, 1])
    if current_idx > 0:
        if col1.button("⬅ Back", use_container_width=True):
            goto(current_idx - 1)
    if current_idx < len(STAGES) - 1:
        if col3.button("Next ➡", type="primary", use_container_width=True):
            goto(current_idx + 1)


def render_case_card(c):
    """Shared 'Lab Dark' case summary card - used on both the Dashboard's
    no-active-case list and Case Details' existing-cases list, so the two
    don't drift out of sync with each other."""
    with st.container(border=True):
        status = c.get("status") or "Open"
        badges = theme.severity_badge(c.get("severity") or "Low")
        badges += " " + theme.badge(status.upper(), "success" if status == "Closed" else "blue")
        st.markdown(
            f"""<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
            <div class="sf-heading" style="font-size:16px;font-weight:600">{theme.esc(c['case_id'])} - {theme.esc(c['name'])}</div>
            {badges}</div>""",
            unsafe_allow_html=True,
        )
        meta = f"TYPE {c.get('case_type') or '-'} · REPORTER {c.get('reporter') or '-'}"
        st.markdown(f'<div class="sf-label" style="margin-top:5px">{theme.esc(meta)}</div>', unsafe_allow_html=True)
        if c.get("story"):
            st.markdown(
                f'<div style="font-size:12.5px;color:{theme.TEXT_SECONDARY};margin-top:7px;line-height:1.5">{theme.esc(c["story"])}</div>',
                unsafe_allow_html=True,
            )


# --------------------------------------------------------------------------
# Dashboard - landing page: case health at a glance + smart "continue" jump
# --------------------------------------------------------------------------

if st.session_state.get("nav") == "dashboard":
    st.title("🏠 Dashboard")
    st.caption("Vehicle Cyber ForenX Tool - a private, local-only case workspace.")

    if not st.session_state.get("case_id"):
        st.info("No active case selected yet.")
        col1, col2 = st.columns(2)
        if col1.button("➕ Create a new case", type="primary", use_container_width=True):
            goto(0)
        if cases:
            st.subheader("Existing cases")
            for c in cases:
                render_case_card(c)
    else:
        case = db.get_case(st.session_state["case_id"])
        evidence = db.list_evidence(case["case_id"])
        findings = db.list_findings(case["case_id"])
        insights = db.list_insights(case["case_id"])
        events = db.list_events(case["case_id"])

        verified_count = len([f for f in findings if f["verification_status"] == "Verified"])
        verify_pct = int(100 * verified_count / len(findings)) if findings else 0
        high_count = len([i for i in insights if i["severity"] == "High"])
        unprocessed = len(db.list_unprocessed_evidence(case["case_id"]))

        # ------------------------------------------------------------------
        # Case header - title + severity/confidentiality badges, description,
        # right-aligned case meta - matches the "Lab Dark" mockup's header.
        # ------------------------------------------------------------------
        opened = (case.get("created_at") or "")[:10]
        head_l, head_r = st.columns([3, 1])
        with head_l:
            badges = theme.severity_badge(case.get("severity") or "Low")
            if case.get("confidentiality"):
                badges += " " + theme.badge(case["confidentiality"].upper(), "neutral")
            st.markdown(
                f"""<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
                <h1 class="sf-heading" style="margin:0;font-size:26px;font-weight:600;letter-spacing:-.01em">
                {case['case_id']} - {case['name']}</h1>{badges}</div>""",
                unsafe_allow_html=True,
            )
            if case.get("story"):
                st.markdown(f'<div style="font-size:13px;line-height:1.55;color:{theme.TEXT_FAINT};margin-top:4px">{case["story"]}</div>',
                            unsafe_allow_html=True)
        with head_r:
            meta_lines = [f"OPENED {opened}" if opened else None,
                          f"REPORTER - {case['reporter']}" if case.get("reporter") else None,
                          f"INVESTIGATOR(S) - {case['investigators']}" if case.get("investigators") else None]
            meta_html = "<br>".join(m for m in meta_lines if m)
            st.markdown(f'<div class="sf-label" style="text-align:right;line-height:1.8">{meta_html}</div>',
                        unsafe_allow_html=True)

        st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)
        t1, t2, t3, t4 = st.columns(4)
        t1.markdown(theme.stat_tile("Evidence files", len(evidence),
                                     delta_text=f"⏳ {unprocessed} pending processing" if unprocessed else None,
                                     delta_color=theme.AMBER), unsafe_allow_html=True)
        t2.markdown(theme.stat_tile("Findings", len(findings), delta_text="deduplicated indicators"),
                    unsafe_allow_html=True)
        t3.markdown(theme.stat_tile("High-severity patterns", high_count,
                                     delta_text=f"of {len(insights)} detected patterns",
                                     accent=theme.RED if high_count else None),
                    unsafe_allow_html=True)
        t4.markdown(theme.stat_tile("Verification progress", f"{verify_pct}%", progress_pct=verify_pct),
                    unsafe_allow_html=True)
        st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)

        # ------------------------------------------------------------------
        # Charts - interactive: a time-range filter scopes both, and a click
        # on either one jumps you straight to the filtered detail view
        # (Findings for a bar, that day's Timeline Story for a point) rather
        # than making you navigate + re-filter by hand.
        # ------------------------------------------------------------------
        st.markdown("#### 📊 Activity")
        range_choice = st.radio(
            "Time range", ["Last 7 days", "Last 30 days", "Last 90 days", "All time"],
            index=3, horizontal=True, key="dash_range", label_visibility="collapsed",
        )

        if range_choice == "All time":
            cutoff_str = None
        else:
            days_back = {"Last 7 days": 7, "Last 30 days": 30, "Last 90 days": 90}[range_choice]
            cutoff_str = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%d")

        if cutoff_str:
            events_in_range = [e for e in events if e.get("timestamp") and e["timestamp"][:10] >= cutoff_str]
            in_range_files = {e["source_file"] for e in events_in_range if e.get("source_file")}
            # Findings aren't timestamped themselves - scope them to the range via
            # the evidence file(s) they were found in. Only paid when a range
            # filter is actually active (the common case, "All time", skips this
            # entirely) so it doesn't cost anything on the default view.
            chart_findings = [f for f in findings
                               if any(o["source_file"] in in_range_files for o in db.get_occurrences(f["id"]))]
            dated = [e for e in events_in_range if e.get("timestamp")]
            st.caption(f"Scoped to **{range_choice.lower()}** - {len(chart_findings)} of {len(findings)} finding(s), "
                       f"{len(dated)} of {len([e for e in events if e.get('timestamp')])} dated event(s).")
        else:
            chart_findings = findings
            dated = [e for e in events if e.get("timestamp")]

        chart_col1, chart_col2 = st.columns(2)

        with chart_col1:
            with st.container(border=True):
                st.markdown(
                    f"""<div style="display:flex;justify-content:space-between;align-items:baseline">
                    <div class="sf-heading" style="font-size:16px;font-weight:600">Findings by type</div>
                    <span class="sf-label">{len(chart_findings)} TOTAL</span></div>""",
                    unsafe_allow_html=True,
                )
                if chart_findings:
                    by_type = {}
                    for f in chart_findings:
                        by_type[f["type"]] = by_type.get(f["type"], 0) + 1
                    items = sorted(by_type.items(), key=lambda x: x[1])
                    types_sorted = [t for t, _ in items]
                    fig = go.Figure(go.Bar(
                        x=[c for _, c in items], y=types_sorted, orientation="h",
                        marker_color=CATEGORICAL[0], text=[c for _, c in items], textposition="outside",
                        customdata=types_sorted,
                        hovertemplate="<b>%{customdata}</b><br>%{x} finding(s)<extra></extra>",
                    ))
                    fig.update_layout(bargap=0.35)
                    findings_event = st.plotly_chart(
                        _plotly_layout(fig), use_container_width=True,
                        on_select="rerun", selection_mode="points", key="dash_findings_chart",
                    )
                    pts = (findings_event or {}).get("selection", {}).get("points", [])
                    if pts:
                        # Plotly returns a single customdata array as a bare scalar per
                        # point (not wrapped in a list) - only multi-column customdata
                        # comes back as a list. Handle both shapes defensively.
                        raw = pts[0].get("customdata")
                        clicked = raw[0] if isinstance(raw, (list, tuple)) else raw
                        if not clicked:
                            clicked = pts[0].get("y")  # fallback: the category label itself
                        if clicked:
                            st.session_state["find_type_filter"] = clicked
                            goto(3)
                else:
                    st.caption("No findings yet - upload and process evidence to see this chart.")

        with chart_col2:
            with st.container(border=True):
                st.markdown(
                    f"""<div style="display:flex;justify-content:space-between;align-items:baseline">
                    <div class="sf-heading" style="font-size:16px;font-weight:600">Event activity over time</div>
                    <span class="sf-label">{len(dated):,} EVENTS</span></div>""",
                    unsafe_allow_html=True,
                )
                if dated:
                    from collections import Counter
                    by_day = Counter(e["timestamp"][:10] for e in dated)
                    days = sorted(by_day.keys())
                    fig = go.Figure(go.Scatter(
                        x=days, y=[by_day[d] for d in days], mode="lines+markers",
                        line=dict(color=CATEGORICAL[0], width=2), marker=dict(size=8),
                        fill="tozeroy", fillcolor="rgba(57,135,229,0.15)",
                        hovertemplate="<b>%{x}</b><br>%{y} event(s)<extra></extra>",
                    ))
                    fig.update_xaxes(type="category")
                    activity_event = st.plotly_chart(
                        _plotly_layout(fig, hovermode="x unified", spikes=True),
                        use_container_width=True, on_select="rerun", selection_mode="points", key="dash_activity_chart",
                    )
                    pts = (activity_event or {}).get("selection", {}).get("points", [])
                    if pts:
                        clicked_day = pts[0].get("x")
                        if clicked_day:
                            st.session_state["story_date_filter"] = clicked_day
                            goto(2)
                else:
                    st.caption("No dated events yet - upload and process evidence to see this chart.")

        if chart_findings or dated:
            st.caption("💡 Click a bar to jump to those findings, or a point on the timeline to jump to that day's story.")

        # ------------------------------------------------------------------
        # Detected patterns panel + "next step" CTA - matches the mockup's
        # severity-pill row + pattern list, and the gradient blue CTA card.
        # ------------------------------------------------------------------
        if not evidence:
            next_step, next_label, next_body = 1, "Upload your first evidence", "This case has no evidence on file yet."
        elif unprocessed:
            next_step, next_label = 1, f"Process {unprocessed} pending file(s)"
            next_body = "Uploaded but not yet run through the extraction pipeline."
        elif findings and verify_pct < 100:
            next_step, next_label = 4, "Continue verifying findings"
            next_body = f"{len(findings) - verified_count} finding(s) still need a verification decision."
        else:
            next_step, next_label, next_body = 6, "Generate the report", "Findings are verified and ready to write up."

        panel_col, cta_col = st.columns([1.6, 1])
        with panel_col:
            with st.container(border=True):
                st.markdown('<div class="sf-heading" style="font-size:16px;font-weight:600">Detected patterns</div>', unsafe_allow_html=True)
                if insights:
                    sev_counts = {"High": 0, "Medium": 0, "Low": 0}
                    for i in insights:
                        sev_counts[i["severity"]] = sev_counts.get(i["severity"], 0) + 1
                    pill_cols = st.columns(3)
                    pill_style = {
                        "High": ("rgba(230,103,103,.1)", "rgba(230,103,103,.3)", theme.RED),
                        "Medium": ("rgba(250,178,25,.08)", "rgba(250,178,25,.28)", theme.AMBER),
                        "Low": ("rgba(12,163,12,.08)", "rgba(12,163,12,.28)", theme.GREEN),
                    }
                    for col, sev in zip(pill_cols, ["High", "Medium", "Low"]):
                        bg, bd, fg = pill_style[sev]
                        col.markdown(
                            f"""<div style="padding:11px 13px;border-radius:8px;background:{bg};border:1px solid {bd}">
                            <div class="sf-label" style="color:{fg}">{STATUS_ICON[sev]} {sev.upper()}</div>
                            <div class="sf-heading" style="font-size:24px;font-weight:600;margin-top:3px">{sev_counts.get(sev, 0)}</div></div>""",
                            unsafe_allow_html=True,
                        )
                    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
                    rows_html = "".join(
                        theme.pattern_row(ins["severity"], ins["title"], f"{len(ins.get('event_refs', []))} EVENTS")
                        for ins in insights[:5]
                    )
                    st.markdown(f'<div style="display:flex;flex-direction:column;gap:8px">{rows_html}</div>', unsafe_allow_html=True)
                    if len(insights) > 5:
                        st.caption(f"+{len(insights) - 5} more - see Investigation Story for the full list.")
                else:
                    st.caption("No patterns detected yet - upload and process evidence first.")
        with cta_col:
            st.markdown(theme.cta_card("NEXT FOR THIS CASE", next_label, next_body, next_label), unsafe_allow_html=True)
            if st.button(f"➡ {next_label}", type="primary", use_container_width=True, key="dash_cta_btn"):
                goto(next_step)

    st.stop()

# --------------------------------------------------------------------------
# Case-stage flow - stepper nav, then the current stage's content
# --------------------------------------------------------------------------

current_idx = st.session_state.get("nav", 0)
if not isinstance(current_idx, int) or not (0 <= current_idx < len(STAGES)):
    current_idx = 0
    st.session_state["nav"] = 0

render_stepper(current_idx)
stage = STAGES[current_idx]

# --------------------------------------------------------------------------
# Stage: Case Details
# --------------------------------------------------------------------------

if stage == STAGES[0]:
    st.header("Case Details")

    with st.expander("Create a new case", expanded=(not cases)):
        suggested_id = db.next_case_id()
        with st.form("new_case_form"):
            col1, col2 = st.columns(2)
            case_id = col1.text_input("Case ID", value=suggested_id)
            name = col2.text_input("Case name")
            story = st.text_area(
                "Case story / overview",
                help="Freeform narrative - used later to give findings context, and searchable against uploaded evidence.",
                height=120,
            )
            col1, col2, col3 = st.columns(3)
            company = col1.text_input("Analysed by (company)")
            reporter = col2.text_input("Reporter name")
            investigators = col3.text_input("Investigator(s)", help="Comma-separated if more than one")
            col1, col2, col3 = st.columns(3)
            case_type = col1.selectbox("Case type", ["Malware", "Data Breach", "Insider Threat", "Phishing", "Fraud", "Other"])
            severity = col2.selectbox("Severity", ["Low", "Medium", "High", "Critical"])
            confidentiality = col3.selectbox("Confidentiality", ["Internal", "Confidential", "Restricted"])
            incident_date = st.date_input("Incident date")

            submitted = st.form_submit_button("Create case")
            if submitted:
                if not case_id or not name:
                    st.error("Case ID and case name are required.")
                else:
                    db.create_case(case_id, name, story, company, reporter, investigators,
                                    case_type, severity, confidentiality, str(incident_date))
                    mark_dirty()
                    st.session_state["case_id"] = case_id
                    st.success(f"Case {case_id} created.")
                    goto(1)

    st.subheader("Existing cases")
    if not cases:
        st.caption("No cases yet.")
    else:
        for c in cases:
            render_case_card(c)

    render_back_next(current_idx)

# --------------------------------------------------------------------------
# Stage: Upload Evidence
# --------------------------------------------------------------------------

elif stage == STAGES[1]:
    case = require_case()
    head_l, head_r = st.columns([2, 1])
    head_l.header(f"Upload Evidence - {case['case_id']}")
    head_r.markdown(
        f'<div class="sf-label" style="text-align:right;padding-top:22px;color:{theme.TEAL}">'
        f'SHA-256 HASHED AT INGEST · NOTHING LEAVES THIS MACHINE</div>',
        unsafe_allow_html=True,
    )

    main_col, info_col = st.columns([2, 1])

    with main_col:
        st.markdown('<div class="sf-label">Evidence category - applied to this batch</div>', unsafe_allow_html=True)
        category = st.pills(
            "Evidence category",
            ["Log", "Email", "Document", "Spreadsheet", "M365 Export", "Vehicle Telematics", "Image", "Other"],
            default="Log", label_visibility="collapsed", key="upload_category",
        ) or "Other"
        uploaded = st.file_uploader(
            "Upload logs, emails, documents, spreadsheets (incl. M365/Entra or vehicle telematics exports), or images",
            type=["txt", "log", "csv", "eml", "pdf", "docx", "doc", "rtf", "odt", "xlsx", "xlsm", "xls",
                  "png", "jpg", "jpeg", "bmp", "tiff"],
            accept_multiple_files=True,
        )
        store_clicked = st.button("Store + Process Evidence", type="primary", use_container_width=True,
                                   disabled=not uploaded)
        st.caption("Incremental - only files that have never been processed are parsed.")

    with info_col:
        st.markdown(
            f"""<div class="sf-card" style="border-color:rgba(25,158,112,.3);background:rgba(25,158,112,.06)">
            <div class="sf-label" style="color:{theme.TEAL}">Chain of custody</div>
            <div style="font-size:12px;line-height:1.55;color:{theme.TEXT_SECONDARY};margin-top:6px">
            Every file is SHA-256 hashed at ingest and written into the encrypted vault. The hash is shown on
            screen and carried into Appendix A of the report.</div></div>""",
            unsafe_allow_html=True,
        )
        st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
        st.markdown(
            f"""<div class="sf-card">
            <div class="sf-label">Recognised schemas</div>
            <div style="font-size:12px;line-height:1.7;color:{theme.TEXT_SECONDARY};margin-top:6px">
            Unified Audit Log<br>Entra ID sign-in logs<br>OAuth consent grants<br>Mailbox delegation &amp; inbox rules
            <br>Vehicle telematics / GPS-OBD-II exports
            </div></div>""",
            unsafe_allow_html=True,
        )
        st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
        with st.expander("⚙️ Advanced: force full reprocess"):
            st.caption(
                "Re-applies updated detection logic to evidence already processed. Slower - normally only "
                "newly uploaded files are (re)parsed."
            )
            evidence_for_reprocess = db.list_evidence(case["case_id"])
            if evidence_for_reprocess and st.button("🔁 Reprocess ALL evidence from scratch (slower)"):
                with st.spinner("Reprocessing every evidence file for this case from scratch..."):
                    file_specs = [(e["stored_path"], e["filename"]) for e in evidence_for_reprocess]
                    findings, skipped, events = run_pipeline_on_files(file_specs)
                    db.upsert_findings(case["case_id"], findings)
                    insights = run_all_detectors(events, case)
                    db.replace_events_and_insights(case["case_id"], events, insights)
                    db.mark_evidence_processed([e["id"] for e in evidence_for_reprocess])
                    mark_dirty()
                st.success(f"Reprocessed all {len(evidence_for_reprocess)} evidence file(s) from scratch.")
                if skipped:
                    st.warning(f"Skipped/unsupported: {skipped}")

    if uploaded and store_clicked:
        with st.spinner("Hashing files, extracting findings, building the timeline - everything runs locally..."):
            for uf in uploaded:
                file_bytes = uf.getvalue()
                stored_path, sha256 = db.store_evidence_file(case["case_id"], uf.name, file_bytes, category)
                st.write(f"✅ {uf.name} stored - SHA-256 `{sha256[:16]}...`")

            # Incremental: only NEW (never-before-processed) evidence gets
            # parsed here - re-parsing everything on every batch is the
            # single biggest avoidable cost on cases with large files.
            new_evidence = db.list_unprocessed_evidence(case["case_id"])
            file_specs = [(e["stored_path"], e["filename"]) for e in new_evidence]
            findings, skipped, new_events = run_pipeline_on_files(file_specs)
            db.upsert_findings(case["case_id"], findings)
            db.append_events(case["case_id"], new_events)
            db.mark_evidence_processed([e["id"] for e in new_evidence])

            # Insights DO need the full picture (a pattern can span old and
            # new evidence together) but this recomputes over
            # already-classified structured events already in the DB -
            # fast, unlike re-parsing raw files - so only this step
            # revisits the whole case, not the expensive parsing step.
            full_events = db.list_events(case["case_id"])
            for i, e in enumerate(full_events):
                e["_idx"] = i
            insights = run_all_detectors(full_events, case)
            pos_to_dbid = {i: full_events[i]["id"] for i in range(len(full_events))}
            for ins in insights:
                ins["event_refs"] = [pos_to_dbid[i] for i in ins.get("event_refs", []) if i in pos_to_dbid]
            db.replace_insights(case["case_id"], insights)
            mark_dirty()

        st.success(
            f"Processed {len(new_evidence)} new file(s): {len(findings)} deduplicated findings, "
            f"{len(new_events)} new timeline events added, {len(insights)} detected pattern(s) across all evidence."
        )
        st.caption("See the Investigation Story stage for the readable summary.")
        if skipped:
            st.warning(f"Skipped/unsupported: {skipped}")

    evidence = db.list_evidence(case["case_id"])
    processed_count = sum(1 for e in evidence if e.get("processed"))
    st.markdown(
        f"""<div style="display:flex;justify-content:space-between;align-items:baseline;margin-top:4px">
        <div class="sf-heading" style="font-size:16px;font-weight:600">Evidence on file for this case</div>
        <span class="sf-label">{len(evidence)} FILES · {processed_count} PROCESSED</span></div>""",
        unsafe_allow_html=True,
    )
    if not evidence:
        st.caption("No evidence uploaded yet.")
    else:
        rows = [
            [
                theme.esc(e["filename"]),
                f'<span style="color:{theme.TEXT_FAINT}">{theme.esc(e.get("category") or "-")}</span>',
                f'<span class="sf-hash">{e["sha256"][:14]}…</span>',
                f'<span style="color:{theme.TEXT_FAINT}">{e["uploaded_at"][:16].replace("T", " ")}</span>',
                (f'<span style="color:{theme.TEAL}">✅ processed</span>' if e.get("processed")
                 else f'<span style="color:{theme.AMBER}">⏳ pending</span>'),
            ]
            for e in evidence
        ]
        st.markdown(
            theme.evidence_table_html(["Filename", "Category", "SHA-256", "Uploaded", "Status"], rows),
            unsafe_allow_html=True,
        )
        unprocessed_count = len(evidence) - processed_count
        if unprocessed_count:
            st.warning(f"{unprocessed_count} file(s) uploaded but not yet processed - click 'Store + Process Evidence' above to run them through the pipeline.")

    render_back_next(current_idx)

# --------------------------------------------------------------------------
# Stage: Investigation Story
# --------------------------------------------------------------------------

elif stage == STAGES[2]:
    case = require_case()
    st.header(f"Investigation Story - {case['case_id']}")
    st.caption("A readable summary of the timeline, built so you don't have to read every log line yourself.")

    events = db.list_events(case["case_id"])
    insights = db.list_insights(case["case_id"])

    if not events:
        st.info("No timeline yet - upload and process evidence first.")
    else:
        for e in events:
            e["_idx"] = e["id"]

        story = build_story(events, insights, case)

        st.subheader("Executive Summary")
        st.write(story["executive_summary"])

        st.subheader(f"Key Findings ({len(insights)} auto-detected pattern(s))")
        if not insights:
            st.caption("No automated patterns matched yet - check the timeline below.")
        for ins in insights:
            with st.container(border=True):
                st.markdown(
                    f"""<div style="display:flex;align-items:center;gap:9px;flex-wrap:wrap">
                    <div class="sf-heading" style="font-size:15px;font-weight:600">{theme.esc(ins['title'])}</div>
                    {theme.severity_badge(ins['severity'])}</div>""",
                    unsafe_allow_html=True,
                )
                st.write(ins["description"])
                supporting = db.get_events_by_ids(ins["event_refs"])
                with st.expander(f"Supporting evidence ({len(supporting)} event(s))"):
                    for x in supporting:
                        ts_label = (x["timestamp"] or "undated")[:19]
                        st.caption(f"`{ts_label}` - {x['source_file']} → {x['location']}")
                        st.code(x["raw"], language=None)

        st.subheader("📅 Timeline Story")
        st.caption(
            "Every doubtful / notable moment in this case, in the order it happened - "
            "read this top to bottom and you have the whole story: what happened, when, "
            "and what it means, without opening a single raw log line."
        )
        if not story["timeline_story"]:
            st.caption("Nothing flagged as notable yet - the activity below was all classified as routine.")

        points = story["timeline_story"]
        available_dates = sorted({p["start"].strftime("%Y-%m-%d") for p in points})
        date_options = ["All dates"] + available_dates
        # key="story_date_filter" lets the Dashboard's activity chart pre-select
        # a day here (by setting this in session_state before switching stage,
        # since clicking a point there jumps straight to that day's story).
        if st.session_state.get("story_date_filter") not in date_options:
            st.session_state["story_date_filter"] = "All dates"
        selected_date = st.selectbox(
            "📅 Filter to a specific day (or click a point on the Dashboard's activity chart)",
            date_options, key="story_date_filter",
        )
        if selected_date != "All dates":
            points = [p for p in points if p["start"].strftime("%Y-%m-%d") == selected_date]
            st.caption(f"Showing {len(points)} point(s) for {selected_date} - pick \"All dates\" above to clear.")

        MAX_INLINE = 30
        shown, rest = (points[:MAX_INLINE], points[MAX_INLINE:]) if len(points) > MAX_INLINE else (points, [])

        def _render_timeline_point(point):
            time_label = point["start"].strftime("%Y-%m-%d %H:%M:%S")
            if point["end"] != point["start"]:
                time_label += f" - {point['end'].strftime('%H:%M:%S')}"
            approx_tag = " (approx.)" if point.get("approximate") else ""
            with st.container(border=True):
                st.markdown(f"**`{time_label}{approx_tag}`** · `{point['category']}` - {point['technical_line']}")
                st.caption(f"source: {', '.join(point['source_files'])}")
                for ins in point["explanations"]:
                    icon = STATUS_ICON.get(ins["severity"], "")
                    st.markdown(f"{icon} **What this means:** {ins['description']}")
                    if ins.get("impact"):
                        st.markdown(f"⚠️ **Impact:** {ins['impact']}")

        for point in shown:
            _render_timeline_point(point)
        if rest:
            with st.expander(f"Show {len(rest)} more timeline point(s)"):
                for point in rest:
                    _render_timeline_point(point)

        st.subheader("Routine Activity (compressed)")
        total_routine_events = sum(r["event_count"] for r in story["routine_summary"])
        st.caption(
            f"{total_routine_events} everyday event(s) across {len(story['routine_bursts'])} distinct patterns "
            f"were classified as routine (no detected anomaly) and are summarized below by category instead of "
            f"listed line by line - this is the reading time this tool saves you."
        )
        if story["routine_summary"]:
            st.dataframe(
                [{"Category": r["category"], "Events": r["event_count"],
                  "Distinct actors": len(r["actors"]), "Distinct source IPs": len(r["source_ips"]),
                  "From": r["start"].strftime("%Y-%m-%d %H:%M"), "To": r["end"].strftime("%Y-%m-%d %H:%M")}
                 for r in story["routine_summary"]],
                use_container_width=True,
            )
        if story["undated_count"]:
            st.caption(f"{story['undated_count']} additional event(s) had no detectable timestamp and are excluded from the timeline (see Findings for their content).")

        with st.expander(f"Show all {len(story['routine_bursts'])} routine timeline entries (full detail)"):
            for b in story["routine_bursts"]:
                time_label = b["start"].strftime("%Y-%m-%d %H:%M:%S")
                if b["end"] != b["start"]:
                    time_label += f" - {b['end'].strftime('%H:%M:%S')}"
                st.caption(f"{time_label} · `{b['category']}` - {burst_sentence(b)}")

    render_back_next(current_idx)

# --------------------------------------------------------------------------
# Stage: Findings
# --------------------------------------------------------------------------

elif stage == STAGES[3]:
    case = require_case()
    st.header(f"Findings - {case['case_id']}")

    if st.session_state.get("find_type_filter") not in (["All"] + ENTITY_TYPES):
        st.session_state["find_type_filter"] = "All"

    col1, col2, col3 = st.columns(3)
    # key="find_type_filter" lets a Dashboard chart click pre-select a type
    # (by setting this in session_state before switching stage) - see the
    # Dashboard's "Findings by type" chart above.
    type_filter = col1.selectbox("Type", ["All"] + ENTITY_TYPES, key="find_type_filter")
    status_filter = col2.selectbox("Verification status", ["All"] + STATUS_OPTIONS)
    search = col3.text_input("Search value contains")

    findings = db.list_findings(case["case_id"], type_filter, status_filter, search)
    st.caption(f"{len(findings)} finding(s)")

    STATUS_EXPANDER_ICON = {"Verified": "✅", "False Positive": "❌", "Needs Further Investigation": "🟡", "Unverified": "⚪"}
    for f in findings:
        occs = db.get_occurrences(f["id"])
        notes = json.loads(f["notes"]) if f["notes"] else []
        status_icon = STATUS_EXPANDER_ICON.get(f["verification_status"], "")
        with st.expander(f"{status_icon} [{f['type']}] {f['value']}  ·  confidence {confidence_label(f)}  ·  {len(occs)} source(s)"):
            if notes:
                st.info(" / ".join(notes))
            st.write(f"**Status:** {f['verification_status']}" + (f" - {f['verification_notes']}" if f.get("verification_notes") else ""))
            st.markdown("**Source traceability:**")
            for o in occs:
                st.markdown(f"- `{o['source_file']}` → *{o['location']}*  \n  <span style='color:{theme.TEXT_MUTED}'>{o['context']}</span>", unsafe_allow_html=True)

    render_back_next(current_idx)

# --------------------------------------------------------------------------
# Stage: Human Verification
# --------------------------------------------------------------------------

elif stage == STAGES[4]:
    case = require_case()
    st.header(f"Human Verification - {case['case_id']}")
    st.caption("Every finding requires a human decision before it belongs in a final report. POC attachment is optional.")

    col1, col2 = st.columns(2)
    type_filter = col1.selectbox("Filter by type", ["All"] + ENTITY_TYPES, key="v_type")
    status_filter = col2.selectbox("Filter by status", ["All"] + STATUS_OPTIONS, key="v_status", index=1)

    findings = db.list_findings(case["case_id"], type_filter, status_filter)
    reviewer = st.text_input("Your name (reviewer)", value=case.get("reporter") or "")

    # Computed once per page load (not per finding) - the story/timeline
    # context every finding below is matched against.
    all_events = db.list_events(case["case_id"])
    for e in all_events:
        e["_idx"] = e["id"]
    all_bursts, _undated = aggregate_events(all_events)

    VERIFY_BADGE_KIND = {"Verified": "success", "False Positive": "neutral",
                         "Needs Further Investigation": "medium", "Unverified": "blue"}
    for f in findings:
        with st.container(border=True):
            st.markdown(
                f"""<div style="display:flex;align-items:center;gap:9px;flex-wrap:wrap">
                <div class="sf-heading" style="font-size:15px;font-weight:600">[{theme.esc(f['type'])}] {theme.esc(f['value'])}</div>
                <span class="sf-label">CONF {theme.esc(confidence_label(f))}</span>
                {theme.badge(f['verification_status'].upper(), VERIFY_BADGE_KIND.get(f['verification_status'], 'neutral'))}
                </div>""",
                unsafe_allow_html=True,
            )

            st.caption("📖 Story context (from Investigation Story)")
            story_matches = find_bursts_for_value(all_bursts, f["value"])
            if story_matches:
                for b in sorted(story_matches, key=lambda x: x["start"]):
                    approx_tag = " (approx.)" if b.get("approximate") else ""
                    st.markdown(f"- `{b['start'].strftime('%Y-%m-%d %H:%M:%S')}{approx_tag}` - {burst_sentence(b)}")
            else:
                st.caption("No matching timeline event found for this value.")

            st.caption("📁 Found in (file → location)")
            occs = db.get_occurrences(f["id"])
            if occs:
                for o in occs:
                    st.markdown(f"- `{o['source_file']}` → *{o['location']}*")
            else:
                st.caption("No source occurrences recorded.")

            # --- POC: every finding gets BOTH an upload option and a
            # clipboard-paste option (point 5) - an analyst can screenshot
            # a proof (e.g. an email header, a portal screen) and paste it
            # straight in, no save-to-disk-then-upload round trip needed.
            st.caption("📎 Proof of concept (POC) - upload a file, or paste a screenshot")
            existing_pocs = db.get_poc_paths(f["id"])
            if existing_pocs:
                with st.expander(f"Existing POC(s) attached ({len(existing_pocs)})"):
                    for p in existing_pocs:
                        if p.lower().endswith((".png", ".jpg", ".jpeg", ".bmp", ".gif")):
                            st.image(p, caption=os.path.basename(p), width=300)
                        else:
                            st.caption(f"📄 {os.path.basename(p)}")

            paste_result = paste_image_button(
                "📋 Paste screenshot from clipboard", key=f"paste_{f['id']}"
            )
            pasted_poc_path = None
            if paste_result.image_data is not None:
                st.image(paste_result.image_data, caption="Pasted image (will attach on save)", width=300)
                pasted_poc_path = db.save_poc_image(case["case_id"], f["id"], paste_result.image_data)
                mark_dirty()

            with st.form(f"verify_form_{f['id']}"):
                new_status = st.selectbox("Verification status", STATUS_OPTIONS,
                                           index=STATUS_OPTIONS.index(f["verification_status"]) if f["verification_status"] in STATUS_OPTIONS else 0,
                                           key=f"status_{f['id']}")
                notes = st.text_area("Notes", value=f.get("verification_notes") or "", key=f"notes_{f['id']}")
                poc = st.file_uploader("Attach POC file (optional)", key=f"poc_{f['id']}")
                submit = st.form_submit_button("Save verification")
                if submit:
                    poc_path = pasted_poc_path  # already saved above the instant it was pasted
                    if poc is not None:
                        poc_path = db.save_poc_file(case["case_id"], f["id"], poc.name, poc.getvalue())
                    if not reviewer:
                        st.error("Enter a reviewer name before saving.")
                    else:
                        db.set_verification(f["id"], new_status, reviewer, notes, poc_path)
                        mark_dirty()
                        st.success("Saved.")
                        st.rerun()

            log = db.get_verification_log(f["id"])
            if log:
                with st.expander(f"Audit trail ({len(log)} change(s))"):
                    for entry in log:
                        poc_note = f" · POC: {os.path.basename(entry['poc_path'])}" if entry["poc_path"] else ""
                        st.caption(f"{entry['timestamp'][:19]} - {entry['old_status']} → {entry['new_status']} by {entry['reviewer']}{poc_note}")
                        if entry["notes"]:
                            st.caption(f"  \"{entry['notes']}\"")

    st.divider()
    with st.expander("⚡ Bulk actions"):
        st.caption("Apply one status to every finding currently shown above (respects the type/status filters).")
        bulk_status = st.selectbox("Set status to", STATUS_OPTIONS, key="bulk_status")
        if st.button(f"Apply '{bulk_status}' to all {len(findings)} shown finding(s)"):
            if not reviewer:
                st.error("Enter a reviewer name before saving.")
            else:
                for f in findings:
                    db.set_verification(f["id"], bulk_status, reviewer, f.get("verification_notes") or "", None)
                mark_dirty()
                st.success(f"Updated {len(findings)} finding(s) to '{bulk_status}'.")
                st.rerun()

    render_back_next(current_idx)

# --------------------------------------------------------------------------
# Stage: Artifacts (file library + extracted forensic artifacts)
# --------------------------------------------------------------------------

elif stage == STAGES[5]:
    case = require_case()
    st.header(f"Artifacts - {case['case_id']}")
    st.caption(
        "Everything on file for this case in one place, plus artifacts extracted OUT of the evidence itself - "
        "email header forensics, document authorship metadata, and image EXIF data. Computed on demand here, "
        "not during upload, so it never slows down evidence processing."
    )

    tab1, tab2 = st.tabs(["📁 Case File Library", "🔬 Extracted Forensic Artifacts"])

    with tab1:
        evidence = db.list_evidence(case["case_id"])
        st.subheader(f"Evidence files ({len(evidence)})")
        for e in evidence:
            col1, col2 = st.columns([4, 1])
            col1.markdown(f"`{e['filename']}` - {e.get('category') or 'Uncategorized'} · SHA-256 `{e['sha256'][:16]}...`")
            if os.path.exists(e["stored_path"]):
                with open(e["stored_path"], "rb") as fh:
                    col2.download_button("⬇️", fh, file_name=e["filename"], key=f"dl_ev_{e['id']}")

        findings_with_poc = [f for f in db.list_findings(case["case_id"]) if db.get_poc_paths(f["id"])]
        st.subheader(f"POC attachments ({sum(len(db.get_poc_paths(f['id'])) for f in findings_with_poc)})")
        if not findings_with_poc:
            st.caption("No POCs attached yet - see the Verification stage.")
        for f in findings_with_poc:
            for p in db.get_poc_paths(f["id"]):
                col1, col2 = st.columns([4, 1])
                col1.markdown(f"`{os.path.basename(p)}` - POC for [{f['type']}] {f['value']}")
                if os.path.exists(p):
                    with open(p, "rb") as fh:
                        col2.download_button("⬇️", fh, file_name=os.path.basename(p), key=f"dl_poc_{p}")

        reports_dir = os.path.join(db.REPORTS_DIR, case["case_id"])
        report_files = sorted(os.listdir(reports_dir)) if os.path.isdir(reports_dir) else []
        st.subheader(f"Generated reports ({len(report_files)})")
        if not report_files:
            st.caption("No reports generated yet - see the Generate Report stage.")
        for fname in report_files:
            fpath = os.path.join(reports_dir, fname)
            col1, col2 = st.columns([4, 1])
            col1.markdown(f"`{fname}`")
            with open(fpath, "rb") as fh:
                col2.download_button("⬇️", fh, file_name=fname, key=f"dl_report_{fname}")

    with tab2:
        evidence = db.list_evidence(case["case_id"])
        eml_files = [e for e in evidence if e["filename"].lower().endswith(".eml")]
        docx_files = [e for e in evidence if e["filename"].lower().endswith(".docx")]
        image_files = [e for e in evidence if e["filename"].lower().endswith((".png", ".jpg", ".jpeg", ".bmp", ".tiff"))]

        @st.cache_data(show_spinner=False)
        def _cached_email_artifacts(stored_path):
            return extract_email_artifacts(stored_path)

        @st.cache_data(show_spinner=False)
        def _cached_docx_metadata(stored_path):
            return extract_docx_metadata(stored_path)

        @st.cache_data(show_spinner=False)
        def _cached_image_exif(stored_path):
            return extract_image_exif(stored_path)

        st.subheader(f"✉️ Email header forensics ({len(eml_files)} .eml file(s))")
        if not eml_files:
            st.caption("No .eml files in this case's evidence.")
        for e in eml_files:
            art = _cached_email_artifacts(e["stored_path"]) if os.path.exists(e["stored_path"]) else None
            with st.expander(f"{e['filename']}"):
                if not art:
                    st.caption("Could not parse this file as an email.")
                    continue
                st.markdown(f"**From:** {art['from_']}")
                if art["reply_to"]:
                    tag = " 🔴 **MISMATCH - classic spoofing tell**" if art["from_reply_to_mismatch"] else ""
                    st.markdown(f"**Reply-To:** {art['reply_to']}{tag}")
                if art["x_originating_ip"]:
                    st.markdown(f"**X-Originating-IP:** `{art['x_originating_ip']}`")
                if art["auth_results_raw"]:
                    def _auth_kind(v):
                        return "success" if v == "pass" else "high" if v else "neutral"
                    st.markdown(
                        f'<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">'
                        f'<span class="sf-label">SPF</span>{theme.badge(art["spf"] or "n/a", _auth_kind(art["spf"]))}'
                        f'<span class="sf-label">DKIM</span>{theme.badge(art["dkim"] or "n/a", _auth_kind(art["dkim"]))}'
                        f'<span class="sf-label">DMARC</span>{theme.badge(art["dmarc"] or "n/a", _auth_kind(art["dmarc"]))}'
                        f'</div>',
                        unsafe_allow_html=True,
                    )
                if art["received_chain"]:
                    with st.expander(f"Received chain ({len(art['received_chain'])} hop(s))"):
                        for hop in art["received_chain"]:
                            st.code(hop, language=None)
                if art["attachments"]:
                    st.markdown("**Attachments:** " + ", ".join(f"{a['filename']} ({a['size']} bytes)" for a in art["attachments"]))

        st.subheader(f"📄 Document metadata ({len(docx_files)} .docx file(s))")
        st.caption("Legacy .doc/.rtf/.odt files are converted via LibreOffice for parsing elsewhere in this tool, which doesn't preserve original metadata - only native .docx uploads are covered here.")
        if not docx_files:
            st.caption("No .docx files in this case's evidence.")
        for e in docx_files:
            meta = _cached_docx_metadata(e["stored_path"]) if os.path.exists(e["stored_path"]) else None
            with st.expander(f"{e['filename']}"):
                if not meta:
                    st.caption("Could not read document metadata.")
                    continue
                st.markdown(f"**Author:** {meta['author'] or '-'}  ·  **Last modified by:** {meta['last_modified_by'] or '-'}")
                st.markdown(f"**Created:** {meta['created'] or '-'}  ·  **Modified:** {meta['modified'] or '-'}")
                st.markdown(f"**Revision:** {meta['revision'] or '-'}  ·  **Company:** {meta['company'] or '-'}")
                if meta["title"] or meta["subject"] or meta["comments"]:
                    st.caption(f"Title: {meta['title'] or '-'} · Subject: {meta['subject'] or '-'} · Comments: {meta['comments'] or '-'}")

        st.subheader(f"🖼️ Image EXIF ({len(image_files)} image file(s))")
        if not image_files:
            st.caption("No image files in this case's evidence.")
        for e in image_files:
            exif = _cached_image_exif(e["stored_path"]) if os.path.exists(e["stored_path"]) else None
            with st.expander(f"{e['filename']}"):
                if not exif:
                    st.caption("No EXIF data found (common for screenshots and web-saved images).")
                    continue
                st.markdown(f"**Device:** {exif['camera_make'] or '-'} {exif['camera_model'] or ''}")
                st.markdown(f"**Software:** {exif['software'] or '-'}")
                st.markdown(f"**Original capture time:** {exif['original_datetime'] or '-'}")
                if exif["gps_lat"] is not None:
                    st.markdown(f"**GPS:** {exif['gps_lat']}, {exif['gps_lon']}")
                    st.map(data=[{"lat": exif["gps_lat"], "lon": exif["gps_lon"]}])

    render_back_next(current_idx)

# --------------------------------------------------------------------------
# Stage: Generate Report
# --------------------------------------------------------------------------

elif stage == STAGES[6]:
    case = require_case()
    st.header(f"Generate Report - {case['case_id']}")

    templates = db.list_report_templates()
    template_names = ["(custom - not saved)"] + [t["template_name"] for t in templates]
    chosen_template = st.selectbox("Start from a saved template", template_names)
    preset = next((t for t in templates if t["template_name"] == chosen_template), None)

    font_names = list(FONT_CHOICES.keys())

    def _font_index(value):
        return font_names.index(value) if value in font_names else 0

    with st.form("report_settings"):
        col1, col2 = st.columns(2)
        company_name = col1.text_input("Company name (for header)", value=(preset["company_name"] if preset else case.get("company") or ""))
        primary_color = col2.color_picker("Primary/accent color (tables, page header/footer)", value=(preset["primary_color"] if preset else "#1F2937"))
        header_text = st.text_input("Header text", value=(preset["header_text"] if preset else company_name))
        footer_text = st.text_input("Footer text", value=(preset["footer_text"] if preset else f"Confidential - {case['case_id']}"))
        col1, col2 = st.columns(2)
        heading_style = col1.selectbox("Heading style", ["Distinct", "Same"], index=(["Distinct", "Same"].index(preset["heading_style"]) if preset and preset.get("heading_style") in ["Distinct", "Same"] else 0))
        body_style = col2.selectbox("Body text style", ["Formal", "Plain"], index=(["Formal", "Plain"].index(preset["body_style"]) if preset and preset.get("body_style") in ["Formal", "Plain"] else 0))
        col1, col2 = st.columns(2)
        include_bullets = col1.checkbox("Use bullet points where applicable", value=(bool(preset["include_bullets"]) if preset else True))
        include_tables = col2.checkbox("Use tables for findings", value=(bool(preset["include_tables"]) if preset else True))
        include_unverified = st.checkbox("Include unverified / not-yet-reviewed findings", value=True,
                                          help="Turn off to generate a client-ready report containing only analyst-verified findings.")

        st.markdown("**Typography & color - headings, subheadings, and body content**")
        col1, col2, col3 = st.columns(3)
        heading_font = col1.selectbox("Heading font", font_names, index=_font_index(preset["heading_font"] if preset else "Calibri (Sans-serif)"), key="heading_font")
        heading_color = col2.color_picker("Heading color", value=(preset["heading_color"] if preset else "#1F2937"), key="heading_color")
        heading_size = col3.number_input("Heading size (pt)", min_value=12, max_value=36, value=(preset["heading_size"] if preset else 20), key="heading_size")
        col1, col2, col3 = st.columns(3)
        subheading_font = col1.selectbox("Subheading font", font_names, index=_font_index(preset["subheading_font"] if preset else "Calibri (Sans-serif)"), key="subheading_font")
        subheading_color = col2.color_picker("Subheading color", value=(preset["subheading_color"] if preset else "#1F2937"), key="subheading_color")
        subheading_size = col3.number_input("Subheading size (pt)", min_value=10, max_value=28, value=(preset["subheading_size"] if preset else 14), key="subheading_size")
        col1, col2, col3 = st.columns(3)
        body_font = col1.selectbox("Body font", font_names, index=_font_index(preset["body_font"] if preset else "Calibri (Sans-serif)"), key="body_font")
        body_color = col2.color_picker("Body text color", value=(preset["body_color"] if preset else "#000000"), key="body_color")
        body_size = col3.number_input("Body size (pt)", min_value=8, max_value=16, value=(preset["body_size"] if preset else 11), key="body_size")

        save_as = st.text_input("Save these settings as a template (optional)", value="")

        col1, col2 = st.columns(2)
        gen_docx = col1.form_submit_button("Generate DOCX", type="primary")
        gen_pdf = col2.form_submit_button("Generate PDF")

    settings = dict(company_name=company_name, header_text=header_text, footer_text=footer_text,
                     primary_color=primary_color, heading_style=heading_style, body_style=body_style,
                     include_bullets=include_bullets, include_tables=include_tables,
                     heading_font=heading_font, heading_color=heading_color, heading_size=heading_size,
                     subheading_font=subheading_font, subheading_color=subheading_color, subheading_size=subheading_size,
                     body_font=body_font, body_color=body_color, body_size=body_size)

    if gen_docx or gen_pdf:
        if save_as:
            db.save_report_template(save_as, company_name, header_text, footer_text, primary_color,
                                      heading_style, body_style, include_bullets, include_tables,
                                      heading_font, heading_color, heading_size,
                                      subheading_font, subheading_color, subheading_size,
                                      body_font, body_color, body_size)
        findings = db.list_findings(case["case_id"])
        evidence = db.list_evidence(case["case_id"])
        events = db.list_events(case["case_id"])
        insights = db.list_insights(case["case_id"])
        out_dir = os.path.join(db.REPORTS_DIR, case["case_id"])
        os.makedirs(out_dir, exist_ok=True)

        if gen_docx:
            out_path = os.path.join(out_dir, f"{case['case_id']}_report.docx")
            generate_docx(case, findings, evidence, settings, out_path, include_unverified, events, insights)
            mark_dirty()
            with open(out_path, "rb") as f:
                st.download_button("⬇️ Download DOCX report", f, file_name=os.path.basename(out_path))
        if gen_pdf:
            out_path = os.path.join(out_dir, f"{case['case_id']}_report.pdf")
            generate_pdf(case, findings, evidence, settings, out_path, include_unverified, events, insights)
            mark_dirty()
            with open(out_path, "rb") as f:
                st.download_button("⬇️ Download PDF report", f, file_name=os.path.basename(out_path))

    render_back_next(current_idx)

# --------------------------------------------------------------------------
# Reseal the encrypted vault - but ONLY if something actually changed this
# run. Streamlit reruns this whole script on every interaction (switching
# stages, expanding a section, etc.), and re-tarring + re-encrypting the
# entire case folder on every single one of those is a real cost on a
# large case - mark_dirty() is called only at genuine mutation points
# above, so most reruns skip this entirely.
# --------------------------------------------------------------------------

if st.session_state.get("authenticated") and st.session_state.get("vault_key") and st.session_state.get("vault_dirty"):
    auth.reseal_vault(st.session_state["vault_key"])
    st.session_state["vault_dirty"] = False
