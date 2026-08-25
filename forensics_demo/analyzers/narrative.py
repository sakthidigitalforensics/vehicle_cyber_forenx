"""
Compresses a (potentially huge) event list into something an analyst can
actually read: an executive summary, the detected patterns (Insights) in
plain English, and a chronological timeline where repeated near-identical
events are collapsed into one "12x failed login..." line instead of 12
separate lines.

This module produces plain dicts/strings - the Streamlit page and the
report generator both render the same underlying structure.
"""

from datetime import datetime, timedelta

GAP_SECONDS = 300  # events of the same kind within this gap get merged into one burst


def _ts(e):
    return datetime.fromisoformat(e["timestamp"]) if e.get("timestamp") else None


def _group_key(e):
    return (e["category"], e.get("actor"), e.get("source_ip"), e.get("dest_ip"), e.get("outcome"), e.get("action"))


def aggregate_events(events):
    """
    Returns (bursts, undated_count). Each burst:
    {start, end, count, category, actor, source_ip, dest_ip, port, protocol,
     outcome, action, objects, source_files, event_refs, approximate}
    `approximate` is True if ANY contributing event's timestamp was
    inferred (date-only or carried-forward) rather than parsed exactly -
    used to hedge reconstructed timestamps ("around", not exact).
    """
    dated = [e for e in events if e.get("timestamp")]
    undated_count = len(events) - len(dated)
    dated.sort(key=lambda e: e["timestamp"])

    bursts = []
    current = None
    for e in dated:
        key = _group_key(e)
        t = _ts(e)
        if current and current["_key"] == key and (t - current["end"]) <= timedelta(seconds=GAP_SECONDS):
            current["end"] = t
            current["count"] += 1
            current["source_files"].add(e["source_file"])
            current["event_refs"].append(e["_idx"])
            current["approximate"] = current["approximate"] or bool(e.get("approximate"))
            for o in e.get("objects", []):
                if o not in current["objects"]:
                    current["objects"].append(o)
        else:
            if current:
                bursts.append(current)
            current = {
                "_key": key, "start": t, "end": t, "count": 1,
                "category": e["category"], "actor": e.get("actor"),
                "source_ip": e.get("source_ip"), "dest_ip": e.get("dest_ip"),
                "port": e.get("port"), "protocol": e.get("protocol"),
                "outcome": e.get("outcome"), "action": e.get("action"),
                "objects": list(e.get("objects", [])),
                "source_files": {e["source_file"]},
                "event_refs": [e["_idx"]],
                "approximate": bool(e.get("approximate")),
            }
    if current:
        bursts.append(current)
    return bursts, undated_count


def burst_sentence(b):
    """
    Compose a readable sentence from the burst's fields. When the action
    text is itself a full raw sentence (the no-template-matched fallback),
    it typically already mentions the actor/IPs, so we skip re-appending
    a field if its value already appears in the action text - otherwise
    you get "...connection to X. from Y to X" duplicating X.
    """
    action_lower = b["action"].lower()

    def already_mentioned(value):
        return bool(value) and str(value).lower() in action_lower

    prefix = f"{b['count']}x " if b["count"] > 1 else ""
    parts = [f"{prefix}{b['action']}"]
    if b.get("actor") and not already_mentioned(b["actor"]):
        parts.append(f"for '{b['actor']}'")
    if b.get("source_ip") and not already_mentioned(b["source_ip"]):
        parts.append(f"from {b['source_ip']}")
    if b.get("dest_ip") and not already_mentioned(b["dest_ip"]):
        dest = f"to {b['dest_ip']}"
        if b.get("port"):
            dest += f":{b['port']}"
        parts.append(dest)
    if b.get("objects"):
        unmentioned = [o for o in b["objects"] if not already_mentioned(o)]
        if unmentioned:
            shown = ", ".join(str(o) for o in unmentioned[:3])
            if len(unmentioned) > 3:
                shown += f", +{len(unmentioned) - 3} more"
            parts.append(f"({shown})")
    if b.get("outcome"):
        parts.append(f"[{b['outcome']}]")
    return " ".join(parts)


SEVERITY_ICON = {"High": "🔴", "Medium": "🟠", "Low": "🟡"}


def build_executive_summary(events, insights, case=None):
    dated = [e for e in events if e.get("timestamp")]
    if dated:
        start = min(_ts(e) for e in dated)
        end = max(_ts(e) for e in dated)
        span = f"{start.strftime('%Y-%m-%d %H:%M')} to {end.strftime('%Y-%m-%d %H:%M')}"
    else:
        span = "an unknown time range (no parseable timestamps found)"

    high = [i for i in insights if i["severity"] == "High"]
    actors = sorted({e["actor"] for e in events if e.get("actor")})
    ips = sorted({e.get("source_ip") for e in events if e.get("source_ip")})

    lines = []
    lines.append(
        f"This case covers {len(events)} classified event(s) across the uploaded evidence, spanning {span}."
    )
    if high:
        titles = "; ".join(i["title"] for i in high[:3])
        lines.append(f"{len(high)} high-severity pattern(s) were detected: {titles}.")
    else:
        lines.append("No high-severity attack patterns were automatically detected - review the timeline below for manual confirmation.")
    if actors:
        lines.append(f"Accounts/identities seen: {', '.join(actors[:8])}" + (", ..." if len(actors) > 8 else "") + ".")
    if ips:
        lines.append(f"Source IPs seen: {', '.join(ips[:8])}" + (", ..." if len(ips) > 8 else "") + ".")
    return " ".join(lines)


def find_bursts_for_value(bursts, value):
    """
    Link a Finding (a deduplicated entity like an IP or hash) back to its
    place in the Investigation Story: any timeline burst whose actor,
    source/dest IP, action text, or referenced objects mention this value.
    This is what lets the Verification page and the report show "here's
    the story context for this finding" instead of the analyst having to
    go search the timeline by hand.
    """
    value_l = str(value).lower()
    matches = []
    for b in bursts:
        haystack_parts = [b.get("actor"), b.get("source_ip"), b.get("dest_ip"), b.get("action")] + list(b.get("objects", []))
        haystack = " ".join(str(p) for p in haystack_parts if p).lower()
        if value_l in haystack:
            matches.append(b)
    return matches


def reconstruct_finding_timestamps(value, bursts):
    """
    Returns (first_seen: datetime|None, last_seen: datetime|None, approximate: bool)
    for a Finding's value, reconstructed from every timeline burst that
    references it. approximate=True if ANY contributing event's timestamp
    was inferred (date-only or carried-forward) rather than parsed exactly.
    """
    matches = find_bursts_for_value(bursts, value)
    if not matches:
        return None, None, False
    first_seen = min(b["start"] for b in matches)
    last_seen = max(b["end"] for b in matches)
    approximate = any(b.get("approximate") for b in matches)
    return first_seen, last_seen, approximate


def split_notable_and_routine(bursts, insights):
    """
    An analyst reading this tool's output shouldn't have to wade through
    every burst to find the ones that matter. A burst is "notable" if any
    of its underlying events is referenced by a detected pattern (Insight);
    everything else is "routine" and gets compressed into a per-category
    count summary instead of being listed line by line.
    """
    # Only High/Medium severity patterns promote their events into the
    # "must read" notable timeline. Low-severity insights (e.g. off-hours
    # logins) are already fully described in the Key Findings summary with
    # their own supporting-evidence view - repeating dozens of their events
    # in the main timeline would recreate the noise problem this exists to solve.
    flagged_ids = set()
    for ins in insights:
        if ins.get("severity") in ("High", "Medium"):
            flagged_ids.update(ins.get("event_refs", []))

    notable, routine = [], []
    for b in bursts:
        if flagged_ids.intersection(b["event_refs"]):
            notable.append(b)
        else:
            routine.append(b)
    return notable, routine


def summarize_routine(routine_bursts):
    """Collapse routine bursts into one row per category: total event count, actor/IP diversity, time span."""
    by_cat = {}
    for b in routine_bursts:
        s = by_cat.setdefault(b["category"], {
            "category": b["category"], "event_count": 0, "actors": set(), "source_ips": set(),
            "start": b["start"], "end": b["end"],
        })
        s["event_count"] += b["count"]
        if b.get("actor"):
            s["actors"].add(b["actor"])
        if b.get("source_ip"):
            s["source_ips"].add(b["source_ip"])
        s["start"] = min(s["start"], b["start"])
        s["end"] = max(s["end"], b["end"])
    return sorted(by_cat.values(), key=lambda s: -s["event_count"])


def build_unified_story(notable_bursts, insights):
    """
    The actual "story" of the case: one chronological list where every
    notable timeline point carries BOTH the raw technical line AND a
    plain-language explanation of what happened and why it matters -
    e.g. "09:00 - sign-in from an unusual location" followed immediately
    by "What this means: ... / Impact: ...", not a separate list the
    reader has to cross-reference themselves. Includes every notable
    point with no cap, so no suspicious timestamp is left out.

    Returns a list of dicts, oldest first:
    {start, end, approximate, category, technical_line, source_files,
     explanations: [{severity, title, description, impact}, ...]}
    """
    idx_to_insights = {}
    for ins in insights:
        for idx in ins.get("event_refs", []):
            idx_to_insights.setdefault(idx, []).append(ins)

    points = []
    for b in sorted(notable_bursts, key=lambda x: x["start"]):
        matched, seen = [], set()
        for idx in b["event_refs"]:
            for ins in idx_to_insights.get(idx, []):
                key = (ins["severity"], ins["title"])
                if key not in seen:
                    seen.add(key)
                    matched.append(ins)
        if not matched:
            continue
        points.append(dict(
            start=b["start"], end=b["end"], approximate=b.get("approximate", False),
            category=b["category"], technical_line=burst_sentence(b),
            source_files=sorted(b["source_files"]),
            explanations=matched,
        ))
    return points


def build_story(events, insights, case=None):
    """
    Returns a dict ready for rendering:
    {executive_summary, insights (already sorted), notable_bursts,
     timeline_story, routine_summary, routine_bursts, undated_count, total_events}
    """
    for i, e in enumerate(events):
        # Prefer the DB row id when present, since that's what Insight
        # event_refs are expressed in for events loaded back from storage
        # (see db.replace_events_and_insights) - falling back to positional
        # index only for fresh in-memory events that were never persisted.
        # Getting this wrong silently empties the "notable" timeline rather
        # than erroring, so it must be consistent with how insights were built.
        e.setdefault("_idx", e.get("id", i))
    bursts, undated_count = aggregate_events(events)
    notable, routine = split_notable_and_routine(bursts, insights)
    return dict(
        executive_summary=build_executive_summary(events, insights, case),
        insights=insights,
        notable_bursts=notable,
        timeline_story=build_unified_story(notable, insights),
        routine_bursts=routine,
        routine_summary=summarize_routine(routine),
        undated_count=undated_count,
        total_events=len(events),
    )
