"""
Rule-based pattern detectors over a chronologically-sorted event list.

Each detector is a plain function: (events: list[dict], case: dict|None) ->
list of Insight dicts. `events` are the dicts produced by event_classifier,
each carrying its own index (added by the caller as "_idx") so an Insight
can reference exactly which events support its claim - the narrative and
the UI both use event_refs to let an analyst jump straight to the evidence.

This is a starting rule set, not a finished detection product - the right
way to grow it is to add a new detector function and register it in
ALL_DETECTORS, informed by real logs run through the tool.
"""

from datetime import datetime, timedelta
import ipaddress
import math

from analyzers.vehicle_classifier import AUTHORIZED_TECHNICIAN_IDS

SUSPICIOUS_PORTS = {4444, 1337, 31337, 6667, 6666, 12345, 54321}
BRUTE_FORCE_FAIL_THRESHOLD = 2
BRUTE_FORCE_WINDOW_MIN = 15
BEACON_MIN_COUNT = 3
BEACON_TIGHT_WINDOW_MIN = 10     # count>=BEACON_MIN_COUNT all within this many minutes -> likely real beaconing
BEACON_MAX_MEAN_GAP_SEC = 300    # ...or a regular, frequent cadence even if spread out
BEACON_MAX_COEFF_VAR = 0.6      # low variance between gaps = regular/automated, not human-driven noise

HIGH_RISK_OAUTH_SCOPES = [
    "mail.read", "mail.readwrite", "mail.send", "full_access_as_app",
    "directory.readwrite.all", "files.readwrite.all", "offline_access",
    "mailboxsettings.readwrite", "user.read.all", "sites.fullcontrol.all",
]
IMPOSSIBLE_TRAVEL_WINDOW_MIN = 120


def _object_value(e, prefix):
    """Pull the value out of a tagged object string like 'ForwardTo:evil@x.com' (see m365_classifier)."""
    for o in e.get("objects", []):
        o = str(o)
        if o.lower().startswith(prefix.lower() + ":"):
            return o.split(":", 1)[1]
    return None


def _infer_internal_domains(events, case=None):
    """
    Best-effort guess at the organization's own email domain(s), so
    delegation/forwarding destinations can be judged internal vs external.
    Uses the case's company name if it looks like a domain hint, otherwise
    the most frequently-seen actor email domain in the evidence.
    """
    from collections import Counter
    counts = Counter()
    for e in events:
        actor = e.get("actor")
        if actor and "@" in str(actor):
            counts[str(actor).split("@")[-1].lower()] += 1
    if not counts:
        return set()
    top_count = counts.most_common(1)[0][1]
    return {d for d, c in counts.items() if c >= max(1, top_count * 0.5)}


def _ts(e):
    return datetime.fromisoformat(e["timestamp"]) if e.get("timestamp") else None


def _is_public_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local)
    except ValueError:
        return False


def _levenshtein(a, b):
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
        prev = cur
    return prev[-1]


def brute_force_detector(events, case=None):
    insights = []
    by_source = {}
    for e in events:
        if e["category"] != "Authentication" or not e.get("source_ip"):
            continue
        by_source.setdefault(e["source_ip"], []).append(e)

    for ip, evs in by_source.items():
        evs = sorted([e for e in evs if e.get("timestamp")], key=lambda e: e["timestamp"])
        fail_streak = []
        for e in evs:
            if e["outcome"] == "Failure":
                fail_streak.append(e)
            elif e["outcome"] == "Success":
                if len(fail_streak) >= BRUTE_FORCE_FAIL_THRESHOLD:
                    window_ok = (_ts(e) - _ts(fail_streak[0])) <= timedelta(minutes=BRUTE_FORCE_WINDOW_MIN)
                    if window_ok:
                        actor = e.get("actor") or fail_streak[0].get("actor") or "an account"
                        insights.append(dict(
                            severity="High",
                            title=f"Likely brute-force access from {ip}",
                            description=(
                                f"{len(fail_streak)} failed login attempt(s) against '{actor}' from {ip} "
                                f"between {_ts(fail_streak[0]).strftime('%H:%M:%S')} and {_ts(fail_streak[-1]).strftime('%H:%M:%S')}, "
                                f"followed by a successful login at {_ts(e).strftime('%H:%M:%S')} from the same source."
                            ),
                            impact=(
                                "Someone guessed or cracked this account's password and got in. Whoever now controls "
                                f"'{actor}' can read its email, access anything it's permitted to, and use it as a "
                                "foothold to attack the rest of the organization."
                            ),
                            event_refs=[ev["_idx"] for ev in fail_streak] + [e["_idx"]],
                        ))
                fail_streak = []
            else:
                fail_streak = []
        if len(fail_streak) >= BRUTE_FORCE_FAIL_THRESHOLD + 2 and not any(
            ip in ins["title"] for ins in insights
        ):
            insights.append(dict(
                severity="Medium",
                title=f"Repeated failed logins from {ip} (no success observed)",
                description=f"{len(fail_streak)} failed login attempts from {ip}, with no successful login seen in the evidence provided.",
                impact=(
                    "Someone is actively trying to guess this account's password. They don't appear to have "
                    "gotten in yet (based on the evidence reviewed), but the account should be checked and the "
                    "password changed as a precaution."
                ),
                event_refs=[ev["_idx"] for ev in fail_streak],
            ))
    return insights


def _is_regular_beacon(evs):
    """
    Distinguish real beaconing (tight cluster, or a steady automated
    cadence) from coincidental repeat connections scattered randomly across
    a whole day of normal traffic - the latter is just noise at scale and
    should NOT become an insight the analyst has to read.
    """
    times = sorted(_ts(e) for e in evs if e.get("timestamp"))
    if len(times) < 2:
        return False
    span_min = (times[-1] - times[0]).total_seconds() / 60
    if span_min <= BEACON_TIGHT_WINDOW_MIN:
        return True
    gaps = [(times[i + 1] - times[i]).total_seconds() for i in range(len(times) - 1)]
    mean_gap = sum(gaps) / len(gaps)
    if mean_gap > BEACON_MAX_MEAN_GAP_SEC:
        return False
    variance = sum((g - mean_gap) ** 2 for g in gaps) / len(gaps)
    coeff_var = (variance ** 0.5) / mean_gap if mean_gap else 999
    return coeff_var <= BEACON_MAX_COEFF_VAR


def beaconing_detector(events, case=None):
    insights = []
    groups = {}
    for e in events:
        if e["category"] != "Network" or not (e.get("source_ip") and e.get("dest_ip")):
            continue
        key = (e["source_ip"], e["dest_ip"], e.get("port"))
        groups.setdefault(key, []).append(e)

    for (src, dst, port), evs in groups.items():
        if len(evs) < BEACON_MIN_COUNT or not _is_regular_beacon(evs):
            continue
        severity = "Medium"
        reasons = [f"{len(evs)} repeated connections {src} -> {dst}" + (f":{port}" if port else "")]
        if port and int(port) in SUSPICIOUS_PORTS:
            severity = "High"
            reasons.append(f"destination port {port} is commonly associated with malware C2 activity")
        if _is_public_ip(dst):
            reasons.append(f"{dst} is a public/external address")
        insights.append(dict(
            severity=severity,
            title=f"Possible C2 beaconing: {src} -> {dst}",
            description=" · ".join(reasons) + ". Worth confirming whether this destination is expected business traffic.",
            impact=(
                f"If this traffic is malicious, the device at {src} is likely infected and is quietly "
                "'checking in' with an attacker on a regular schedule - it may be leaking data or waiting for "
                "further instructions right now."
            ),
            event_refs=[e["_idx"] for e in evs],
        ))
    return insights


def malware_drop_detector(events, case=None):
    insights = []
    file_events = [e for e in events if e["category"] == "File" and any(
        str(o).lower().endswith((".exe", ".dll", ".sh", ".bat", ".ps1", ".scr")) for o in e.get("objects", []))]
    sec_events = [e for e in events if e["category"] == "Security"]

    for fe in file_events:
        ft = _ts(fe)
        nearby_hits = []
        if ft:
            for se in sec_events:
                st = _ts(se)
                if st and abs((st - ft).total_seconds()) <= 300:
                    nearby_hits.append(se)
        dropped_file = next((o for o in fe["objects"] if str(o).lower().endswith((".exe", ".dll", ".sh", ".bat", ".ps1", ".scr"))), "a file")
        if nearby_hits:
            hashes = [h for se in nearby_hits for h in se.get("objects", [])]
            insights.append(dict(
                severity="High",
                title=f"Malware indicator: {dropped_file} dropped and flagged",
                description=(
                    f"{dropped_file} was written to disk" + (f" at {ft.strftime('%H:%M:%S')}" if ft else "") +
                    (f", matching hash {hashes[0][:16]}..." if hashes else "") +
                    " which was flagged by AV/security tooling within 5 minutes of being dropped."
                ),
                impact=(
                    "A file that security software recognizes as malicious was placed on this machine. It can let "
                    "an attacker keep access to the machine, steal data from it, or use it to spread further into "
                    "the network - it should be treated as an active infection until confirmed otherwise."
                ),
                event_refs=[fe["_idx"]] + [se["_idx"] for se in nearby_hits],
            ))
        else:
            insights.append(dict(
                severity="Medium",
                title=f"Unverified file drop: {dropped_file}",
                description=f"{dropped_file} was written to disk; no AV/security hit was correlated with it in this evidence set - worth checking manually.",
                impact=(
                    "This is a program file appearing where one wasn't expected. It may be harmless (a legitimate "
                    "install or update), but it hasn't been confirmed safe, so it's worth a manual look before "
                    "ruling it out."
                ),
                event_refs=[fe["_idx"]],
            ))
    return insights


def _event_strings_for_domains(e):
    """Actor (sender/account email) plus objects - both can carry a domain worth comparing for lookalikes."""
    vals = list(e.get("objects", []))
    if e.get("actor"):
        vals.append(e["actor"])
    return vals


def lookalike_domain_detector(events, case=None):
    insights = []
    domains = set()
    for e in events:
        for o in _event_strings_for_domains(e):
            o = str(o)
            if "@" in o:
                domains.add(o.split("@")[-1].lower())
            elif "." in o and "/" not in o and ":" not in o and len(o) < 60:
                # ":" excludes our own "Tag:value" object convention (GPSLat:13.09,
                # Scope:mail.read, etc.) and Windows-style "C:\..." paths - a bare,
                # untagged domain-shaped string never contains a colon.
                domains.add(o.lower())

    domains = list(domains)
    flagged = set()
    for i, d1 in enumerate(domains):
        for d2 in domains[i + 1:]:
            if d1 == d2 or (d1, d2) in flagged or (d2, d1) in flagged:
                continue
            dist = _levenshtein(d1, d2)
            if 0 < dist <= 2 and abs(len(d1) - len(d2)) <= 2:
                flagged.add((d1, d2))
                refs = [e["_idx"] for e in events if any(
                    str(o).lower().endswith(d1) or str(o).lower().endswith(d2)
                    for o in _event_strings_for_domains(e)
                )]
                insights.append(dict(
                    severity="High",
                    title=f"Possible lookalike domain: {d1} vs {d2}",
                    description=(
                        f"'{d1}' and '{d2}' differ by only {dist} character(s) - a classic typosquatting/lookalike-domain "
                        f"pattern used in phishing. Verify which one is the legitimate organizational domain."
                    ),
                    impact=(
                        "Emails from the fake look-alike domain can trick employees into handing over passwords, "
                        "approving fraudulent payments, or opening malicious attachments, because the sender address "
                        "looks correct at a glance."
                    ),
                    event_refs=refs,
                ))
    return insights


def suspicious_outbound_mail_detector(events, case=None):
    insights = []
    high_sev_times = []  # timestamps of other High severity findings would be ideal, but detectors run independently;
    for e in events:
        if e["category"] != "Email" or not e.get("actor") or not e.get("objects"):
            continue
        actor_domain = e["actor"].split("@")[-1].lower() if "@" in e["actor"] else None
        for recipient in e["objects"]:
            if "@" not in str(recipient):
                continue
            recip_domain = recipient.split("@")[-1].lower()
            if actor_domain and recip_domain and actor_domain != recip_domain:
                insights.append(dict(
                    severity="Medium",
                    title=f"External outbound email: {e['actor']} -> {recipient}",
                    description=(
                        f"Mail sent from '{e['actor']}' (internal-looking) to an external address '{recipient}'"
                        + (f" at {_ts(e).strftime('%H:%M:%S')}" if e.get("timestamp") else "") +
                        ". Verify this wasn't triggered by a compromised account (possible exfiltration)."
                    ),
                    impact=(
                        "If this account is compromised, this could be company data or sensitive information "
                        "leaving the organization to an address the attacker controls."
                    ),
                    event_refs=[e["_idx"]],
                ))
    return insights


def offhours_access_detector(events, case=None):
    """
    Off-hours logins are common enough in a real environment (shift work,
    on-call, different time zones) that flagging every single one would
    bury the analyst in low-value noise - exactly the problem this tool is
    meant to solve, not reproduce. So this rolls ALL off-hours successes
    into one summary insight rather than one per login.
    """
    matches = [
        e for e in events
        if e["category"] == "Authentication" and e["outcome"] == "Success" and e.get("timestamp")
        and (_ts(e).hour < 6 or _ts(e).hour >= 22)
    ]
    if not matches:
        return []
    examples = ", ".join(
        f"{e.get('actor') or 'unknown'}@{_ts(e).strftime('%H:%M')} from {e.get('source_ip') or '?'}"
        for e in matches[:5]
    )
    more = f", +{len(matches) - 5} more" if len(matches) > 5 else ""
    return [dict(
        severity="Low",
        title=f"{len(matches)} off-hours login(s) observed",
        description=(
            f"{len(matches)} successful login(s) occurred outside typical business hours (before 06:00 or after 22:00). "
            f"Examples: {examples}{more}. Review if off-hours access is not expected for this environment/role."
        ),
        impact=(
            "On its own this is often normal (shift work, travel, a different time zone) - but if it's not "
            "expected for these people, it can mean an account is being used by someone other than its owner."
        ),
        event_refs=[e["_idx"] for e in matches],
    )]


def suspicious_inbox_rule_detector(events, case=None):
    """
    A classic BEC persistence move: once an attacker has a mailbox, they
    create an inbox rule that forwards mail to an address they control
    and/or silently deletes or hides the evidence (moves it to an
    unmonitored folder) - often to intercept password-reset emails or
    hide replies to phishing sent from the compromised account.
    """
    internal_domains = _infer_internal_domains(events, case)
    insights = []
    for e in events:
        if e["category"] != "Mailbox Rule":
            continue
        forward = _object_value(e, "ForwardTo")
        delete_flag = _object_value(e, "DeleteMessage") == "True"
        move = _object_value(e, "MoveToFolder")
        rule_name = _object_value(e, "RuleName") or "unnamed rule"
        if not (forward or delete_flag or move):
            continue

        reasons = []
        severity = "Medium"
        if forward:
            forward_domain = forward.split("@")[-1].lower() if "@" in forward else forward
            external = internal_domains and forward_domain not in internal_domains
            reasons.append(f"forwards mail to {forward}" + (" (external domain)" if external else ""))
            if external:
                severity = "High"
        if delete_flag:
            reasons.append("automatically deletes matching messages")
            severity = "High"
        if move:
            reasons.append(f"moves matching messages to '{move}' (often used to hide activity from the mailbox owner)")
            if severity != "High":
                severity = "Medium"

        insights.append(dict(
            severity=severity,
            title=f"Suspicious inbox rule: '{rule_name}' on {e.get('actor') or 'a mailbox'}",
            description=f"Inbox rule '{rule_name}' " + "; ".join(reasons) + ". Review whether the mailbox owner created this rule intentionally.",
            impact=(
                "This is a common way attackers keep access to a mailbox after breaking in: mail (like password "
                "reset codes or replies to phishing they sent) is quietly redirected or deleted before the real "
                "owner ever sees it, so the compromise stays hidden."
            ),
            event_refs=[e["_idx"]],
        ))
    return insights


def high_risk_oauth_consent_detector(events, case=None):
    """Illicit consent grant is a well-known OAuth phishing technique: trick a user (or an admin) into granting a malicious app broad Graph API permissions, which then persist even after a password reset."""
    insights = []
    for e in events:
        if e["category"] != "OAuth Consent":
            continue
        scope = (_object_value(e, "Scope") or "").lower()
        app = _object_value(e, "App") or "an application"
        consent_type = _object_value(e, "ConsentType")
        matched_scopes = [s for s in HIGH_RISK_OAUTH_SCOPES if s in scope]
        is_admin = consent_type == "Admin"

        if not matched_scopes and not is_admin:
            continue
        severity = "High" if (matched_scopes and is_admin) else ("High" if is_admin else "Medium")
        reasons = []
        if matched_scopes:
            reasons.append(f"requested high-risk permission(s): {', '.join(matched_scopes)}")
        if is_admin:
            reasons.append("granted as ADMIN consent (applies org-wide, not just to one user)")
        insights.append(dict(
            severity=severity,
            title=f"High-risk OAuth consent: {app}",
            description=f"'{app}' was granted consent by {e.get('actor') or 'a user'} - " + "; ".join(reasons) +
                         ". Verify this application is legitimate and expected; revoke if not.",
            impact=(
                "If this application is malicious, it can now read, send, or manage this person's mail on an "
                "ongoing basis - and unlike a stolen password, resetting the password does NOT remove this access. "
                "It has to be manually revoked."
            ),
            event_refs=[e["_idx"]],
        ))
    return insights


def mailbox_delegation_detector(events, case=None):
    """Flags mailbox delegation grants, especially FullAccess/SendAs given to an account outside the organization's own domain(s)."""
    internal_domains = _infer_internal_domains(events, case)
    insights = []
    for e in events:
        if e["category"] != "Mailbox Delegation":
            continue
        rights = _object_value(e, "AccessRights") or ""
        delegate = e.get("actor") or ""
        mailbox = _object_value(e, "Mailbox") or "a mailbox"
        delegate_domain = delegate.split("@")[-1].lower() if "@" in delegate else None
        external = bool(internal_domains and delegate_domain and delegate_domain not in internal_domains)
        if not rights and not external:
            continue
        severity = "High" if external and rights.lower() in ("fullaccess", "full access", "sendas", "send as") else "Medium"
        insights.append(dict(
            severity=severity,
            title=f"Mailbox delegation granted: {mailbox} -> {delegate}",
            description=f"'{delegate}' was granted {rights or 'access'} on {mailbox}" +
                         (" - delegate's domain is external to the organization." if external else "") +
                         " Verify this delegation was intentional.",
            impact=(
                f"'{delegate}' can now read, send, or manage mail on {mailbox} as if they were the owner" +
                (" - and because that account is outside the organization, this is especially concerning." if external else ". ")
            ),
            event_refs=[e["_idx"]],
        ))
    return insights


def impossible_travel_detector(events, case=None):
    """
    Same account, two sign-ins from different reported locations too close
    together in time to be physically plausible - a strong signal of
    credential compromise (attacker signing in from elsewhere while the
    legitimate user is also active, or the account being used from two
    places at once).
    """
    insights = []
    by_actor = {}
    for e in events:
        if e["category"] == "Authentication" and e.get("actor") and e.get("timestamp"):
            loc = _object_value(e, "Location")
            if loc:
                by_actor.setdefault(e["actor"], []).append((_ts(e), loc, e))

    for actor, entries in by_actor.items():
        entries.sort(key=lambda x: x[0])
        for i in range(len(entries) - 1):
            t1, loc1, e1 = entries[i]
            t2, loc2, e2 = entries[i + 1]
            if loc1 != loc2 and (t2 - t1) <= timedelta(minutes=IMPOSSIBLE_TRAVEL_WINDOW_MIN):
                insights.append(dict(
                    severity="High",
                    title=f"Impossible travel: {actor}",
                    description=(
                        f"'{actor}' signed in from '{loc1}' at {t1.strftime('%Y-%m-%d %H:%M')} and then from "
                        f"'{loc2}' at {t2.strftime('%Y-%m-%d %H:%M')} - only {int((t2 - t1).total_seconds() / 60)} "
                        f"minute(s) apart, which is not physically plausible if these are genuinely different locations."
                    ),
                    impact=(
                        f"This strongly suggests '{actor}'s username and password are known to someone else, who is "
                        "signing in from a different location while the real user may not even realize it."
                    ),
                    event_refs=[e1["_idx"], e2["_idx"]],
                ))
    return insights


GPS_TELEPORT_MAX_PLAUSIBLE_KMH = 900  # faster than this and it's not a car - it's a spoofed/teleported GPS fix
ODOMETER_ROLLBACK_TOLERANCE_KM = 1    # allow trivial GPS/odometer read noise without flagging every 0.1km wobble


def _haversine_km(lat1, lon1, lat2, lon2):
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlambda / 2) ** 2
    return 2 * r * math.asin(min(1, math.sqrt(a)))


def _vehicle_events_by_vin(events):
    by_vin = {}
    for e in events:
        if e.get("category") != "Vehicle Telematics":
            continue
        vin = e.get("actor") or _object_value(e, "VIN")
        if not vin:
            continue
        by_vin.setdefault(vin, []).append(e)
    return by_vin


def gps_teleport_detector(events, case=None):
    """
    A genuine vehicle can't jump hundreds of kilometers between two GPS
    fixes seconds apart. When that happens, the far more likely explanation
    is a spoofed/replayed GPS feed (or a tampered telematics unit) rather
    than the vehicle itself - the vehicle-world equivalent of "impossible
    travel" for user sign-ins.
    """
    insights = []
    for vin, evs in _vehicle_events_by_vin(events).items():
        fixes = []
        for e in evs:
            lat = _object_value(e, "GPSLat")
            lon = _object_value(e, "GPSLon")
            if lat and lon and e.get("timestamp"):
                try:
                    fixes.append((_ts(e), float(lat), float(lon), e))
                except ValueError:
                    continue
        fixes.sort(key=lambda x: x[0])
        for i in range(len(fixes) - 1):
            t1, lat1, lon1, e1 = fixes[i]
            t2, lat2, lon2, e2 = fixes[i + 1]
            hours = max((t2 - t1).total_seconds() / 3600, 1 / 3600)
            distance_km = _haversine_km(lat1, lon1, lat2, lon2)
            implied_kmh = distance_km / hours
            if distance_km >= 50 and implied_kmh > GPS_TELEPORT_MAX_PLAUSIBLE_KMH:
                insights.append(dict(
                    severity="High",
                    title=f"Likely GPS spoofing / vehicle teleport: VIN {vin}",
                    description=(
                        f"VIN {vin} reported a GPS fix at ({lat1:.4f}, {lon1:.4f}) at {t1.strftime('%H:%M:%S')}, then "
                        f"at ({lat2:.4f}, {lon2:.4f}) at {t2.strftime('%H:%M:%S')} - {distance_km:,.0f} km apart in "
                        f"{(t2 - t1).total_seconds():.0f} second(s), an implied speed of {implied_kmh:,.0f} km/h."
                    ),
                    impact=(
                        "No road vehicle can cover that distance in that time. The telematics unit's GPS feed is "
                        "most likely being spoofed or replayed to hide the vehicle's real location - a common way "
                        "to mask unauthorized use, cargo diversion, or an unauthorized border crossing."
                    ),
                    event_refs=[e1["_idx"], e2["_idx"]],
                ))
    return insights


def odometer_rollback_detector(events, case=None):
    """Mileage should only ever go up. A drop between two readings for the same VIN is a classic odometer-tampering signature (used to hide true mileage, or mask that a different set of trips actually happened)."""
    insights = []
    for vin, evs in _vehicle_events_by_vin(events).items():
        readings = []
        for e in evs:
            odo = _object_value(e, "Odometer")
            if odo and e.get("timestamp"):
                try:
                    readings.append((_ts(e), float(str(odo).replace(",", "")), e))
                except ValueError:
                    continue
        readings.sort(key=lambda x: x[0])
        for i in range(len(readings) - 1):
            t1, odo1, e1 = readings[i]
            t2, odo2, e2 = readings[i + 1]
            if odo2 < odo1 - ODOMETER_ROLLBACK_TOLERANCE_KM:
                insights.append(dict(
                    severity="High",
                    title=f"Possible odometer rollback: VIN {vin}",
                    description=(
                        f"VIN {vin} reported {odo1:,.0f} km at {t1.strftime('%Y-%m-%d %H:%M')}, then {odo2:,.0f} km "
                        f"at {t2.strftime('%Y-%m-%d %H:%M')} - a drop of {odo1 - odo2:,.0f} km with no maintenance "
                        f"reset documented."
                    ),
                    impact=(
                        "Odometer readings should be monotonically increasing. A drop like this usually means the "
                        "reading was tampered with - often to understate true mileage (resale fraud) or to obscure "
                        "unauthorized trips taken during the period the rollback covers."
                    ),
                    event_refs=[e1["_idx"], e2["_idx"]],
                ))
    return insights


def unauthorized_obd_access_detector(events, case=None):
    """An OBD-II diagnostic session is a privileged interface - it can read/clear fault codes and reflash firmware. One opened by a technician ID outside the authorized list is worth a hard look, especially off-hours."""
    insights = []
    for e in events:
        if e.get("category") != "Vehicle Telematics" or "diagnostic session" not in (e.get("action") or "").lower():
            continue
        technician = _object_value(e, "TechnicianID")
        vin = e.get("actor") or _object_value(e, "VIN")
        if technician and technician.upper() in AUTHORIZED_TECHNICIAN_IDS:
            continue
        off_hours = e.get("timestamp") and (_ts(e).hour < 6 or _ts(e).hour >= 22)
        insights.append(dict(
            severity="High",
            title=f"Unauthorized OBD-II diagnostic access: VIN {vin}",
            description=(
                f"An OBD-II diagnostic session was opened on VIN {vin} by technician ID '{technician or 'unknown'}', "
                "which is not on the authorized fleet-maintenance technician list"
                + (f", at {_ts(e).strftime('%H:%M:%S')} (outside normal service hours)" if off_hours else "") + "."
            ),
            impact=(
                "OBD-II access can read live sensor data, clear fault codes, and in some cases reflash ECU firmware. "
                "An unauthorized diagnostic session is a plausible way to disable/alter safety or tracking systems, "
                "or to cover up tampering evidence by clearing the trouble codes it caused."
            ),
            event_refs=[e["_idx"]],
        ))
    return insights


def geofence_breach_detector(events, case=None):
    """A vehicle crossing into a zone it's specifically fenced out of (a restricted depot, a border, a customer exclusion zone) is either a real security incident or a policy violation worth a human look either way."""
    insights = []
    for e in events:
        if e.get("category") != "Vehicle Telematics" or e.get("outcome") != "Breach":
            continue
        vin = e.get("actor") or _object_value(e, "VIN")
        zone = _object_value(e, "GeofenceZone") or "a restricted zone"
        high_risk = any(w in zone.lower() for w in ("border", "unauthorized", "restricted", "exclusion"))
        insights.append(dict(
            severity="High" if high_risk else "Medium",
            title=f"Geofence breach: VIN {vin}",
            description=(
                f"VIN {vin} entered '{zone}'" + (f" at {_ts(e).strftime('%Y-%m-%d %H:%M')}" if e.get("timestamp") else "") +
                " - a zone this vehicle is fenced out of."
            ),
            impact=(
                "This can mean cargo/asset diversion, an unauthorized cross-border movement, or a compromised "
                "vehicle being driven somewhere it has no legitimate reason to be. Worth confirming against the "
                "driver's actual assignment for that shift."
            ),
            event_refs=[e["_idx"]],
        ))
    return insights


ALL_DETECTORS = [
    brute_force_detector,
    beaconing_detector,
    malware_drop_detector,
    lookalike_domain_detector,
    suspicious_outbound_mail_detector,
    offhours_access_detector,
    suspicious_inbox_rule_detector,
    high_risk_oauth_consent_detector,
    mailbox_delegation_detector,
    impossible_travel_detector,
    gps_teleport_detector,
    odometer_rollback_detector,
    unauthorized_obd_access_detector,
    geofence_breach_detector,
]


def _dedupe_insights(insights):
    """
    The same real-world issue can legitimately show up in more than one
    piece of evidence (e.g. a mailbox delegation grant appears in both the
    Unified Audit Log AND a dedicated delegation report) - each detector
    run sees it once per source and would otherwise report it twice.
    Merge insights that share a (severity, title) into one, combining
    their supporting event references rather than dropping evidence.
    """
    merged = {}
    order = []
    for ins in insights:
        key = (ins["severity"], ins["title"])
        if key not in merged:
            merged[key] = dict(ins)
            merged[key]["event_refs"] = list(dict.fromkeys(ins.get("event_refs", [])))
            order.append(key)
        else:
            existing_refs = merged[key]["event_refs"]
            for ref in ins.get("event_refs", []):
                if ref not in existing_refs:
                    existing_refs.append(ref)
    return [merged[k] for k in order]


def run_all_detectors(events, case=None):
    for i, e in enumerate(events):
        e["_idx"] = i
    insights = []
    for detector in ALL_DETECTORS:
        insights.extend(detector(events, case))
    insights = _dedupe_insights(insights)
    severity_rank = {"High": 0, "Medium": 1, "Low": 2}
    insights.sort(key=lambda ins: severity_rank.get(ins["severity"], 9))
    return insights
