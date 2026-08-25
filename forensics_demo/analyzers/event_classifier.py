"""
Turns one line of text (a log line, a CSV row rendered as key=value pairs,
an email header/body line, an OCR'd terminal screenshot line - anything)
into a structured Event: who, did what, when, from/to where, with what
outcome. This is the layer that makes a 1000-line log readable as a story
instead of a wall of text.

Strategy, in order:
  1. A library of specific phrasing templates for common security-log
     verbs (failed login, outbound connection, DNS resolution, file
     dropped, AV hash hit, outbound mail, ARP update, ssh/wget commands).
     These give the most precise, natural-sounding action text.
  2. A generic key=value parser (source_ip=..., dest_port=..., etc.) for
     structured/CSV-style lines that don't match a specific template -
     this is what lets the tool handle log formats it has never seen
     before, not just the ones we hand-wrote templates for.
  3. A keyword-scoring fallback that guesses a category (Authentication /
     Network / DNS / File / Email / Security / Process / Other) so every
     line becomes *some* event rather than being silently dropped - a
     20-line gap in the story is worse than one vague "Other" entry.

Nothing here is exhaustive - it's a starting rule set meant to be extended
as real logs get run through it. New templates are just new entries in
LINE_TEMPLATES.
"""

import re
from core.timeparse import extract_timestamp
from extractors.regex_extractors import extract_entities

TAG_MAP = {
    "auth": "Authentication", "login": "Authentication", "sshd": "Authentication",
    "firewall": "Network", "net": "Network", "fw": "Network", "vpn": "Network",
    "dns": "DNS",
    "file": "File", "fs": "File",
    "av": "Security", "ids": "Security", "ips": "Security", "edr": "Security",
    "mail": "Email", "smtp": "Email",
    "proc": "Process", "process": "Process",
    "telematics": "Vehicle Telematics", "obd": "Vehicle Telematics", "gps": "Vehicle Telematics",
}

CATEGORY_KEYWORDS = {
    "Authentication": ["login", "logon", "authentication", "password", "sudo", " su ", "session opened", "session closed", "credential"],
    "Network": ["connection", "connect", "tcp", "udp", "firewall", "port", "vpn", "traffic"],
    "DNS": ["dns", "resolved", "resolve", "query for"],
    "File": ["file ", "wrote", "dropped", "deleted", "modified", "created", "downloaded"],
    "Security": ["malware", "virus", "antivirus", "quarantine", "hash detected", "signature", "ioc", "threat"],
    "Email": ["mail", "smtp", "email", "attachment"],
    "Process": ["process", "spawned", "pid ", "executed", "exec("],
    "Vehicle Telematics": ["ignition", "immobilizer", "key fob", "odometer", "geofence", "diagnostic session",
                            "obd-ii", "obd ii", "gps fix", "gps ping", "telematics", " dtc ", "vin ", "vehicle"],
}

SUCCESS_WORDS = ["success", "successful", "succeeded", "allowed", "permitted", "granted", "opened"]
FAIL_WORDS = ["fail", "failed", "invalid", "denied", "blocked", "rejected", "unauthorized", "error"]

IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")


def _find_ip_near(text, keyword, ips):
    """Return the IP closest after `keyword` in the text, if any."""
    idx = text.lower().find(keyword)
    if idx == -1:
        return None
    best, best_dist = None, 10 ** 9
    for ip in ips:
        pos = text.find(ip)
        if pos == -1:
            continue
        dist = pos - idx
        if 0 <= dist < best_dist:
            best, best_dist = ip, dist
    return best


def _handle_failed_login(m, ips):
    return dict(category="Authentication", action="failed login attempt", actor=m.group(1),
                outcome="Failure", source_ip=ips[0] if ips else None)


def _handle_success_login(m, ips):
    return dict(category="Authentication", action="successful login", actor=m.group(1),
                outcome="Success", source_ip=ips[0] if ips else None)


def _handle_outbound_conn(m, ips):
    port = m.group(3) if m.lastindex and m.lastindex >= 3 else None
    return dict(category="Network", action="outbound connection", outcome=None,
                source_ip=m.group(1), dest_ip=m.group(2), port=port)


def _handle_blocked_conn(m, ips):
    return dict(category="Network", action="connection attempt blocked", outcome="Blocked",
                dest_ip=m.group(1), source_ip=m.group(2), port=m.group(3) if m.lastindex and m.lastindex >= 3 else None)


def _handle_dns(m, ips):
    return dict(category="DNS", action="DNS resolution", outcome=None,
                dest_ip=m.group(2), objects=[m.group(1)])


def _handle_file_dropped(m, ips):
    return dict(category="File", action="file dropped", outcome=None, objects=[m.group(1)])


def _handle_hash_detect(m, ips):
    return dict(category="Security", action="AV hash detection", outcome="Failure", objects=[m.group(1)])


def _handle_outbound_mail(m, ips):
    return dict(category="Email", action="outbound mail", outcome=None, actor=m.group(1), objects=[m.group(2)])


def _handle_arp(m, ips):
    return dict(category="Network", action="ARP table update", outcome=None, objects=[m.group(1)])


def _handle_ssh_cmd(m, ips):
    return dict(category="Authentication", action="SSH session initiated", outcome=None,
                actor=m.group(1), dest_ip=m.group(2), protocol="SSH")


def _handle_download_cmd(m, ips):
    return dict(category="Network", action="file download command", outcome=None,
                objects=[m.group(2)], protocol=m.group(1).upper())


def _clean(s):
    """Strip trailing sentence punctuation a greedy \\S+ capture can pick up (mirrors the entity extractor's own rstrip)."""
    return s.rstrip(".,;:)") if s else s


def _handle_ignition_bypass(m, ips):
    return dict(category="Vehicle Telematics", actor=_clean(m.group(1)),
                action="ignition without authorized key fob (immobilizer bypass suspected)",
                outcome="Anomaly")


def _handle_gps_fix(m, ips):
    return dict(category="Vehicle Telematics", actor=_clean(m.group(1)), action="GPS fix",
                objects=[f"GPSCoord:{m.group(2)}"])


def _handle_obd_unauthorized(m, ips):
    return dict(category="Vehicle Telematics", actor=_clean(m.group(1)), action="OBD-II diagnostic session opened",
                objects=[f"TechnicianID:{_clean(m.group(2))}"])


def _handle_odometer_rollback(m, ips):
    return dict(category="Vehicle Telematics", actor=_clean(m.group(1)), action="odometer reading",
                outcome="Anomaly",
                objects=[f"Odometer:{m.group(2).replace(',', '')}", f"PreviousOdometer:{m.group(3).replace(',', '')}"])


def _handle_geofence_breach(m, ips):
    return dict(category="Vehicle Telematics", actor=_clean(m.group(1)), action="geofence breach", outcome="Breach",
                objects=[f"GeofenceZone:{m.group(2)}"])


def _handle_dtc_set(m, ips):
    return dict(category="Vehicle Telematics", actor=_clean(m.group(2)), action="diagnostic trouble code set",
                objects=[f"DTC:{m.group(1)}"])


LINE_TEMPLATES = [
    (re.compile(r"failed login attempt for user (\S+)", re.I), _handle_failed_login),
    (re.compile(r"successful login for user (\S+)", re.I), _handle_success_login),
    (re.compile(r"outbound connection from ([\d.]+) to ([\d.]+)(?::(\d+))?", re.I), _handle_outbound_conn),
    (re.compile(r"connection attempt to ([\d.]+) from ([\d.]+)(?::(\d+))? blocked", re.I), _handle_blocked_conn),
    (re.compile(r"query for (\S+) resolved to ([\d.]+)", re.I), _handle_dns),
    (re.compile(r"file dropped:?\s*(\S+)", re.I), _handle_file_dropped),
    (re.compile(r"(?:hash detected|SHA256|MD5)\s*:?\s*([a-fA-F0-9]{32,64})", re.I), _handle_hash_detect),
    (re.compile(r"outbound mail from (\S+) to (\S+)", re.I), _handle_outbound_mail),
    (re.compile(r"arp entry updated for ([0-9a-f:]{17})", re.I), _handle_arp),
    (re.compile(r"ssh\s+(\S+)@([\d.]+)", re.I), _handle_ssh_cmd),
    (re.compile(r"(wget|curl)\s+(\S+)", re.I), _handle_download_cmd),
    (re.compile(r"Ignition ON for VIN (\S+).{0,40}key fob not recognized", re.I), _handle_ignition_bypass),
    (re.compile(r"GPS fix for VIN (\S+):\s*([\-\d.]+,\s*[\-\d.]+)", re.I), _handle_gps_fix),
    (re.compile(r"OBD-II diagnostic session opened on VIN (\S+) by technician (\S+)", re.I), _handle_obd_unauthorized),
    (re.compile(r"Odometer reading for VIN (\S+):\s*([\d,]+)\s*km\s*\(previous reading\s*([\d,]+)\s*km", re.I), _handle_odometer_rollback),
    (re.compile(r"Geofence breach:\s*VIN (\S+) entered restricted zone '([^']+)'", re.I), _handle_geofence_breach),
    (re.compile(r"DTC (\S+) \([^)]+\) set on VIN (\S+)", re.I), _handle_dtc_set),
]

KV_KEY_MAP = {
    "source_ip": "source_ip", "src_ip": "source_ip", "srcip": "source_ip",
    "dest_ip": "dest_ip", "destination_ip": "dest_ip", "dst_ip": "dest_ip", "dstip": "dest_ip",
    "dest_port": "port", "port": "port", "dport": "port",
    "protocol": "protocol", "proto": "protocol",
    "user": "actor", "username": "actor", "account": "actor",
    "status": "outcome", "result": "outcome",
    "action": "action", "event": "action",
}


def _parse_kv(text):
    pairs = re.findall(r"(\w+)\s*=\s*([^,]+)", text)
    out = {}
    for k, v in pairs:
        mapped = KV_KEY_MAP.get(k.lower())
        if mapped:
            out[mapped] = v.strip()
    return out


def _guess_category(lower_text):
    for cat, kws in CATEGORY_KEYWORDS.items():
        if any(kw in lower_text for kw in kws):
            return cat
    return "Other"


def _guess_outcome(lower_text):
    if any(w in lower_text for w in FAIL_WORDS):
        return "Failure"
    if any(w in lower_text for w in SUCCESS_WORDS):
        return "Success"
    return None


def classify_line(text, fallback_date=None):
    """
    Returns a dict of Event fields (minus source_file/location, which the
    caller/pipeline knows). Never returns None - every line becomes an
    event, even if a vague "Other" one, so the timeline has no silent gaps.
    """
    timestamp, approximate = extract_timestamp(text, fallback_date)
    lower = text.lower()
    ips = IP_RE.findall(text)

    fields = dict(category=None, actor=None, action=None, outcome=None,
                  source_ip=None, dest_ip=None, port=None, protocol=None, objects=[])

    tag_match = re.search(r"\[([A-Za-z]+)\]", text)
    if tag_match:
        fields["category"] = TAG_MAP.get(tag_match.group(1).lower())

    kv_used = False
    for pattern, handler in LINE_TEMPLATES:
        m = pattern.search(text)
        if m:
            fields.update({k: v for k, v in handler(m, ips).items() if v is not None})
            break
    else:
        kv = _parse_kv(text)
        if kv:
            fields.update(kv)
            kv_used = True

    if not fields.get("category"):
        fields["category"] = _guess_category(lower)
    if not fields.get("outcome"):
        fields["outcome"] = _guess_outcome(lower)
    if not fields.get("action"):
        if kv_used:
            # Structured/tabular line (e.g. a CSV row) with no explicit
            # action/event column - use a short category label rather than
            # dumping the whole "col=val, col=val, ..." string as the action.
            default_actions = {
                "Authentication": "authentication event", "Network": "network activity",
                "DNS": "DNS activity", "File": "file activity", "Security": "security event",
                "Email": "email activity", "Process": "process activity",
            }
            fields["action"] = default_actions.get(fields["category"], "activity")
        else:
            # Natural-language line with no template match - the raw text
            # itself is the most informative thing we can show.
            fields["action"] = text.strip()[:120]

    # IP fallback: never assign the same address to both source and dest
    # just because it's the only IP on the line (e.g. a DNS line naming the
    # resolved IP once shouldn't also become its own "source").
    available_ips = [ip for ip in ips if ip != fields.get("dest_ip")]
    if not fields.get("source_ip") and available_ips:
        near_from = _find_ip_near(text, "from", available_ips)
        fields["source_ip"] = near_from or available_ips[0]
    if not fields.get("dest_ip") and len(ips) > 1:
        near_to = _find_ip_near(text, "to", ips)
        remaining = [ip for ip in ips if ip != fields.get("source_ip")]
        fields["dest_ip"] = near_to or (remaining[0] if remaining else None)

    if not fields.get("actor"):
        um = re.search(r"\buser[s]?\s+([A-Za-z0-9_.\-]{2,32})", text, re.I)
        if um:
            fields["actor"] = um.group(1)

    entities = extract_entities(text)
    obj_types = {"email", "domain", "url", "hash_sha256", "hash_sha1", "hash_md5",
                 "crypto_btc", "crypto_eth", "mac_address", "file_path"}
    existing_lower = {str(o).lower() for o in fields["objects"]}
    for ent in entities:
        if ent["type"] in obj_types and ent["value"].lower() not in existing_lower:
            fields["objects"].append(ent["value"])
            existing_lower.add(ent["value"].lower())
        if not fields.get("actor") and ent["type"] == "email":
            fields["actor"] = ent["value"]

    # Don't list the actor a second time as a bare "object" (e.g. the
    # sender's own address showing up in an "outbound mail" event's objects).
    if fields.get("actor"):
        fields["objects"] = [o for o in fields["objects"] if str(o).lower() != fields["actor"].lower()]

    return dict(
        timestamp=timestamp.isoformat() if timestamp else None,
        approximate=approximate,
        category=fields["category"],
        actor=fields["actor"],
        action=fields["action"],
        outcome=fields["outcome"],
        source_ip=fields["source_ip"],
        dest_ip=fields["dest_ip"],
        port=fields["port"],
        protocol=fields["protocol"],
        objects=fields["objects"],
        raw=text,
    )
