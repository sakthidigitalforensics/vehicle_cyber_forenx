"""
Schema-aware classification for common Microsoft 365 / Entra ID forensic
export formats:
  - Unified Audit Log (Purview / Search-UnifiedAuditLog export)
  - Entra ID (Azure AD) sign-in logs
  - OAuth application consent reports
  - Mailbox delegation reports
  - Inbox rule detail reports

These exports have real, if loosely standardized, column schemas - so
rather than running them through the generic line classifier (which would
just guess from keywords), we detect the schema from the header row and
map known columns directly to Event fields. This is far more accurate for
these specific, high-value BEC/account-compromise artifacts, which is the
whole point of naming them explicitly rather than treating everything as
a generic log.

Falls back to returning None (letting the caller use the generic
classifier) for any row that doesn't match a known schema, so unrelated
CSVs/spreadsheets are unaffected.
"""

import json
import re
from core.timeparse import extract_timestamp

IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")


def _norm(key):
    return str(key).strip().lower().replace(" ", "").replace("_", "").replace("-", "")


def _get(row, *names):
    """Case/space/underscore-insensitive column lookup."""
    normed = {_norm(k): v for k, v in row.items()}
    for name in names:
        v = normed.get(_norm(name))
        if v not in (None, ""):
            return v
    return None


def _deep_find(obj, keys):
    """Search a nested dict/list (e.g. a decoded AuditData blob) for the first scalar value whose key matches (case-insensitive) any of `keys`."""
    keys = {_norm(k) for k in keys}
    stack = [obj]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for k, v in node.items():
                if _norm(k) in keys and not isinstance(v, (dict, list)):
                    return v
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return None


def _deep_find_pairs(obj):
    """
    AuditData commonly nests its real detail inside lists of
    {"Name": ..., "Value"/"NewValue": ...} dicts (Exchange "Parameters",
    "ModifiedProperties", Azure AD "ExtendedProperties"/"TargetResources"
    modifiedProperties, etc.) - schema varies by workload, so rather than
    hardcode each workload's exact path, we walk the whole structure and
    collect every such pair we find.
    """
    pairs = []
    stack = [obj]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if "Name" in node and ("Value" in node or "NewValue" in node):
                val = node.get("Value", node.get("NewValue"))
                pairs.append((str(node["Name"]), str(val)))
            for k, v in node.items():
                if k not in ("Name", "Value", "NewValue"):
                    stack.append(v)
        elif isinstance(node, list):
            stack.extend(node)
    return pairs


def _pairs_value(pairs, *name_fragments):
    """Find the value of the first pair whose Name contains any of the given fragments (case-insensitive)."""
    frags = [f.lower() for f in name_fragments]
    for name, value in pairs:
        if any(f in name.lower() for f in frags):
            return value
    return None


# --------------------------------------------------------------------------
# Schema detection
# --------------------------------------------------------------------------

def detect_schema(row):
    keys = {_norm(k) for k in row.keys()}

    if "operations" in keys and ("auditdata" in keys or "userids" in keys):
        return "ual"
    if ("status" in keys and "ipaddress" in keys and "auditdata" not in keys
            and keys & {"application", "resourcedisplayname", "requestid", "signinerrorcode"}):
        return "signin"
    if "mailbox" in keys and (keys & {"rulename", "forwardto", "redirectto", "actions", "ruledetail"}):
        return "inboxrule"
    if "mailbox" in keys and (keys & {"accessrights", "delegate", "permissiontype", "granteddelegate"}):
        return "delegation"
    if (keys & {"appdisplayname", "applicationdisplayname", "appname"}
            and keys & {"permission", "scope", "permissionsgranted", "scopes"}):
        return "consent"
    return None


# --------------------------------------------------------------------------
# Per-schema classifiers -> Event field dicts (same shape as event_classifier.classify_line)
# --------------------------------------------------------------------------

def _base_event(timestamp, approximate, category, actor, action, outcome=None,
                 source_ip=None, dest_ip=None, port=None, protocol=None, objects=None, raw=""):
    return dict(timestamp=timestamp.isoformat() if timestamp else None, approximate=approximate,
                category=category, actor=actor, action=action, outcome=outcome,
                source_ip=source_ip, dest_ip=dest_ip, port=port, protocol=protocol,
                objects=objects or [], raw=raw)


def classify_ual_row(row, fallback_date=None):
    ts_raw = _get(row, "creationdate", "creation date", "creationtime")
    timestamp, approx = extract_timestamp(str(ts_raw), fallback_date) if ts_raw else (None, True)

    actor = _get(row, "userids", "user ids", "userid")
    operation = _get(row, "operations", "operation") or "AuditEvent"
    audit_raw = _get(row, "auditdata", "audit data")

    audit = {}
    if audit_raw:
        try:
            audit = json.loads(audit_raw) if isinstance(audit_raw, str) else audit_raw
        except (ValueError, TypeError):
            audit = {}

    client_ip = _deep_find(audit, ["ClientIP", "ClientIPAddress", "ActorIpAddress"])
    if client_ip:
        m = IP_RE.search(str(client_ip))
        client_ip = m.group(0) if m else None
    result_status = _deep_find(audit, ["ResultStatus", "Result"])
    outcome = None
    if result_status:
        outcome = "Success" if str(result_status).lower() in ("succeeded", "success", "true") else "Failure"

    pairs = _deep_find_pairs(audit)
    op_lower = str(operation).lower()
    objects = []

    if "inboxrule" in op_lower.replace("-", "").replace(" ", ""):
        category, action = "Mailbox Rule", f"inbox rule change ({operation})"
        forward = _pairs_value(pairs, "forwardto", "redirectto", "forwardingsmtpaddress")
        delete = _pairs_value(pairs, "deletemessage")
        move = _pairs_value(pairs, "movetofolder")
        rule_name = _pairs_value(pairs, "rulename", "name") or _deep_find(audit, ["Name"])
        if rule_name:
            objects.append(f"RuleName:{rule_name}")
        if forward:
            objects.append(f"ForwardTo:{forward}")
        if delete and str(delete).lower() == "true":
            objects.append("DeleteMessage:True")
        if move:
            objects.append(f"MoveToFolder:{move}")
    elif "mailboxpermission" in op_lower.replace("-", "").replace(" ", "") or "recipientpermission" in op_lower.replace("-", "").replace(" ", ""):
        category, action = "Mailbox Delegation", f"mailbox permission change ({operation})"
        rights = _pairs_value(pairs, "accessrights", "permission")
        mailbox = _deep_find(audit, ["ObjectId", "MailboxOwnerUPN"]) or _get(row, "objectids", "objectid")
        # UserIds on a UAL row is whoever PERFORMED the action, which for
        # Add-MailboxPermission is not the delegate - the actual grantee is
        # in the Parameters "User" field. mailbox_delegation_detector
        # expects `actor` to be the delegate (matching the dedicated
        # delegation-report schema), so re-point it here and keep the
        # original UserIds as a "GrantedBy" object instead.
        delegate = _pairs_value(pairs, "user")
        if delegate:
            objects.append(f"GrantedBy:{actor}")
            actor = delegate
        if rights:
            objects.append(f"AccessRights:{rights}")
        if mailbox:
            objects.append(f"Mailbox:{mailbox}")
    elif "consent" in op_lower:
        category, action = "OAuth Consent", f"application consent ({operation})"
        app_name = _deep_find(audit, ["ApplicationDisplayName", "ApplicationId", "Application"])
        scope = _pairs_value(pairs, "scope", "permission", "consentaction")
        is_admin = _pairs_value(pairs, "isadminconsent") or _deep_find(audit, ["IsAdminConsent"])
        if app_name:
            objects.append(f"App:{app_name}")
        if scope:
            objects.append(f"Scope:{scope}")
        objects.append(f"ConsentType:{'Admin' if str(is_admin).lower() == 'true' else 'User'}")
    elif "login" in op_lower or "loggedin" in op_lower.replace(" ", ""):
        category, action = "Authentication", f"UAL sign-in event ({operation})"
    elif op_lower in ("send", "sendas", "sendonbehalf") or op_lower.startswith("send"):
        category, action = "Email", f"mail sent ({operation})"
        recipient = _deep_find(audit, ["To", "Recipients"])
        if recipient:
            objects.append(str(recipient))
    else:
        category, action = "Audit", operation

    workload = _deep_find(audit, ["Workload"])
    if workload:
        objects.append(f"Workload:{workload}")

    return _base_event(timestamp, approx, category, actor, action, outcome,
                        source_ip=client_ip, objects=objects,
                        raw=f"[UAL] {operation} by {actor}" + (f" from {client_ip}" if client_ip else ""))


def classify_signin_row(row, fallback_date=None):
    ts_raw = _get(row, "date (utc)", "date", "createddatetime", "timestamp")
    timestamp, approx = extract_timestamp(str(ts_raw), fallback_date) if ts_raw else (None, True)

    actor = _get(row, "user", "username", "userprincipalname", "user principal name")
    app = _get(row, "application", "resourcedisplayname", "resource")
    status = _get(row, "status", "result")
    ip = _get(row, "ip address", "ipaddress", "client ip")
    location = _get(row, "location")
    error_code = _get(row, "sign-in error code", "signinerrorcode", "error code")
    conditional_access = _get(row, "conditional access", "conditionalaccessstatus")

    outcome = None
    if status is not None:
        outcome = "Success" if str(status).strip().lower() in ("success", "0", "succeeded") else "Failure"

    objects = []
    if location:
        objects.append(f"Location:{location}")
    if error_code and outcome == "Failure":
        objects.append(f"ErrorCode:{error_code}")
    if conditional_access:
        objects.append(f"ConditionalAccess:{conditional_access}")

    action = f"Entra sign-in ({app})" if app else "Entra sign-in"
    return _base_event(timestamp, approx, "Authentication", actor, action, outcome,
                        source_ip=str(ip) if ip else None, objects=objects,
                        raw=f"[Entra sign-in] {actor} -> {app} [{status}] from {ip} ({location})")


def classify_consent_row(row, fallback_date=None):
    ts_raw = _get(row, "consent date", "date", "timestamp", "created")
    timestamp, approx = extract_timestamp(str(ts_raw), fallback_date) if ts_raw else (None, True)

    actor = _get(row, "user", "principal display name", "granted by", "assigned to")
    app = _get(row, "app display name", "application display name", "app name", "application")
    scope = _get(row, "permission", "scope", "permissions granted", "scopes")
    is_admin = _get(row, "isadminconsent", "admin consent", "consent type")

    objects = []
    if app:
        objects.append(f"App:{app}")
    if scope:
        objects.append(f"Scope:{scope}")
    admin_flag = str(is_admin).lower() in ("true", "admin", "allprincipals", "yes")
    objects.append(f"ConsentType:{'Admin' if admin_flag else 'User'}")

    return _base_event(timestamp, approx, "OAuth Consent", actor, f"consent granted to {app or 'an application'}",
                        objects=objects, raw=f"[OAuth consent] {actor} granted {scope} to {app}")


def classify_inboxrule_row(row, fallback_date=None):
    ts_raw = _get(row, "date", "created", "lastmodifiedtime", "timestamp")
    timestamp, approx = extract_timestamp(str(ts_raw), fallback_date) if ts_raw else (None, True)

    mailbox = _get(row, "mailbox")
    rule_name = _get(row, "rulename", "rule name")
    forward = _get(row, "forwardto", "redirectto", "forwardingsmtpaddress")
    delete = _get(row, "deletemessage")
    move = _get(row, "movetofolder")
    enabled = _get(row, "enabled")

    objects = []
    if rule_name:
        objects.append(f"RuleName:{rule_name}")
    if forward:
        objects.append(f"ForwardTo:{forward}")
    if delete and str(delete).lower() == "true":
        objects.append("DeleteMessage:True")
    if move:
        objects.append(f"MoveToFolder:{move}")
    if enabled is not None:
        objects.append(f"Enabled:{enabled}")

    return _base_event(timestamp, approx, "Mailbox Rule", mailbox, f"inbox rule '{rule_name or 'unnamed'}'",
                        objects=objects, raw=f"[Inbox rule] {mailbox}: {rule_name} forward={forward} delete={delete}")


def classify_delegation_row(row, fallback_date=None):
    ts_raw = _get(row, "date", "whenchanged", "timestamp")
    timestamp, approx = extract_timestamp(str(ts_raw), fallback_date) if ts_raw else (None, True)

    mailbox = _get(row, "mailbox")
    delegate = _get(row, "user", "delegate", "grantee", "granteddelegate")
    rights = _get(row, "accessrights", "permission", "permissiontype", "access rights")

    objects = [f"Mailbox:{mailbox}"] if mailbox else []
    if rights:
        objects.append(f"AccessRights:{rights}")

    return _base_event(timestamp, approx, "Mailbox Delegation", delegate, f"granted {rights or 'access'} on {mailbox}",
                        objects=objects, raw=f"[Mailbox delegation] {delegate} granted {rights} on {mailbox}")


CLASSIFIERS = {
    "ual": classify_ual_row,
    "signin": classify_signin_row,
    "consent": classify_consent_row,
    "inboxrule": classify_inboxrule_row,
    "delegation": classify_delegation_row,
}


#: Human-readable label per detected schema, used to describe evidence
#: files in the report's "Scope & Evidence Reviewed" section without the
#: analyst having to remember which export is which.
SCHEMA_LABELS = {
    "ual": "M365 Unified Audit Log",
    "signin": "Entra ID Interactive Sign-in Log",
    "consent": "OAuth Application Consent Report",
    "inboxrule": "Inbox Rule Detail Report",
    "delegation": "Mailbox Delegation Report",
}


def try_classify(row_data, fallback_date=None):
    """Returns an Event field dict if row_data matches a known M365 log schema, else None."""
    if not row_data:
        return None
    schema = detect_schema(row_data)
    if not schema:
        return None
    event = CLASSIFIERS[schema](row_data, fallback_date)
    # Tagged onto the event (and persisted in the events table) so the
    # report can later say "this file is an Entra sign-in log" etc.
    # without re-parsing/re-detecting anything.
    event["schema"] = schema
    return event
