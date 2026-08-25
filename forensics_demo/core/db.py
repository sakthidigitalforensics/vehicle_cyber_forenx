"""
Local SQLite persistence layer. Everything lives in one file on disk under
data/live/forensic_tool.db - no server, no network, nothing leaves the machine.

`data/live/` is the DECRYPTED working copy of the case vault - it only
exists while the app is unlocked (see core/auth.py + core/vault.py). It gets
sealed into the single encrypted data/vault.enc file on every write and on
lock/exit, so nothing sensitive sits around in plaintext once you're done.

Schema:
  cases              - one row per investigation
  evidence            - uploaded files, hashed at ingest for chain-of-custody
  findings            - deduplicated extracted entities, tied to a case
  occurrences         - source traceability rows for each finding
  verification_log    - full audit trail of every verification status change
  report_templates    - saved report styling presets (company branding etc.)
"""

import sqlite3
import os
import json
import hashlib
import shutil
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
LIVE_DIR = os.path.join(DATA_DIR, "live")
DB_PATH = os.path.join(LIVE_DIR, "forensic_tool.db")
EVIDENCE_DIR = os.path.join(LIVE_DIR, "evidence")
POC_DIR = os.path.join(LIVE_DIR, "poc")
REPORTS_DIR = os.path.join(LIVE_DIR, "reports")

os.makedirs(LIVE_DIR, exist_ok=True)
os.makedirs(EVIDENCE_DIR, exist_ok=True)
os.makedirs(POC_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_conn()
    c = conn.cursor()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS cases (
        case_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        story TEXT,
        company TEXT,
        reporter TEXT,
        investigators TEXT,
        case_type TEXT,
        severity TEXT,
        confidentiality TEXT,
        incident_date TEXT,
        status TEXT DEFAULT 'Open',
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT NOT NULL REFERENCES cases(case_id),
        filename TEXT NOT NULL,
        stored_path TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        category TEXT,
        uploaded_at TEXT NOT NULL,
        processed INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT NOT NULL REFERENCES cases(case_id),
        type TEXT NOT NULL,
        value TEXT NOT NULL,
        confidence REAL,
        notes TEXT,
        verification_status TEXT DEFAULT 'Unverified',
        verification_notes TEXT,
        created_at TEXT NOT NULL,
        UNIQUE(case_id, type, value)
    );

    CREATE TABLE IF NOT EXISTS occurrences (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id INTEGER NOT NULL REFERENCES findings(id),
        source_file TEXT,
        location TEXT,
        context TEXT,
        evidence_type TEXT
    );

    CREATE TABLE IF NOT EXISTS verification_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id INTEGER NOT NULL REFERENCES findings(id),
        old_status TEXT,
        new_status TEXT,
        reviewer TEXT,
        notes TEXT,
        poc_path TEXT,
        timestamp TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT NOT NULL REFERENCES cases(case_id),
        timestamp TEXT,
        approximate INTEGER,
        category TEXT,
        actor TEXT,
        action TEXT,
        outcome TEXT,
        source_ip TEXT,
        dest_ip TEXT,
        port TEXT,
        protocol TEXT,
        objects TEXT,
        raw TEXT,
        source_file TEXT,
        location TEXT,
        schema TEXT
    );

    CREATE TABLE IF NOT EXISTS insights (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT NOT NULL REFERENCES cases(case_id),
        severity TEXT,
        title TEXT,
        description TEXT,
        impact TEXT,
        event_refs TEXT
    );

    CREATE TABLE IF NOT EXISTS report_templates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        template_name TEXT UNIQUE,
        company_name TEXT,
        header_text TEXT,
        footer_text TEXT,
        primary_color TEXT,
        heading_style TEXT,
        body_style TEXT,
        include_bullets INTEGER DEFAULT 1,
        include_tables INTEGER DEFAULT 1,
        heading_font TEXT DEFAULT 'Calibri',
        heading_color TEXT DEFAULT '#1F2937',
        heading_size INTEGER DEFAULT 20,
        subheading_font TEXT DEFAULT 'Calibri',
        subheading_color TEXT DEFAULT '#1F2937',
        subheading_size INTEGER DEFAULT 14,
        body_font TEXT DEFAULT 'Calibri',
        body_color TEXT DEFAULT '#000000',
        body_size INTEGER DEFAULT 11,
        created_at TEXT NOT NULL
    );
    """)
    conn.commit()

    # --- Backward-compatible migrations for DBs created by earlier
    # versions of this tool (before the "schema" / font+color columns
    # existed). ALTER TABLE ADD COLUMN fails if the column is already
    # there, which is exactly the "already migrated" case - safe to ignore.
    migrations = [
        "ALTER TABLE events ADD COLUMN schema TEXT",
        "ALTER TABLE evidence ADD COLUMN processed INTEGER DEFAULT 0",
        "ALTER TABLE insights ADD COLUMN impact TEXT",
        "ALTER TABLE report_templates ADD COLUMN heading_font TEXT DEFAULT 'Calibri'",
        "ALTER TABLE report_templates ADD COLUMN heading_color TEXT DEFAULT '#1F2937'",
        "ALTER TABLE report_templates ADD COLUMN heading_size INTEGER DEFAULT 20",
        "ALTER TABLE report_templates ADD COLUMN subheading_font TEXT DEFAULT 'Calibri'",
        "ALTER TABLE report_templates ADD COLUMN subheading_color TEXT DEFAULT '#1F2937'",
        "ALTER TABLE report_templates ADD COLUMN subheading_size INTEGER DEFAULT 14",
        "ALTER TABLE report_templates ADD COLUMN body_font TEXT DEFAULT 'Calibri'",
        "ALTER TABLE report_templates ADD COLUMN body_color TEXT DEFAULT '#000000'",
        "ALTER TABLE report_templates ADD COLUMN body_size INTEGER DEFAULT 11",
    ]
    for stmt in migrations:
        try:
            conn.execute(stmt)
            conn.commit()
        except sqlite3.OperationalError:
            pass  # column already exists - already migrated
    conn.close()


def next_case_id():
    """Generate the next sequential case id, e.g. CF-2026-0001."""
    year = datetime.now().strftime("%Y")
    conn = get_conn()
    rows = conn.execute(
        "SELECT case_id FROM cases WHERE case_id LIKE ?", (f"CF-{year}-%",)
    ).fetchall()
    conn.close()
    nums = []
    for r in rows:
        try:
            nums.append(int(r["case_id"].split("-")[-1]))
        except ValueError:
            pass
    next_n = (max(nums) + 1) if nums else 1
    return f"CF-{year}-{next_n:04d}"


def create_case(case_id, name, story, company, reporter, investigators,
                case_type, severity, confidentiality, incident_date):
    conn = get_conn()
    conn.execute(
        """INSERT INTO cases (case_id, name, story, company, reporter, investigators,
                               case_type, severity, confidentiality, incident_date, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (case_id, name, story, company, reporter, investigators,
         case_type, severity, confidentiality, incident_date, datetime.now().isoformat()),
    )
    conn.commit()
    conn.close()


def list_cases():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM cases ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_case(case_id):
    conn = get_conn()
    row = conn.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def store_evidence_file(case_id, uploaded_filename, file_bytes, category):
    """
    Hash the file BEFORE it's written anywhere else, then copy it into the
    case's evidence folder under its own hash-stamped name. This is the
    chain-of-custody guarantee: the stored copy's hash is verifiable at any
    later point, so tampering after upload is detectable.
    """
    sha256 = hashlib.sha256(file_bytes).hexdigest()
    case_dir = os.path.join(EVIDENCE_DIR, case_id)
    os.makedirs(case_dir, exist_ok=True)
    ext = os.path.splitext(uploaded_filename)[1]
    stored_name = f"{sha256[:16]}_{uploaded_filename}"
    stored_path = os.path.join(case_dir, stored_name)
    with open(stored_path, "wb") as f:
        f.write(file_bytes)

    conn = get_conn()
    conn.execute(
        """INSERT INTO evidence (case_id, filename, stored_path, sha256, category, uploaded_at)
           VALUES (?,?,?,?,?,?)""",
        (case_id, uploaded_filename, stored_path, sha256, category, datetime.now().isoformat()),
    )
    conn.commit()
    conn.close()
    return stored_path, sha256


def list_evidence(case_id):
    conn = get_conn()
    rows = conn.execute("SELECT * FROM evidence WHERE case_id=? ORDER BY uploaded_at", (case_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def list_unprocessed_evidence(case_id):
    """
    Evidence rows never run through the extraction pipeline yet. This is
    the key to incremental processing: on a case that's accumulated
    several large uploads, re-parsing everything on every batch is the
    single biggest avoidable cost for big files - this lets the caller
    parse ONLY what's actually new.
    """
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM evidence WHERE case_id=? AND (processed IS NULL OR processed=0) ORDER BY uploaded_at",
        (case_id,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def mark_evidence_processed(evidence_ids):
    if not evidence_ids:
        return
    conn = get_conn()
    placeholders = ",".join("?" * len(evidence_ids))
    conn.execute(f"UPDATE evidence SET processed=1 WHERE id IN ({placeholders})", evidence_ids)
    conn.commit()
    conn.close()


def upsert_findings(case_id, findings):
    """
    findings: list of Finding objects (from extractors.pipeline).
    Merges into existing findings for the case rather than duplicating on
    re-run - occurrences are additive, confidence keeps the higher value.
    """
    conn = get_conn()
    for f in findings:
        existing = conn.execute(
            "SELECT id, confidence FROM findings WHERE case_id=? AND type=? AND value=?",
            (case_id, f.type, f.value),
        ).fetchone()
        if existing:
            finding_id = existing["id"]
            new_conf = max(existing["confidence"] or 0, f.confidence)
            conn.execute("UPDATE findings SET confidence=? WHERE id=?", (new_conf, finding_id))
        else:
            cur = conn.execute(
                """INSERT INTO findings (case_id, type, value, confidence, notes, created_at)
                   VALUES (?,?,?,?,?,?)""",
                (case_id, f.type, f.value, f.confidence, json.dumps(f.notes), datetime.now().isoformat()),
            )
            finding_id = cur.lastrowid

        for occ in f.occurrences:
            dup = conn.execute(
                "SELECT id FROM occurrences WHERE finding_id=? AND source_file=? AND location=?",
                (finding_id, occ.source_file, occ.location),
            ).fetchone()
            if not dup:
                conn.execute(
                    """INSERT INTO occurrences (finding_id, source_file, location, context, evidence_type)
                       VALUES (?,?,?,?,?)""",
                    (finding_id, occ.source_file, occ.location, occ.context, occ.evidence_type),
                )
    conn.commit()
    conn.close()


def replace_events_and_insights(case_id, events, insights):
    """
    Full wipe + rebuild of BOTH events and insights from the given list -
    the expensive path. Kept as an explicit "reprocess everything from
    scratch" option (e.g. after a detector/classifier update you want
    retroactively applied), but normal day-to-day evidence uploads should
    use append_events() + replace_insights() below instead, which don't
    re-parse or re-insert evidence that's already been processed.
    `events` is a list of dicts with an "_idx" key (0-based position);
    insights reference events by that same _idx in "event_refs" - we
    translate those into real DB row ids as we insert.
    """
    conn = get_conn()
    conn.execute("DELETE FROM insights WHERE case_id=?", (case_id,))
    conn.execute("DELETE FROM events WHERE case_id=?", (case_id,))

    idx_to_dbid = {}
    for e in events:
        cur = conn.execute(
            """INSERT INTO events (case_id, timestamp, approximate, category, actor, action,
                                    outcome, source_ip, dest_ip, port, protocol, objects, raw,
                                    source_file, location, schema)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (case_id, e.get("timestamp"), int(bool(e.get("approximate"))), e.get("category"),
             e.get("actor"), e.get("action"), e.get("outcome"), e.get("source_ip"), e.get("dest_ip"),
             e.get("port"), e.get("protocol"), json.dumps(e.get("objects", [])), e.get("raw"),
             e.get("source_file"), e.get("location"), e.get("schema")),
        )
        idx_to_dbid[e["_idx"]] = cur.lastrowid

    for ins in insights:
        db_refs = [idx_to_dbid[i] for i in ins.get("event_refs", []) if i in idx_to_dbid]
        conn.execute(
            "INSERT INTO insights (case_id, severity, title, description, impact, event_refs) VALUES (?,?,?,?,?,?)",
            (case_id, ins["severity"], ins["title"], ins["description"], ins.get("impact"), json.dumps(db_refs)),
        )
    conn.commit()
    conn.close()


def append_events(case_id, events):
    """
    INSERT-only: adds newly parsed events without touching anything
    already stored. This is what makes incremental processing possible -
    events from evidence already processed in a previous batch are never
    re-parsed or re-inserted, only genuinely new ones are added here.
    """
    if not events:
        return
    conn = get_conn()
    for e in events:
        conn.execute(
            """INSERT INTO events (case_id, timestamp, approximate, category, actor, action,
                                    outcome, source_ip, dest_ip, port, protocol, objects, raw,
                                    source_file, location, schema)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (case_id, e.get("timestamp"), int(bool(e.get("approximate"))), e.get("category"),
             e.get("actor"), e.get("action"), e.get("outcome"), e.get("source_ip"), e.get("dest_ip"),
             e.get("port"), e.get("protocol"), json.dumps(e.get("objects", [])), e.get("raw"),
             e.get("source_file"), e.get("location"), e.get("schema")),
        )
    conn.commit()
    conn.close()


def replace_insights(case_id, insights):
    """
    Insights (detected patterns) DO need full recomputation whenever new
    evidence arrives, since a pattern like brute-force or beaconing can
    span old and new events together - but that recomputation runs over
    already-classified structured events already in the DB, which is fast
    compared to re-parsing raw files. Only this table gets wiped/rebuilt;
    the (potentially large) events table is left untouched.
    `insights` here must already carry REAL DB event ids in event_refs
    (not positional indices) - see app.py's processing flow for how those
    get translated before calling this.
    """
    conn = get_conn()
    conn.execute("DELETE FROM insights WHERE case_id=?", (case_id,))
    for ins in insights:
        conn.execute(
            "INSERT INTO insights (case_id, severity, title, description, impact, event_refs) VALUES (?,?,?,?,?,?)",
            (case_id, ins["severity"], ins["title"], ins["description"], ins.get("impact"),
             json.dumps(ins.get("event_refs", []))),
        )
    conn.commit()
    conn.close()


def list_events(case_id):
    conn = get_conn()
    rows = conn.execute("SELECT * FROM events WHERE case_id=? ORDER BY timestamp", (case_id,)).fetchall()
    conn.close()
    out = []
    for r in rows:
        d = dict(r)
        d["objects"] = json.loads(d["objects"]) if d["objects"] else []
        out.append(d)
    return out


def list_insights(case_id):
    conn = get_conn()
    rows = conn.execute("SELECT * FROM insights WHERE case_id=?", (case_id,)).fetchall()
    conn.close()
    severity_rank = {"High": 0, "Medium": 1, "Low": 2}
    out = []
    for r in rows:
        d = dict(r)
        d["event_refs"] = json.loads(d["event_refs"]) if d["event_refs"] else []
        out.append(d)
    out.sort(key=lambda i: severity_rank.get(i["severity"], 9))
    return out


def get_events_by_ids(event_ids):
    if not event_ids:
        return []
    conn = get_conn()
    placeholders = ",".join("?" * len(event_ids))
    rows = conn.execute(f"SELECT * FROM events WHERE id IN ({placeholders})", event_ids).fetchall()
    conn.close()
    out = []
    for r in rows:
        d = dict(r)
        d["objects"] = json.loads(d["objects"]) if d["objects"] else []
        out.append(d)
    return out


def list_findings(case_id, type_filter=None, status_filter=None, search=None):
    conn = get_conn()
    query = "SELECT * FROM findings WHERE case_id=?"
    params = [case_id]
    if type_filter and type_filter != "All":
        query += " AND type=?"
        params.append(type_filter)
    if status_filter and status_filter != "All":
        query += " AND verification_status=?"
        params.append(status_filter)
    if search:
        query += " AND value LIKE ?"
        params.append(f"%{search}%")
    query += " ORDER BY confidence DESC"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_occurrences(finding_id):
    conn = get_conn()
    rows = conn.execute("SELECT * FROM occurrences WHERE finding_id=?", (finding_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def set_verification(finding_id, new_status, reviewer, notes, poc_path=None):
    conn = get_conn()
    old = conn.execute("SELECT verification_status FROM findings WHERE id=?", (finding_id,)).fetchone()
    old_status = old["verification_status"] if old else None
    conn.execute(
        "UPDATE findings SET verification_status=?, verification_notes=? WHERE id=?",
        (new_status, notes, finding_id),
    )
    conn.execute(
        """INSERT INTO verification_log (finding_id, old_status, new_status, reviewer, notes, poc_path, timestamp)
           VALUES (?,?,?,?,?,?,?)""",
        (finding_id, old_status, new_status, reviewer, notes, poc_path, datetime.now().isoformat()),
    )
    conn.commit()
    conn.close()


def get_verification_log(finding_id):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM verification_log WHERE finding_id=? ORDER BY timestamp", (finding_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def save_poc_file(case_id, finding_id, uploaded_filename, file_bytes):
    """Store an uploaded POC file (any type - image, PDF, screenshot, etc.) for a finding. A finding can have several; each call adds one more."""
    finding_dir = os.path.join(POC_DIR, case_id, str(finding_id))
    os.makedirs(finding_dir, exist_ok=True)
    # Timestamp-prefix so repeated uploads of a same-named file never collide/overwrite each other.
    stamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
    stored_path = os.path.join(finding_dir, f"{stamp}_{uploaded_filename}")
    with open(stored_path, "wb") as f:
        f.write(file_bytes)
    return stored_path


def save_poc_image(case_id, finding_id, pil_image):
    """Store a pasted-from-clipboard screenshot (PIL Image) as a POC for a finding - the paste-to-verify shortcut."""
    finding_dir = os.path.join(POC_DIR, case_id, str(finding_id))
    os.makedirs(finding_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
    stored_path = os.path.join(finding_dir, f"{stamp}_pasted.png")
    pil_image.save(stored_path, format="PNG")
    return stored_path


def get_poc_paths(finding_id):
    """All POC file paths ever attached to a finding (upload or paste), newest first, deduplicated, existing-on-disk only."""
    conn = get_conn()
    rows = conn.execute(
        "SELECT poc_path, timestamp FROM verification_log WHERE finding_id=? AND poc_path IS NOT NULL ORDER BY timestamp DESC",
        (finding_id,),
    ).fetchall()
    conn.close()
    seen, out = set(), []
    for r in rows:
        p = r["poc_path"]
        if p and p not in seen and os.path.exists(p):
            seen.add(p)
            out.append(p)
    return out


def save_report_template(name, company_name, header_text, footer_text,
                          primary_color, heading_style, body_style,
                          include_bullets, include_tables,
                          heading_font="Calibri", heading_color="#1F2937", heading_size=20,
                          subheading_font="Calibri", subheading_color="#1F2937", subheading_size=14,
                          body_font="Calibri", body_color="#000000", body_size=11):
    conn = get_conn()
    conn.execute(
        """INSERT INTO report_templates (template_name, company_name, header_text, footer_text,
                                          primary_color, heading_style, body_style,
                                          include_bullets, include_tables,
                                          heading_font, heading_color, heading_size,
                                          subheading_font, subheading_color, subheading_size,
                                          body_font, body_color, body_size, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(template_name) DO UPDATE SET
             company_name=excluded.company_name, header_text=excluded.header_text,
             footer_text=excluded.footer_text, primary_color=excluded.primary_color,
             heading_style=excluded.heading_style, body_style=excluded.body_style,
             include_bullets=excluded.include_bullets, include_tables=excluded.include_tables,
             heading_font=excluded.heading_font, heading_color=excluded.heading_color, heading_size=excluded.heading_size,
             subheading_font=excluded.subheading_font, subheading_color=excluded.subheading_color, subheading_size=excluded.subheading_size,
             body_font=excluded.body_font, body_color=excluded.body_color, body_size=excluded.body_size""",
        (name, company_name, header_text, footer_text, primary_color, heading_style,
         body_style, int(include_bullets), int(include_tables),
         heading_font, heading_color, heading_size, subheading_font, subheading_color, subheading_size,
         body_font, body_color, body_size, datetime.now().isoformat()),
    )
    conn.commit()
    conn.close()


def list_report_templates():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM report_templates ORDER BY template_name").fetchall()
    conn.close()
    return [dict(r) for r in rows]
