"""
Public-demo-only helper: preloads two synthetic sample cases (one cyber
case, one vehicle-telematics case) the first time this deployment starts,
so a visitor lands on a populated Dashboard instead of an empty one.

This runs the EXACT same pipeline the real "Store + Process Evidence"
button in app.py uses (extractors.pipeline.run_pipeline_on_files +
analyzers.pattern_detectors.run_all_detectors) against the sample files
already shipped in samples/ - nothing here is faked or hand-written, it's
the tool's real output on its own bundled sample evidence.

Not part of the private production tool - only shipped in this demo copy.
"""

import os
from core import db
from extractors.pipeline import run_pipeline_on_files
from analyzers.pattern_detectors import run_all_detectors

APP_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(APP_DIR, "samples")

CYBER_CASE = dict(
    name="Compromised Finance Mailbox",
    story=(
        "Suspected BEC compromise of a finance mailbox - suspicious sign-ins, an inbox rule, "
        "and a mailbox delegation grant surfaced within days of each other."
    ),
    company="Sakthi",
    reporter="Sakthi",
    investigators="Sakthi",
    case_type="Phishing",
    severity="High",
    confidentiality="Confidential",
    files=["phishing_alert.eml", "server.log", "big_noisy_day.log", "incident_report.docx"],
)

VEHICLE_CASE = dict(
    name="Fleet Vehicle Tampering & Unauthorized Telematics Access",
    story=(
        "A delivery van's telematics unit reported an off-hours ignition without a registered key fob, "
        "a GPS fix thousands of kilometers away moments later, an unauthorized OBD-II diagnostic session, "
        "an odometer rollback, and a geofence breach into a restricted zone."
    ),
    company="Sakthi",
    reporter="Sakthi",
    investigators="Sakthi",
    case_type="Fraud",
    severity="Critical",
    confidentiality="Restricted",
    files=["vehicle/telematics_log.csv", "vehicle/vehicle_security_alerts.log"],
)


def _seed_one(spec, incident_date):
    case_id = db.next_case_id()
    db.create_case(
        case_id, spec["name"], spec["story"], spec["company"], spec["reporter"],
        spec["investigators"], spec["case_type"], spec["severity"], spec["confidentiality"],
        incident_date,
    )

    for rel in spec["files"]:
        path = os.path.join(SAMPLES, rel)
        with open(path, "rb") as f:
            file_bytes = f.read()
        category = "Vehicle Telematics" if "vehicle" in rel else "Log"
        db.store_evidence_file(case_id, os.path.basename(rel), file_bytes, category)

    new_evidence = db.list_unprocessed_evidence(case_id)
    file_specs = [(e["stored_path"], e["filename"]) for e in new_evidence]
    findings, skipped, new_events = run_pipeline_on_files(file_specs)
    db.upsert_findings(case_id, findings)
    db.append_events(case_id, new_events)
    db.mark_evidence_processed([e["id"] for e in new_evidence])

    full_events = db.list_events(case_id)
    for i, e in enumerate(full_events):
        e["_idx"] = i
    case_row = next(c for c in db.list_cases() if c["case_id"] == case_id)
    insights = run_all_detectors(full_events, case_row)
    pos_to_dbid = {i: full_events[i]["id"] for i in range(len(full_events))}
    for ins in insights:
        ins["event_refs"] = [pos_to_dbid[i] for i in ins.get("event_refs", []) if i in pos_to_dbid]
    db.replace_insights(case_id, insights)
    return case_id


def ensure_seeded():
    """Seed the two sample cases only if this is a fresh/empty database."""
    if db.list_cases():
        return
    _seed_one(CYBER_CASE, "2026-08-10")
    _seed_one(VEHICLE_CASE, "2026-08-20")


def reset_and_reseed():
    """Wipe every case (and everything under it) and reseed the two sample cases fresh."""
    conn = db.get_conn()
    conn.executescript(
        """
        DELETE FROM verification_log;
        DELETE FROM occurrences;
        DELETE FROM findings;
        DELETE FROM insights;
        DELETE FROM events;
        DELETE FROM evidence;
        DELETE FROM cases;
        """
    )
    conn.commit()
    conn.close()
    import shutil
    for d in (db.EVIDENCE_DIR, db.POC_DIR, db.REPORTS_DIR):
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d, exist_ok=True)
    ensure_seeded()
