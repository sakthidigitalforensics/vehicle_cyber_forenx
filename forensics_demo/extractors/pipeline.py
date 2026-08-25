"""
End-to-end pipeline: folder of evidence -> parsed chunks -> (a) extracted
entities -> deduplicated Findings with source traceability, and (b)
classified Events for the chronological "story" -> both in a single parse
pass, so a 1000-line log file is only read once.
"""

import os
from datetime import datetime
from core.models import Finding, Occurrence
from parsers import parse_file, SUPPORTED_EXT
from extractors.regex_extractors import extract_entities
from analyzers.event_classifier import classify_line
from analyzers.m365_classifier import try_classify as try_classify_m365
from analyzers.vehicle_classifier import try_classify as try_classify_vehicle

CONTEXT_MAX_LEN = 160


def _make_context(text: str, raw_value: str) -> str:
    text = text.strip()
    if len(text) <= CONTEXT_MAX_LEN:
        return text
    idx = text.find(raw_value)
    if idx == -1:
        return text[:CONTEXT_MAX_LEN] + "..."
    start = max(0, idx - 40)
    end = min(len(text), idx + len(raw_value) + 40)
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(text) else ""
    return f"{prefix}{text[start:end]}{suffix}"


def _process_chunks(chunks, findings_by_key, events, fallback_date):
    """Shared per-chunk work: entity extraction + event classification. Mutates findings_by_key/events in place. Returns updated fallback_date (per-file date carry-forward)."""
    for chunk in chunks:
        if not chunk.text:
            continue

        entities = extract_entities(chunk.text)
        for ent in entities:
            key = (ent["type"], ent["value"])
            occurrence = Occurrence(
                source_file=chunk.source_file,
                location=chunk.location,
                context=_make_context(chunk.text, ent["raw"]),
                evidence_type=chunk.evidence_type,
            )
            if key not in findings_by_key:
                findings_by_key[key] = Finding(
                    type=ent["type"], value=ent["value"],
                    confidence=ent["confidence"], notes=list(ent["notes"]),
                )
            finding = findings_by_key[key]
            finding.occurrences.append(occurrence)
            distinct_sources = len({o.source_file for o in finding.occurrences})
            if distinct_sources > 1:
                finding.confidence = min(0.99, finding.confidence + 0.02 * (distinct_sources - 1))

        # Structured rows (CSV/XLSX) get a shot at schema-aware M365
        # classification first (Unified Audit Log, Entra sign-in, OAuth
        # consent, mailbox delegation/inbox rule) - far more accurate for
        # those specific formats than the generic keyword-based classifier.
        event = None
        if chunk.row_data:
            event = try_classify_m365(chunk.row_data, fallback_date) or try_classify_vehicle(chunk.row_data, fallback_date)
        if event is None:
            event = classify_line(chunk.text, fallback_date=fallback_date)
        event["source_file"] = chunk.source_file
        event["location"] = chunk.location
        events.append(event)
        if event.get("timestamp"):
            fallback_date = datetime.fromisoformat(event["timestamp"])

    return fallback_date


def run_pipeline_on_files(file_specs):
    """
    Driven by an explicit list of (stored_path, display_name) pairs rather
    than walking a directory - used by the app so findings/events trace
    back to the evidence's original filename.
    Returns (findings: list[Finding], skipped_files: list[str], events: list[dict]).
    """
    findings_by_key = {}
    skipped_files = []
    events = []

    for stored_path, display_name in file_specs:
        ext = os.path.splitext(display_name)[1].lower()
        if ext not in SUPPORTED_EXT:
            skipped_files.append(display_name)
            continue
        try:
            chunks = parse_file(stored_path, display_name)
        except Exception as e:
            skipped_files.append(f"{display_name} (parse error: {e})")
            continue

        _process_chunks(chunks, findings_by_key, events, fallback_date=None)

    findings = sorted(
        findings_by_key.values(),
        key=lambda f: (-f.occurrence_count, -f.confidence, f.type, f.value),
    )
    return findings, skipped_files, events


def run_pipeline(evidence_dir: str):
    """
    Walk evidence_dir, parse every supported file, extract entities + events.
    Returns (findings, skipped_files, files_processed, events).
    """
    findings_by_key = {}
    skipped_files = []
    events = []
    files_processed = 0

    for root, _dirs, files in os.walk(evidence_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            rel_path = os.path.relpath(fpath, evidence_dir)
            ext = os.path.splitext(fname)[1].lower()

            if ext not in SUPPORTED_EXT:
                skipped_files.append(rel_path)
                continue

            try:
                chunks = parse_file(fpath, rel_path)
            except Exception as e:
                skipped_files.append(f"{rel_path} (parse error: {e})")
                continue

            files_processed += 1
            _process_chunks(chunks, findings_by_key, events, fallback_date=None)

    findings = sorted(
        findings_by_key.values(),
        key=lambda f: (-f.occurrence_count, -f.confidence, f.type, f.value),
    )
    return findings, skipped_files, files_processed, events
