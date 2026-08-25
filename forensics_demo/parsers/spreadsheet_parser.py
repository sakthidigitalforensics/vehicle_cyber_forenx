"""
Parsers for Excel evidence: modern .xlsx/.xlsm (openpyxl) and legacy .xls
(xlrd, with a LibreOffice-headless fallback since xlrd's .xls support is
occasionally finicky on real-world files).

Every row becomes a ParsedChunk with BOTH a human-readable "col=val, ..."
text (for entity extraction / display / the generic classifier fallback)
AND a `row_data` dict of the raw cell values (for schema-aware parsing -
see analyzers/m365_classifier.py - which needs real values, e.g. a JSON
blob in one cell, not a comma-joined string that would mangle it).
"""

import os
import subprocess
import tempfile
import openpyxl
from core.models import ParsedChunk


def _row_chunks(rows_iter, rel_path, sheet_name, evidence_type):
    chunks = []
    rows_iter = iter(rows_iter)
    try:
        header = next(rows_iter)
    except StopIteration:
        return chunks
    header = [str(h) if h is not None else f"col{i}" for i, h in enumerate(header)]

    for i, row in enumerate(rows_iter, start=2):
        row = list(row)
        row_dict = {header[j] if j < len(header) else f"col{j}": val for j, val in enumerate(row)}
        labeled = ", ".join(f"{k}={v}" for k, v in row_dict.items() if v not in (None, ""))
        if not labeled.strip():
            continue
        chunks.append(ParsedChunk(
            text=labeled,
            source_file=rel_path,
            location=f"sheet '{sheet_name}', row {i}",
            evidence_type=evidence_type,
            row_data=row_dict,
        ))
    return chunks


def parse_xlsx(file_path: str, rel_path: str, evidence_type: str = "spreadsheet"):
    chunks = []
    wb = openpyxl.load_workbook(file_path, data_only=True, read_only=True)
    for sheet in wb.worksheets:
        chunks.extend(_row_chunks(sheet.iter_rows(values_only=True), rel_path, sheet.title, evidence_type))
    return chunks


def parse_xls(file_path: str, rel_path: str, evidence_type: str = "spreadsheet"):
    try:
        import xlrd
        chunks = []
        wb = xlrd.open_workbook(file_path)
        for sheet in wb.sheets():
            rows = (sheet.row_values(r) for r in range(sheet.nrows))
            chunks.extend(_row_chunks(rows, rel_path, sheet.name, evidence_type))
        if chunks:
            return chunks
    except Exception:
        pass  # fall through to LibreOffice conversion below

    with tempfile.TemporaryDirectory() as tmp:
        result = subprocess.run(
            ["soffice", "--headless", "--convert-to", "xlsx", "--outdir", tmp, file_path],
            capture_output=True, timeout=60,
        )
        converted = os.path.join(tmp, os.path.splitext(os.path.basename(file_path))[0] + ".xlsx")
        if result.returncode != 0 or not os.path.exists(converted):
            raise RuntimeError(f"could not read legacy .xls file (xlrd and LibreOffice conversion both failed): {result.stderr.decode(errors='ignore')[:200]}")
        return parse_xlsx(converted, rel_path, evidence_type)
