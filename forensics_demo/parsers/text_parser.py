"""Parser for plain text logs (.txt, .log) and tabular (.csv) evidence."""

import csv
from core.models import ParsedChunk


def parse_text(file_path: str, rel_path: str, evidence_type: str = "log"):
    """Yield one ParsedChunk per line, so every finding can be traced to an exact line number."""
    chunks = []
    with open(file_path, "r", errors="ignore") as f:
        for i, line in enumerate(f, start=1):
            line = line.rstrip("\n")
            if not line.strip():
                continue
            chunks.append(ParsedChunk(
                text=line,
                source_file=rel_path,
                location=f"line {i}",
                evidence_type=evidence_type,
            ))
    return chunks


def parse_csv(file_path: str, rel_path: str, evidence_type: str = "log"):
    """
    Yield one ParsedChunk per row. We keep the header so context snippets
    read as "source_ip=10.1.1.5" rather than a bare unlabeled value.
    """
    chunks = []
    with open(file_path, "r", errors="ignore", newline="") as f:
        reader = csv.reader(f)
        rows = list(reader)
    if not rows:
        return chunks
    header = rows[0]
    for i, row in enumerate(rows[1:], start=2):
        row_dict = {header[j] if j < len(header) else f"col{j}": val for j, val in enumerate(row)}
        labeled = ", ".join(f"{k}={v}" for k, v in row_dict.items() if v not in (None, ""))
        chunks.append(ParsedChunk(
            text=labeled,
            source_file=rel_path,
            location=f"row {i}",
            evidence_type=evidence_type,
            row_data=row_dict,
        ))
    return chunks
