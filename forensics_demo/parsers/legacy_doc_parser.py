"""
Parsers for legacy/alternate word-processor formats: .doc (Word 97-2003),
.rtf (Rich Text Format), and .odt (OpenDocument Text). python-docx only
reads the modern .docx (OOXML) format, so each of these is converted
locally to .docx via headless LibreOffice (already installed on-machine,
no network involved) and then run through the existing docx parser.
"""

import os
import subprocess
import tempfile
from parsers.document_parser import parse_docx


def _convert_and_parse(file_path: str, rel_path: str, evidence_type: str, source_label: str):
    with tempfile.TemporaryDirectory() as tmp:
        result = subprocess.run(
            ["soffice", "--headless", "--convert-to", "docx", "--outdir", tmp, file_path],
            capture_output=True, timeout=60,
        )
        converted = os.path.join(tmp, os.path.splitext(os.path.basename(file_path))[0] + ".docx")
        if result.returncode != 0 or not os.path.exists(converted):
            raise RuntimeError(f"could not convert {source_label} file via LibreOffice: {result.stderr.decode(errors='ignore')[:200]}")
        return parse_docx(converted, rel_path, evidence_type)


def parse_doc(file_path: str, rel_path: str, evidence_type: str = "document"):
    return _convert_and_parse(file_path, rel_path, evidence_type, "legacy .doc")


def parse_rtf(file_path: str, rel_path: str, evidence_type: str = "document"):
    return _convert_and_parse(file_path, rel_path, evidence_type, ".rtf")


def parse_odt(file_path: str, rel_path: str, evidence_type: str = "document"):
    return _convert_and_parse(file_path, rel_path, evidence_type, ".odt")
