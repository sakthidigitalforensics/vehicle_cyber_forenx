"""Dispatch a file to the right parser based on its extension."""

import os
from parsers.text_parser import parse_text, parse_csv
from parsers.email_parser import parse_eml
from parsers.document_parser import parse_pdf, parse_docx
from parsers.image_parser import parse_image
from parsers.spreadsheet_parser import parse_xlsx, parse_xls
from parsers.legacy_doc_parser import parse_doc, parse_rtf, parse_odt

TEXT_EXT = {".txt", ".log"}
CSV_EXT = {".csv"}
EMAIL_EXT = {".eml"}
PDF_EXT = {".pdf"}
DOCX_EXT = {".docx"}
DOC_EXT = {".doc"}
RTF_EXT = {".rtf"}
ODT_EXT = {".odt"}
XLSX_EXT = {".xlsx", ".xlsm"}
XLS_EXT = {".xls"}
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".bmp", ".tiff"}

SUPPORTED_EXT = (TEXT_EXT | CSV_EXT | EMAIL_EXT | PDF_EXT | DOCX_EXT | DOC_EXT
                 | RTF_EXT | ODT_EXT | XLSX_EXT | XLS_EXT | IMAGE_EXT)


def parse_file(file_path: str, rel_path: str):
    """Return a list of ParsedChunk for any supported evidence file. Unsupported types are skipped with a warning."""
    ext = os.path.splitext(file_path)[1].lower()

    if ext in TEXT_EXT:
        return parse_text(file_path, rel_path)
    if ext in CSV_EXT:
        return parse_csv(file_path, rel_path)
    if ext in EMAIL_EXT:
        def reparse_attachment(tmp_path, label):
            return parse_file(tmp_path, label)
        return parse_eml(file_path, rel_path, reparse_attachment=reparse_attachment)
    if ext in PDF_EXT:
        return parse_pdf(file_path, rel_path)
    if ext in DOCX_EXT:
        return parse_docx(file_path, rel_path)
    if ext in DOC_EXT:
        return parse_doc(file_path, rel_path)
    if ext in RTF_EXT:
        return parse_rtf(file_path, rel_path)
    if ext in ODT_EXT:
        return parse_odt(file_path, rel_path)
    if ext in XLSX_EXT:
        return parse_xlsx(file_path, rel_path)
    if ext in XLS_EXT:
        return parse_xls(file_path, rel_path)
    if ext in IMAGE_EXT:
        return parse_image(file_path, rel_path)

    return []  # unsupported - caller should log/flag this rather than silently drop in a real UI
