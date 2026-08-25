"""
Parser for .eml evidence.

Emails get special treatment vs plain text because the metadata often
matters more than the body: the Received: chain reveals the actual relay
path (useful for spotting spoofing), and attachments need to be recursed
into rather than just noted as "attachment present".
"""

import email
import email.policy
import os
import tempfile
from core.models import ParsedChunk


def parse_eml(file_path: str, rel_path: str, evidence_type: str = "email", reparse_attachment=None):
    """
    reparse_attachment: optional callback(attachment_path, attachment_rel_label) -> List[ParsedChunk]
    used to recursively run the main parser dispatcher over attachments
    (e.g. a PDF or image attached to an email should be OCR'd/text-extracted too).
    """
    chunks = []
    with open(file_path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=email.policy.default)

    # --- Headers ---
    header_fields = ["From", "To", "Cc", "Bcc", "Reply-To", "Subject", "Date", "Message-ID"]
    for field in header_fields:
        val = msg.get(field)
        if val:
            chunks.append(ParsedChunk(
                text=str(val),
                source_file=rel_path,
                location=f"header:{field}",
                evidence_type=evidence_type,
            ))

    # Received chain reveals the actual relay path - each hop is its own chunk
    received_headers = msg.get_all("Received", [])
    for i, r in enumerate(received_headers, start=1):
        chunks.append(ParsedChunk(
            text=str(r),
            source_file=rel_path,
            location=f"header:Received[{i}]",
            evidence_type=evidence_type,
        ))

    # --- Body ---
    body_parts = []
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = part.get_content_disposition()
            if disposition == "attachment":
                continue
            if content_type in ("text/plain", "text/html"):
                try:
                    body_parts.append(part.get_content())
                except Exception:
                    pass
    else:
        try:
            body_parts.append(msg.get_content())
        except Exception:
            pass

    for i, body in enumerate(body_parts, start=1):
        for j, line in enumerate(str(body).splitlines(), start=1):
            if line.strip():
                chunks.append(ParsedChunk(
                    text=line,
                    source_file=rel_path,
                    location=f"body[{i}]:line {j}",
                    evidence_type=evidence_type,
                ))

    # --- Attachments (recursive) ---
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                filename = part.get_filename() or "unnamed_attachment"
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                with tempfile.NamedTemporaryFile(delete=False, suffix="_" + filename) as tmp:
                    tmp.write(payload)
                    tmp_path = tmp.name
                attach_label = f"{rel_path} > attachment:{filename}"
                if reparse_attachment:
                    try:
                        chunks.extend(reparse_attachment(tmp_path, attach_label))
                    except Exception as e:
                        chunks.append(ParsedChunk(
                            text=f"[could not parse attachment {filename}: {e}]",
                            source_file=rel_path,
                            location=f"attachment:{filename}",
                            evidence_type=evidence_type,
                        ))
                os.unlink(tmp_path)

    return chunks
