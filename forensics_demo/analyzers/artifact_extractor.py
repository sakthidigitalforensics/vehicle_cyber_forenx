"""
Classic digital-forensics "artifacts" - things pulled OUT of a file rather
than the file itself: email header forensics (the real relay path, spoofing
tells), document authorship/edit-history metadata, and image EXIF data
(device, GPS, timestamps). None of this changes the Investigation Story or
Findings - it's a separate, deeper layer surfaced on the Artifacts page,
computed lazily (only when that page is opened) so it never slows down the
main upload/processing step.

Every function here is defensive: a file that can't be parsed this way
returns None rather than raising, since not every evidence file will have
these artifacts (e.g. a .txt log has no EXIF, a scanned image has no email
headers) - the caller just skips it.
"""

import email
import email.policy
import re

from PIL import Image, ExifTags
from docx import Document as DocxDocument


# --------------------------------------------------------------------------
# Email header forensics
# --------------------------------------------------------------------------

def _gpstag_name(tag_id):
    return ExifTags.GPSTAGS.get(tag_id, tag_id)


def extract_email_artifacts(file_path):
    """
    Returns a dict of forensically-relevant email header findings, or None
    if the file isn't a parsable email:
    {from_, reply_to, from_reply_to_mismatch, x_originating_ip,
     received_chain: [str, ...], auth_results_raw, spf, dkim, dmarc,
     attachments: [{filename, size}, ...]}
    """
    try:
        with open(file_path, "rb") as f:
            msg = email.message_from_binary_file(f, policy=email.policy.default)
    except Exception:
        return None

    from_ = str(msg.get("From") or "")
    reply_to = str(msg.get("Reply-To") or "")

    def _addr(s):
        m = re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", s)
        return m.group(0).lower() if m else None

    from_addr, reply_addr = _addr(from_), _addr(reply_to)
    mismatch = bool(reply_addr and from_addr and reply_addr != from_addr)

    x_originating_ip = str(msg.get("X-Originating-IP") or "").strip("[]") or None

    received_chain = [str(r) for r in msg.get_all("Received", [])]

    auth_results = str(msg.get("Authentication-Results") or "")

    def _extract_result(mechanism):
        m = re.search(rf"{mechanism}=(\w+)", auth_results, re.IGNORECASE)
        return m.group(1).lower() if m else None

    spf, dkim, dmarc = _extract_result("spf"), _extract_result("dkim"), _extract_result("dmarc")

    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                filename = part.get_filename() or "unnamed_attachment"
                payload = part.get_payload(decode=True)
                attachments.append(dict(filename=filename, size=len(payload) if payload else 0))

    return dict(
        from_=from_, reply_to=reply_to, from_reply_to_mismatch=mismatch,
        x_originating_ip=x_originating_ip, received_chain=received_chain,
        auth_results_raw=auth_results or None, spf=spf, dkim=dkim, dmarc=dmarc,
        attachments=attachments,
    )


# --------------------------------------------------------------------------
# Document metadata (authorship / edit-history) forensics
# --------------------------------------------------------------------------

def extract_docx_metadata(file_path):
    """
    Returns the docx's "core properties" - the classic "who really made
    this, and when" tell (e.g. Author doesn't match the claimed sender;
    Last Modified By is someone else entirely; the file was edited minutes
    before being sent). Returns None if it's not a readable .docx.
    Note: legacy .doc/.rtf/.odt evidence is converted to .docx via
    LibreOffice before parsing elsewhere in this tool, which does NOT
    preserve the original file's own metadata - so this only reflects
    native .docx uploads.
    """
    try:
        doc = DocxDocument(file_path)
        p = doc.core_properties
    except Exception:
        return None

    return dict(
        author=p.author or None,
        last_modified_by=p.last_modified_by or None,
        created=p.created.isoformat() if p.created else None,
        modified=p.modified.isoformat() if p.modified else None,
        last_printed=p.last_printed.isoformat() if p.last_printed else None,
        revision=p.revision,
        title=p.title or None,
        subject=p.subject or None,
        comments=p.comments or None,
        company=getattr(p, "company", None),
    )


# --------------------------------------------------------------------------
# Image EXIF forensics
# --------------------------------------------------------------------------

def _dms_to_decimal(dms, ref):
    try:
        degrees, minutes, seconds = (float(v) for v in dms)
        decimal = degrees + minutes / 60 + seconds / 3600
        if ref in ("S", "W"):
            decimal = -decimal
        return round(decimal, 6)
    except Exception:
        return None


def extract_image_exif(file_path):
    """
    Returns EXIF metadata relevant to authenticity questions - device
    model, editing software, GPS location, and the original capture
    timestamp (worth comparing against the upload/modified time - a
    mismatch can indicate the image was edited or is a re-save rather than
    an original camera/phone capture). Returns None if the image has no
    EXIF block (common for screenshots and web-saved images) or can't be
    opened.
    """
    try:
        img = Image.open(file_path)
        exif = img.getexif()
    except Exception:
        return None
    if not exif:
        return None

    tags = {ExifTags.TAGS.get(k, k): v for k, v in exif.items()}

    gps_info = exif.get_ifd(ExifTags.IFD.GPSInfo) if hasattr(exif, "get_ifd") else {}
    lat = lon = None
    if gps_info:
        gps = {_gpstag_name(k): v for k, v in gps_info.items()}
        if "GPSLatitude" in gps and "GPSLongitude" in gps:
            lat = _dms_to_decimal(gps["GPSLatitude"], gps.get("GPSLatitudeRef", "N"))
            lon = _dms_to_decimal(gps["GPSLongitude"], gps.get("GPSLongitudeRef", "E"))

    result = dict(
        camera_make=tags.get("Make"),
        camera_model=tags.get("Model"),
        software=tags.get("Software"),
        original_datetime=tags.get("DateTimeOriginal") or tags.get("DateTime"),
        gps_lat=lat, gps_lon=lon,
    )
    if not any(result.values()):
        return None
    return result
