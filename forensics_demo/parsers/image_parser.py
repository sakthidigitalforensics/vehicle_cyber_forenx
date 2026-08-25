"""
Parser for image evidence (.png, .jpg, .jpeg, .bmp, .tiff).

Two independent sources of findings from a single image:
1. OCR'd text (Tesseract, fully offline) - catches text visible IN the image
   (screenshots of chats, terminals, documents photographed on a phone, etc.)
2. EXIF metadata - catches device/GPS/timestamp info embedded BY the camera,
   which is often more forensically valuable than the visible content.
"""

from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import pytesseract
from core.models import ParsedChunk


def _decode_exif(img):
    raw = img._getexif() if hasattr(img, "_getexif") else None
    if not raw:
        return {}
    exif = {}
    for tag_id, value in raw.items():
        tag = TAGS.get(tag_id, tag_id)
        if tag == "GPSInfo":
            gps = {}
            for gps_id, gps_val in value.items():
                gps_tag = GPSTAGS.get(gps_id, gps_id)
                gps[gps_tag] = gps_val
            exif["GPSInfo"] = gps
        else:
            exif[tag] = value
    return exif


def parse_image(file_path: str, rel_path: str, evidence_type: str = "image"):
    chunks = []
    img = Image.open(file_path)

    # --- OCR ---
    try:
        ocr_text = pytesseract.image_to_string(img)
    except Exception as e:
        ocr_text = ""
        chunks.append(ParsedChunk(
            text=f"[OCR failed: {e}]",
            source_file=rel_path,
            location="ocr:error",
            evidence_type=evidence_type,
        ))
    for i, line in enumerate(ocr_text.splitlines(), start=1):
        if line.strip():
            chunks.append(ParsedChunk(
                text=line,
                source_file=rel_path,
                location=f"ocr:line {i}",
                evidence_type=evidence_type,
            ))

    # --- EXIF metadata ---
    exif = _decode_exif(img)
    for tag, value in exif.items():
        chunks.append(ParsedChunk(
            text=f"{tag}={value}",
            source_file=rel_path,
            location=f"exif:{tag}",
            evidence_type=evidence_type,
        ))

    return chunks
