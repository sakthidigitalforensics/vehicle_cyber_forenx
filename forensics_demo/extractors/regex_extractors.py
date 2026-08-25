"""
Regex-based entity extraction.

Each entity type has: a compiled pattern, a base confidence (how trustworthy
a bare regex match is for that type - hashes are near-unambiguous, phone
numbers are very ambiguous), a normalizer (for dedup consistency), and an
optional note function that can flag things like "private IP range" or
"ambiguous format" without changing the confidence score itself.

Patterns are deliberately bounded with \\b so that, e.g., a 64-char SHA-256
string is never also reported as a 32-char MD5 substring - \\b only matches
at the edges of a contiguous run of word characters, so a shorter pattern
cannot match inside a longer hex run.
"""

import re
import ipaddress

PATTERNS = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
    ),
    "ipv6": re.compile(
        r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b"
    ),
    "email": re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    ),
    "url": re.compile(
        r"\bhttps?://[^\s\"'<>]+"
    ),
    "hash_sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "hash_sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "hash_md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "mac_address": re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),
    "crypto_eth": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "crypto_btc": re.compile(r"\b(?:bc1[a-zA-HJ-NP-Z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
    "phone": re.compile(r"\+?\d{1,3}[-.\s]?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b"),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"(?:com|net|org|io|gov|edu|co|info|biz|ru|cn|uk|de|in|xyz|top|club|online|site)\b"
    ),
    "file_path": re.compile(
        r"\b[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]+"
        r"|(?:/[^\s/]+){2,}/?[^\s/]*"
    ),
    # Vehicle telematics evidence (fleet GPS/OBD-II logs) - a VIN is always
    # exactly 17 chars and, by ISO 3779, never contains I/O/Q (reserved so
    # they can't be confused with 1/0). An OBD-II DTC is a 5-char code:
    # one of P(owertrain)/B(ody)/C(hassis)/U(network) followed by 4 hex digits.
    "vin": re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"),
    "obd_dtc": re.compile(r"\b[PBCU][0-9A-Fa-f]{4}\b"),
}

BASE_CONFIDENCE = {
    "ipv4": 0.9,
    "ipv6": 0.6,
    "email": 0.9,
    "url": 0.9,
    "hash_sha256": 0.95,
    "hash_sha1": 0.85,
    "hash_md5": 0.75,
    "mac_address": 0.8,
    "crypto_eth": 0.85,
    "crypto_btc": 0.65,
    "phone": 0.5,
    "domain": 0.6,
    "file_path": 0.55,
    "vin": 0.85,
    "obd_dtc": 0.8,
}

# Order matters: run hash patterns longest-first isn't strictly required (see
# module docstring) but we keep extraction order stable for readability.
EXTRACTION_ORDER = [
    "hash_sha256", "hash_sha1", "hash_md5",
    "ipv4", "ipv6", "mac_address",
    "email", "url", "domain",
    "crypto_eth", "crypto_btc",
    "phone", "file_path",
    "vin", "obd_dtc",
]


def _normalize(entity_type: str, raw: str) -> str:
    if entity_type in ("email", "url", "domain", "ipv6"):
        return raw.strip().lower()
    if entity_type in ("hash_sha256", "hash_sha1", "hash_md5"):
        return raw.lower()
    if entity_type == "mac_address":
        return raw.lower().replace("-", ":")
    if entity_type in ("vin", "obd_dtc"):
        return raw.strip().upper()
    return raw.strip()


def _notes_for(entity_type: str, value: str):
    notes = []
    if entity_type == "ipv4":
        try:
            ip = ipaddress.ip_address(value)
            if ip.is_private:
                notes.append("private/internal IP range")
            elif ip.is_loopback:
                notes.append("loopback address")
            elif ip.is_reserved:
                notes.append("reserved IP range")
        except ValueError:
            pass
    if entity_type == "phone":
        digit_count = sum(c.isdigit() for c in value)
        if digit_count < 7:
            notes.append("short digit sequence - may be a false positive (ID/code, not a phone number)")
    if entity_type == "domain" and value.count(".") == 1 and len(value.split(".")[0]) <= 2:
        notes.append("short label - verify this is a real domain and not an abbreviation")
    if entity_type == "vin":
        notes.append("vehicle identification number (ISO 3779)")
    if entity_type == "obd_dtc":
        system = {"P": "Powertrain", "B": "Body", "C": "Chassis", "U": "Network/Communication"}.get(value[0])
        if system:
            notes.append(f"OBD-II diagnostic trouble code - {system} system")
    return notes


def extract_entities(text: str):
    """
    Run all entity patterns against a chunk of text.
    Returns a list of dicts: {type, raw, value, confidence, notes}
    Does NOT deduplicate or attach source info - that happens one layer up
    where we have the ParsedChunk's file/location context.
    """
    results = []
    claimed_spans = []  # avoid an email's domain also firing the standalone "domain" pattern

    for entity_type in EXTRACTION_ORDER:
        pattern = PATTERNS[entity_type]
        for m in pattern.finditer(text):
            span = m.span()
            raw = m.group(0).rstrip(".,;:)")

            if entity_type in ("domain", "file_path"):
                # domain would otherwise also fire on the domain part of
                # every email/url; file_path would otherwise match the
                # "//host/path" portion embedded in "http://host/path".
                if any(span[0] >= s and span[1] <= e for s, e in claimed_spans):
                    continue

            value = _normalize(entity_type, raw)

            if entity_type == "ipv6":
                # The loose colon-separated-hex pattern above also matches
                # timestamps (03:14:22) and MAC addresses. A real IPv6
                # address must parse as one - this is the actual validity
                # check, not just a regex shape.
                try:
                    ipaddress.ip_address(value)
                except ValueError:
                    continue

            results.append({
                "type": entity_type,
                "raw": raw,
                "value": value,
                "confidence": BASE_CONFIDENCE[entity_type],
                "notes": _notes_for(entity_type, value),
            })
            if entity_type in ("email", "url"):
                claimed_spans.append(span)

    return results
