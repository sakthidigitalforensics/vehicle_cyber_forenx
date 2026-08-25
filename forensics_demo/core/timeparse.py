"""
Multi-format timestamp extraction, with per-file "date carry-forward" so a
file that logs bare times (03:14:22) on each line still gets a full
timestamp once we've seen a date earlier in the same file (or fall back to
the case's incident date).

This is what makes chronological ordering across 1000s of lines from
different tools/log formats possible in the first place.
"""

import re
from datetime import datetime

MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

# Ordered most-specific first.
PATTERNS = [
    # 2026-08-10 03:14:22(.123)(Z / +05:30)
    (re.compile(r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})"), "iso"),
    # 08/10/2026 03:14:22
    (re.compile(r"(\d{2})/(\d{2})/(\d{4})\s+(\d{2}):(\d{2}):(\d{2})"), "us_date"),
    # Aug 10 03:14:22  (syslog - no year)
    (re.compile(r"\b([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\b"), "syslog"),
    # 2026-08-10 (date only)
    (re.compile(r"\b(\d{4})-(\d{2})-(\d{2})\b"), "date_only"),
    # 03:14:22 (time only, needs a carried-forward date)
    (re.compile(r"\b(\d{2}):(\d{2}):(\d{2})\b"), "time_only"),
]


def extract_timestamp(text: str, fallback_date=None):
    """
    Returns (datetime_or_None, is_approximate: bool).
    is_approximate=True means we only had a date (no time) or only a time
    (borrowed from fallback_date) - still useful for ordering, but the
    narrative should hedge ("around", "that day") rather than state it exactly.
    """
    for pattern, kind in PATTERNS:
        m = pattern.search(text)
        if not m:
            continue
        try:
            if kind == "iso":
                y, mo, d, h, mi, s = map(int, m.groups())
                return datetime(y, mo, d, h, mi, s), False
            if kind == "us_date":
                mo, d, y, h, mi, s = map(int, m.groups())
                return datetime(y, mo, d, h, mi, s), False
            if kind == "syslog":
                mon_str, d, h, mi, s = m.groups()
                mo = MONTHS.get(mon_str.lower()[:3])
                if not mo:
                    continue
                year = (fallback_date or datetime.now()).year
                return datetime(year, mo, int(d), int(h), int(mi), int(s)), False
            if kind == "date_only":
                y, mo, d = map(int, m.groups())
                return datetime(y, mo, d, 0, 0, 0), True
            if kind == "time_only":
                if not fallback_date:
                    continue
                h, mi, s = map(int, m.groups())
                return fallback_date.replace(hour=h, minute=mi, second=s, microsecond=0), True
        except ValueError:
            continue
    return None, True
