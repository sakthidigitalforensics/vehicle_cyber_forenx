"""
Core data models for the extraction engine.

Design notes:
- Every extracted entity (Finding) keeps a list of Occurrences, each of
  which points back to the exact file + location the value was seen in.
  This is the "source traceability" requirement from the case design:
  an analyst should always be able to click a finding and see exactly
  where it came from.
- Findings are deduplicated by (type, normalized value) across the whole
  evidence set for a case, so the same IP seen in 12 log lines becomes
  ONE finding with 12 occurrences rather than 12 separate findings.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Optional
import hashlib


@dataclass
class Occurrence:
    """Exactly where a finding's value was seen."""
    source_file: str          # relative path of the evidence file
    location: str              # human-readable pointer, e.g. "line 42", "page 3", "header:From", "attachment:invoice.pdf > page 1"
    context: str                # short surrounding text snippet, for quick human review
    evidence_type: Optional[str] = None  # e.g. "log", "email", "document", "image" - set by the parser


@dataclass
class Finding:
    """A single deduplicated entity extracted from evidence."""
    type: str                  # e.g. "ip", "email", "domain", "url", "hash_sha256", "phone", "crypto_btc", "mac_address", "file_path"
    value: str                  # normalized value (lowercased where case-insensitive, etc.)
    confidence: float           # 0.0 - 1.0
    occurrences: List[Occurrence] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)  # e.g. "private IP range", "ambiguous phone format"

    @property
    def id(self) -> str:
        """Stable id derived from type+value so re-runs produce the same id."""
        return hashlib.sha1(f"{self.type}:{self.value}".encode()).hexdigest()[:12]

    @property
    def occurrence_count(self) -> int:
        return len(self.occurrences)

    def to_dict(self):
        d = asdict(self)
        d["id"] = self.id
        d["occurrence_count"] = self.occurrence_count
        return d


@dataclass
class Event:
    """
    A single classified log/activity event - the unit the "story" is built
    from. Unlike a Finding (a deduplicated entity), an Event represents one
    thing that happened at one point in time.
    """
    timestamp: Optional[str]     # ISO string, or None if no timestamp could be parsed
    approximate: bool             # True if timestamp was inferred (date-only or carried-forward)
    category: str                  # Authentication, Network, DNS, File, Email, Security, Process, Other
    actor: Optional[str]           # user/account/email associated with the event, if identifiable
    action: str                     # short verb phrase, e.g. "failed login", "outbound connection"
    outcome: Optional[str]         # Success, Failure, Blocked, or None
    source_ip: Optional[str]
    dest_ip: Optional[str]
    port: Optional[str]
    protocol: Optional[str]
    objects: List[str] = field(default_factory=list)   # files/hashes/domains mentioned
    raw: str = ""
    source_file: str = ""
    location: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class Insight:
    """A detected pattern (brute force, beaconing, etc.) tying several Events together into one narrative claim."""
    severity: str            # High, Medium, Low
    title: str
    description: str
    event_refs: List[int] = field(default_factory=list)   # indices into the case's event list

    def to_dict(self):
        return asdict(self)


@dataclass
class ParsedChunk:
    """
    A unit of text produced by a parser, tagged with where it came from.
    Extractors run against ParsedChunk.text and inherit its location info.

    row_data (optional): for tabular sources (CSV/XLSX/XLS), the raw
    per-row dict of {column_name: value} - preserved as real Python values
    rather than flattened into `text`, so schema-aware parsing (e.g.
    recognizing a Unified Audit Log export and decoding its AuditData JSON
    cell) can work off real data instead of re-splitting a comma-joined
    string, which breaks the moment a cell value itself contains a comma.
    """
    text: str
    source_file: str
    location: str
    evidence_type: str
    row_data: Optional[dict] = None
