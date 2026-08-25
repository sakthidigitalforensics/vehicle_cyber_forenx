# Vehicle Cyber ForenX Tool (Local Prototype)

A private, custom-built, local-only offline forensic case management tool -
built by **Sakthi**, not a third-party product. It covers case
intake → evidence upload → automated indicator extraction → human
verification → forensic artifact extraction → customizable report generation
(DOCX/PDF), all through a guided dashboard + step-by-step flow rather than a
plain sidebar. Alongside general cyber evidence (logs, email, M365/Entra
exports), it recognizes **vehicle telematics / GPS-OBD-II exports** as a
first-class evidence type - see "Vehicle telematics support" below.

**Nothing leaves your machine.** There are no network calls anywhere in this
app or its extraction engine. All case data, evidence, findings, and reports
are stored on disk under `./data/` inside this project folder, and - see
below - actually **encrypted** there, not just password-gated. `.streamlit/config.toml`
also explicitly disables Streamlit's own default usage-telemetry ping, which
would otherwise be the one thing in this whole tool that phones home.

## Do you need internet to *run* this?

**No** - once it's installed, running the app and working a case (creating
cases, uploading evidence, generating the timeline/findings, unlocking the
encrypted vault, writing reports) needs zero internet access. You can use it
on a fully air-gapped laptop.

**Internet is only needed once, up front, to install things** - the same
way installing any desktop app needs a download first:
- Downloading Python packages via `pip install -r requirements.txt`.
- Downloading Tesseract OCR and LibreOffice (only if you'll process
  OCR'd images or legacy `.doc`/`.xls` files).
- Downloading 7-Zip/WinRAR if you needed one to extract this delivery.

After that one-time setup, you can disconnect entirely and the tool works
exactly the same.

## 1. One-time setup

You need Python 3.9+, Tesseract OCR (used for text-in-images extraction),
and LibreOffice (used to convert legacy `.doc`/`.xls` files locally - no
network involved, it's just used as a local file converter).

```bash
# macOS
brew install tesseract libreoffice

# Ubuntu/Debian
sudo apt-get install tesseract-ocr libreoffice

# Windows
# Tesseract: https://github.com/UB-Mannheim/tesseract/wiki (add to PATH)
# LibreOffice: https://www.libreoffice.org/download/ (add soffice.exe to PATH)
# Both are only needed if you plan to upload OCR'd images or legacy .doc/.xls files.
```

Then install the Python dependencies (a virtual environment is recommended):

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## 2. Run it

```bash
streamlit run app.py
```

This opens the app in your browser at `http://localhost:8501` - it is only
reachable from this machine (localhost), nothing is exposed externally.

### Dashboard + guided flow (instead of a plain sidebar)

After unlocking, you land on a **🏠 Dashboard** - case health at a glance
(evidence/findings/high-severity-pattern counts, verification progress, a
findings-by-type chart, an event-activity-over-time chart) with a smart
"➡ Continue" button that jumps you straight to whatever's next for that case
(upload pending files, keep verifying, generate the report). From there, a
numbered **stepper** across the top of every stage (Case Details → Upload
Evidence → Investigation Story → Findings → Verification → Artifacts →
Generate Report) replaces the old left-sidebar-only navigation - click any
step to jump directly to it, or use the **⬅ Back / Next ➡** buttons at the
bottom of each stage to move through the case in order. The sidebar itself is
now just case selection, the Dashboard shortcut, and **🔒 Lock & Exit**.

The Dashboard's two charts are genuinely interactive, not just pictures:

- **Time-range filter** - Last 7 / 30 / 90 days or All time, sitting right
  above the charts. It re-scopes both of them together (findings are matched
  to the range via the evidence file they came from), and a caption shows
  exactly how much of the case that range covers (e.g. "10 of 18 findings, 11
  of 11 dated events") so you always know what you're looking at.
- **Click a bar in "Findings by type"** to jump straight to the Findings
  stage, pre-filtered to that exact type - no manually re-selecting the
  filter dropdown.
- **Click a point on "Event activity over time"** to jump straight to the
  Investigation Story for that one day - the Timeline Story gets a "filter to
  a specific day" control that pre-selects the day you clicked (or pick any
  day from the dropdown yourself; choose "All dates" to clear it).
- Hovering either chart shows a themed tooltip (matching the dark chart
  surface rather than a plain white box); the activity chart also gets a
  vertical crosshair line following your cursor.

### Visual theme - "Midnight Sparkle"

The whole app runs a single playful, pill-everything visual system (built
from a Claude Design mockup) rather than Streamlit's default look: a dark
plum surface, bright pink/purple/mint accents, Fredoka headings + Nunito
body text, colored severity/status badges (🔴 High / 🟠 Medium / 🟢 Low, plus
verification-status pills), rounded stat tiles and cards with a springy
hover lift, "pressed"-style bottom-shadow buttons, and a custom evidence
table - all driven from one place, `core/theme.py`, so every stage stays
visually consistent. (An earlier round of this same UI work used a darker,
denser "Lab Dark" instrument-panel look - this replaced it end to end,
including the fonts and every stage's styling.) **This still makes zero
network calls**: the fonts are bundled locally as WOFF2 files under
`static/fonts/` (Nunito + Fredoka fetched once at build time from the
`@fontsource` npm packages, which ship the actual font files rather than a
Google Fonts CDN reference; IBM Plex Mono stays bundled for `st.code()` /
raw log line display) and wired up via Streamlit's native
`[[theme.fontFaces]]` config - nothing is fetched from the internet to
render the UI, consistent with the tool's offline-only design throughout.

### Password lock, machine lock, and real encryption

If someone else gets hold of this folder - a copied USB drive, a stray
backup, a shared laptop - none of the following should work for them.
Three things all have to line up before any case data is readable:

1. **One-time password.** The first time anyone runs this specific
   downloaded copy, it asks you to set a password before showing anything
   else. It can be set exactly **once** - there is no "forgot password" or
   reset option anywhere in the app afterwards, and `core/auth.py`
   actively refuses to let it be set a second time even by a future code
   path that forgets to check first.
2. **Machine lock.** That password only works on the laptop it was set up
   on. If this folder is copied to a different machine, the app refuses to
   unlock - even with the correct password - because it checks an
   offline, no-network machine fingerprint (an OS-level machine ID where
   available) before it will even try the password.
3. **Real encryption, not just a login screen.** The password doubles as
   the encryption passphrase for the actual case data. All of it - the
   database, uploaded evidence, POC screenshots, generated reports - lives
   encrypted at rest in a single file, `data/vault.enc` (AES via Fernet,
   key derived from your password with PBKDF2-SHA256). Someone with direct
   filesystem access who skips the app entirely and tries to open the raw
   files with some other tool gets ciphertext, not your case data.

**There is no back door.** Because the password is genuinely the
encryption key (not a separate check next to unencrypted data), if it's
forgotten, the case data it protects cannot be recovered by anyone,
including us. Store it somewhere safe before you start a real case.

While the app is unlocked, the decrypted working copy lives at
`data/live/` - it's what the database and file operations actually use
while you work, and it's necessarily plaintext on disk during that time
(true of any local tool, encrypted database engines included). Every
action reseals `data/vault.enc` with the latest state automatically, and
there's a **🔒 Lock & Exit** button in the sidebar that seals it and then
deletes `data/live/` outright before you close the app - use that instead
of just closing the terminal window, so nothing lingers in plaintext
longer than it has to.

Two out-of-band recovery utilities exist for legitimate edge cases, both
deliberately absent from the app UI (they require direct terminal access
to the machine, not just app access):

- `python3 -c "from core.auth import rebind_this_machine; rebind_this_machine('your-password')"`
  - if your machine's identity legitimately changes (OS reinstall, new
  disk) but you still know the password, this re-binds the lock to the
  current machine without touching your case data.
- `python3 -c "from core.auth import factory_reset; factory_reset()"`
  - wipes the password, the vault, and any decrypted data, letting you
  set up fresh. Only use this if the password is genuinely and permanently
  lost - it does not recover the old data, because nothing can.

## 3. Using the tool

1. **Case Details** - create a case (auto-generated Case ID, name, case
   story/overview, company, reporter, investigators, classification,
   severity, confidentiality).
2. **Upload Evidence** - upload logs/CSVs, `.eml` emails, PDFs,
   DOCX/DOC/RTF/ODT documents, XLSX/XLSM/XLS spreadsheets, or images -
   including Microsoft 365/Entra ID forensic exports (see below). Every
   file is SHA-256 hashed at ingest (shown on screen) for chain-of-custody,
   then run through the extraction + timeline engine automatically - this
   is where every line/row gets classified into an event (who, what, when,
   outcome) and cross-checked for attack patterns. **Processing is
   incremental**: each click of "Store + Process Evidence" only parses
   files that haven't been processed before (each evidence row tracks a
   `processed` flag) - on a case that's accumulated several large uploads,
   this avoids re-parsing everything from scratch on every batch, which
   matters a lot on big files. Detected patterns (insights) still
   recompute across the *whole* case each time, since a pattern can span
   old and new evidence together - but that recomputation runs over
   already-classified structured events already in the database, not raw
   files, so it stays fast even as the recomputation covers everything. An
   "⚙️ Advanced: force full reprocess" option is available if you've
   updated the detection logic and want it retroactively re-applied to
   evidence already processed.
3. **Investigation Story** - the main payoff: instead of reading every log
   line yourself, you get an executive summary, a list of auto-detected
   patterns in plain English (brute-force logins, C2 beaconing, malware
   drops correlated with AV hits, lookalike/spoofed domains, suspicious
   outbound mail, off-hours access, plus the M365/BEC patterns below), and
   then a **📅 Timeline Story** - every doubtful/notable moment in the
   case in chronological order, each shown as its raw technical line
   (e.g. "09:00:00 08/08/2026 - sign-in from an unusual location
   (87.76.65.9)") immediately followed by a plain-language "What this
   means" / "Impact" explanation, so you can read top to bottom and get
   the whole story without opening a single raw log line. A compressed
   "Routine Activity" summary table covers everything else so ordinary
   traffic doesn't bury the signal. On a 1,800-line test log with a buried
   multi-stage attack, this reduced what an analyst has to actually read
   to a handful of story points plus a 5-row summary table.
4. **Findings** - browse deduplicated indicators (IPs, emails, domains,
   URLs, hashes, MAC addresses, crypto addresses, file paths, phone
   numbers, vehicle VINs, OBD-II diagnostic trouble codes), filter/search,
   and expand any finding to see exactly which file/line/page it came
   from. (Email findings show "-" instead of a confidence score -
   deduplication confidence isn't a meaningful risk signal for an email
   address the way it is for an IP or hash.)
5. **Verification** - for every finding you get the story context and
   file/row it came from by default, then can mark it Verified / False
   Positive / Needs Further Investigation, add notes, and attach a POC -
   either by uploading a file **or** by taking a screenshot and pasting it
   straight in (no save-to-disk round trip). A finding can have more than
   one POC attached; all of them are listed and shown. Every change is
   logged in a full audit trail (who, when, old→new status).
6. **Artifacts** - two tabs. **📁 Case File Library** lists every evidence
   file, POC attachment, and generated report for the case with a
   download button each, in one place. **🔬 Extracted Forensic
   Artifacts** goes one layer deeper than the timeline/findings view,
   pulling classic digital-forensics artifacts *out of* the evidence
   itself: for `.eml` files, the real `Received:` relay chain, SPF/DKIM/DMARC
   results, X-Originating-IP, and a From/Reply-To mismatch check (a
   textbook spoofing tell); for native `.docx` files, the document's own
   core properties (Author, Last Modified By, Created/Modified timestamps,
   revision count - worth comparing against who the file was claimed to
   come from); for images, EXIF data (camera make/model, editing software,
   original capture timestamp, GPS coordinates plotted on a map where
   present). This tab is computed **lazily** (only when you open it,
   cached after that) so it never slows down the main upload/processing
   step - it's a deliberately separate, deeper pass.
7. **Generate Report** - customize header/footer text, company name,
   accent color, and separately the font/size/color for headings,
   subheadings, and body text; choose heading style and whether to use
   bullets/tables; save your settings as a reusable template. Generates a
   DOCX or PDF structured into exactly 7 sections so a non-technical
   reader can follow the case end-to-end: (1) Executive Summary, (2) Scope
   & Evidence Reviewed (every file, its detected type, and the mailbox it
   concerns), (3) Timeline of Key Events (the full Timeline Story, no
   cap), (4) Detailed Findings (with attached POC images/files embedded
   inline), (5) Indicator of Compromise Summary (IP addresses with what
   happened and where, inbox rules, other indicators), (6) Risk Assessment
   (finding / status / impact), and (7) Recommendations (immediate actions
   plus follow-up/hardening, generated from whichever pattern types were
   actually detected in that case) - followed by an Appendix A
   chain-of-custody evidence manifest.

### Microsoft 365 / Entra ID support

The tool specifically recognizes four common M365/Entra forensic export
formats (CSV or XLSX/XLS - it detects the schema from the header row, so
it works either way):

- **Unified Audit Log** exports (Purview / `Search-UnifiedAuditLog`) -
  decodes the `AuditData` JSON column to pull out the real client IP,
  result status, and operation-specific parameters (inbox rule forwarding
  targets, mailbox permission grants, OAuth consent scopes, etc.), not
  just the outer columns.
- **Entra ID (Azure AD) sign-in logs** - maps Status/IP address/Location
  into proper Authentication events, enabling **impossible-travel
  detection** (same account signing in from two different reported
  locations too close together in time to be physically plausible).
- **OAuth application consent logs** - flags **high-risk consent grants**:
  admin consent, or scopes like `Mail.Read`, `full_access_as_app`,
  `Directory.ReadWrite.All`, etc. (the "illicit consent grant" phishing
  technique).
- **Mailbox delegation and inbox rule reports** - flags **inbox rules that
  forward/redirect mail to an external address and/or silently delete or
  hide messages** (classic BEC persistence used to intercept password
  resets or hide phishing replies), and **delegation grants to accounts
  outside the organization's own domain**.

These four detectors, plus the general-purpose ones, all report through
the same Investigation Story / Findings / Report pipeline - a BEC case
built purely from M365 exports gets the same "notable timeline +
executive summary" treatment as a network intrusion case built from
server logs. See `samples/m365/` for a worked example (a compromised
mailbox: phishing → risky OAuth consent → malicious inbox rule → external
delegation grant, spread across CSV, XLSX, and XLS versions of the same
data to prove the schema detection works regardless of file format).

### Vehicle telematics support

The tool also recognizes a **vehicle telematics / GPS-OBD-II export**
schema (CSV - detected from the header row, so any fleet-tracking or
telematics-control-unit platform that exports `vin` alongside
`odometer_km`/`ignition_state`/`event_type`/`geofence_zone`/`dtc_code`
columns will be picked up automatically):

- **GPS spoofing / vehicle teleport detection** - flags two GPS fixes for
  the same VIN that are physically impossible to have driven between in
  the time elapsed (the vehicle-world equivalent of "impossible travel"
  for user sign-ins).
- **Odometer rollback detection** - mileage should only ever increase; a
  drop between two readings for the same VIN is flagged as likely
  tampering.
- **Unauthorized OBD-II diagnostic access** - flags a diagnostic session
  opened by a technician ID outside the authorized fleet-maintenance list
  (`analyzers/vehicle_classifier.AUTHORIZED_TECHNICIAN_IDS`), especially
  off-hours.
- **Geofence breach detection** - flags a VIN entering a zone it's
  specifically fenced out of (a restricted depot, a border, a customer
  exclusion zone).

These detectors report through the same Investigation Story / Findings /
Report pipeline as everything else - a fleet-tampering case reads exactly
like a network-intrusion case, just with VINs and GPS coordinates instead
of IPs and domains. See `samples/vehicle/` for a worked example (a
delivery van: an off-hours immobilizer bypass → a spoofed GPS fix
thousands of kilometers away → an unauthorized OBD-II session → a masked
diagnostic trouble code → an odometer rollback → a geofence breach into a
restricted border zone - plus a second, unaffected vehicle as a clean
baseline).

### How the "story" is built

Every parsed line (log line, CSV row, email header/body, OCR'd image text)
is run through a classifier that extracts a timestamp, category
(Authentication/Network/DNS/File/Email/Security/Process), actor, outcome,
source/destination IP, and any referenced objects (hashes, domains,
files) - using a mix of hand-written phrasing templates, a generic
key=value parser for structured/CSV-style lines, and a keyword-based
fallback so no line is silently dropped. A set of rule-based detectors then
scans the full chronological event list for known patterns (see stage 3
above). This is a starting rule set, not a finished detection product -
the way to make it recognize more of *your* real logs is to run them
through it and extend `analyzers/event_classifier.py` (new phrasing
templates) and `analyzers/pattern_detectors.py` (new pattern rules) based
on what it misses.

## Project layout

```
app.py                  Streamlit UI (dashboard + 7-stage guided flow) + the password/machine/vault gate
core/
  auth.py               One-time password, machine-lock fingerprint, vault orchestration
  vault.py              Encrypts/decrypts data/live/ <-> data/vault.enc (Fernet/PBKDF2)
  db.py                 SQLite persistence (cases, evidence, findings, events, insights, audit log) -
                         incremental-processing helpers (list_unprocessed_evidence, append_events,
                         replace_insights) alongside the full-reprocess path (replace_events_and_insights)
  models.py             Finding / Occurrence / ParsedChunk / Event / Insight data classes
  timeparse.py           Multi-format timestamp extraction with date carry-forward
  report_generator.py   DOCX + PDF report builders (includes the Investigation Story)
parsers/                Per-file-type parsers: text, csv, eml, pdf, docx, doc/rtf/odt (via LibreOffice),
                         xlsx (openpyxl), xls (xlrd / LibreOffice fallback), image+OCR
extractors/
  regex_extractors.py   Entity extraction patterns + validation
  pipeline.py            Orchestrates parse -> extract entities + classify events, in one pass
analyzers/
  event_classifier.py   Turns one line into a structured Event (who/what/when/outcome)
  m365_classifier.py     Schema-aware classification for UAL/Entra sign-in/OAuth consent/delegation exports
  vehicle_classifier.py  Schema-aware classification for vehicle telematics / GPS-OBD-II exports
  pattern_detectors.py  Rule-based attack-pattern detectors over the event timeline
  narrative.py            Aggregates events into bursts, splits notable vs routine, builds the unified story
  artifact_extractor.py  Email header / docx metadata / image EXIF forensics for the Artifacts page
                         (lazy + cached - only runs when that page is opened)
data/                   Created on first run:
  vault_meta.json         Salt, password-verification marker, machine fingerprint hash (no plaintext password)
  vault.enc                The ENCRYPTED case data at rest (everything below, as one sealed blob)
  live/                     DECRYPTED working copy while unlocked - db, evidence, poc, reports
main.py                  Standalone CLI for the extraction engine only (no UI):
                         python3 main.py <folder-of-evidence> --out findings.json
```

## Known limitations (prototype stage)

- OCR accuracy on small/low-resolution text in images is limited by
  Tesseract itself - verify OCR-derived findings against the original image.
- Supported evidence types so far: text/log/CSV, `.eml`, PDF,
  DOCX/DOC/RTF/ODT, XLSX/XLSM/XLS, common image formats, the four
  M365/Entra export schemas, and the vehicle telematics/GPS-OBD-II export
  schema, all listed above. PCAP, EVTX, and disk/memory images are not yet
  supported (flagged as a possible next phase).
- M365 schema detection is header-based and covers the column names seen
  in common exports - if your organization's export tool uses very
  different column names, a row may fall through to the generic
  classifier instead of the schema-aware one. Extend `detect_schema()` in
  `analyzers/m365_classifier.py` with your actual column names if so.
- Legacy `.doc`/`.xls` parsing shells out to local LibreOffice to convert
  the file first - if LibreOffice isn't installed, those two formats
  won't parse (everything else works without it).
- Phone number and generic file-path extraction are inherently ambiguous
  pattern matches - treat their confidence scores as lower-trust and always
  verify manually before including in a final report.
- Single-user, single-machine design by intent: this copy is now
  cryptographically bound to one laptop, and the password controls access
  to *everything* inside it - there's no per-case or per-user permissions,
  anyone who knows the password sees every case. If a case genuinely needs
  to move to another analyst or machine, the receiving side needs their
  own fresh copy of this tool (set up with their own password on their own
  machine) and the evidence files copied over into it - not this same
  running copy, since it will refuse to unlock anywhere else.
- The machine fingerprint prefers a stable OS-level machine ID (e.g.
  `/etc/machine-id` on Linux, the platform UUID on macOS, the registry
  `MachineGuid` on Windows) and falls back to hostname + network adapter
  ID if that's unavailable. A major OS reinstall can legitimately change
  this ID - if the app refuses to unlock on what really is the same
  physical laptop after such a change, use `rebind_this_machine()` (above)
  rather than assuming the tool is broken.
- While unlocked, the decrypted `data/live/` copy is genuinely plaintext on
  disk for as long as the app stays open - encryption protects the data at
  rest between sessions and against anyone who doesn't have the password,
  not against something reading the machine's disk *during* an active,
  unlocked session. Use "🔒 Lock & Exit" when you're done rather than
  leaving the app open longer than needed.
- PDF report fonts are "family" choices (sans-serif/serif/monospace), not
  exact typefaces - ReportLab's built-in PDF fonts are limited to
  Helvetica/Times/Courier without bundling a TTF file, so e.g. choosing
  "Georgia" for a PDF renders in Times-family metrics. DOCX reports use the
  exact font name chosen (rendered correctly if that font is installed on
  whoever opens the file, same as any Word document).
- Clipboard-paste POC capture depends on the browser's clipboard
  permissions (usually a one-time "allow" prompt) - if paste doesn't work,
  the file-upload POC option always works as a fallback.
- The encrypted vault only reseals (re-tars + re-encrypts the whole case
  folder) when something actually changed - a genuine mutation (storing
  evidence, processing it, changing a verification status, generating a
  report) sets an internal "dirty" flag for that run. Switching stages,
  expanding a section, or just browsing does not trigger a reseal, which
  matters on large cases since Streamlit reruns the whole script on every
  interaction.
- This is a private, single-analyst tool built for and branded to
  **Sakthi** - the page title, sidebar, and lock screen all
  say so explicitly, specifically so that anyone who sees it running knows
  it's a personal custom tool and not an unauthorized copy of someone
  else's private/proprietary software.
