# PhishGuard — Phishing Awareness & Email Threat Analysis System

PhishGuard is a local-first educational tool for inspecting sample email text and URL structure. It demonstrates practical phishing awareness using an explainable Python rule engine, Flask pages and persistent SQLite storage. It does not open URLs, inspect live websites, fetch threat intelligence or open attachments. A low score does not prove a message safe.

## Features and objectives

- Detect suspicious phrases, urgency, sender patterns, credential/payment requests, attachment mentions and links.
- Statically inspect URLs for IP hosts, shorteners, lookalike patterns, punycode, deep subdomains, HTTP and unusual structure.
- Show a bounded 0–100 score, LOW/MEDIUM/HIGH/CRITICAL classification, SAFE/SUSPICIOUS/PHISHING verdict, explanations and recommendations.
- Landing page, database-backed dashboard, email analyzer, URL scanner, awareness center and eight fictional sample messages.
- SQLite history with search, verdict filtering, sorting, detailed reports, deletion and clear-history action.
- Download reports as TXT; TXT export works without a platform-specific PDF dependency.
- Responsive dashboard with Chart.js and Font Awesome.

## Technology

Python 3.10+, Flask 3.x, SQLite, HTML5, CSS3, JavaScript, Chart.js and Font Awesome. Detection uses standard-library parsing. No paid service or AI API is required.

## Install and run

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`. On Linux/macOS activate with `source venv/bin/activate`. SQLite initializes automatically as `phishguard.sqlite3`. Set `PHISHGUARD_DB`, `PHISHGUARD_SECRET` and `PORT` to configure local storage, form token and port. For an internet-facing deployment, configure a strong secret, production WSGI server, HTTPS, authentication and access control.

## Use

Open **Email analyzer**, enter sender, subject and body, then analyze. The report explains triggered indicators. Use **Sample email lab** to load fictional messages. The URL scanner accepts `http://`, `https://` or `www.` text and inspects it locally. Dashboard counts and chart values come from SQLite.

JSON endpoints: `POST /api/analyze` accepts `{ "sender": "...", "recipient": "...", "subject": "...", "body": "...", "csrf_token": "..." }`; `POST /api/scan-url` accepts `{ "url": "...", "csrf_token": "..." }`. JSON requests require the configured token as `csrf_token`. No URL network request is made.

## Detection methodology and limitations

Independent rule groups contribute bounded points once each; score is capped at 100. Risk levels are LOW 0–24, MEDIUM 25–49, HIGH 50–74 and CRITICAL 75–100. SAFE means the enabled rules did not find meaningful signals; SUSPICIOUS means warnings exist; PHISHING requires score 50+ and multiple rule groups. Heuristics may miss novel attacks or flag benign mail. The engine does not inspect message headers, authenticate senders, resolve URLs, validate certificates, query reputation services or assess attachment safety. Treat results as educational guidance, not a security verdict.

Message text is saved locally for history and reports; protect the database and avoid entering passwords, codes or confidential material. Attachments are never uploaded or opened. URLs are never followed.

## Tests

```powershell
python -m unittest discover -s tests -v
```

Tests cover safe and phishing messages, keywords, URL extraction, IP and shortener indicators, score boundaries, input validation, routes, persistence and TXT report downloads.

## Project structure

```text
app.py, config.py, requirements.txt, README.md
detection/       Email, URL, vocabulary and score logic
database/        SQLite initialization and connection lifecycle
templates/       Shared shell and pages
static/          Responsive CSS and browser scripts
tests/           unittest suite
```

## Future improvements

Possible extensions include strict `.eml` parsing, authenticated user storage, configurable policies, PDF export, improved domain normalization and accessibility review. Any reputation lookup should be opt-in and disclose its network behavior.

## Screenshots

No screenshots are included yet. Capture the landing page, dashboard, analysis report and URL scan after a local run.

**Cyber Security Project 3 · DecodeLabs · Batch 2026**
