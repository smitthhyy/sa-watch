# SA Parliament Watch
Lightweight monitor for South Australian parliamentary and legislation websites. It scans key landing pages and follows bill links, searches for configurable keywords using regular expressions, logs results to CSV/JSONL, deduplicates via a state file, and can email a plain-text report via SMTP or AWS SES.
## What it watches
- SA Legislation “Bills (current)” list and bill pages it links to
- SA Parliament “Bills & Motions” tracking page and linked bill/tracker pages
- Hansard landing page
- Committees landing page

Matches are identified by regex keywords you can customize.
## Key features
- Configurable regex keywords
- Safe domain allowlist for crawling
- Deduplication with a local state file (prevents repeated alerts for unchanged pages)
- Plain-text email reports via SMTP or AWS SES
- Machine-readable logs: CSV and JSONL
- Conservative throttling between followed links
- Timezone-aware timestamps (Australia/Adelaide with graceful fallback to UTC)

## Prerequisites
- Python 3.8+ (recommended; the script uses standard libraries plus a few common packages)
- virtualenv
- Network access to the monitored domains and your chosen email delivery service

## Installation
1. Create and activate a virtual environment:
```
python3 -m venv sa-watch
cd sa-watch
. bin/activate
```
2. Install dependencies:
```
pip install requests beautifulsoup4 python-dotenv boto3 tzdata
```
- boto3 is only required if you plan to send email via AWS SES. For SMTP-only usage, you can omit it.

## Configuration
Configure via environment variables. You can set them in your shell or create a `.env` file in the project root.
Required for email (choose one method):
- Common
    - EMAIL_METHOD: smtp or ses (default: smtp)
    - EMAIL_FROM: sender address (e.g., alerts@example.org)
    - EMAIL_TO: comma-separated recipient addresses (e.g., a@example.org,b@example.org)

- SMTP method
    - SMTP_HOST: SMTP server hostname
    - SMTP_PORT: SMTP port (default: 587)
    - SMTP_USER: SMTP username (optional if server allows unauthenticated send)
    - SMTP_PASS: SMTP password

Example `.env` for SMTP:
```
EMAIL_METHOD=smtp
EMAIL_FROM=alerts@example.org
EMAIL_TO=recipient1@example.org,recipient2@example.org

SMTP_HOST=smtp.example.org
SMTP_PORT=587
SMTP_USER=myuser
SMTP_PASS=mypassword
```
Example `.env` for SES:
```
EMAIL_METHOD=ses
EMAIL_FROM=alerts@example.org
EMAIL_TO=recipient1@example.org,recipient2@example.org

# Ensure your environment has AWS credentials configured (env vars, shared credentials file, or IAM role)
# AWS_REGION may also be required depending on your setup.
```
Notes:
- If EMAIL settings are incomplete, the script will still run and log matches locally; it will simply skip sending email.
- For SES, ensure the sender and recipients are verified if your SES account is in sandbox mode.

## Running
From the project directory:
```
cd sa-watch
bin/activate
python sa-watch.py
```
On each run the script:
- Ensures an output directory exists
- Crawls the configured sources
- Logs new matches
- Sends a single consolidated email report (if configured)

You can schedule this to run periodically, for example via cron:
```
*/30 * * * * /path/to/project/.venv/bin/python /path/to/project/sa-watch.py >> /path/to/project/sa-watch.log 2>&1
```
## Output
All files are created under sa_watch_output:
- history.csv: append-only CSV log of matches
- history.jsonl: append-only JSON Lines log (one match per line)
- state_seen.json: internal deduplication state keyed by URL and content hash

The email report includes a human-readable list of new matches and attaches history.csv for convenience.
## Customizing keywords
The default keyword list includes terms like “vilification”, “hate speech”, and related phrases. You can update the list to suit your needs by editing the keywords to be either:
- Plain words (matched case-insensitively with word boundaries), or
- Full regular expressions for advanced matching (e.g., “anti[-\s]*vilification”).

After changing keywords, the script will start matching against the new patterns. Deduplication considers both the URL and the matched snippets, so materially different matches on the same page will still be logged.
## Adding or changing sources
You can extend or modify the set of monitored URLs and the crawler rules to include other official parliamentary resources. Keep the allowlist restricted to trusted domains to avoid unintended crawling.
## Timezone behavior
Timestamps use the Australia/Adelaide timezone when available. If the local system lacks the required timezone data, the script gracefully falls back to UTC. All timestamps are ISO 8601.
## Throttling and timeouts
- Requests include a modest User-Agent and a per-request timeout to be a good citizen.
- A short delay is applied when following bill links to avoid stressing the sites.

## Security and reliability tips
- Store credentials in environment variables or a `.env` file with appropriate filesystem permissions.
- Rotate SMTP/SES credentials periodically.
- Back up the sa_watch_output directory if you rely on the accumulated history.
- Consider running behind a simple supervisor (systemd, PM2, or cron with health checks) for resilience.

## Troubleshooting
- No email received:
    - Verify EMAIL_FROM/EMAIL_TO and SMTP/SES settings.
    - For SES, ensure identities are verified and account is out of sandbox or recipients are verified.

- “SMTP not configured” or “SES not installed”: Confirm your `.env` and installed packages.
- Timezone warnings: The script will use UTC if Australia/Adelaide is unavailable; this is safe.
- No matches appear: Confirm your keywords aren’t too strict; test with broader terms.

## License
See LICENSE.md file
## Disclaimer
This tool is intended for noncommercial monitoring of public parliamentary and legislation sources. Respect the target sites’ terms of use and robots guidelines.
