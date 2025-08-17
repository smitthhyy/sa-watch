#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SA Parliament watcher (fixed keys):
- Scans SA Legislation 'Bills (current)' and follows bill links
- Scans Parliament 'Bills & Motions' (listing) + follows links
- Scans Hansard and Committees landing pages
- Regex keywords, logs CSV/JSONL, de-dupes via state file
- Email via SMTP or AWS SES (configurable with EMAIL_METHOD)
"""

import os
import re
import csv
import json
import time
import hashlib
import smtplib
import socket
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from datetime import datetime
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv

# ---- Timezone with graceful fallback (Windows may need tzdata) ----
try:
    from zoneinfo import ZoneInfo
    try:
        TZ = ZoneInfo("Australia/Adelaide")
    except Exception:
        TZ = ZoneInfo("UTC")
except Exception:
    TZ = None

# Optional (only used if EMAIL_METHOD=ses)
try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
    HAS_BOTO3 = True
except Exception:
    HAS_BOTO3 = False

# =========================
# Configuration
# =========================

KEYWORDS = [
    r"vilification",
    r"anti[-\s]*vilification",
    r"hate\s*speech",
    r"discrimination\s+bill",
    r"social\s+cohesion",
]

URLS = {
    "Bills (current session)": "https://www.legislation.sa.gov.au/legislation/bills/current",
    "Bills & Motions": "https://www.parliament.sa.gov.au/en/Legislation/Bills-and-Motions",
    "Hansard": "https://hansardsearch.parliament.sa.gov.au/search/",
    "Committees": "https://www.parliament.sa.gov.au/en/Legislation/Legislation-Home",
}

ALLOWED_NETLOCS = {"www.legislation.sa.gov.au", "www.parliament.sa.gov.au"}

OUT_DIR = "sa_watch_output"
HISTORY_CSV = os.path.join(OUT_DIR, "history.csv")
HISTORY_JSONL = os.path.join(OUT_DIR, "history.jsonl")
STATE_FILE = os.path.join(OUT_DIR, "state_seen.json")

TIMEOUT = 25
HEADERS = {"User-Agent": "SA-Watch/1.2 (+noncommercial monitoring)"}

# =========================
# Env / Email configuration
# =========================

load_dotenv()

EMAIL_METHOD = os.environ.get("EMAIL_METHOD", "smtp").strip().lower()  # 'smtp' or 'ses'
EMAIL_FROM = os.environ.get("EMAIL_FROM", "").strip()
EMAIL_TO = [e.strip() for e in os.environ.get("EMAIL_TO", "").split(",") if e.strip()]

# SMTP config (if EMAIL_METHOD=smtp)
SMTP_HOST = os.environ.get("SMTP_HOST", "").strip()
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "").strip()
SMTP_PASS = os.environ.get("SMTP_PASS", "").strip()

# =========================
# Helpers
# =========================

def now_iso():
    if TZ:
        return datetime.now(TZ).isoformat(timespec="seconds")
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"

def ensure_dirs():
    os.makedirs(OUT_DIR, exist_ok=True)
    if not os.path.exists(HISTORY_CSV):
        with open(HISTORY_CSV, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["timestamp", "source", "url", "title", "keywords", "snippet"])
    if not os.path.exists(HISTORY_JSONL):
        open(HISTORY_JSONL, "a", encoding="utf-8").close()
    if not os.path.exists(STATE_FILE):
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump({"seen": {}}, f)

def get_state():
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"seen": {}}

def save_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)

def fetch(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        r.raise_for_status()
        return r.text
    except Exception as e:
        print(f"[WARN] fetch failed {url}: {e}")
        return None

def text_from_html(html):
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    title = soup.title.get_text(strip=True) if soup.title else ""
    text = soup.get_text(separator=" ")
    text = re.sub(r"\s+", " ", text).strip()
    return title, text

def compile_patterns(words):
    pats = []
    for w in words:
        # If it looks like regex, keep; else word-boundary it
        if re.search(r"[\\\[\]\(\)\|\?\+\*\{\}]", w):
            pats.append(re.compile(w, re.I))
        else:
            pats.append(re.compile(rf"\b{re.escape(w)}\b", re.I))
    return pats

PATTERNS = compile_patterns(KEYWORDS)

def find_matches(text):
    hits = []
    for pat in PATTERNS:
        for m in pat.finditer(text):
            start = max(0, m.start() - 120)
            end = min(len(text), m.end() + 120)
            snippet = text[start:end].strip()
            hits.append({"pattern": pat.pattern, "span": (m.start(), m.end()), "snippet": snippet})
    return hits

def hash_key(url, matches):
    blob = "\n".join(m["snippet"] for m in matches)
    h = hashlib.sha256()
    h.update(url.encode("utf-8"))
    h.update(blob.encode("utf-8"))
    return h.hexdigest()

def log_hit(ts, source, url, title, keywords, snippet):
    with open(HISTORY_CSV, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([ts, source, url, title, "; ".join(sorted(set(keywords))), snippet])
    with open(HISTORY_JSONL, "a", encoding="utf-8") as f:
        record = {
            "timestamp": ts,
            "source": source,
            "url": url,
            "title": title,
            "keywords": sorted(set(keywords)),
            "snippet": snippet,
        }
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

def extract_bill_links(bills_html, base_url):
    soup = BeautifulSoup(bills_html, "html.parser")
    links = set()
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith("#"):
            continue
        abs_url = urljoin(base_url, href)
        p = urlparse(abs_url)
        if p.netloc and p.netloc not in ALLOWED_NETLOCS:
            continue
        lower_path = p.path.lower()
        if "/legislation/bills" in lower_path or "bill" in lower_path:
            links.add(abs_url)
    return sorted(links)

# =========================
# Scanning
# =========================

def scan_single_page(source_name, url, state):
    html = fetch(url)
    if not html:
        return []

    title, text = text_from_html(html)
    matches = find_matches(text)
    if not matches:
        return []

    key = hash_key(url, matches)
    prev = state["seen"].get(url)
    if prev == key:
        return []

    state["seen"][url] = key

    ts = now_iso()
    first_snip = matches[0]["snippet"]
    kws = [m["pattern"] for m in matches]
    log_hit(ts, source_name, url, title, kws, first_snip)

    return [{
        "timestamp": ts,
        "source": source_name,
        "url": url,
        "title": title,
        "keywords": kws,
        "snippet": first_snip,
    }]

def crawl_bills(state):
    """
    Updated to use the NEW keys:
      - 'Bills (current session)'  (Legislation site)
      - 'Bills & Motions'          (Parliament tracker)
    """
    new_hits = []

    # 1) Official Legislation bills list (primary)
    base_leg = URLS["Bills (current session)"]
    html_leg = fetch(base_leg)
    if html_leg:
        new_hits += scan_single_page("Bills (current session) (listing)", base_leg, state)
        for link in extract_bill_links(html_leg, base_leg):
            new_hits += scan_single_page("Bill", link, state)
            time.sleep(0.8)

    # 2) Parliament tracker page (secondary)
    base_par = URLS["Bills & Motions"]
    html_par = fetch(base_par)
    if html_par:
        new_hits += scan_single_page("Bills & Motions (listing)", base_par, state)
        for link in extract_bill_links(html_par, base_par):
            new_hits += scan_single_page("Bill/Tracker", link, state)
            time.sleep(0.8)

    return new_hits

# =========================
# Email (SMTP / SES)
# =========================

def build_plain_report(hits):
    lines = [f"SA Watch Report — {now_iso()} ({socket.gethostname()})", ""]
    for h in hits:
        lines.append(f"- Source: {h['source']}")
        lines.append(f"  Title : {h['title']}")
        lines.append(f"  URL   : {h['url']}")
        lines.append(f"  Terms : {', '.join(sorted(set(h['keywords'])))}")
        lines.append(f"  Snip  : {h['snippet']}")
        lines.append("")
    return "\n".join(lines)

def email_via_smtp(subject, body_text, attach_history=True):
    if not (SMTP_HOST and EMAIL_FROM and EMAIL_TO):
        print("[INFO] SMTP not configured; skipping email.")
        return
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = EMAIL_FROM
    msg["To"] = ", ".join(EMAIL_TO)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid()
    msg.set_content(body_text)

    if attach_history:
        try:
            with open(HISTORY_CSV, "rb") as f:
                data = f.read()
            msg.add_attachment(data, maintype="text", subtype="csv", filename="history.csv")
        except Exception as e:
            print(f"[WARN] SMTP attach failed: {e}")

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as s:
            s.starttls()
            if SMTP_USER and SMTP_PASS:
                s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
        print("[INFO] SMTP email sent.")
    except Exception as e:
        print(f"[ERROR] SMTP send failed: {e}")

def email_via_ses(subject, body_text, attach_history=True):
    if not (EMAIL_FROM and EMAIL_TO):
        print("[INFO] SES not configured; skipping email.")
        return
    if not HAS_BOTO3:
        print("[ERROR] boto3 not installed; cannot use SES.")
        return

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = EMAIL_FROM
    msg["To"] = ", ".join(EMAIL_TO)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid()
    msg.set_content(body_text)

    if attach_history:
        try:
            with open(HISTORY_CSV, "rb") as f:
                data = f.read()
            msg.add_attachment(data, maintype="text", subtype="csv", filename="history.csv")
        except Exception as e:
            print(f"[WARN] SES attach failed: {e}")

    try:
        ses = boto3.client("ses")
        resp = ses.send_raw_email(RawMessage={"Data": msg.as_bytes()})
        print(f"[INFO] SES email sent: {resp.get('MessageId','<no-id>')}")
    except (BotoCoreError, ClientError) as e:
        print(f"[ERROR] SES send failed: {e}")

def send_email(hits):
    if not hits:
        return
    subject = f"[SA Watch] {len(hits)} new match(es) found"
    body = build_plain_report(hits)
    if EMAIL_METHOD == "ses":
        email_via_ses(subject, body, attach_history=True)
    else:
        email_via_smtp(subject, body, attach_history=True)

# =========================
# Main
# =========================

def main():
    ensure_dirs()
    state = get_state()
    all_new = []

    # Crawl Bills (with following) — uses new keys
    all_new += crawl_bills(state)

    # Scan Hansard & Committees landing pages
    all_new += scan_single_page("Hansard (landing)", URLS["Hansard"], state)
    all_new += scan_single_page("Committees (landing)", URLS["Committees"], state)

    save_state(state)

    if all_new:
        print(f"[INFO] {len(all_new)} new match(es) at {now_iso()}")
        for h in all_new:
            print(f" - {h['source']} | {h['title']} | {h['url']}")
        send_email(all_new)
    else:
        print(f"[INFO] No new matches at {now_iso()}")

if __name__ == "__main__":
    main()
