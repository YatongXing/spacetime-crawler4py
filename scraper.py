import os
import re
import sys
import atexit
from collections import Counter
from urllib.parse import urlparse, urljoin, urldefrag, parse_qsl, urlencode

# ---------- Quick-test settings ----------
TEST_MODE = True            # set False for full crawl
PAGE_BUDGET = 50            # stop expanding links after this many pages recorded
# If you leave TEST_ALLOWED_HOSTS empty, quick-test host/path restriction is skipped.
TEST_ALLOWED_HOSTS = {
    # "informatics.uci.edu": ["/about", "/people"],   # example
    # "stat.ics.uci.edu": ["/people", "/about"],      # example
}

# keeps a simple in-process page counter
_PAGES_RECORDED = {"count": 0}

# =====================================================================================
# Utilities
# =====================================================================================

def _html_text(resp) -> str:
    """Return page HTML as text (utf-8; ignore decode errors)."""
    try:
        return resp.raw_response.content.decode("utf-8", errors="ignore")
    except Exception:
        return ""

# =====================================================================================
# Core scraper: extract links and validate URLs
# =====================================================================================

def scraper(url, resp):
    """
    Return a list of absolute, defragmented, valid links found in 'resp'.
    Also records page text & visited URLs for end-of-run reporting (no other files changed).
    """
    if resp is None or getattr(resp, "status", None) != 200 or resp.raw_response is None:
        return []

    # Only HTML
    hdrs = getattr(resp.raw_response, "headers", {}) or {}
    ctype = str(hdrs.get("Content-Type", "")).lower()
    if "text/html" not in ctype:
        _record_visit(url, "")
        return []

    html = _html_text(resp)
    if not html:
        _record_visit(url, "")
        return []

    # Visible text (HTML markup doesn’t count as words)
    clean = re.sub(r"(?is)<(script|style).*?>.*?</\1>", "", html)
    visible = re.sub(r"(?is)<[^>]+>", " ", clean)
    visible = re.sub(r"\s+", " ", visible).strip()

    # Tokenize with assignment-friendly rules (ignore stopwords, 1-char except a/i, non-letters)
    tokens = _tokenize_for_report(visible)
    words = len(tokens)

    # Light content gate to avoid thin templates
    if words < 120 or (len(visible) / max(1, len(html))) < 0.05:
        _record_visit(url, visible)  # still record text (may be short)
        return []

    # If we’ve already recorded enough pages, emit no outlinks anymore (quick-test).
    if TEST_MODE and _PAGES_RECORDED["count"] >= PAGE_BUDGET:
        _record_visit(url, visible)
        return []

    # Extract links then validate
    links = extract_next_links(url, resp)
    links = [link for link in links if is_valid(link)]

    # Now that this page is accepted, increment the budget counter (quick-test).
    if TEST_MODE:
        _PAGES_RECORDED["count"] += 1

    # Record page for report
    _record_visit(url, visible)

    return links

def extract_next_links(url, resp):
    html = _html_text(resp)
    if not html:
        return []

    hrefs = re.findall(r'''(?i)\bhref\s*=\s*["']([^"']+)["']''', html)

    out = set()
    base = resp.url or url
    for href in hrefs:
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            continue
        abs_url = urljoin(base, href)
        abs_url, _ = urldefrag(abs_url)
        abs_url = _strip_tracking_params(abs_url)
        out.add(abs_url)
    return list(out)

# ---- URL validation filters -------------------------------------------------

_ALLOWED_SUFFIXES = (
    ".informatics.uci.edu",
    ".stat.ics.uci.edu",
    ".ics.uci.edu",
    ".cs.uci.edu",
)

_BLOCK_HOSTS = {
    "wics.ics.uci.edu",
    "ngs.ics.uci.edu",
}

_LOW_VALUE_SUBPATHS = (
    "/slideshows",
    "/videos",
    "/video-",
    "/media",
    "/gallery",
)

_BAD_PATH_PARTS = (
    "calendar", "cal", "wp-json", "feed", "feeds", "atom", "rss",
    "login", "logout", "signin", "signup", "register", "account",
    "cart", "checkout", "wp-admin", "admin", "cgi-bin", "session",
    "share", "print", "preview", "format=pdf", "download", "plugins",
)

_CALENDAR_HINTS = ("ical", "tribe")

_NON_HTML_RE = re.compile(
    r""".*\.(?:css|js|bmp|gif|jpe?g|ico
        |png|tiff?|mid|mp2|mp3|mp4|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf
        |ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names|data|dat|exe|bz2|tar|msi|bin|7z
        |psd|dmg|iso|epub|dll|cnf|tgz|sha1|thmx|mso|arff|rtf|jar|csv
        |rm|smil|wmv|swf|wma|zip|rar|gz|ics)$
    """,
    re.IGNORECASE | re.VERBOSE,
)

def _allowed_domain(hostname: str) -> bool:
    if not hostname:
        return False
    for suf in _ALLOWED_SUFFIXES:
        bare = suf[1:]
        if hostname == bare or hostname.endswith(suf):
            return True
    return False

def _too_deep(path: str, max_depth: int = 3) -> bool:
    depth = len([p for p in path.split("/") if p])
    return depth > max_depth

def _has_repetition(path: str) -> bool:
    segs = [s for s in path.split("/") if s]
    if not segs:
        return False
    for s in set(segs):
        if segs.count(s) >= 3:
            return True
    numeric_segments = sum(ch.isdigit() for seg in segs for ch in seg)
    return numeric_segments >= 10

def _strip_tracking_params(u: str) -> str:
    parsed = urlparse(u)
    if not parsed.query:
        return u
    bad_keys = {
        "utm_source","utm_medium","utm_campaign","utm_term","utm_content",
        "gclid","fbclid","mc_cid","mc_eid","replytocom","share","ref","source",
        "amp","ts","ns_mchannel","ns_campaign",
    }
    params = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
              if k.lower() not in bad_keys]
    new_q = urlencode(params, doseq=True)
    return parsed._replace(query=new_q).geturl()

def is_valid(url):
    try:
        parsed = urlparse(url)

        if parsed.scheme not in {"http", "https"}:
            return False

        host = (parsed.hostname or "").lower()
        if host in _BLOCK_HOSTS:
            return False

        if not _allowed_domain(host):
            return False

        low = parsed.path.lower()

        # Block orphaned STAT news slugs: /<hyphenated-slug>
        if host.endswith("stat.ics.uci.edu"):
            segs = [s for s in parsed.path.split("/") if s]
            if len(segs) == 1 and "-" in segs[0]:
                return False

        # Block WP uploads without an actual file extension
        if re.search(r"/wp-content/uploads/", parsed.path, re.I):
            filename = parsed.path.rsplit("/", 1)[-1]
            allowed_exts = {
                ".pdf",".png",".jpg",".jpeg",".gif",".tif",".tiff",".svg",".webp",
                ".doc",".docx",".ppt",".pptx",".xls",".xlsx",".zip",".rar",".gz",".bz2",".7z"
            }
            if not any(filename.lower().endswith(ext) for ext in allowed_exts):
                return False

        if any(hint in low for hint in _CALENDAR_HINTS):
            return False

        if any(low.startswith(p) or p in low for p in _LOW_VALUE_SUBPATHS):
            return False

        if _has_repetition(parsed.path):
            return False
        if _NON_HTML_RE.match(low):
            return False
        if any(bad in low for bad in _BAD_PATH_PARTS):
            return False
        if len(url) > 200:
            return False

        if parsed.query:
            if re.search(r"(page|paged|offset|start|sort|order|filter)=", parsed.query, re.I):
                m = re.search(r"(?:page|paged|offset)=(\d+)", parsed.query, re.I)
                if m and int(m.group(1)) > 10:
                    return False

        # ----------------- TEST MODE: restrict scope heavily -----------------
        if TEST_MODE and TEST_ALLOWED_HOSTS:
            # Only allow specific small hosts + path prefixes
            if host not in TEST_ALLOWED_HOSTS:
                return False
            allowed_prefixes = TEST_ALLOWED_HOSTS[host]
            low_path = parsed.path.rstrip("/") or "/"
            if allowed_prefixes and not any(low_path.startswith(pfx) for pfx in allowed_prefixes):
                return False
            # Keep it shallow during quick test
            if _too_deep(parsed.path, max_depth=2):
                return False
        # ---------------------------------------------------------------------

        return True
    except (TypeError, ValueError):
        return False

# =====================================================================================
# Reporting (only modifies scraper.py). No DB, no other files touched.
# =====================================================================================

# Paths
VISITED_FILE = "visited_urls.txt"
PAGES_DIR    = "pages"
REPORT_FILE  = "report.txt"

# English stopwords
STOPWORDS = set("""
a about above after again against all am an and any are aren't as at be because been 
before being below between both but by can't cannot could couldn't did didn't do does 
doesn't doing don't down during each few for from further had hadn't has hasn't have 
haven't having he he'd he'll he's her here here's hers herself him himself his how 
how's i i'd i'll i'm i've if in into is isn't it it's its itself let's me more most 
mustn't my myself no nor not of off on once only or other ought our ours ourselves out 
over own same shan't she she'd she'll she's should shouldn't so some such than that 
that's the their theirs them themselves then there there's these they they'd they'll 
they're they've this those through to too under until up very was wasn't we we'd we'll 
we're we've were weren't what what's when when's where where's which while who who's 
whom why why's with won't would wouldn't you you'd you'll you're you've your yours 
yourself yourselves
""".split())

_HTML_ARTIFACTS = {"nbsp"}  # common entity noise

def _tokenize_for_report(text: str):
    """
    Normalize and tokenize visible text for the assignment's 'word' notion:
    - letters only
    - lowercase
    - drop stopwords
    - drop one-letter tokens except 'a' and 'i'
    - drop common HTML artifacts like 'nbsp'
    """
    raw = re.findall(r"[A-Za-z]+", text.lower())
    out = []
    for w in raw:
        if w in _HTML_ARTIFACTS:
            continue
        if w in STOPWORDS:
            continue
        if len(w) == 1 and w not in {"a", "i"}:
            continue
        out.append(w)
    return out

# Restart cleanup (delete previous report & scratch)
if "--restart" in sys.argv or "restart" in sys.argv:
    try:
        if os.path.exists(VISITED_FILE): os.remove(VISITED_FILE)
        if os.path.exists(REPORT_FILE): os.remove(REPORT_FILE)
        if os.path.isdir(PAGES_DIR):
            for f in os.listdir(PAGES_DIR):
                try: os.remove(os.path.join(PAGES_DIR, f))
                except Exception: pass
        else:
            os.makedirs(PAGES_DIR, exist_ok=True)
    except Exception:
        pass

# Safe file name for storing page text
def _safe_name_from_url(u: str) -> str:
    p = urlparse(u)
    name = (p.netloc + p.path).strip("/")
    if not name:
        name = p.netloc or "page"
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name)
    return name[:180]  # safety cap

# Append URL and write text snapshot for reporting
def _record_visit(url: str, visible_text: str):
    try:
        os.makedirs(PAGES_DIR, exist_ok=True)
        # 1) append url to visited list (for uniqueness by URL)
        with open(VISITED_FILE, "a", encoding="utf-8") as vf:
            vf.write(url.strip() + "\n")
        # 2) store visible text (HTML stripped)
        if visible_text is not None:
            fname = _safe_name_from_url(url) + ".txt"
            with open(os.path.join(PAGES_DIR, fname), "w", encoding="utf-8", errors="ignore") as tf:
                tf.write(visible_text)
    except Exception:
        pass  # best-effort only; never break crawling

def _generate_report():
    try:
        if not os.path.exists(VISITED_FILE):
            print("[REPORT] No visited_urls.txt; nothing to report.")
            return

        # Unique pages by URL (discarding fragments already handled by urldefrag elsewhere)
        with open(VISITED_FILE, "r", encoding="utf-8", errors="ignore") as f:
            url_list = [u.strip() for u in f if u.strip()]
        unique_urls = sorted(set(url_list))

        # Aggregate words & lengths from saved text files
        word_counter = Counter()
        page_lengths  = {}  # filename -> word count
        for fname in os.listdir(PAGES_DIR):
            if not fname.endswith(".txt"):
                continue
            fpath = os.path.join(PAGES_DIR, fname)
            try:
                text = open(fpath, "r", encoding="utf-8", errors="ignore").read()
            except Exception:
                continue
            toks = _tokenize_for_report(text)
            word_counter.update(toks)
            page_lengths[fname] = len(toks)

        # Subdomain counts from URLs (only uci.edu)
        subdomain_counter = {}
        for u in unique_urls:
            host = urlparse(u).netloc
            if host.endswith(".uci.edu") or host == "uci.edu":
                subdomain_counter[host] = subdomain_counter.get(host, 0) + 1

        # Longest page by counted words
        longest_line = "N/A"
        if page_lengths:
            longest_file = max(page_lengths, key=page_lengths.get)
            longest_line = f"{longest_file}, {page_lengths[longest_file]} words"

        # Write report
        with open(REPORT_FILE, "w", encoding="utf-8") as rpt:
            rpt.write(f"Total unique pages: {len(unique_urls)}\n")
            rpt.write(f"\nLongest page: {longest_line}\n")

            rpt.write("\nTop 50 common words:\n")
            for w, c in word_counter.most_common(50):
                rpt.write(f"{w}: {c}\n")

            rpt.write("\nSubdomains and counts:\n")
            for sd in sorted(subdomain_counter):
                rpt.write(f"{sd}: {subdomain_counter[sd]}\n")

        print(f"[REPORT] Generated {REPORT_FILE} (unique={len(unique_urls)})")
    except Exception as e:
        try:
            print(f"[REPORT] Failed to generate report: {e}")
        except Exception:
            pass

# Register exit hook (called when the crawler process exits)
atexit.register(_generate_report)
