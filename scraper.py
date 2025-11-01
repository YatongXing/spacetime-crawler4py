import os
import json
import re
from collections import Counter, defaultdict
from threading import RLock
from urllib.parse import (
    urlparse, urljoin, urldefrag,
    urlsplit, urlunsplit, parse_qsl, urlencode, parse_qs
)
from bs4 import BeautifulSoup

# --------------------------- Scope: allowed domains ---------------------------
_ALLOWED_SUFFIXES = (
    "ics.uci.edu",
    "cs.uci.edu",
    "informatics.uci.edu",
    "stat.uci.edu",
)

# --------------------------- Trap keywords (coarse) ---------------------------
_TRAP_KEYWORDS = {
    # feeds / apis / sitemaps
    "wp-json", "xmlrpc", "sitemap", "feed", "rss", "atom", "format=xml",
    "ical", "ics",

    # media/file browsers and attachments (parameter-driven)
    "do=media", "tab=files", "media=", "image=", "file=", "attachment=",

    # low-info render modes
    "format=pdf", "print=", "view=print", "preview=", "untitled%20folder%202", "~wscacchi/Presentations",

    # misc noise / comment reply & social share
    "replytocom", "share="
}

# --------------------------- Thin-content thresholds --------------------------
# If a 200-HTML page has fewer than these, treat as "no useful text" → don't expand.
_MIN_TEXT_CHARS = 60
_MIN_TEXT_WORDS = 12

# Hard cap to avoid massive HTML dumps with little value
_MAX_HTML_BYTES = 3_000_000

# Drop typical marketing/tracking params to reduce near-duplicate URLs
_DROP_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "gclid", "fbclid", "mc_cid", "mc_eid"
}

# --------------------------- Lightweight analytics ----------------------------
AN_DIR = "analytics"
os.makedirs(AN_DIR, exist_ok=True)

_lock = RLock()
_seen_pages = set()                 # defragmented URLs of successfully parsed HTML pages
_word_freq = Counter()              # global word frequencies (stopwords removed)
_subdomain_pages = defaultdict(int) # host -> unique pages count (for *.uci.edu)
_longest = {"url": None, "word_count": 0}
_pages_since_save = 0

# Compact English stopword set (extend as needed)
_STOP = {
    "a","an","and","are","as","at","be","been","but","by","can","did","do","does","for","from",
    "had","has","have","he","her","here","hers","him","his","how","i","if","in","into","is","it",
    "its","just","me","more","most","my","no","not","of","on","or","our","ours","out","s","she",
    "so","t","that","the","their","theirs","them","then","there","these","they","this","those",
    "to","too","up","was","we","were","what","when","where","which","who","why","will","with",
    "you","your","yours"
}

def _save_snapshot():
    """Write report-ready files periodically."""
    data = {
        "unique_pages_downloaded": len(_seen_pages),
        "longest_page": _longest,
        "subdomains": dict(sorted(_subdomain_pages.items())),
        "top_200_words": _word_freq.most_common(200),
    }
    with open(os.path.join(AN_DIR, "snapshot.json"), "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    with open(os.path.join(AN_DIR, "subdomains.csv"), "w", encoding="utf-8") as f:
        for host, cnt in sorted(_subdomain_pages.items()):
            f.write(f"{host}, {cnt}\n")

    with open(os.path.join(AN_DIR, "top50.txt"), "w", encoding="utf-8") as f:
        for w, c in _word_freq.most_common(50):
            f.write(f"{w} {c}\n")

    with open(os.path.join(AN_DIR, "longest.txt"), "w", encoding="utf-8") as f:
        f.write(f"{_longest['url']}, {_longest['word_count']}\n")

def _maybe_save():
    global _pages_since_save
    _pages_since_save += 1
    if _pages_since_save % 50 == 0:
        _save_snapshot()

# ================================= API =======================================

def scraper(url, resp):
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]

def extract_next_links(url, resp):
    """Extract hyperlinks from an HTML page, with dead-200 + thin-text guards and analytics."""
    result = []

    # Basic validity: need a 200 HTML-ish page with a raw_response object
    if resp is None or resp.status != 200 or resp.raw_response is None:
        return result

    headers = getattr(resp.raw_response, "headers", {}) or {}
    ctype = (headers.get("Content-Type", "") or "").lower()
    if "text/html" not in ctype and "application/xhtml+xml" not in ctype:
        return result

    # Dead-200 by header: Content-Length: 0
    clen = headers.get("Content-Length")
    if clen is not None:
        try:
            if int(clen) == 0:
                return result
        except Exception:
            pass

    # Fetch body; discard empty or extremely large HTML
    content = getattr(resp.raw_response, "content", b"") or b""
    if len(content) == 0 or len(content) > _MAX_HTML_BYTES:
        return result

    # Parse HTML
    try:
        soup = BeautifulSoup(content, "lxml")
    except Exception:
        return result

    # Remove non-text elements and check visible text
    for t in soup(["script", "style", "noscript"]):
        t.decompose()

    text = soup.get_text(" ", strip=True)
    words_raw = re.findall(r"[A-Za-z]{2,}", text)
    if len(text.replace(" ", "")) < _MIN_TEXT_CHARS or len(words_raw) < _MIN_TEXT_WORDS:
        # Thin content: do not expand
        return result

    # Use the final resolved URL as base, defragmented
    base = (getattr(resp.raw_response, "url", None) or resp.url or url)
    base, _ = urldefrag(base)

    # --------------------- Analytics update (unique, longest, words) ---------------------
    filtered_words = [w.lower() for w in words_raw if w.lower() not in _STOP]
    wc = len(filtered_words)
    page_url = base
    host = urlparse(page_url).netloc.lower().split(":")[0]

    with _lock:
        if page_url not in _seen_pages:
            _seen_pages.add(page_url)

            # Count subdomains under uci.edu only
            if host.endswith(".uci.edu") or host == "uci.edu":
                _subdomain_pages[host] += 1

            # Update global vocabulary and longest-page tracker
            _word_freq.update(filtered_words)
            if wc > _longest["word_count"]:
                _longest["url"] = page_url
                _longest["word_count"] = wc

            _maybe_save()
    # -------------------------------------------------------------------------------------

    # Extract hyperlinks
    seen = set()
    for a in soup.find_all("a", href=True):
        href = a.get("href", "").strip()

        # Skip pseudo-schemes and obvious junk
        if not href or href.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
            continue
        if any(c in href for c in ["[", "]", " ", "{", "}", "|", "\\"]):
            continue

        # Normalize: absolute URL + defragment + drop tracking params
        try:
            abs_url = urljoin(base, href)
        except Exception:
            continue
        abs_url, _ = urldefrag(abs_url)

        # Drop tracking/marketing query params to reduce near-duplicates
        try:
            u = urlsplit(abs_url)
            q_pairs = parse_qsl(u.query, keep_blank_values=True)
            q_pairs = [(k, v) for (k, v) in q_pairs if k.lower() not in _DROP_PARAMS]
            abs_url = urlunsplit((u.scheme, u.netloc, u.path, urlencode(q_pairs, doseq=True), ""))
        except Exception:
            pass

        if abs_url and abs_url not in seen:
            seen.add(abs_url)
            result.append(abs_url)

    return result

def is_valid(url):
    """
    Return True for URLs we want to crawl:
      - http(s)
      - within the four allowed domains (any subdomain)
      - not a known trap, calendar/timeline infinite set, or low-value file type
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return False

        # Host must be under allowed suffixes (strip port if present)
        host = (parsed.netloc or "").lower().split(":")[0]
        if not any(host == d or host.endswith("." + d) for d in _ALLOWED_SUFFIXES):
            return False

        path = (parsed.path or "").lower()
        query = (parsed.query or "").lower()

        # Obvious junk in host (e.g., IPv6 literal brackets)
        if "[" in host or "]" in host:
            return False

        # Block non-HTML / binary-like file extensions early
        if re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            r"|png|tiff?|mid|mp2|mp3|mp4"
            r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            r"|epub|dll|cnf|tgz|sha1"
            r"|thmx|mso|arff|rtf|jar|csv"
            r"|rm|smil|wmv|swf|wma|zip|rar|gz)$",
            path
        ):
            return False

        # ----------------------- Calendar / Events (incl. WordPress The Events Calendar) -----------------------
        # Block path- and query-based calendar pages that explode into many near-duplicates.
        if (
            "/events/" in path or "/event/" in path or "/calendar" in path
            or "post_type=tribe_events" in query or "eventdisplay=" in query
            or "tribe_" in query or "eventdate=" in query
        ):
            # 1) Path-based day/week/month views
            if ("/day/" in path or "/week/" in path or "/month/" in path):
                return False

            # 2) Path-based date archives: /YYYY-MM, /YYYY/MM, /YYYY-MM-DD, /YYYY/MM/DD
            if re.search(r"/\d{4}[-/]\d{1,2}([-/]\d{1,2})?(/|$)", path):
                return False

            # 3) Query-based views (day/week/month)
            if ("eventdisplay=day" in query or "eventdisplay=week" in query or "eventdisplay=month" in query):
                return False

            # 4) Query-based specific day, e.g., ?eventDate=YYYY-MM-DD (via lower-casing)
            if re.search(r"(?:^|[?&])eventdate=\d{4}-\d{2}-\d{2}(?:$|&)", query):
                return False

            # 5) Pagination combined with event parameters (e.g., /page/3/?...tribe...)
            if re.search(r"/page/\d+/", path):
                return False
        # seminar-series archive

        if len(re.findall(r"seminar-series-\d{4}-\d{4}", path)) >= 2:
            return False

        if "/seminar-series/seminar-series-archive" in path and re.search(r"seminar-series-\d{4}-\d{4}", path):
            return False

        if "/wp-content/uploads/" in path:
            return False

        # ----------------------- Trac / timeline trap (infinite time windows) -----------------------
        # Example: /wiki/.../timeline?from=...&precision=second
        if "/timeline" in path:
            return False
        if "precision=second" in query:
            return False
        if re.search(r"(?:^|[?&])from=[^&]+", query):
            return False
        if "/doku.php" in path:
            q = parse_qs(query or "", keep_blank_values=True)
            # Block low-value / explosive DokuWiki views
            if any(k in q for k in ("do", "tab", "idx", "rev", "ns", "image", "media")):
                return False
        # Apache autoindex sorter duplicates (e.g., ?C=N;O=D or ?C=N%3BO%3DD)
        # Block when sorting params appear on directory listings to avoid near-duplicates.
        if path.endswith("/") and (
                "%3bo%3d" in query  # encoded ";O="
                or "%20uai%20" in query
                or ";o=" in query  # raw ";O="
                or re.search(r"(?:^|&)\bc=[nmsd]\b", query)  # C=N|M|S|D
                or re.search(r"(?:^|&)\bo=[ad]\b", query)  # O=A|D
        ):
            return False

        # Query directly pointing to files via parameter
        if re.search(
            r"(image|file|media|attachment)=[^&]+\.(png|jpe?g|gif|svg|pdf|zip|rar|gz|mp4|mp3|avi|mov|pptx?|docx?|xlsx?)",
            query
        ):
            return False

        # Feeds/APIs/sitemaps/etc. (low textual value for our goal)
        if any(k in f"{path}?{query}" for k in (
            "wp-json", "xmlrpc", "sitemap", "feed", "rss", "atom", "format=pdf"
        )):
            return False

        # Excessive pagination/offset → likely infinite listing
        if re.search(r"(^|[?&])page=\d{3,}", query) or re.search(r"(^|[?&])offset=\d{3,}", query):
            return False

        # Repeating path segments (e.g., /a/b/a/b/a/b/)
        segs = [s for s in path.split("/") if s]
        if len(segs) >= 6:
            for w in range(1, min(4, len(segs) // 2 + 1)):
                if segs[:w] * (len(segs) // w) == segs[: w * (len(segs) // w)]:
                    return False

        # Path depth & URL length sanity limits
        if len(url) > 2048 or len(query) > 600 or len(segs) > 20:
            return False

        # Coarse trap keywords (path + query)
        pq = f"{path}?{query}"
        if any(k in pq for k in _TRAP_KEYWORDS):
            return False

        return True

    except Exception:
        # Be safe on any parsing error
        return False
