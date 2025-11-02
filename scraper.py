import os
import re
import sys
import atexit
from collections import Counter
from urllib.parse import urlparse, urljoin, urldefrag, parse_qsl, urlencode
from bs4 import BeautifulSoup  # required by extract_next_links()

# ----------------------------- Non-HTML extensions -----------------------------
_NON_HTML_EXTS = (
    ".css",".js",".bmp",".gif",".jpg",".jpeg",".ico",".png",".tif",".tiff",".psp",".h5",".java",".seq",
    ".mid",".mp2",".mp3",".mp4",".wav",".avi",".mov",".mpeg",".ram",".m4v",".mkv",".ogg",".ogv",".nb",
    ".pdf",".ps",".eps",".tex",".ppt",".pptx",".doc",".docx",".xls",".xlsx",".ppsx",".bib",".sdf",".tsv",".conf",
    ".names",".data",".dat",".exe",".bz2",".tar",".msi",".bin",".7z",".psd",".dmg",".iso",".mol",".ismsmi",".war",
    ".epub",".dll",".cnf",".tgz",".sha1",".thmx",".mso",".arff",".rtf",".jar",".csv", ".sql",".target",".fpkm",".class",
    ".rm",".smil",".wmv",".swf",".wma",".zip",".rar",".gz", ".ics", ".mpg", ".txt", ".apk", ".img", ".odp", ".ipynb",
    ".xml",".sh", ".svg"
)

# ----------------------------- Error pattern heuristics -----------------------------
_ERROR_PATTERNS = [
    re.compile(p) for p in (
        r"\b404\b",
        r"\bpage\s+not\s+found\b",
        r"\boops\b|\bwhoops\b",
        r"\bnot\s+found\b",
        r"\bdoesn?t?\s+exist\b",
        r"\bwe\s+are\s+having\s+trouble\s+locating\s+your\s+page\b",
        r"\bnothing\s+found\b",
        r"\bcontent\s+you\s+requested\s+could\s+not\s+be\s+found\b",
        r"\bforbidden\b",
        r"\berror\b",
        r"\brequested\s+url\s+was\s+not\s+found\b",
        r"\bthat\s+page\s+can\s*t\s+be\s+found\b",
        r"\bwe\s+can\s*t\s+seem\s+to\s+find\b"
    )
]

# ----------------------------- Allowed suffixes -----------------------------
_ALLOWED_SUFFIXES = (
    #"ics.uci.edu",
    #"cs.uci.edu",
    "informatics.uci.edu",
    #"stat.uci.edu",
)

# ----------------------------- Trap heuristics and regexes -----------------------------
_TRAP_KEYWORDS = {
    "wp-json", "xmlrpc", "sitemap", "feed", "rss", "atom", "format=xml",
    "do=media", "tab=files", "media=", "image=", "file=", "attachment=",
    "format=pdf", "print=", "view=print", "preview=", "login", "register",
    "replytocom", "share=",
    "demo", "makefile", "readme"
}

_RE_EVENTS_PAGE_IN_PATH = re.compile(r"/events?/.*/page/\d+/?$")
_RE_TRIBE_QS          = re.compile(r"(?:^|[?&])tribe-bar-date=\d{4}-\d{2}-\d{2}(?:&|$)")
_RE_EVENTDISPLAY      = re.compile(r"(?:^|[?&])eventDisplay=(?:upcoming|past|list|month|day)(?:&|$)")

_RE_MEDIA_PARAM_FILE = re.compile(
    r"(?:^|[?&])(img|image|file|media|attachment|format)=[^&]+\.(?:png|jpe?g|gif|svg|pdf|zip|rar|gz|mp4|mp3|avi|mov|pptx?|docx?|xlsx?|txt)",
    re.I
)

_RE_APACHE_AUTOINDEX_QS = re.compile(
    r"(?:^|[?&;])(?:c=(?:n|m|s|d)|o=(?:a|d)|f=\d+)(?:[;&]|$)", re.I
)

_RE_ICAL_EXPORT_QS = re.compile(
    r"(?:^|[?&;])(outlook-)?ical=\d+(?:[&;]|$)", re.I
)

_RE_STATIC_CALENDAR = re.compile(r"/calendar(?:\.html?)?/?$")
_RE_STATIC_GALLERY  = re.compile(r"/gallery(?:\.html?)?/?$")

_RE_WSC_BLOCK = re.compile(r"^/~wscacchi/(presentations|gamelab)(?:/|$)", re.I)

_RE_MLPHYSICS_DATA_SEG = re.compile(r"(?:^|/)data(?:/|$)", re.I)

_RE_PATH_PAGINATION_DEEP = re.compile(
    r"/(?:page|paged|pagenum|pagination)/\d{3,}/?$", re.I
)

# =====================================================================================
# Reporting (integrated here; no other files modified)
# =====================================================================================

VISITED_FILE = "visited_urls.txt"
PAGES_DIR    = "pages"
REPORT_FILE  = "report.txt"

# English stopwords for Top-50
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

_HTML_ARTIFACTS = {"nbsp"}  # common entity leakage to drop

def _tokenize_for_report(text: str):
    """
    Normalize/tokenize visible text:
      - letters only, lowercase
      - drop stopwords
      - drop 1-char tokens except 'a' and 'i'
      - drop known artifacts
    """
    raw = re.findall(r"[A-Za-z]+", (text or "").lower())
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

def _safe_name_from_url(u: str) -> str:
    p = urlparse(u)
    name = (p.netloc + p.path).strip("/") or (p.netloc or "page")
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name)
    return name[:180]

def _record_visit(url: str, visible_text: str):
    """Append URL and save a text snapshot (best-effort; never break crawling)."""
    try:
        os.makedirs(PAGES_DIR, exist_ok=True)
        with open(VISITED_FILE, "a", encoding="utf-8") as vf:
            vf.write(url.strip() + "\n")
        if visible_text is not None:
            fname = _safe_name_from_url(url) + ".txt"
            with open(os.path.join(PAGES_DIR, fname), "w", encoding="utf-8", errors="ignore") as tf:
                tf.write(visible_text)
    except Exception:
        pass

def _generate_report():
    """Build report.txt per assignment spec."""
    try:
        if not os.path.exists(VISITED_FILE):
            print("[REPORT] No visited_urls.txt; nothing to report.")
            return

        # 1) Unique pages by URL
        with open(VISITED_FILE, "r", encoding="utf-8", errors="ignore") as f:
            url_list = [u.strip() for u in f if u.strip()]
        unique_urls = sorted(set(url_list))

        # 2) Words & longest page
        word_counter = Counter()
        page_lengths  = {}
        for fname in os.listdir(PAGES_DIR) if os.path.isdir(PAGES_DIR) else []:
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

        longest_line = "N/A"
        if page_lengths:
            longest_file = max(page_lengths, key=page_lengths.get)
            longest_line = f"{longest_file}, {page_lengths[longest_file]} words"

        # 3) Subdomain counts (only uci.edu hosts)
        subdomain_counter = {}
        for u in unique_urls:
            host = urlparse(u).netloc
            if host.endswith(".uci.edu") or host == "uci.edu":
                subdomain_counter[host] = subdomain_counter.get(host, 0) + 1

        # 4) Write report
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

# Delete previous report/snapshots when restarted
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

# Register the report generator to run when the crawler process exits
atexit.register(_generate_report)

# =====================================================================================
# Scraper pipeline
# =====================================================================================

def scraper(url, resp):
    """
    Our framework entry point:
      - Records a text snapshot (for reporting).
      - Extracts links and applies is_valid().
    """
    links = extract_next_links(url, resp)

    # Record snapshot for reporting (only for successful HTML pages)
    try:
        if resp is not None and resp.status == 200 and resp.raw_response is not None:
            headers = getattr(resp.raw_response, "headers", {}) or {}
            ctype = (headers.get("Content-Type", "") or "").lower()
            if "text/html" in ctype:
                html = resp.raw_response.content.decode("utf-8", errors="ignore")
                # visible text: strip scripts/styles then tags
                clean = re.sub(r"(?is)<(script|style).*?>.*?</\1>", "", html)
                visible = re.sub(r"(?is)<[^>]+>", " ", clean)
                visible = re.sub(r"\s+", " ", visible).strip()
                _record_visit(resp.url or url, visible)
    except Exception:
        # never break crawling for reporting
        pass

    return [link for link in links if is_valid(link)]

def _page_stats(soup):
    text = soup.get_text(" ", strip=True)
    norm = re.sub(r"[^a-z0-9]+", " ", (text or "").lower()).strip()
    word_count = len(norm.split())
    a_count = len(soup.find_all("a", href=True))
    title = (soup.title.string or "").lower() if soup.title and soup.title.string else ""
    title_norm = re.sub(r"[^a-z0-9]+", " ", title).strip()
    return word_count, a_count, title_norm

def _looks_like_login_wall(soup) -> bool:
    if soup.find("input", {"type": "password"}):
        return True
    for form in soup.find_all("form"):
        action = (form.get("action") or "").lower()
        if any(w in action for w in ("login", "signin", "sign-in", "webauth", "shibboleth", "cas", "saml", "oauth")):
            return True
    return False

def _looks_like_error_200_from_stats(soup, word_count, a_count, title_norm) -> bool:
    # WordPress/STAT "not found" templates etc.
    if soup.select_one(".error-404, .page-404, body.error404, #error404, .not-found, .page-not-found"):
        return True
    if any(p.search(title_norm) for p in _ERROR_PATTERNS):
        return True
    for hdr in soup.find_all(["h1", "h2"]):
        h = re.sub(r"[^a-z0-9]+", " ", (hdr.get_text(strip=True) or "").lower())
        if any(p.search(h) for p in _ERROR_PATTERNS):
            return True
    for m in soup.find_all("meta"):
        if (m.get("name", "").lower() == "robots"):
            c = (m.get("content", "").lower())
            if "noindex" in c or "nofollow" in c:
                return True
    if a_count > 120 and word_count < 80:
        return True
    return False

def extract_next_links(url, resp):
    """
    Parse the page and extract outbound links (BeautifulSoup).
    """
    result = []

    if resp is None or resp.status != 200 or resp.raw_response is None:
        return result

    headers = getattr(resp.raw_response, "headers", {}) or {}
    ctype = headers.get("Content-Type", "") or ""
    ctype_l = ctype.lower()
    if "text/html" not in ctype_l:
        return result

    content = getattr(resp.raw_response, "content", b"") or b""
    if not content:
        return result

    if "xml" in ctype_l and "xhtml" not in ctype_l:
        return result

    head = (content[:512] or b"").lstrip().lower()
    if head.startswith(b"<?xml") or head.startswith(b"<rss") or head.startswith(b"<feed") or b"<urlset" in head or b"<sitemapindex" in head:
        return result

    try:
        soup = BeautifulSoup(content, "lxml")
    except Exception:
        return result

    for t in soup(['script', 'style', 'noscript', 'svg']):
        t.decompose()

    word_count, a_count, title_norm = _page_stats(soup)
    if _looks_like_error_200_from_stats(soup, word_count, a_count, title_norm):
        return result
    if _looks_like_login_wall(soup):
        return result

    a_tags = soup.find_all("a", href=True)

    base = resp.url or url
    seen = set()
    for a in a_tags:
        href = a.get("href", "").strip()
        if not href or href.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
            continue
        if any(c in href for c in ["[", "]", " ", "{", "}", "|", "\\"]):
            continue
        try:
            abs_url = urljoin(base, href)
        except Exception:
            continue
        abs_url, _ = urldefrag(abs_url)
        if abs_url and abs_url not in seen:
            seen.add(abs_url)
            result.append(abs_url)
    return result

def is_valid(url):
    """
    URL filters. Return True to keep crawling.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return False

        host = (parsed.hostname or "").rstrip(".").lower()
        if not any(host == d or host.endswith("." + d) for d in _ALLOWED_SUFFIXES):
            return False

        path = (parsed.path or "").lower().rstrip("/")
        query = (parsed.query or "").lower()
        pq = f"{path}?{query}"

        if path.endswith(_NON_HTML_EXTS):
            return False

        if "/events/" in path or "/event/" in path or "/calendar" in path:
            if ("/day/" in path or "/week/" in path or "/month/" in path
                    or re.search(r"\d{4}[-/]\d{1,2}[-/]\d{1,2}", path)):
                return False
            if re.search(r"/20\d{2}-?(0[1-9]|1[0-2])/?$", path) or re.search(r"/20\d{2}/(0[1-9]|1[0-2])/?$", path):
                return False
            if _RE_EVENTS_PAGE_IN_PATH.search(path) or _RE_TRIBE_QS.search(query) or _RE_EVENTDISPLAY.search(query):
                return False

        if host == "www.ics.uci.edu" and path.startswith("/~eppstein/pix/"):
            return False

        if "doku.php" in path and ("do=" in query or "tab=" in query or "idx=" in query):
            return False

        if host == "wics.ics.uci.edu":
            if re.search(r"/\d{6,}(?:_[0-9a-f]{4,})+(?:_[a-z])?/?$", path):
                return False
            if re.search(r"/(img|dsc|photo)[_-]?\d{3,}(/|$)", path):
                return False
            if re.search(r"/\d{2}(?:-\d{2}){1,2}-[a-z0-9-]+-\d{2,4}/?$", path):
                return False

        if _RE_APACHE_AUTOINDEX_QS.search(query):
            return False

        if _RE_MEDIA_PARAM_FILE.search(query):
            return False

        if _RE_ICAL_EXPORT_QS.search(query):
            return False

        if _RE_STATIC_CALENDAR.search(path) or _RE_STATIC_GALLERY.search(path):
            return False

        if host == "www.ics.uci.edu" and _RE_WSC_BLOCK.search(path):
            return False

        if host == "mailman.ics.uci.edu":
            return False

        if host == "instdav.ics.uci.edu":
            return False

        if host == "mlphysics.ics.uci.edu" and _RE_MLPHYSICS_DATA_SEG.search(path):
            return False

        if host == "grape.ics.uci.edu":
            segs = [s for s in path.split("/") if s]
            if "asterix" in segs or "timeline" in segs:
                return False
            if ("action=" in query) or ("format=" in query):
                return False

        if _RE_PATH_PAGINATION_DEEP.search(path):
            return False

        if any(k in pq for k in _TRAP_KEYWORDS):
            return False

        if re.search(r"(^|[?&])(page|paged|pagenum|start|offset)=\d{3,}", query):
            return False

        segs = [s for s in path.split("/") if s]
        if len(segs) >= 6:
            for w in range(1, min(4, len(segs) // 2 + 1)):
                if segs[:w] * (len(segs) // w) == segs[: w * (len(segs) // w)]:
                    return False

        if len(url) > 2048 or len(query) > 600 or len(segs) > 20:
            return False

        return True

    except Exception:
        return False
