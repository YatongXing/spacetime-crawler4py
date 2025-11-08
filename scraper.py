import re
from urllib.parse import urlparse, urljoin, urldefrag, urlsplit, urlunsplit
from bs4 import BeautifulSoup
import os, hashlib, threading
from utils import similarity

# Output locations (can be overridden with env var CRAWL_OUT)
_OUT_DIR = os.environ.get("CRAWL_OUT", "crawl_out")
_PAGES_DIR = os.path.join(_OUT_DIR, "pages")
_MANIFEST = os.path.join(_OUT_DIR, "manifest.tsv")

# In-process de-dup for saved pages (thread-safe)
_SEEN_SAVE = set()
_SEEN_LOCK = threading.Lock()

def _norm_url_no_fragment(u: str) -> str:
    """Normalize a URL by stripping only the fragment (#...), as required by the assignment."""
    try:
        p = urlsplit(u)
        # Remove fragment but keep scheme, host, path, and query intact
        return urlunsplit((p.scheme, p.netloc, p.path, p.query, ""))
    except Exception:
        return u

def _safe_save_page(url: str, html_bytes: bytes) -> str:
    """
    Persist the current page to disk and append a row to the manifest file.

    - Saves under crawl_out/pages/<sha1(url_without_fragment)>.html
    - Writes a one-line HTML comment header: <!-- URL: ... --> (useful for offline scans)
    - Appends: "<URL_without_fragment>\t<absolute_file_path>" to crawl_out/manifest.tsv
    - Thread-safe within a single process (coarse-grained set + lock)
    """
    os.makedirs(_PAGES_DIR, exist_ok=True)

    key = _norm_url_no_fragment(url)
    h = hashlib.sha1(key.encode("utf-8")).hexdigest()
    path = os.path.join(_PAGES_DIR, f"{h}.html")

    # Ensure we only save once per normalized URL in this process
    with _SEEN_LOCK:
        if key in _SEEN_SAVE:
            return path
        _SEEN_SAVE.add(key)

    if not os.path.exists(path):
        tmp = path + ".tmp"
        # Write a URL hint in the header so the URL can be recovered from the file alone
        with open(tmp, "wb") as f:
            f.write(b"<!-- URL: " + key.encode("utf-8") + b" -->\n")
            f.write(html_bytes)
        os.replace(tmp, path)

        # Append to the manifest (best-effort; slight duplicates across processes are harmless)
        os.makedirs(_OUT_DIR, exist_ok=True)
        with open(_MANIFEST, "a", encoding="utf-8") as mf:
            mf.write(f"{key}\t{path}\n")

    return path

_NON_HTML_EXTS = (
    ".css",".js",".bmp",".gif",".jpg",".jpeg",".ico",".png",".tif",".tiff",".psp",".h5",".java",".seq",
    ".mid",".mp2",".mp3",".mp4",".wav",".avi",".mov",".mpeg",".ram",".m4v",".mkv",".ogg",".ogv",".nb",
    ".pdf",".ps",".eps",".tex",".ppt",".pptx",".doc",".docx",".xls",".xlsx",".ppsx",".bib",".sdf",".tsv",".conf",
    ".names",".data",".dat",".exe",".bz2",".tar",".msi",".bin",".7z",".psd",".dmg",".iso",".mol",".ismsmi",".war",
    ".epub",".dll",".cnf",".tgz",".sha1",".thmx",".mso",".arff",".rtf",".jar",".csv", ".sql",".target",".fpkm",".class",
    ".rm",".smil",".wmv",".swf",".wma",".zip",".rar",".gz", ".ics", ".mpg", ".txt", ".apk", ".img", ".odp", ".ipynb",
    ".xml",".sh", ".svg"
)

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

_ALLOWED_SUFFIXES = (
    "ics.uci.edu",
    "cs.uci.edu",
    "informatics.uci.edu",
    "stat.uci.edu",
)

_TRAP_KEYWORDS = {
    # feeds / apis / sitemaps
    "wp-json", "xmlrpc", "sitemap", "feed", "rss", "atom", "format=xml",

    # media/file browsers and attachments (parameter-driven)
    "do=media", "tab=files", "media=", "image=", "file=", "attachment=",

    # low-info render modes/login
    "format=pdf", "print=", "view=print", "preview=", "login", "register",

    # misc noise / comment reply & social share
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

def scraper(url, resp):
    links = extract_next_links(url, resp)
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
    # 1) Common 404/error CSS hooks
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
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content
    result = []

    # 1) Basic guards: must have a successful HTTP 200 HTML response
    if resp is None or resp.status != 200 or resp.raw_response is None:
        return result

    headers = getattr(resp.raw_response, "headers", {}) or {}
    ctype = (headers.get("Content-Type", "") or "").lower()
    if "text/html" not in ctype:
        return result

    content = getattr(resp.raw_response, "content", b"") or b""
    if not content:
        return result

    # Skip true XML feeds and sitemaps (even though they can be served as text/html sometimes)
    head = (content[:512] or b"").lstrip().lower()
    if head.startswith(b"<?xml") or head.startswith(b"<rss") or head.startswith(b"<feed") \
       or b"<urlset" in head or b"<sitemapindex" in head:
        return result

    # 2) Parse HTML safely (assignment requires lxml)
    try:
        soup = BeautifulSoup(content, "lxml")
    except Exception:
        # If lxml isn't installed at runtime, parsing will fail here.
        return result

    # Remove non-content elements before computing stats and text
    for t in soup(['script', 'style', 'noscript', 'svg']):
        t.decompose()

    # 3) Page-quality filtering
    word_count, a_count, title_norm = _page_stats(soup)
    if _looks_like_error_200_from_stats(soup, word_count, a_count, title_norm):
        return result
    if _looks_like_login_wall(soup):
        return result

    # 4) Duplicate detection
    #    a) exact dupes by checksum of raw bytes
    chk = similarity.checksum_bytes(content)
    if not similarity.seen_exact(chk):
        similarity.remember_exact(chk)
    #    b) near dupes by Jaccard over 3-gram fingerprints (text only)
    page_text = soup.get_text(" ", strip=True)
    doc_id = _norm_url_no_fragment(resp.url or url)
    nd = similarity.is_near_duplicate_of(page_text, tau=similarity.NEAR_DUP_TAU)
    skip_save = bool(nd)  # skip saving if near-duplicate of an already-seen page
    # Index this page so *future* pages can be compared to it
    similarity.add_document(doc_id, page_text)

    # 5) Save page if not near-duplicate (we still always return outlinks)
    try:
        if not skip_save:
            _safe_save_page(resp.url or url, content)
    except Exception:
        pass

    # 6) Extract and normalize links
    base = resp.url or url
    seen = set()
    for a in soup.find_all("a", href=True):
        href = a.get("href", "").strip()
        # Ignore javascript/mailto/tel/data fragments, empty, or obviously broken hrefs
        if not href or href.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
            continue
        if any(c in href for c in ["[", "]", "{", "}", "|", "\\"]):
            continue
        try:
            abs_url = urljoin(base, href)
        except Exception:
            continue
        abs_url, _ = urldefrag(abs_url)   # remove #fragment
        if abs_url and abs_url not in seen:
            seen.add(abs_url)
            result.append(abs_url)

    return result

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False
            
        host = (parsed.hostname or "").rstrip(".").lower()
        # Only *.ics|cs|informatics|stat.uci.edu (and subdomains)
        if not any(host == d or host.endswith("." + d) for d in _ALLOWED_SUFFIXES):
            return False

        path = (parsed.path or "").lower().rstrip("/")
        query = (parsed.query or "").lower()
        pq = f"{path}?{query}"

        # Very large non-HTML files (low information value)
        if path.endswith(_NON_HTML_EXTS):
            return False

        # Calendar / events day-week-month views or explicit dates
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

        # DokuWiki/RM media browsers and file tabs (tons of parameter permutations)
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

        # Query directly pointing to a file via parameter
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

        # Feeds/APIs/sitemaps/etc. (low textual value for our goal)
        if any(k in pq for k in _TRAP_KEYWORDS):
            return False

        # Excessive pagination/offset -> likely infinite listing
        if re.search(r"(^|[?&])(page|paged|pagenum|start|offset)=\d{3,}", query):
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

        return True

    except Exception:
        # Be safe on any parsing error

        return False







