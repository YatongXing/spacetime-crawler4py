import re
from urllib.parse import urlparse, urljoin, urldefrag, parse_qsl, urlencode

# Soft-404 detection
import hashlib

_SOFT404_HOST_PATTERNS = {
    # ICS Statistics site returns 200 with this template
    "stat.ics.uci.edu": [
        r"Whoops!\s*We are having trouble locating your page",
        r"\bPage not found\b",
        r"\bSearch ICS\b",
    ],
    "www.stat.uci.edu": [
        r"Whoops!\s*We are having trouble locating your page",
        r"\bPage not found\b",
        r"\bSearch ICS\b",
    ],
    # Generic campus/CMS patterns
    "*": [
        r"\b(page|file|content)\s+not\s+found\b",
        r"\b404\b",
        r"\bthe page you are looking for (does not exist|cannot be found)\b",
        r"\bno results\b",
        r"\bThe requested URL was not found on this server\b",
    ],
}

_ERROR_TEMPLATE_FPS = {}  # host -> set(md5 fingerprints)


def _html_text(resp) -> str:
    try:
        return resp.raw_response.content.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _html_title(html: str) -> str:
    m = re.search(r"(?is)<title[^>]*>(.*?)</title>", html)
    return re.sub(r"\s+", " ", m.group(1)).strip() if m else ""


def _fingerprint_visible_text(html: str) -> str:
    # strip scripts/styles/tags; normalize
    text = re.sub(r"(?is)<script.*?</script>", " ", html)
    text = re.sub(r"(?is)<style.*?</style>", " ", text)
    text = re.sub(r"(?is)<[^>]+>", " ", text)
    text = re.sub(r"https?://\S+", " ", text)
    text = re.sub(r"\d+", " ", text)
    text = re.sub(r"\s+", " ", text).strip().lower()
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def is_soft_404(url: str, resp) -> (bool, str):
    """
    Heuristic to catch 200 pages that are actually error templates.
    Returns (True/False, reason).
    """
    if resp is None or resp.raw_response is None or getattr(resp, "status", None) != 200:
        return False, ""

    rr = resp.raw_response
    host = urlparse(url).netloc.lower()

    # Respect X-Robots-Tag: noindex
    try:
        xrt = rr.headers.get("X-Robots-Tag", "")
        if "noindex" in xrt.lower():
            return True, "X-Robots-Tag: noindex"
    except Exception:
        pass

    html = _html_text(resp)
    if not html:
        return True, "empty body"

    # Extremely tiny bodies are likely error pages
    if len(html) < 500:
        return True, f"tiny body ({len(html)} bytes)"

    title = _html_title(html).lower()
    if any(t in title for t in ("404", "not found", "page not found", "error")):
        return True, f'404-like title "{title}"'

    pats = []
    # host-specific patterns
    for h, arr in _SOFT404_HOST_PATTERNS.items():
        if h != "*" and h in host:
            pats.extend(arr)
    # generic fallbacks
    pats.extend(_SOFT404_HOST_PATTERNS["*"])

    for pat in pats:
        if re.search(pat, html, re.I):
            return True, f"matched soft404 pattern: /{pat}/"

    # Template fingerprint repetition heuristic
    fp = _fingerprint_visible_text(html)
    seen = _ERROR_TEMPLATE_FPS.setdefault(host, set())
    if fp in seen:
        return True, "repeated error-template fingerprint"
    # learn fingerprints when typical 404 cues are present
    if re.search(r"\b(404|not\s+found|whoops)\b", html, re.I):
        seen.add(fp)
        return True, "error-template fingerprint learned"

    return False, ""

def scraper(url, resp):
    """
    Return a list of absolute, defragmented, valid links found in 'resp'.
    """
    # If request failed or we didn't get a page back, don't emit links.
    if resp is None or getattr(resp, "status", None) != 200 or resp.raw_response is None:
        return []

    # Soft-404 guard
    soft, reason = is_soft_404(url, resp)
    if soft:
        # Avoid indexing & link extraction on soft-404s
        try:
            import logging
            logging.getLogger(__name__).info(f"SOFT404 skip: {url} ({reason})")
        except Exception:
            pass
        return []
    
    # Content filter: only crawl HTML pages with meaningful visible text
    hdrs = getattr(resp.raw_response, "headers", {}) or {}
    ctype = str(hdrs.get("Content-Type", "")).lower()
    if "text/html" not in ctype:
        return []

    html = _html_text(resp)
    if not html:
        return []

    # Require some visible text to avoid empty templates
    clean = re.sub(r"(?is)<(script|style).*?>.*?</\1>", "", html)
    visible = re.sub(r"(?is)<[^>]+>", " ", clean)
    words = len(visible.split())
    if words < 120 or (len(visible) / max(1, len(html))) < 0.05:
        return []
    
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]

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
    html = _html_text(resp)
    if not html:
        return []

    # Basic HREF extraction
    hrefs = re.findall(r'''(?i)\bhref\s*=\s*["']([^"']+)["']''', html)

    out = set()
    base = resp.url or url
    for href in hrefs:
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        abs_url = urljoin(base, href)
        abs_url, _ = urldefrag(abs_url) # remove fragments

        # Canonicalize query parameters a bit (drop tracking)
        abs_url = _strip_tracking_params(abs_url)

        out.add(abs_url)
    return list(out)

# URL validation filters
# Allowed domains (and subdomains)
_ALLOWED_SUFFIXES = (
    #".ics.uci.edu",
    #".cs.uci.edu",
    ".informatics.uci.edu",
    ".stat.uci.edu",
)

# Whole hosts to skip (noisy/low-value for this assignment)
_BLOCK_HOSTS = {
    "wics.ics.uci.edu",
    "ngs.ics.uci.edu",
}

# Sections that are almost always media or near-empty wrappers
_LOW_VALUE_SUBPATHS = (
    "/slideshows",              # e.g., /slideshows/
    "/videos",                  # e.g., /videos/ and /videos/video-rick-rolled/
    "/video-",                  # slugs like /video-foo/
    "/media",
    "/gallery",
)

# Calendar / feeds / traps
_BAD_PATH_PARTS = (
    "calendar", "cal", "wp-json", "feed", "feeds", "atom", "rss",
    "login", "logout", "signin", "signup", "register", "account",
    "cart", "checkout", "wp-admin", "admin", "cgi-bin", "session",
    "share", "print", "preview", "format=pdf", "download", "plugins",
)

# Pages with calendar indicators anywhere (path or query)
_CALENDAR_HINTS = ("ical", "tribe")   # common from “The Events Calendar”, ICS feeds

# Non-HTML/resource extensions
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
    # allow exact domain (without the leading dot) and any of its subdomains
    for suf in _ALLOWED_SUFFIXES:
        bare = suf[1:]
        if hostname == bare or hostname.endswith(suf):
            return True
    return False

def _too_deep(path: str, max_depth: int = 3) -> bool:
    # e.g., "/a/b/c" -> depth=3
    depth = len([p for p in path.split("/") if p])
    return depth > max_depth

def _has_repetition(path: str) -> bool:
    # Block obvious repeating segments like /foo/foo/foo or year/month/day cascades
    segs = [s for s in path.split("/") if s]
    if not segs:
        return False
    # 1) repeated same segment 3+ times
    for s in set(segs):
        if segs.count(s) >= 3:
            return True
    # 2) many numeric-only segments (often calendars, archives)
    numeric_segments = sum(ch.isdigit() for seg in segs for ch in seg)
    return numeric_segments >= 10

def _strip_tracking_params(u: str) -> str:
    """
    Remove obvious tracking/query-noise parameters; keep stable ordering.
    """
    parsed = urlparse(u)
    if not parsed.query:
        return u
    bad_keys = {
        "utm_source",
        "utm_medium",
        "utm_campaign",
        "utm_term",
        "utm_content",
        "gclid",
        "fbclid",
        "mc_cid",
        "mc_eid",
        "replytocom",
        "share",
        "ref",
        "source",
        "amp",
        "ts",
        "ns_mchannel",
        "ns_campaign",
    }
    params = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if k.lower() not in bad_keys]
    new_q = urlencode(params, doseq=True)
    return parsed._replace(query=new_q).geturl()

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
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

        # Calendar / tribe hints anywhere in path
        if any(hint in low for hint in _CALENDAR_HINTS):
            return False

        # Drop known low-text sections
        if any(low.startswith(p) or p in low for p in _LOW_VALUE_SUBPATHS):
            return False

        # Depth, repetition, resource types, trap-like path parts
        if _too_deep(parsed.path):
            return False
        # Avoid repeating segments / loops
        if _has_repetition(parsed.path):
            return False
        if _NON_HTML_RE.match(low):
            return False
        if any(bad in low for bad in _BAD_PATH_PARTS):
            return False
        # Disallow super-long URLs (often dynamic traps)
        if len(url) > 200:
            return False

        # Block query-only changes that look like pagination/search noise
        if parsed.query:
            if re.search(r"(page|paged|offset|start|sort|order|filter)=", parsed.query, re.I):
                # Allow a small page index but avoid deep pagination:
                m = re.search(r"(?:page|paged|offset)=(\d+)", parsed.query, re.I)
                if m and int(m.group(1)) > 10:
                    return False

        # --- Block orphaned STAT slugs (migrated old news posts) ---
        if host.endswith("stat.ics.uci.edu"):
            segs = [s for s in parsed.path.split("/") if s]
            # Single path segment AND looks like a news slug (contains hyphens)
            if len(segs) == 1 and "-" in segs[0]:
                return False

        # WordPress "uploads" w/o a real file extension (prevents 404s like
        # /wp-content/uploads/XinTongAbstract4-25-19)
        if re.search(r"/wp-content/uploads/", parsed.path, re.I):
            filename = parsed.path.rsplit("/", 1)[-1]
            allowed_exts = {
                ".pdf",".png",".jpg",".jpeg",".gif",".tif",".tiff",".svg",".webp",
                ".doc",".docx",".ppt",".pptx",".xls",".xlsx",".zip",".rar",".gz",".bz2",".7z"
            }
            if not any(filename.lower().endswith(ext) for ext in allowed_exts):
                return False
        
        return True

    except (TypeError, ValueError):
        return False








