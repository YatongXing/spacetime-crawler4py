import re
from urllib.parse import urlparse, urljoin, urldefrag

def scraper(url, resp):
    """
    Return a list of absolute, defragmented, valid links found in 'resp'.
    """
    # If request failed or we didn't get a page back, don't emit links.
    if resp is None or getattr(resp, "status", None) != 200 or resp.raw_response is None:
        return []

    # Content filter: only crawl HTML pages with meaningful visible text
    hdrs = getattr(resp.raw_response, "headers", {}) or {}
    ctype = str(hdrs.get("Content-Type", "")).lower()
    if "text/html" not in ctype:
        return []

    body = getattr(resp.raw_response, "content", b"")
    # Size guard: avoid huge “HTML” responses
    if not body or len(body) > 5_000_000:  # ~5 MB
        return []

    try:
        html = body.decode("utf-8", errors="ignore")
        # remove script/style, then strip tags to approximate visible text
        clean = re.sub(r"(?is)<(script|style).*?>.*?</\1>", "", html)
        visible = re.sub(r"(?is)<[^>]+>", " ", clean)
        words = len(visible.split())
        # require some real text and a minimal text/markup ratio
        if words < 120 or (len(visible) / max(1, len(html))) < 0.05:
            return []
    except Exception:
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
    try:
        # Decode bytes -> str defensively
        html = resp.raw_response.content.decode("utf-8", errors="ignore")
    except Exception:
        return []

    # Very simple href extractor (good enough for first run)
    hrefs = re.findall(r'''(?i)\bhref\s*=\s*["']([^"']+)["']''', html)

    out = set()
    base = resp.url or url
    for href in hrefs:
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        abs_url = urljoin(base, href)
        abs_url, _ = urldefrag(abs_url)
        out.add(abs_url)
    return list(out)

# Allowed domains (and subdomains)
_ALLOWED_SUFFIXES = (
    #".ics.uci.edu",
    #".cs.uci.edu",
    ".informatics.uci.edu",
    #".stat.uci.edu",
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

        # Disallow any query/params (kills ?ical=1, ?tribe_event, etc.)
        if parsed.query or parsed.params:
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
        if _has_repetition(parsed.path):
            return False
        if _NON_HTML_RE.match(low):
            return False
        if any(bad in low for bad in _BAD_PATH_PARTS):
            return False

        if len(url) > 200:
            return False

        return True

    except (TypeError, ValueError):
        return False





