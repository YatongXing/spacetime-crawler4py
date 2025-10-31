import re
from urllib.parse import urlparse, urljoin, urldefrag

def scraper(url, resp):
    """
    Return a list of absolute, defragmented, valid links found in 'resp'.
    """
    # If request failed or we didn't get a page back, don't emit links.
    if resp is None or getattr(resp, "status", None) != 200 or resp.raw_response is None:
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
        # Skip javascript/mailto/telephone & empty refs
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue

        # Resolve relative -> absolute and drop fragments
        abs_url = urljoin(base, href)
        abs_url, _frag = urldefrag(abs_url)

        out.add(abs_url)

    return list(out)

# Policy
_ALLOWED_SUFFIXES = (
    #".ics.uci.edu",
    #//".cs.uci.edu",
    ".informatics.uci.edu",
    #".stat.uci.edu",
)

# Disallow common non-HTML/resource extensions (starter list + a few extras)
_NON_HTML_RE = re.compile(
    r""".*\.(?:css|js|bmp|gif|jpe?g|ico
        |png|tiff?|mid|mp2|mp3|mp4|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf
        |ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names|data|dat|exe|bz2|tar|msi|bin|7z
        |psd|dmg|iso|epub|dll|cnf|tgz|sha1|thmx|mso|arff|rtf|jar|csv
        |rm|smil|wmv|swf|wma|zip|rar|gz)$
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Paths that often create traps or have little value for text search
_BAD_PATH_PARTS = (
    "calendar", "cal", "wp-json", "feed", "feeds", "atom", "rss",
    "login", "logout", "signin", "signup", "register", "account",
    "cart", "checkout", "wp-admin", "admin", "cgi-bin", "session",
    "share", "print", "preview", "format=pdf",
    "action=", "do=", "download", "wp-content", "plugins",
)

def _allowed_domain(hostname: str) -> bool:
    if not hostname:
        return False
    # Accept the four exact domains and any of their subdomains
    return any(hostname.endswith(suf) or hostname == suf[1:] for suf in _ALLOWED_SUFFIXES)

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
        
        if parsed.scheme not in set(["http", "https"]):
            return False

        if not _allowed_domain(parsed.hostname):
            return False

        # Disallow queries/params (search, calendars, infinite traps)
        if parsed.query or parsed.params:
            return False

        # depth limit
        if _too_deep(parsed.path):
            return False

        # Block repeated/number-heavy paths that often explode
        if _has_repetition(parsed.path):
            return False

        # Block resource files
        if _NON_HTML_RE.match(parsed.path.lower()):
            return False

        # Common trap/low-value path pieces
        low = parsed.path.lower()
        if any(bad in low for bad in _BAD_PATH_PARTS):
            return False

        # Defensive total length cap
        if len(url) > 200:
            return False

        return True

        """
        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())
        """

    except TypeError:
        print ("TypeError for ", parsed)
        raise


