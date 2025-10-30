import re
from urllib.parse import urlparse, urljoin, urldefrag
from bs4 import BeautifulSoup

_ALLOWED_SUFFIXES = (
    "ics.uci.edu",
    "cs.uci.edu",
    "informatics.uci.edu",
    "stat.uci.edu",
)

#trap guards
_TRAP_KEYWORDS = {
    # feeds / apis / sitemaps
    "wp-json", "xmlrpc", "sitemap", "feed", "rss", "atom", "format=xml",
    "ical", "ics",

    # media/file browsers and attachments (parameter-driven)
    "do=media", "tab=files", "media=", "image=", "file=", "attachment=",

    # low-info render modes
    "format=pdf", "print=", "view=print", "preview=",

    # misc noise / comment reply & social share
    "replytocom", "share="
}

def scraper(url, resp):
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
    result = []

    # skip if no response, non-200 status, or no raw response object.
    if resp is None or resp.status != 200 or resp.raw_response is None:
        return result

    # Only handle HTML documents
    headers = getattr(resp.raw_response, "headers", {}) or {}
    ctype = headers.get("Content-Type", "")
    if "text/html" not in ctype.lower():
        return result

    # Get the raw page bytes; if empty, nothing to parse.
    content = getattr(resp.raw_response, "content", b"") or b""
    if not content:
        return result

    # Parse HTML with BeautifulSoup (lxml parser is fast and tolerant).
    try:
        soup = BeautifulSoup(content, "lxml")
    except Exception:
        return result

    # Use the final resolved URL (after redirects) as the base for resolving relative links.
    base = resp.url or url
    seen = set()

    # Extract all <a> elements that have an href attribute.
    for a in soup.find_all("a", href=True):
        href = a.get("href", "").strip()

        # Skip empty hrefs and non-HTTP pseudo-schemes.
        if not href or href.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
            continue
        if any(c in href for c in ["[", "]", " ", "{", "}", "|", "\\"]):
            continue

        # Normalize: make absolute and remove URL fragment
        try:
            abs_url = urljoin(base, href)
        except Exception:
            continue
        abs_url, _ = urldefrag(abs_url)

        # Deduplicate within this page, then add to the result list.
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
            
        host = (parsed.netloc or "").lower()
        # Only *.ics|cs|informatics|stat.uci.edu (and subdomains)
        if not any(host == d or host.endswith("." + d) for d in _ALLOWED_SUFFIXES):
            return False

        path = (parsed.path or "").lower()
        query = (parsed.query or "").lower()

        # Obvious junk in host (e.g., [YOUR_IP])
        if "[" in host or "]" in host:
            return False

        # Very large non-HTML files (low information value)
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

        # Calendar / events day-week-month views or explicit dates
        if "/events/" in path or "/event/" in path or "/calendar" in path:
            if ("/day/" in path or "/week/" in path or "/month/" in path
                    or re.search(r"\d{4}[-/]\d{1,2}[-/]\d{1,2}", path)):
                return False

        # DokuWiki/RM media browsers and file tabs (tons of parameter permutations)
        if "doku.php" in path and ("do=media" in query or "tab=files" in query):
            return False

        # Query directly pointing to a file via parameter
        if re.search(
                r"(image|file|media|attachment)=[^&]+\.(png|jpe?g|gif|svg|pdf|zip|rar|gz|mp4|mp3|avi|mov|pptx?|docx?|xlsx?)",
                query):
            return False

        # Feeds/APIs/sitemaps/etc. (low textual value for our goal)
        if any(k in f"{path}?{query}" for k in (
                "wp-json", "xmlrpc", "sitemap", "feed", "rss", "atom", "format=pdf"
        )):
            return False

        # Excessive pagination/offset -> likely infinite listing
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

        pq = f"{path}?{query}"
        if any(k in pq for k in _TRAP_KEYWORDS):
            return False
        return True

    except Exception:
        # Be safe on any parsing error
        return False