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
    "calendar", "ical", "wp-json", "xmlrpc", "attachment",
    "replytocom", "format=pdf", "feed", "rss", "share=",
    "sort=", "action="
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

    # # Only handle HTML documents
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
        if not href or href.startswith(("javascript:", "mailto:", "tel:")):
            continue

        # Normalize: make absolute and remove URL fragment
        abs_url = urljoin(base, href)
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
        query = (parsed.query or "")

        # Very long URL/query → likely trap
        if len(url) > 2048 or len(query) > 600:
            return False

        # Repeating path segments like /2020/01/2020/01/2020/01/
        segs = [s for s in path.split("/") if s]
        if segs and any(segs.count(s) >= 3 for s in set(segs)):
            return False

        # Calendars/feeds/attachments/etc.
        pq = f"{path}?{query}"
        if any(k in pq for k in _TRAP_KEYWORDS):
            return False
        
        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

    except TypeError:
        print ("TypeError for ", parsed)
        raise

