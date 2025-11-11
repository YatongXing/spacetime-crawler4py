import argparse
import csv
import os
import re
import sys
import json
from collections import Counter, defaultdict
from urllib.parse import urlsplit, urlunsplit

from bs4 import BeautifulSoup

# Stopwords (fallback)
DEFAULT_STOPWORDS = {
    "a","about","above","after","again","against","all","am","an","and","any","are","as","at",
    "be","because","been","before","being","below","between","both","but","by",
    "can","cannot","could",
    "did","do","does","doing","down","during",
    "each",
    "few","for","from","further",
    "had","has","have","having","he","her","here","hers","herself","him","himself","his","how",
    "i","if","in","into","is","it","its","itself",
    "just",
    "me","more","most","my","myself",
    "no","nor","not",
    "of","off","on","once","only","or","other","our","ours","ourselves","out","over","own",
    "same","she","should","so","some","such",
    "than","that","the","their","theirs","them","themselves","then","there","these","they",
    "this","those","through","to","too",
    "under","until","up",
    "very",
    "was","we","were","what","when","where","which","while","who","whom","why","with",
    "you","your","yours","yourself","yourselves",
}

# Tokenization
# Ignore single-letter tokens to prevent 's', 'e', ... from dominating counts
WORD_RE = re.compile(r"[a-z]{2,}")

# Obvious filename/extension-like noise words we don't want in top list
NOISE_WORDS = {
    "html","htm","pdf","jpg","jpeg","png","gif","svg","css","js","xml","json",
    "zip","rar","gz","tar","bz2","ppt","pptx","doc","docx","xls","xlsx","csv",
    "php","jsp"
}

def norm_url_strip_fragment(u: str) -> str:
    """Normalize a URL by stripping only the fragment (#...)."""
    try:
        p = urlsplit(u)
        return urlunsplit((p.scheme, p.netloc, p.path, p.query, ""))
    except Exception:
        return u

def load_stopwords(path: str | None) -> set[str]:
    if not path:
        return set(DEFAULT_STOPWORDS)
    sw = set()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.strip().lower()
            if w:
                sw.add(w)
    return sw

def extract_text(html_bytes: bytes) -> str:
    """Parse HTML and return visible text."""
    soup = BeautifulSoup(html_bytes, "lxml")

    # Strip obvious non-content nodes
    for t in soup(["script", "style", "noscript", "svg"]):
        t.decompose()

    # Optionally reduce chrome noise
    for t in soup.select('[hidden], [aria-hidden="true"], [style*="display:none"], [style*="visibility:hidden"]'):
        t.decompose()
    for tag in ("nav", "footer", "header"):
        for t in soup.select(tag):
            t.decompose()

    return soup.get_text(" ", strip=True)

def tokenize_words(text: str) -> list[str]:
    """Lowercase, normalize possessives, and split into words (>=2 letters)."""
    s = text.lower()
    # normalize possessives "university's" -> "university"
    s = re.sub(r"\b([a-z]+)[’']s\b", r"\1", s)
    return WORD_RE.findall(s)

def read_manifest(manifest_path: str) -> list[tuple[str, str]]:
    """Read URL<tab>local_html_path pairs."""
    pairs = []
    with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
        sample = f.read(4096); f.seek(0)
        dialect = csv.excel_tab if ("\t" in sample) else csv.excel
        reader = csv.reader(f, dialect=dialect)
        for row in reader:
            if len(row) >= 2:
                url, path = row[0].strip(), row[1].strip()
                if url and path:
                    pairs.append((url, path))
    return pairs

def scan_pages_dir(pages_dir: str) -> list[tuple[str, str]]:
    """
    Recover (URL, path) pairs by reading <!-- URL: ... --> from saved HTML files.
    """
    out = []
    url_hint_re = re.compile(r"<!--\s*url\s*:\s*(.*?)\s*-->", re.I)
    for root, _, files in os.walk(pages_dir):
        for name in files:
            if not name.lower().endswith((".html", ".htm")):
                continue
            path = os.path.join(root, name)
            url = None
            try:
                with open(path, "rb") as f:
                    head = f.read(8192).decode("utf-8", errors="ignore")
                m = url_hint_re.search(head)
                if m:
                    url = m.group(1).strip()
            except Exception:
                pass
            if url:
                out.append((url, path))
    return out

def read_urls_only(urls_file: str) -> list[str]:
    urls = []
    with open(urls_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            u = line.strip()
            if u:
                urls.append(u)
    return urls

# Parse URLs out of worker logs (best-effort)
LOG_URL_RE = re.compile(
    r"\b(?:Downloaded|Fetching|Fetched|Crawling|d)\s+(https?://[^\s,)\]]+)",
    re.I
)
def read_worker_log(paths: list[str]) -> list[str]:
    urls = []
    for p in paths:
        if not os.path.exists(p):
            continue
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                m = LOG_URL_RE.search(line)
                if m:
                    urls.append(m.group(1))
    return urls

def main():
    ap = argparse.ArgumentParser(description="Analyze crawled pages for CS121 A2 metrics.")
    ap.add_argument("--manifest", help="TSV/CSV: URL<TAB>local_html_path")
    ap.add_argument("--pages_dir", help="Directory with saved HTML files")
    ap.add_argument("--urls_only", help="File with one URL per line (no content)")
    ap.add_argument("--worker_log", action="append", help="Path to worker log (can be used multiple times)")
    ap.add_argument("--stopwords", help="Stopwords file (one per line)")
    ap.add_argument("--topk", type=int, default=50, help="Top-K most common words (default 50)")
    ap.add_argument("--report", help="Write JSON report to this path")
    ap.add_argument("--verbose", action="store_true", help="Print progress every 200 pages")
    args = ap.parse_args()

    stopwords = load_stopwords(args.stopwords)

    url_path_pairs: list[tuple[str, str]] = []
    urls_extra: list[str] = []

    if args.manifest and os.path.exists(args.manifest):
        url_path_pairs.extend(read_manifest(args.manifest))

    if args.pages_dir and os.path.isdir(args.pages_dir):
        url_path_pairs.extend(scan_pages_dir(args.pages_dir))

    if args.urls_only and os.path.exists(args.urls_only):
        urls_extra.extend(read_urls_only(args.urls_only))

    if args.worker_log:
        urls_extra.extend(read_worker_log(args.worker_log))

    if not url_path_pairs and not urls_extra:
        print("No input found. Provide at least one of --manifest / --pages_dir / --urls_only / --worker_log.", file=sys.stderr)
        sys.exit(2)

    # Unique URLs (strip fragment only)
    unique_urls: set[str] = set()
    for u, _ in url_path_pairs:
        unique_urls.add(norm_url_strip_fragment(u))
    for u in urls_extra:
        unique_urls.add(norm_url_strip_fragment(u))

    # Subdomain counts under uci.edu
    subdomain_counts: defaultdict[str, int] = defaultdict(int)
    for u in unique_urls:
        try:
            host = urlsplit(u).hostname or ""
        except Exception:
            host = ""
        if host.endswith(".uci.edu"):
            subdomain_counts[host] += 1

    # Longest page & top words (only if HTML files exist)
    word_counter = Counter()
    longest_page_url = None
    longest_page_wordcount = -1

    total_pages = len(url_path_pairs)
    if args.verbose and total_pages:
        print(f"Scanning {total_pages} HTML files...", flush=True)

    for i, (url, path) in enumerate(url_path_pairs, 1):
        if not os.path.exists(path):
            continue
        try:
            with open(path, "rb") as f:
                html = f.read()
        except Exception:
            continue

        text = extract_text(html)
        if not text:
            continue

        tokens = tokenize_words(text)

        # Heuristic: skip pages that look like pure index/noise (almost no real tokens)
        if len(tokens) < 20:
            continue

        # Longest page: count all tokens we keep (>=2 letters), no stopword removal here
        total_words = len(tokens)
        if total_words > longest_page_wordcount:
            longest_page_wordcount = total_words
            longest_page_url = url

        # Top words: remove stopwords and common noise tokens
        filtered = (w for w in tokens if w not in stopwords and w not in NOISE_WORDS)
        word_counter.update(filtered)

        if args.verbose and i % 200 == 0:
            print(f"[progress] processed {i}/{total_pages} pages...", flush=True)

    most_common = word_counter.most_common(args.topk)

    # ---- Output ----
    print("=== Crawl Analysis Report ===")
    print(f"Unique pages (URL dedup, ignoring fragments): {len(unique_urls)}")
    if longest_page_url is not None and longest_page_wordcount >= 0:
        print(f"Longest page by word count: {longest_page_url}")
        print(f"Word count (no HTML markup): {longest_page_wordcount}")
    else:
        print("Longest page by word count: N/A (no HTML files provided)")
    print(f"\nTop {args.topk} most common words (stopwords removed):")
    if most_common:
        for w, c in most_common:
            print(f"{w}\t{c}")
    else:
        print("N/A (no HTML files provided)")

    print("\nSubdomains under uci.edu (alphabetical):")
    for sub in sorted(subdomain_counts.keys()):
        print(f"{sub}, {subdomain_counts[sub]}")

    if args.report:
        report = {
            "unique_pages": len(unique_urls),
            "longest_page": {
                "url": longest_page_url,
                "word_count": longest_page_wordcount,
            },
            "top_words": most_common,
            "subdomains": sorted(((k, v) for k, v in subdomain_counts.items()), key=lambda x: x[0]),
        }
        with open(args.report, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(f"\nReport written to: {args.report}")

if __name__ == "__main__":
    main()
