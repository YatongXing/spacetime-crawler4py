# utils/similarity.py
# Minimal duplicate & near-duplicate detector for text pages.
# Implements:
#   - exact dupes by checksum of raw bytes
#   - near dupes by Jaccard over hashed 3-gram shingles

from typing import Iterable, Set, Tuple, Optional

# --- Tunables ---------------------------------------------------------------
NGRAM_N: int = 3                 # length of contiguous word n-grams
NEAR_DUP_TAU: float = 0.9        # Jaccard threshold for near-duplicate
FINGERPRINT_MOD: int = 4         # keep n-grams whose hash % MOD == 0
# ---------------------------------------------------------------------------

# Exact duplicate memory (checksums of raw bytes)
_exact_seen: Set[int] = set()

# Fingerprints per document id: doc_id -> set of int hashes
_fingerprints = {}  # type: dict[str, Set[int]]

def checksum_bytes(b: bytes) -> int:
    """Fast exact-dupe checksum (sum of bytes). Collisions are possible but rare for our use."""
    # (Could use CRC32/MD5 if allowed; assignment says “from scratch”, so keep it simple.)
    return sum(b) & 0xFFFFFFFF

def seen_exact(chk: int) -> bool:
    """Return True if this checksum has been seen before."""
    return chk in _exact_seen

def remember_exact(chk: int) -> None:
    """Record an exact-dupe checksum."""
    _exact_seen.add(chk)

# -------- Near-duplicate helpers -------------------------------------------

def _normalize(text: str) -> list[str]:
    """Lowercase and split on whitespace; drop obvious punctuation-only tokens."""
    # Keep it simple—slides only need words, no stemming/stopwords.
    import re
    tokens = re.findall(r"[A-Za-z0-9]+", text.lower())
    return tokens

def _ngrams(tokens: list[str], n: int) -> Iterable[tuple[str, ...]]:
    for i in range(len(tokens) - n + 1):
        yield tuple(tokens[i:i+n])

def _fingerprint(text: str) -> Set[int]:
    """Return a compact set of hashed n-grams (min-hash style sampling with modulo)."""
    toks = _normalize(text)
    fps: Set[int] = set()
    for g in _ngrams(toks, NGRAM_N):
        h = hash(g)
        # Select a subset to keep representation compact (like winnowing).
        if h % FINGERPRINT_MOD == 0:
            fps.add(h)
    return fps

def add_document(doc_id: str, text: str) -> Set[int]:
    """Compute & store fingerprints for a document id. Returns the set."""
    fps = _fingerprint(text)
    _fingerprints[doc_id] = fps
    return fps

def jaccard(a: Set[int], b: Set[int]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    inter = len(a & b)
    uni = len(a | b)
    return inter / uni if uni else 0.0

def is_near_duplicate_of(text: str, tau: float = NEAR_DUP_TAU) -> Optional[Tuple[str, float]]:
    """Compare text against all stored docs; return (doc_id, sim) if any sim >= tau, else None."""
    cand = _fingerprint(text)
    best_id, best_sim = None, 0.0
    for doc_id, fps in _fingerprints.items():
        sim = jaccard(cand, fps)
        if sim > best_sim:
            best_id, best_sim = doc_id, sim
    if best_id is not None and best_sim >= tau:
        return best_id, best_sim
    return None
