import re
import hashlib
import threading
from typing import Iterable, Set, Dict, Tuple, Optional, List

# Tunables
N_GRAM       = 3        # shingle size (words)
SAMPLE_MOD   = 8        # keep h where h % SAMPLE_MOD == 0 (subsampling)
NEAR_DUP_TAU = 0.90     # Jaccard threshold

# In-memory state (protected by a single lock)
_LOCK       = threading.RLock()
_DOC_FPS: Dict[str, Set[int]] = {}   # doc_id -> fingerprint set
_SEEN_CKSUM: Set[str] = set()        # exact-dedup checksums (hex string)

# Tokenization / n-grams
_WORD_RE = re.compile(r"[A-Za-z0-9]+")

def _words(text: str) -> Iterable[str]:
    for m in _WORD_RE.finditer(text.lower()):
        yield m.group(0)

def _ngrams(tokens: Iterable[str], n: int) -> Iterable[Tuple[str, ...]]:
    buf: List[str] = []
    for t in tokens:
        buf.append(t)
        if len(buf) >= n:
            yield tuple(buf[-n:])

def _hash_ngram(ng: Tuple[str, ...]) -> int:
    # fast 64-bit hash of the n-gram
    h = hashlib.blake2b((" ".join(ng)).encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(h, "big", signed=False)

# Fingerprints
def fingerprints_from_text(text: str,
                           n_gram: int = N_GRAM,
                           sample_mod: int = SAMPLE_MOD) -> Set[int]:
    toks = list(_words(text))
    fps: Set[int] = set()
    for ng in _ngrams(toks, n_gram):
        h = _hash_ngram(ng)
        if sample_mod <= 1 or (h % sample_mod) == 0:
            fps.add(h)
    return fps

def jaccard(a: Set[int], b: Set[int]) -> float:
    if not a and not b:  # both empty
        return 1.0
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0

# Exact duplicates
def checksum_bytes(b: bytes) -> str:
    return hashlib.sha1(b).hexdigest()  # simple checksum for exact dup

def seen_exact(hex_digest: str) -> bool:
    with _LOCK:
        return hex_digest in _SEEN_CKSUM

def remember_exact(hex_digest: str) -> None:
    with _LOCK:
        _SEEN_CKSUM.add(hex_digest)

# Index & search
def add_document(doc_id: str, text: str) -> Set[int]:
    """Compute and store fingerprints for doc_id. Returns the set."""
    fps = fingerprints_from_text(text)
    with _LOCK:
        _DOC_FPS[doc_id] = fps
    return fps

def best_matches_for(text: str, top_k: int = 10) -> List[Tuple[str, float]]:
    """Return up to top_k (doc_id, similarity) against currently indexed docs."""
    fps_q = fingerprints_from_text(text)
    with _LOCK:
        items = list(_DOC_FPS.items())      # snapshot to avoid mutation during iteration
    scores: List[Tuple[str, float]] = []
    for d, fps in items:
        scores.append((d, jaccard(fps_q, fps)))
    scores.sort(key=lambda x: x[1], reverse=True)
    return scores[:top_k]

def is_near_duplicate_of(text: str, tau: float = NEAR_DUP_TAU) -> Optional[Tuple[str, float]]:
    """Return (doc_id, sim) if any indexed doc meets the threshold; else None."""
    for d, s in best_matches_for(text, top_k=10):
        if s >= tau:
            return d, s
    return None
