# utils/similarity.py
# Minimal dup / near-dup detection (no external libs).
from __future__ import annotations
import re, hashlib, threading
from typing import Iterable, Set, Dict, Tuple, List

# --- Tunables ---------------------------------------------------------------
N_GRAM: int = 3              # word shingle size (3–5 are common)
SAMPLE_MOD: int = 8          # winnowing: keep hashes with h % SAMPLE_MOD == 0
NEAR_DUP_TAU: float = 0.90   # Jaccard >= tau => near-duplicate

# --- Thread-safe in-memory indexes -----------------------------------------
_LOCK = threading.Lock()

# For exact duplicates (content checksums)
_SEEN_CHECKSUMS: Set[str] = set()

# For near-duplicates (fingerprints + inverted index)
_DOC_FPS: Dict[str, Set[int]] = {}         # doc_id -> set(fingerprint ints)
_FP_TO_DOCS: Dict[int, Set[str]] = {}      # fp -> doc_ids containing that fp


# ----------------------------- helpers --------------------------------------
_WORD_RE = re.compile(r"[a-z0-9]+")

def _words(text: str) -> List[str]:
    text = text.lower()
    return _WORD_RE.findall(text)

def _ngrams(tokens: List[str], n: int) -> Iterable[Tuple[str, ...]]:
    if n <= 0 or len(tokens) < n:
        return ()
    return (tuple(tokens[i:i+n]) for i in range(len(tokens) - n + 1))

def _hash_ngram(g: Tuple[str, ...]) -> int:
    # 64-bit stable hash from sha1
    h = hashlib.sha1((" ".join(g)).encode("utf-8")).digest()
    # take first 8 bytes as unsigned 64-bit integer
    return int.from_bytes(h[:8], "big", signed=False)

def fingerprint(text: str, n: int = N_GRAM, mod: int = SAMPLE_MOD) -> Set[int]:
    """Compute a compact set of fingerprints using n-grams and modular sampling."""
    toks = _words(text)
    fps: Set[int] = set()
    for g in _ngrams(toks, n):
        hv = _hash_ngram(g)
        if mod <= 1 or (hv % mod) == 0:
            fps.add(hv)
    return fps

def jaccard(a: Set[int], b: Set[int]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union


# ----------------------------- exact dups -----------------------------------
def checksum_bytes(content: bytes) -> str:
    """Exact content checksum (sha1 hex)."""
    return hashlib.sha1(content).hexdigest()

def seen_exact(checksum_hex: str) -> bool:
    with _LOCK:
        return checksum_hex in _SEEN_CHECKSUMS

def remember_exact(checksum_hex: str) -> None:
    with _LOCK:
        _SEEN_CHECKSUMS.add(checksum_hex)


# --------------------------- near-dup index ---------------------------------
def add_document(doc_id: str, text: str) -> Set[int]:
    """Index the document's fingerprints (idempotent). Returns the set stored."""
    fps = fingerprint(text)
    with _LOCK:
        if doc_id in _DOC_FPS:
            return _DOC_FPS[doc_id]
        _DOC_FPS[doc_id] = fps
        for f in fps:
            _FP_TO_DOCS.setdefault(f, set()).add(doc_id)
    return fps

def best_matches_for(text: str, top_k: int = 10) -> List[Tuple[str, float]]:
    """Return top_k (doc_id, jaccard) scored against already indexed docs."""
    fps_q = fingerprint(text)
    seen: Set[str] = set()
    scores: List[Tuple[str, float]] = []
    with _LOCK:
        # candidates share at least one fingerprint
        for f in fps_q:
            for d in _FP_TO_DOCS.get(f, ()):
                if d in seen:
                    continue
                seen.add(d)
                sim = jaccard(fps_q, _DOC_FPS.get(d, set()))
                scores.append((d, sim))
    scores.sort(key=lambda x: x[1], reverse=True)
    return scores[:top_k]

def is_near_duplicate_of(text: str, tau: float = NEAR_DUP_TAU):
    """Return (doc_id, sim) of the first existing doc whose similarity >= tau, else None."""
    for d, s in best_matches_for(text, top_k=20):
        if s >= tau:
            return d, s
    return None
