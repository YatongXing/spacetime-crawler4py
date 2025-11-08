# utils/similarity.py
import re
import hashlib
import threading
from typing import Iterable, Set, Dict, Tuple

# ---------------------------
# Parameters (tunable)
# ---------------------------
N_GRAM = 3          # word shingle size, try 3–5
SAMPLE_MOD = 8      # keep hashes with h % SAMPLE_MOD == 0 (larger => fewer kept)
TAU = 0.9           # near-dup threshold for Jaccard similarity

# ---------------------------
# In-memory indexes (thread-safe)
# ---------------------------
_DOC_FPS: Dict[str, Set[int]] = {}      # doc_id -> fingerprint set
_INV: Dict[int, Set[str]] = {}          # fp -> {doc_id,...}  (for candidate gen)
_LOCK = threading.Lock()

_WORD_RE = re.compile(r"[A-Za-z0-9]+")

def _words(text: str) -> Iterable[str]:
    # lowercase, keep alnums only; collapse whitespace by tokenizing
    for m in _WORD_RE.finditer(text.lower()):
        yield m.group(0)

def _ngrams(tokens: Iterable[str], n: int) -> Iterable[Tuple[str, ...]]:
    buf = []
    for t in tokens:
        buf.append(t)
        if len(buf) >= n:
            yield tuple(buf[-n:])

def _hash_ngram(ng: Tuple[str, ...]) -> int:
    # Simple rolling-like hash into 64-bit unsigned range (no libraries)
    # Combine words with a base; avoid Python's non-stable hash().
    h = 1469598103934665603  # FNV offset
    for w in ng:
        for ch in w:
            h ^= ord(ch)
            h = (h * 1099511628211) & ((1 << 64) - 1)
        h ^= 37  # separator tweak between words
        h = (h * 1099511628211) & ((1 << 64) - 1)
    return h

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
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union

def exact_checksum_from_bytes(data: bytes) -> str:
    # Exact-dupe key on normalized HTML bytes
    return hashlib.sha1(data).hexdigest()

def index_page(doc_id: str, text: str) -> None:
    """Add/replace a page’s fingerprints in the in-memory indexes."""
    fps = fingerprints_from_text(text)
    with _LOCK:
        # Remove old fp postings if re-indexing
        old = _DOC_FPS.get(doc_id)
        if old:
            for fp in old:
                s = _INV.get(fp)
                if s:
                    s.discard(doc_id)
                    if not s:
                        _INV.pop(fp, None)
        _DOC_FPS[doc_id] = fps
        for fp in fps:
            _INV.setdefault(fp, set()).add(doc_id)

def candidates_for(text: str) -> Set[str]:
    """Return doc_ids that share at least one fingerprint with this text."""
    fps = fingerprints_from_text(text)
    cands: Set[str] = set()
    with _LOCK:
        for fp in fps:
            for d in _INV.get(fp, ()):
                cands.add(d)
    return cands

def best_matches_for(text: str, top_k: int = 5):
    """Return (doc_id, sim) sorted by similarity for likely matches."""
    fps_q = fingerprints_from_text(text)
    scores = []
    with _LOCK:
        seen = set()
        for fp in fps_q:
            for d in _INV.get(fp, ()):
                if d in seen: 
                    continue
                seen.add(d)
                sim = jaccard(fps_q, _DOC_FPS.get(d, set()))
                scores.append((d, sim))
    scores.sort(key=lambda x: x[1], reverse=True)
    return scores[:top_k]

def is_near_duplicate_of(text: str, tau: float = TAU):
    """Return (doc_id, sim) of first doc meeting the threshold, else None."""
    for d, s in best_matches_for(text, top_k=10):
        if s >= tau:
            return d, s
    return None
