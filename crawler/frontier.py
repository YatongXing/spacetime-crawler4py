import os
import shelve

from threading import Thread, RLock
from queue import Queue, Empty

from utils import get_logger, get_urlhash, normalize
from scraper import is_valid

# ──────────────────────────────────────────────────────────────────────────────
# Thread-safe Frontier with simple persistence.
#  - Uses Queue for TBD urls
#  - Uses sets of url_hashes to de-dupe seen/completed
#  - Normalizes urls before hashing (keeps your utils.normalize / get_urlhash)
#  - Shelve snapshot is best-effort and occasional
# ──────────────────────────────────────────────────────────────────────────────

class Frontier:
    def __init__(self, config, restart: bool):
        self.config = config
        self.log = get_logger("FRONTIER")
        self._q: Queue[str] = Queue()
        self._lock = RLock()
        self._seen = set()       # hashes of normalized urls
        self._completed = set()  # hashes of normalized urls
        self._save_path = config.save_file or "frontier.shelve"

        if restart:
            # wipe any old state and seed fresh
            for ext in ("", ".bak", ".dat", ".dir"):
                p = self._save_path + ext
                if os.path.exists(p):
                    try: os.remove(p)
                    except OSError: pass
            self.add_url(config.seed_url)
        else:
            if not self._load_state():
                self.add_url(config.seed_url)

    # ── public API expected by crawler ────────────────────────────────────────
    def get_tbd_url(self):
        """
        Return one URL to download or None if the frontier is drained.
        """
        try:
            return self._q.get(timeout=0.5)
        except Empty:
            with self._lock:
                drained = (len(self._seen) > 0) and (self._seen == self._completed)
            return None if drained else None

    def add_url(self, url: str):
        if not url:
            return
        # Normalize & hash for stable deduping
        norm = normalize(url)
        h = get_urlhash(norm)
        with self._lock:
            if h in self._seen or h in self._completed:
                return
            self._seen.add(h)
            self._q.put(norm)
        # snapshot occasionally
        if self._q.qsize() % 50 == 0:
            self._save_state()

    def mark_url_complete(self, url: str):
        if not url:
            return
        norm = normalize(url)
        h = get_urlhash(norm)
        with self._lock:
            self._completed.add(h)
        if len(self._completed) % 50 == 0:
            self._save_state()

    # ── persistence helpers ───────────────────────────────────────────────────
    def _load_state(self) -> bool:
        try:
            with shelve.open(self._save_path) as db:
                seen = db.get("seen")
                completed = db.get("completed")
                queued = db.get("queue")
            if seen is None or completed is None or queued is None:
                return False
            with self._lock:
                self._seen = set(seen)
                self._completed = set(completed)
                for u in queued:
                    # Only requeue not-yet-completed items
                    if get_urlhash(normalize(u)) not in self._completed:
                        self._q.put(u)
            self.log.info("Frontier state restored: seen=%d, completed=%d, queued=%d",
                          len(self._seen), len(self._completed), self._q.qsize())
            return True
        except Exception:
            return False

    def _save_state(self):
        try:
            with self._lock:
                seen = list(self._seen)
                completed = list(self._completed)
                queued = list(self._q.queue)
            with shelve.open(self._save_path) as db:
                db["seen"] = seen
                db["completed"] = completed
                db["queue"] = queued
        except Exception:
            pass
