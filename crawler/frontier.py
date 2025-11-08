import os
import shelve

from threading import Thread, RLock
from queue import Queue, Empty

from utils import get_logger, get_urlhash, normalize
from scraper import is_valid


class Frontier:
    """
    Thread-safe Frontier using:
        - Queue for pending URLs
        - sets for seen + completed
        - RLock for safety across multiple Workers
        - shelve for checkpointing

    Fully compatible with the original ICS crawler architecture
    but now safe for multithreading.
    """

    def __init__(self, config, restart: bool):
        self.config = config
        self.logger = get_logger("Frontier")

        # Thread-safe queue for URLs to visit
        self._q = Queue()

        # Protect shared structures
        self._lock = RLock()

        # Track seen and completed URLs
        self._seen = set()
        self._completed = set()

        self._save_path = config.save_file

        # Handle restart
        if restart:
            self._reset_state()
            self.add_url(config.seed_url)
        else:
            loaded = self._load_state()
            if not loaded:
                self.add_url(config.seed_url)

    # ----------------------------------------------------------------------
    # Internal helpers
    # ----------------------------------------------------------------------

    def _reset_state(self):
        """On restart: clear shelve DB files."""
        for ext in ("", ".bak", ".dat", ".dir"):
            p = self._save_path + ext
            try:
                if os.path.exists(p):
                    os.remove(p)
            except OSError:
                pass

    def _load_state(self) -> bool:
        """Try loading frontier state from disk."""
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

                # Only requeue unfinished URLs
                for u in queued:
                    if u not in self._completed:
                        self._q.put(u)

            self.logger.info(f"Frontier loaded with {len(self._seen)} seen, "
                             f"{len(self._completed)} completed.")
            return True

        except Exception:
            return False

    def _save_state(self):
        """Persist the whole frontier to disk safely."""
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
            self.logger.error("Failed to save frontier state.", exc_info=True)

    # ----------------------------------------------------------------------
    # Required API for crawler
    # ----------------------------------------------------------------------

    def get_tbd_url(self):
        """
        Thread-safe fetch:
        - Blocks up to 0.5 seconds
        - Returns None when frontier is drained
        """
        try:
            return self._q.get(timeout=0.5)
        except Empty:
            with self._lock:
                # Drained when: seen is non-empty AND all seen are completed
                if self._seen and self._seen == self._completed:
                    return None
            return None

    def add_url(self, url: str):
        """
        Add a URL to frontier:
        - Normalize
        - Avoid duplicates (seen or completed)
        - Validate using existing scraper.is_valid()
        """
        if not url:
            return

        url = normalize(url)

        if not is_valid(url):
            return

        with self._lock:
            if url in self._seen or url in self._completed:
                return

            self._seen.add(url)
            self._q.put(url)

        # Save occasionally
        if self._q.qsize() % 50 == 0:
            self._save_state()

    def mark_url_complete(self, url: str):
        """Mark completed & snapshot occasionally."""
        if not url:
            return
        url = normalize(url)

        with self._lock:
            self._completed.add(url)

        if len(self._completed) % 50 == 0:
            self._save_state()
