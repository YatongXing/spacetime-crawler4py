from threading import Thread

from inspect import getsource
from utils.download import download
from utils import get_logger
import scraper
import time

# Extra import (we keep your existing imports untouched)
from urllib.parse import urlparse
import threading

# ──────────────────────────────────────────────────────────────────────────────
# Per-domain politeness guard shared by all Worker threads.
# Guarantees >= min_delay seconds spacing between *any* two requests to the
# same domain, even when they come from different threads.
# ──────────────────────────────────────────────────────────────────────────────
class _PolitenessGuard:
    def __init__(self, min_delay_seconds: float):
        self.min_delay = max(0.0, float(min_delay_seconds))
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._next_allowed = {}  # domain -> epoch seconds

    def wait_turn(self, url: str):
        domain = urlparse(url).netloc.lower()
        with self._cond:
            while True:
                now = time.time()
                ready_at = self._next_allowed.get(domain, 0.0)
                wait = ready_at - now
                if wait <= 0:
                    # Reserve the next slot for this domain now.
                    self._next_allowed[domain] = now + self.min_delay
                    return
                self._cond.wait(timeout=wait)

    def notify(self):
        with self._cond:
            self._cond.notify_all()


class Worker(Thread):
    """
    Multithreaded worker that enforces per-domain politeness across threads.
    """
    _guard = None  # shared across all Worker instances (set on first init)

    def __init__(self, worker_id, config, frontier):
        Thread.__init__(self, daemon=True)
        self.worker_id = worker_id
        self.config = config
        self.frontier = frontier
        self.log = get_logger(f"WORKER-{worker_id}")

        # Lazily create the shared guard (cap at 0.5s minimum as per spec).
        if Worker._guard is None:
            # Double-checked locking to be safe in races
            lock = threading.Lock()
            with lock:
                if Worker._guard is None:
                    delay = max(0.5, float(self.config.time_delay))
                    Worker._guard = _PolitenessGuard(delay)

    def run(self):
        while True:
            url = self.frontier.get_tbd_url()
            if url is None:
                break  # frontier drained

            try:
                # Enforce per-domain spacing BEFORE download
                Worker._guard.wait_turn(url)

                resp = download(url, self.config)

                try:
                    next_links = scraper.scraper(url, resp) or []
                except Exception as e:
                    self.log.warning("scraper error on %s: %s", url, e)
                    next_links = []

                for link in next_links:
                    self.frontier.add_url(link)
            finally:
                self.frontier.mark_url_complete(url)
                Worker._guard.notify()  # nudge any waiters if applicable

        self.log.info("Worker %s exiting (frontier drained).", self.worker_id)
