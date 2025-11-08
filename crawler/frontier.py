import heapq
import os
import shelve
import time
from collections import defaultdict, deque
from threading import RLock, Condition
from urllib.parse import urlparse

from utils import get_logger, get_urlhash, normalize
from scraper import is_valid


class Frontier(object):
    def __init__(self, config, restart):
        self.logger = get_logger("FRONTIER")
        self.config = config
        self.lock = RLock()
        self.cv = Condition(self.lock)
        self.domain_queues = defaultdict(deque)
        self.domain_next_time = dict()
        self.domain_heap = list()
        self.total_pending = 0
        self.in_progress = 0
        self.politeness_delay = max(self.config.time_delay, 0.5)

        if not os.path.exists(self.config.save_file) and not restart:
            # Save file does not exist, but request to load save.
            self.logger.info(
                f"Did not find save file {self.config.save_file}, "
                f"starting from seed.")
        elif os.path.exists(self.config.save_file) and restart:
            # Save file does exists, but request to start from seed.
            self.logger.info(
                f"Found save file {self.config.save_file}, deleting it.")
            os.remove(self.config.save_file)
        # Load existing save file, or create one if it does not exist.
        self.save = shelve.open(self.config.save_file)
        if restart:
            for url in self.config.seed_urls:
                self.add_url(url)
        else:
            # Set the frontier state with contents of save file.
            self._parse_save_file()
            if not self.save:
                for url in self.config.seed_urls:
                    self.add_url(url)

    def _parse_save_file(self):
        ''' This function can be overridden for alternate saving techniques. '''
        total_count = len(self.save)
        tbd_count = 0
        with self.cv:
            for url, completed in self.save.values():
                if not completed and is_valid(url):
                    self._enqueue_url(url)
                    tbd_count += 1
        self.logger.info(
            f"Found {tbd_count} urls to be downloaded from {total_count} "
            f"total urls discovered.")

    def get_tbd_url(self):
        with self.cv:
            while True:
                if self.total_pending == 0 and self.in_progress == 0:
                    return None
                if not self.domain_heap:
                    self.cv.wait()
                    continue
                next_time, domain = self.domain_heap[0]
                now = time.monotonic()
                wait_time = next_time - now
                if wait_time > 0:
                    self.cv.wait(timeout=wait_time)
                    continue
                heapq.heappop(self.domain_heap)
                queue = self.domain_queues[domain]
                if not queue:
                    # Should not happen, but continue gracefully.
                    continue
                url = queue.popleft()
                self.total_pending -= 1
                self.in_progress += 1
                next_available = now + self.politeness_delay
                self.domain_next_time[domain] = next_available
                if queue:
                    heapq.heappush(self.domain_heap, (next_available, domain))
                return url

    def add_url(self, url):
        url = normalize(url)
        urlhash = get_urlhash(url)
        with self.cv:
            if urlhash not in self.save:
                self.save[urlhash] = (url, False)
                self.save.sync()
                self._enqueue_url(url)

    def mark_url_complete(self, url):
        urlhash = get_urlhash(url)
        with self.cv:
            if urlhash not in self.save:
                # This should not happen.
                self.logger.error(
                    f"Completed url {url}, but have not seen it before.")

            self.save[urlhash] = (url, True)
            self.save.sync()
            if self.in_progress > 0:
                self.in_progress -= 1
            self.cv.notify_all()

    def _enqueue_url(self, url):
        domain = urlparse(url).netloc
        queue = self.domain_queues[domain]
        was_empty = len(queue) == 0
        queue.append(url)
        self.total_pending += 1
        now = time.monotonic()
        next_ready = self.domain_next_time.get(domain, now)
        if next_ready < now:
            next_ready = now
        self.domain_next_time[domain] = next_ready
        if was_empty:
            heapq.heappush(self.domain_heap, (next_ready, domain))
        self.cv.notify_all()