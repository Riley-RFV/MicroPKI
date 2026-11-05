import threading
import time
from collections import defaultdict

class TokenBucket:
    def __init__(self, rate_per_sec: float, burst: int):
        self.rate = rate_per_sec
        self.burst = burst
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, ip: str) -> tuple[bool, int]:
        if self.rate <= 0:
            return True, 0
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(ip, (float(self.burst), now))
            elapsed = now - last
            tokens = min(self.burst, tokens + elapsed * self.rate)
            if tokens >= 1:
                self._buckets[ip] = (tokens - 1, now)
                return True, 0
            self._buckets[ip] = (tokens, now)
            retry = max(1, int((1 - tokens) / self.rate) + 1)
            return False, retry
