import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self, max_requests=10, window_seconds=60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.request_history = defaultdict(deque)

    def check_request(self, ip_address):
        current_time = time.time()
        requests = self.request_history[ip_address]

        # Remove requests outside the time window
        while requests and current_time - requests[0] > self.window_seconds:
            requests.popleft()

        # Check whether the IP exceeded the limit
        if len(requests) >= self.max_requests:
            return {
                "allowed": False,
                "reason": "Rate limit exceeded",
                "request_count": len(requests)
            }

        requests.append(current_time)

        return {
            "allowed": True,
            "reason": "Request allowed",
            "request_count": len(requests)
        }