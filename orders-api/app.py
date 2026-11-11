"""orders-api: a tiny HTTP service used as the 'patient' for the AI agent.

Stdlib only (no dependencies), so the image is small and builds fast.

Two realistic failure modes for the demo (guide Chapter 11):
  * BALLAST_MB > 0  -> allocates memory at startup, like a release that needs
                       more RAM. With a low memory limit the container is
                       OOMKilled and restarts.
  * a bad release    -> you change STARTUP_CHECK to "fail" in this file,
                       CI ships it, the container exits on start -> CrashLoopBackOff.
"""

import json
import logging
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = os.environ.get("APP_VERSION", "dev")
PORT = int(os.environ.get("PORT", "8080"))
BALLAST_MB = int(os.environ.get("BALLAST_MB", "0"))

# Demo scenario B: set this to "fail" in a commit to simulate a broken release.
STARTUP_CHECK = "ok"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s orders-api %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("orders-api")

ORDERS = [
    {"id": 1, "item": "keyboard", "qty": 2},
    {"id": 2, "item": "monitor", "qty": 1},
]

_ballast = []  # keeps the allocated memory referenced


def startup() -> None:
    log.info("starting version=%s port=%s ballast_mb=%s", VERSION, PORT, BALLAST_MB)
    if STARTUP_CHECK != "ok":
        log.error("startup check failed: required configuration ORDERS_DB_URL is missing")
        sys.exit(1)
    if BALLAST_MB > 0:
        log.info("allocating %s MiB for the new in-memory cache", BALLAST_MB)
        for _ in range(BALLAST_MB):
            _ballast.append(bytearray(1024 * 1024))
            time.sleep(0.02)
        log.info("cache warmed")


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802 (http.server naming)
        if self.path in ("/healthz", "/readyz"):
            self._send(200, {"status": "ok", "version": VERSION})
        elif self.path == "/orders":
            self._send(200, {"orders": ORDERS, "version": VERSION})
        else:
            self._send(404, {"error": "not found"})

    def log_message(self, fmt: str, *args) -> None:
        log.info("%s %s", self.address_string(), fmt % args)


if __name__ == "__main__":
    startup()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    log.info("listening on :%s", PORT)
    server.serve_forever()
