"""HTTP service: JSON API, health endpoint and the reviewer web page.

Endpoints
---------
GET  /health                          liveness/readiness probe
GET  /                                 reviewer page
GET  /static/app.js                    page script
GET  /api/versions                     all published versions
GET  /api/state?version=&serial=       root, status and proof at a version
POST /api/batches                      submit a revocation/unrevocation batch
"""

from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import tree
from .storage import InvalidBatchError, StaleRootError, Storage

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
MAX_BODY = 64 * 1024


class Handler(BaseHTTPRequestHandler):
    server_version = "RevDir/1.0"

    @property
    def storage(self) -> Storage:
        return self.server.storage  # type: ignore[attr-defined]

    # ----------------------------------------------------------------- utils
    def _send_json(self, payload, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_static(self, filename: str, content_type: str) -> None:
        path = os.path.join(STATIC_DIR, filename)
        try:
            with open(path, "rb") as fh:
                body = fh.read()
        except OSError:
            self._send_json({"error": "not found"}, 404)
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args) -> None:
        sys.stderr.write("[http] %s - %s\n" % (self.address_string(), fmt % args))

    # ------------------------------------------------------------------- GET
    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/health":
            version, root = self.storage.latest()
            self._send_json({"status": "ok", "latest_version": version,
                             "latest_root": root.hex()})
            return
        if path == "/":
            self._send_static("index.html", "text/html; charset=utf-8")
            return
        if path == "/static/app.js":
            self._send_static("app.js", "application/javascript; charset=utf-8")
            return
        if path == "/api/versions":
            rows = self.storage.list_versions()
            self._send_json({
                "versions": [
                    {"version": r["version"], "root": r["root"].hex(),
                     "parent_version": r["parent_version"],
                     "created_at": r["created_at"], "comment": r["comment"]}
                    for r in rows
                ],
            })
            return
        if path == "/api/state":
            self._handle_state(parse_qs(parsed.query))
            return
        self._send_json({"error": "not found"}, 404)

    def _handle_state(self, query) -> None:
        serial = (query.get("serial", [""])[0] or "").strip().upper()
        version_raw = (query.get("version", [""])[0] or "").strip()
        try:
            key = tree.serial_to_key(serial)
        except ValueError as exc:
            self._send_json({"error": str(exc)}, 400)
            return
        try:
            version = int(version_raw)
        except ValueError:
            self._send_json({"error": "version must be an integer"}, 400)
            return
        row = self.storage.get_version(version)
        if row is None:
            self._send_json({"error": "unknown version %d" % version}, 404)
            return
        proof = self.storage.proof_for(version, key)
        stored = self.storage.stored_proof(version, key)
        body = {
            "version": version,
            "serial": serial,
            "root": row["root"].hex(),
            "status": tree.STATUS_NAME[proof.status],
            "proof": proof.to_dict(),
            "part_of_latest_batch": stored is not None,
        }
        self._send_json(body)

    # ------------------------------------------------------------------ POST
    def do_POST(self) -> None:  # noqa: N802
        if urlparse(self.path).path != "/api/batches":
            self._send_json({"error": "not found"}, 404)
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY:
            self._send_json({"error": "invalid request body"}, 400)
            return
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json({"error": "body must be valid JSON"}, 400)
            return
        if not isinstance(payload, dict):
            self._send_json({"error": "body must be a JSON object"}, 400)
            return
        items = payload.get("items")
        if not isinstance(items, list):
            self._send_json({"error": "'items' must be a list"}, 400)
            return
        comment = payload.get("comment", "")
        if not isinstance(comment, str):
            self._send_json({"error": "'comment' must be a string"}, 400)
            return
        try:
            version, root = self.storage.submit_batch(
                payload.get("expected_root", ""), items, comment[:200]
            )
        except StaleRootError as exc:
            latest_version, latest_root = self.storage.latest()
            self._send_json({
                "error": str(exc),
                "code": "stale_root",
                "latest_version": latest_version,
                "latest_root": latest_root.hex(),
            }, 409)
        except InvalidBatchError as exc:
            self._send_json({"error": str(exc), "code": "invalid_batch"}, 400)
        else:
            self._send_json({"version": version, "root": root.hex()}, 201)


def build_server(db_path: str, host: str, port: int) -> ThreadingHTTPServer:
    storage = Storage(db_path)

    class _Server(ThreadingHTTPServer):
        daemon_threads = True
        allow_reuse_address = True

        def server_close(self) -> None:
            super().server_close()
            storage.close()

    server = _Server((host, port), Handler)
    server.storage = storage  # type: ignore[attr-defined]
    return server


def main() -> int:
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    db_path = os.environ.get("DB_PATH", "/data/directory.db")
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    server = build_server(db_path, host, port)
    sys.stderr.write("revocation directory listening on %s:%d (db=%s)\n"
                     % (host, port, db_path))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
