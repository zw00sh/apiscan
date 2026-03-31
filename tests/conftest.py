"""Test fixtures including a real ASGI HTTP server for integration tests."""

from __future__ import annotations

import asyncio
import json
import re
import socket
import threading
from typing import Any

import pytest
import uvicorn


# ---------------------------------------------------------------------------
# Minimal ASGI test application
# ---------------------------------------------------------------------------

# Known routes the test server handles
_ROUTES: list[tuple[str, str, int, dict[str, Any]]] = [
    # (method, path_pattern, status, response_body_fields)
    ("GET", r"^/api/v1/users$", 200, {"users": ["alice", "bob"]}),
    ("GET", r"^/api/v1/users/(?P<id>[^/]+)$", 200, None),  # echoes id
    ("POST", r"^/api/v1/users$", 201, {"created": True}),
    ("PUT", r"^/api/v1/users/(?P<id>[^/]+)$", 200, {"updated": True}),
    ("DELETE", r"^/api/v1/users/(?P<id>[^/]+)$", 204, None),
    ("GET", r"^/api/v1/health$", 200, {"status": "ok"}),
    ("GET", r"^/admin/shutdown$", 200, {"shutdown": "initiated"}),
    ("GET", r"^/redirect$", 302, None),
]

# Routes under /api/v2 are soft 404s (200 with fixed body)
_SOFT_404_BODY = json.dumps({"error": "not found", "code": 404}).encode()


async def _app(scope: dict, receive: Any, send: Any) -> None:
    if scope["type"] != "http":
        return

    method = scope["method"]
    path = scope["path"]

    # /echo -- returns everything about the request
    if path == "/echo":
        body_parts = []
        while True:
            msg = await receive()
            body_parts.append(msg.get("body", b""))
            if not msg.get("more_body", False):
                break
        req_body = b"".join(body_parts)
        headers_dict = {k.decode(): v.decode() for k, v in scope.get("headers", [])}
        echo = json.dumps({
            "method": method,
            "path": path,
            "headers": headers_dict,
            "body": req_body.decode("utf-8", errors="replace"),
            "query_string": scope.get("query_string", b"").decode(),
        }).encode()
        await send({"type": "http.response.start", "status": 200,
                     "headers": [[b"content-type", b"application/json"]]})
        await send({"type": "http.response.body", "body": echo})
        return

    # /slow -- 5s delay
    if path == "/slow":
        await asyncio.sleep(5)
        await send({"type": "http.response.start", "status": 200,
                     "headers": [[b"content-type", b"text/plain"]]})
        await send({"type": "http.response.body", "body": b"slow response"})
        return

    # /redirect -> /api/v1/health
    if path == "/redirect" and method == "GET":
        await send({"type": "http.response.start", "status": 302,
                     "headers": [[b"location", b"/api/v1/health"]]})
        await send({"type": "http.response.body", "body": b""})
        return

    # Soft 404s under /api/v2 (returns 200 with fixed body)
    if path.startswith("/api/v2/"):
        await send({"type": "http.response.start", "status": 200,
                     "headers": [[b"content-type", b"application/json"]]})
        await send({"type": "http.response.body", "body": _SOFT_404_BODY})
        return

    # Check defined routes
    for r_method, r_pattern, r_status, r_body_template in _ROUTES:
        if r_method != method:
            # Return 405 if path matches but method doesn't
            m = re.match(r_pattern, path)
            if m:
                await send({"type": "http.response.start", "status": 405,
                             "headers": [[b"content-type", b"text/plain"]]})
                await send({"type": "http.response.body", "body": b"Method Not Allowed"})
                return
            continue
        m = re.match(r_pattern, path)
        if not m:
            continue
        groups = m.groupdict()
        if r_status == 204:
            await send({"type": "http.response.start", "status": 204, "headers": []})
            await send({"type": "http.response.body", "body": b""})
            return
        body = r_body_template or groups
        resp_body = json.dumps(body).encode()
        await send({"type": "http.response.start", "status": r_status,
                     "headers": [[b"content-type", b"application/json"]]})
        await send({"type": "http.response.body", "body": resp_body})
        return

    # Default wildcard: 404 with path echoed in body (for baseline testing)
    not_found_body = f"404 Not Found: {path}".encode()
    await send({"type": "http.response.start", "status": 404,
                 "headers": [[b"content-type", b"text/plain"]]})
    await send({"type": "http.response.body", "body": not_found_body})


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def test_server_url():
    """Start a real HTTP server and return its base URL."""
    port = _free_port()
    config = uvicorn.Config(_app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    # Wait for server to be ready
    import time
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                break
        except OSError:
            time.sleep(0.1)

    yield f"http://127.0.0.1:{port}"

    server.should_exit = True
    thread.join(timeout=2)
