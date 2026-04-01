"""Test fixtures including a real ASGI HTTP server for integration tests.

The test server simulates a multi-service gateway:
- Gateway default: 404 text/html
- /api/v1/*: JSON service with method-aware routing
- /api/v2/*: Different JSON service with soft-404 wildcard
- /deep/*: Handler boundary (403 json) with nested sub-handler
- /deep/secret/*: Sub-handler boundary (401 json) for recursion testing
- /admin/*: Auth-required service with custom headers
- /internal/metrics: Standalone plaintext service
"""

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
# Minimal ASGI test application — multi-service gateway simulation
# ---------------------------------------------------------------------------

# /api/v1 routes — method-aware REST service
_API_V1_ROUTES: list[tuple[str, str, int, dict[str, Any] | None]] = [
    ("GET", r"^/api/v1/users$", 200, {"users": ["alice", "bob"]}),
    ("GET", r"^/api/v1/users/(?P<id>[^/]+)$", 200, None),  # echoes id
    ("POST", r"^/api/v1/users$", 201, {"created": True}),
    ("PUT", r"^/api/v1/users/(?P<id>[^/]+)$", 200, {"updated": True}),
    ("DELETE", r"^/api/v1/users/(?P<id>[^/]+)$", 204, None),
    ("GET", r"^/api/v1/health$", 200, {"status": "ok"}),
]

# /api/v2 — different service, soft 404 (always 200 json)
_SOFT_404_BODY = json.dumps({"error": "not found", "code": 404}).encode()

# /admin — auth-required service with custom headers
_ADMIN_FORBIDDEN_BODY = json.dumps({"error": "forbidden"}).encode()
_ADMIN_UNAUTHORIZED_BODY = json.dumps({"error": "unauthorized", "login": "/auth/login"}).encode()


async def _app(scope: dict, receive: Any, send: Any) -> None:
    if scope["type"] != "http":
        return

    method = scope["method"]
    path = scope["path"]

    # /echo — mirrors request back
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

    # /slow — 5s delay
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

    # /internal/metrics — standalone plaintext service (content-type boundary)
    if path == "/internal/metrics" and method == "GET":
        body = b"requests_total 12345\nerrors_total 42\n"
        await send({"type": "http.response.start", "status": 200,
                     "headers": [[b"content-type", b"text/plain"]]})
        await send({"type": "http.response.body", "body": body})
        return

    # /deep/secret and /deep/secret/* — nested sub-handler (401 json, distinct from /deep's 403)
    if path == "/deep/secret" or path.startswith("/deep/secret/"):
        body = json.dumps({"error": "unauthorized", "area": "secret"}).encode()
        await send({"type": "http.response.start", "status": 401,
                     "headers": [[b"content-type", b"application/json"]]})
        await send({"type": "http.response.body", "body": body})
        return

    # /deep and /deep/* — handler boundary (403 json, distinct from root 404 html)
    if path == "/deep" or path.startswith("/deep/"):
        body = json.dumps({"error": "forbidden", "area": "deep"}).encode()
        await send({"type": "http.response.start", "status": 403,
                     "headers": [[b"content-type", b"application/json"]]})
        await send({"type": "http.response.body", "body": body})
        return

    # /redir-internal -> /deep/secret/panel (in-scope redirect to a handler)
    if path == "/redir-internal" and method == "GET":
        await send({"type": "http.response.start", "status": 302,
                     "headers": [[b"location", b"/deep/secret/panel"]]})
        await send({"type": "http.response.body", "body": b""})
        return

    # /admin/* — auth-required service with custom headers
    if path.startswith("/admin/"):
        headers = [
            [b"content-type", b"application/json"],
            [b"x-request-id", b"req-abc-123"],
        ]
        if path == "/admin/dashboard":
            await send({"type": "http.response.start", "status": 401,
                         "headers": headers})
            await send({"type": "http.response.body", "body": _ADMIN_UNAUTHORIZED_BODY})
            return
        # Everything else under /admin is 403 (admin wildcard)
        await send({"type": "http.response.start", "status": 403,
                     "headers": headers})
        await send({"type": "http.response.body", "body": _ADMIN_FORBIDDEN_BODY})
        return

    # /api/v2/* — soft 404 (different service, always returns 200 json)
    if path.startswith("/api/v2/"):
        await send({"type": "http.response.start", "status": 200,
                     "headers": [[b"content-type", b"application/json"]]})
        await send({"type": "http.response.body", "body": _SOFT_404_BODY})
        return

    # /api/v1/* — method-aware REST service
    if path.startswith("/api/v1/"):
        # Check for method match first
        path_matched = False
        for r_method, r_pattern, r_status, r_body_template in _API_V1_ROUTES:
            m = re.match(r_pattern, path)
            if m:
                path_matched = True
                if r_method == method:
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

        if path_matched:
            # Path exists but method doesn't match — 405 with Allow header
            allowed = [r[0] for r in _API_V1_ROUTES if re.match(r[1], path)]
            allow_header = ", ".join(sorted(set(allowed)))
            await send({"type": "http.response.start", "status": 405,
                         "headers": [
                             [b"content-type", b"application/json"],
                             [b"allow", allow_header.encode()],
                         ]})
            await send({"type": "http.response.body",
                         "body": json.dumps({"error": "method not allowed"}).encode()})
            return

        # Unknown path under /api/v1 — JSON 404 (different from gateway default)
        await send({"type": "http.response.start", "status": 404,
                     "headers": [[b"content-type", b"application/json"]]})
        await send({"type": "http.response.body",
                     "body": json.dumps({"error": "not found"}).encode()})
        return

    # Gateway default: 404 text/html with path echoed
    not_found_body = f"<html><body>404 Not Found: {path}</body></html>".encode()
    await send({"type": "http.response.start", "status": 404,
                 "headers": [[b"content-type", b"text/html"]]})
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
