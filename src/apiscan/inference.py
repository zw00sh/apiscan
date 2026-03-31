"""Inference-based API discovery engine.

Classifies HTTP responses by actively verifying handler behaviour under
perturbation, rather than relying on static baseline matching.  This module
has **no HTTP knowledge** — it receives response data and emits probe
requests via a caller-supplied ``send_fn`` callback.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from uuid import uuid4

from apiscan.kite import Route


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ResponseSignature:
    """Captured signals from a single HTTP response."""

    status_code: int
    content_type: str                # e.g. "application/json"
    content_length: int
    adjusted_content_length: int     # body with path string removed
    adjustment_scale: int            # times path appears in body
    word_count: int
    line_count: int
    header_names: frozenset[str]     # lowercase header names present


@dataclass
class Baseline:
    """Stable response characteristics for a handler boundary."""

    signatures: list[ResponseSignature] = field(default_factory=list)
    stable_fields: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class Finding:
    """A verified route discovery with classification reason."""

    route: Route
    signature: ResponseSignature
    reason: str          # human-readable explanation
    confidence: str      # "high", "medium", "low"


# ---------------------------------------------------------------------------
# Signal extraction
# ---------------------------------------------------------------------------

def compute_signature(
    status_code: int,
    headers: dict[str, str],
    body: bytes,
    path: str,
) -> ResponseSignature:
    """Build a ``ResponseSignature`` from raw HTTP response data."""
    # Content-Type: strip parameters (charset, boundary, etc.)
    raw_ct = headers.get("content-type", "")
    content_type = raw_ct.split(";", 1)[0].strip().lower()

    content_length = len(body)
    word_count = body.count(b" ") + (1 if body else 0)
    line_count = body.count(b"\n") + (1 if body else 0)

    basepath = path.lstrip("/")
    if basepath:
        adjusted_body = body.replace(basepath.encode(), b"")
        adjusted_content_length = len(adjusted_body)
        diff = content_length - adjusted_content_length
        adjustment_scale = diff // len(basepath) if diff > 0 else 0
    else:
        adjusted_content_length = content_length
        adjustment_scale = 0

    header_names = frozenset(k.lower() for k in headers)

    return ResponseSignature(
        status_code=status_code,
        content_type=content_type,
        content_length=content_length,
        adjusted_content_length=adjusted_content_length,
        adjustment_scale=adjustment_scale,
        word_count=word_count,
        line_count=line_count,
        header_names=header_names,
    )


# ---------------------------------------------------------------------------
# Baseline construction
# ---------------------------------------------------------------------------

_BASELINE_COMPARABLE = (
    "status_code", "content_type", "content_length",
    "adjusted_content_length", "word_count", "line_count",
)


def build_baseline(signatures: list[ResponseSignature]) -> Baseline:
    """Determine which response fields are stable across multiple probes."""
    if not signatures:
        return Baseline()
    if len(signatures) == 1:
        return Baseline(
            signatures=list(signatures),
            stable_fields=set(_BASELINE_COMPARABLE),
        )

    stable: set[str] = set()
    first = signatures[0]
    for f in _BASELINE_COMPARABLE:
        vals = {getattr(s, f) for s in signatures}
        if len(vals) == 1:
            stable.add(f)

    return Baseline(signatures=list(signatures), stable_fields=stable)


# ---------------------------------------------------------------------------
# Baseline matching
# ---------------------------------------------------------------------------

def matches_baseline(
    sig: ResponseSignature,
    baseline: Baseline,
    path_len: int,
) -> str | None:
    """Check if *sig* matches a baseline (i.e. should be filtered).

    Returns a short reason string describing *why* it matched, or ``None``
    if the response does not match the baseline.
    """
    if not baseline.signatures:
        return None

    ref = baseline.signatures[0]
    stable = baseline.stable_fields

    # Status code — different code means different handler response
    if "status_code" in stable:
        if sig.status_code != ref.status_code:
            return None

    # Content-Type — a change here is a strong signal of a *different* handler
    if "content_type" in stable:
        if sig.content_type != ref.content_type:
            return None

    # Content-Length — exact or scaled match
    if "content_length" in stable:
        if sig.content_length == ref.content_length:
            return f"status={ref.status_code}, exact length={sig.content_length}"
    if "adjusted_content_length" in stable:
        expected = ref.adjusted_content_length + (ref.adjustment_scale * path_len)
        if sig.content_length == expected:
            return f"status={ref.status_code}, scaled length={sig.content_length} (adj={ref.adjusted_content_length} + {ref.adjustment_scale}*{path_len})"

    # Word / line count fallback
    if "word_count" in stable and "line_count" in stable:
        if sig.word_count == ref.word_count and sig.line_count == ref.line_count:
            return f"status={ref.status_code}, words={sig.word_count}, lines={sig.line_count}"

    return None


# ---------------------------------------------------------------------------
# Baseline tree
# ---------------------------------------------------------------------------

class BaselineTree:
    """Lazily-built tree of handler boundaries, keyed by ``(prefix, method)``."""

    def __init__(self) -> None:
        self._nodes: dict[tuple[str, str], Baseline] = {}

    def set(self, prefix: str, method: str, baseline: Baseline) -> None:
        self._nodes[(prefix, method)] = baseline

    def lookup(self, path: str, method: str) -> tuple[str, Baseline] | None:
        """Return ``(prefix, baseline)`` for the nearest ancestor, or ``None``.

        Falls back to a GET baseline at the same prefix if no method-specific
        baseline exists, since GET is always probed during initialization.
        """
        parts = path.rstrip("/").split("/")
        for i in range(len(parts), 0, -1):
            candidate = "/".join(parts[:i])
            if not candidate:
                candidate = "/"
            # Prefer method-specific baseline
            key = (candidate, method)
            if key in self._nodes:
                return candidate, self._nodes[key]
            # Fall back to GET baseline at this prefix
            get_key = (candidate, "GET")
            if get_key in self._nodes:
                return candidate, self._nodes[get_key]
        # Check root explicitly
        if ("/", method) in self._nodes:
            return "/", self._nodes[("/", method)]
        if ("/", "GET") in self._nodes:
            return "/", self._nodes[("/", "GET")]
        return None


# ---------------------------------------------------------------------------
# Known bad-site detection (ported from old scanner)
# ---------------------------------------------------------------------------

def is_known_bad_site(sig: ResponseSignature) -> bool:
    """Filter known false-positive patterns from Google Cloud and AWS API Gateway."""
    # Google bad request (method/body mismatch)
    if (sig.status_code == 400 and sig.content_length == 1555
            and sig.word_count == 82 and sig.line_count == 12):
        return True
    # AWS API Gateway patterns
    if sig.status_code == 403:
        is_aws = "x-amzn-requestid" in sig.header_names
        if is_aws or (sig.line_count == 1 and sig.word_count == 6
                      and sig.content_length == 54):
            if sig.line_count == 1 and sig.word_count in (6, 13, 28):
                return True
    return False


# ---------------------------------------------------------------------------
# Reason building
# ---------------------------------------------------------------------------

def _build_reason(
    sig: ResponseSignature,
    baseline_ref: ResponseSignature,
    *,
    method_probe_status: int | None = None,
    new_headers: frozenset[str] | None = None,
) -> list[str]:
    """Collect human-readable reason fragments for why this is a finding."""
    parts: list[str] = []

    # Content-type change
    if sig.content_type != baseline_ref.content_type:
        parts.append(f"content-type: {baseline_ref.content_type} -> {sig.content_type}")

    # Method sensitivity
    if method_probe_status == 405:
        parts.append("method-sensitive: 405 Method Not Allowed")
    elif method_probe_status is not None and method_probe_status != sig.status_code:
        parts.append(f"method-sensitive: {method_probe_status} on alternate verb")

    # Status divergence
    if sig.status_code != baseline_ref.status_code:
        label = _status_label(sig.status_code)
        parts.append(f"status: {baseline_ref.status_code} -> {sig.status_code}{label}")

    # New headers
    if new_headers:
        names = ", ".join(sorted(new_headers)[:5])
        parts.append(f"new headers: {names}")

    return parts


def _status_label(code: int) -> str:
    labels = {
        200: "", 201: " (created)", 204: " (no content)",
        301: " (moved)", 302: " (redirect)",
        400: " (bad request)", 401: " (auth required)", 403: " (forbidden)",
        405: " (method not allowed)", 422: " (validation error)",
        429: " (rate limited)", 500: " (server error)",
    }
    return labels.get(code, "")


# ---------------------------------------------------------------------------
# Confidence scoring
# ---------------------------------------------------------------------------

def _score_confidence(reason_parts: list[str]) -> str:
    """Assign confidence based on which signals fired."""
    high_signals = {"method-sensitive: 405 Method Not Allowed", "content-type:"}
    for part in reason_parts:
        for hs in high_signals:
            if part.startswith(hs):
                return "high"
    if len(reason_parts) >= 2:
        return "high"
    # Single signal
    for part in reason_parts:
        if part.startswith("status:"):
            code_str = part.split("-> ")[1].split(" ")[0] if "-> " in part else ""
            if code_str in ("200", "201", "204", "401", "403"):
                return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Probe helpers
# ---------------------------------------------------------------------------

_ALTERNATE_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]


def _random_segment() -> str:
    return uuid4().hex[:16]


def _pick_alternate_method(original: str) -> str:
    """Pick a different HTTP method for a verification probe."""
    candidates = [m for m in _ALTERNATE_METHODS if m != original]
    return random.choice(candidates)


def _parent_prefix(path: str) -> str:
    """Return the parent path of *path* (one segment up)."""
    parts = path.rstrip("/").rsplit("/", 1)
    if len(parts) <= 1 or not parts[0]:
        return "/"
    return parts[0]


# ---------------------------------------------------------------------------
# Inference engine
# ---------------------------------------------------------------------------

class InferenceEngine:
    """Core inference engine for API route discovery.

    Call :meth:`initialize` once to establish the root baseline, then call
    :meth:`process` for each candidate route response.

    ``send_fn`` signature::

        async (method: str, url: str, headers: dict | None, body: str | None)
            -> ResponseSignature
    """

    def __init__(
        self,
        status_blacklist: set[int] | None = None,
        status_whitelist: set[int] | None = None,
        on_filtered=None,
    ) -> None:
        self.tree = BaselineTree()
        self._status_blacklist = status_blacklist
        self._status_whitelist = status_whitelist
        self._on_filtered_cb = on_filtered

    def _on_filtered(self, route: Route, path: str, sig: ResponseSignature, reason: str) -> None:
        if self._on_filtered_cb:
            self._on_filtered_cb(route, path, sig, reason)

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    async def initialize(self, send_fn) -> None:
        """Establish root baselines by probing random paths at ``/``.

        Sends 2 probes per method (GET, POST, PUT, DELETE, PATCH) to capture
        method-specific default responses. Many targets return different error
        shapes per method — a GET 404 might be HTML while a POST 404 is JSON.
        """
        for method in _ALTERNATE_METHODS:
            sigs: list[ResponseSignature] = []
            for _ in range(2):
                path = f"/{_random_segment()}"
                try:
                    sig = await send_fn(method, path, None, None)
                    sigs.append(sig)
                except Exception:
                    pass
            if sigs:
                self.tree.set("/", method, build_baseline(sigs))

    # ------------------------------------------------------------------
    # Status filtering
    # ------------------------------------------------------------------

    def _filter_status(self, status: int) -> bool:
        if self._status_whitelist and status not in self._status_whitelist:
            return True
        if self._status_blacklist and status in self._status_blacklist:
            return True
        return False

    # ------------------------------------------------------------------
    # Main processing
    # ------------------------------------------------------------------

    async def process(
        self,
        route: Route,
        sig: ResponseSignature,
        path: str,
        send_fn,
    ) -> Finding | None:
        """Classify a candidate response. Returns a :class:`Finding` or ``None``.

        Parameters
        ----------
        route:
            The route that was probed.
        sig:
            The response signature from the initial probe.
        path:
            The rendered path that was actually requested.
        send_fn:
            Async callback to send verification probes.
        """
        # --- Pre-filters ---
        if self._filter_status(sig.status_code):
            self._on_filtered(route, path, sig, f"status filter: {sig.status_code}")
            return None
        if is_known_bad_site(sig):
            self._on_filtered(route, path, sig, f"known bad site pattern: {sig.status_code}, length={sig.content_length}")
            return None

        # --- Baseline comparison ---
        path_len = len(path.lstrip("/"))
        method = route.method
        node = self.tree.lookup(path, method)
        if node is not None:
            prefix, baseline = node
            match_reason = matches_baseline(sig, baseline, path_len)
            if match_reason is not None:
                self._on_filtered(route, path, sig, f"baseline match at {prefix}: {match_reason}")
                return None

            baseline_ref = baseline.signatures[0]
        else:
            # No baseline at all — treat everything as novel
            baseline_ref = None

        # --- Verification phase ---
        # Step 1: Walk intermediate path segments to discover handler boundaries.
        # If we only have a root baseline and the candidate is at /foo/bar/bin/baz,
        # we need to check /foo, /foo/bar, /foo/bar/bin to find where boundaries are.
        known_prefix = prefix if node is not None else "/"
        baseline_ref, known_prefix = await self._walk_intermediates(
            path, method, known_prefix, send_fn,
        )

        # Re-compare after discovering any new boundaries
        node = self.tree.lookup(path, method)
        if node is not None:
            prefix, baseline = node
            match_reason = matches_baseline(sig, baseline, path_len)
            if match_reason is not None:
                self._on_filtered(route, path, sig, f"baseline match at {prefix}: {match_reason}")
                return None
            baseline_ref = baseline.signatures[0]

        if baseline_ref is None:
            # Still no baseline reference — can't reason about the response.
            # Report as low-confidence finding.
            return Finding(
                route=route,
                signature=sig,
                reason="no baseline available",
                confidence="low",
            )

        # Step 2: Method change probe — is routing method-aware?
        method_probe_status: int | None = None
        alt_method = _pick_alternate_method(route.method)
        try:
            method_sig = await send_fn(alt_method, path, None, None)
            method_probe_status = method_sig.status_code
        except Exception:
            pass

        # Step 3: Check for new headers
        if node is not None:
            ref_headers = baseline_ref.header_names
            new_headers = sig.header_names - ref_headers
            # Filter out common variable headers
            new_headers -= {"date", "content-length", "transfer-encoding", "connection"}
        else:
            new_headers = frozenset()

        # --- Classification ---
        reason_parts = _build_reason(
            sig, baseline_ref,
            method_probe_status=method_probe_status,
            new_headers=new_headers if new_headers else None,
        )

        if not reason_parts:
            # Deviates from baseline but no clear reason — low confidence
            reason_parts = [f"response differs from baseline"]

        confidence = _score_confidence(reason_parts)
        reason = ", ".join(reason_parts)

        return Finding(
            route=route,
            signature=sig,
            reason=reason,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _walk_intermediates(
        self,
        path: str,
        method: str,
        known_prefix: str,
        send_fn,
    ) -> tuple[ResponseSignature | None, str]:
        """Probe unknown intermediate segments between *known_prefix* and *path*.

        Walks component-by-component from the nearest known baseline toward
        the candidate path.  At each new segment, sends random-path probes to
        check if it's a handler boundary.  Newly discovered boundaries are
        stored in the tree so subsequent routes benefit.

        Returns ``(baseline_ref, deepest_known_prefix)`` — the reference
        signature from the deepest known baseline after the walk.
        """
        parts = path.rstrip("/").split("/")
        # parts[0] is always "" (leading slash), so meaningful segments start at 1
        known_parts = known_prefix.rstrip("/").split("/")
        start_depth = len(known_parts)  # first segment to probe

        # The last segment is the candidate itself — don't probe it
        end_depth = len(parts) - 1
        if end_depth <= start_depth:
            # Nothing to walk — known baseline is already the parent
            node = self.tree.lookup(path, method)
            ref = node[1].signatures[0] if node else None
            return ref, known_prefix

        # Fetch the current baseline to compare each probe against
        node = self.tree.lookup(known_prefix, method)
        current_baseline = node[1] if node else None

        for depth in range(start_depth, end_depth + 1):
            segment_prefix = "/".join(parts[:depth + 1])
            if not segment_prefix:
                segment_prefix = "/"

            # Already in tree? Skip.
            if self.tree.lookup(segment_prefix, method) != self.tree.lookup(known_prefix, method):
                # A more specific baseline exists — advance to it
                node = self.tree.lookup(segment_prefix, method)
                if node is not None:
                    known_prefix = node[0]
                    current_baseline = node[1]
                continue

            # Probe this prefix with random children
            probe_path = f"{segment_prefix.rstrip('/')}/{_random_segment()}"
            try:
                probe_sig = await send_fn(method, probe_path, None, None)
            except Exception:
                continue

            # Does the probe response differ from the current baseline?
            if current_baseline is not None:
                probe_len = len(probe_path.lstrip("/"))
                if matches_baseline(probe_sig, current_baseline, probe_len) is not None:
                    # Same handler — no new boundary here
                    continue

            # New handler boundary — send a second probe for variance detection
            sigs = [probe_sig]
            try:
                extra_path = f"{segment_prefix.rstrip('/')}/{_random_segment()}"
                extra_sig = await send_fn(method, extra_path, None, None)
                sigs.append(extra_sig)
            except Exception:
                pass

            new_baseline = build_baseline(sigs)
            self.tree.set(segment_prefix, method, new_baseline)
            known_prefix = segment_prefix
            current_baseline = new_baseline

        ref = current_baseline.signatures[0] if current_baseline else None
        return ref, known_prefix

    @staticmethod
    def _sigs_similar(a: ResponseSignature, b: ResponseSignature, path_len: int) -> bool:
        """Rough similarity check — used to detect handler boundaries."""
        if a.status_code != b.status_code:
            return False
        if a.content_type != b.content_type:
            return False
        # Allow content-length to differ by path-echo scaling
        len_diff = abs(a.content_length - b.content_length)
        if len_diff > 0 and (path_len == 0 or len_diff > path_len * 3):
            return False
        return True
