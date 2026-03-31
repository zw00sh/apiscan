"""Inference-based API discovery engine.

Classifies HTTP responses by actively verifying handler behaviour under
perturbation.  This module has **no HTTP knowledge** — it receives response
data and emits probe requests via a caller-supplied ``send_fn`` callback.

The ``InferenceEngine`` reads baselines from a :class:`~apiscan.scantree.ScanTree`
(which owns both route ordering and baseline storage) and writes nothing
to the tree itself.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from uuid import uuid4

from apiscan.kite import Route

if TYPE_CHECKING:
    from apiscan.scantree import ScanTree


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

    if "status_code" in stable:
        if sig.status_code != ref.status_code:
            return None

    if "content_type" in stable:
        if sig.content_type != ref.content_type:
            return None

    if "content_length" in stable:
        if sig.content_length == ref.content_length:
            return f"status={ref.status_code}, exact length={sig.content_length}"
    if "adjusted_content_length" in stable:
        expected = ref.adjusted_content_length + (ref.adjustment_scale * path_len)
        if sig.content_length == expected:
            return f"status={ref.status_code}, scaled length={sig.content_length} (adj={ref.adjusted_content_length} + {ref.adjustment_scale}*{path_len})"

    if "word_count" in stable and "line_count" in stable:
        if sig.word_count == ref.word_count and sig.line_count == ref.line_count:
            return f"status={ref.status_code}, words={sig.word_count}, lines={sig.line_count}"

    return None


# ---------------------------------------------------------------------------
# Known bad-site detection
# ---------------------------------------------------------------------------

def is_known_bad_site(sig: ResponseSignature) -> bool:
    """Filter known false-positive patterns from Google Cloud and AWS API Gateway."""
    if (sig.status_code == 400 and sig.content_length == 1555
            and sig.word_count == 82 and sig.line_count == 12):
        return True
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

    if sig.content_type != baseline_ref.content_type:
        parts.append(f"content-type: {baseline_ref.content_type} -> {sig.content_type}")

    if method_probe_status == 405:
        parts.append("method-sensitive: 405 Method Not Allowed")
    elif method_probe_status is not None and method_probe_status != sig.status_code:
        parts.append(f"method-sensitive: {method_probe_status} on alternate verb")

    if sig.status_code != baseline_ref.status_code:
        label = _status_label(sig.status_code)
        parts.append(f"status: {baseline_ref.status_code} -> {sig.status_code}{label}")

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
    high_signals = {"method-sensitive: 405 Method Not Allowed", "content-type:"}
    for part in reason_parts:
        for hs in high_signals:
            if part.startswith(hs):
                return "high"
    if len(reason_parts) >= 2:
        return "high"
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
    candidates = [m for m in _ALTERNATE_METHODS if m != original]
    return random.choice(candidates)


# ---------------------------------------------------------------------------
# Inference engine
# ---------------------------------------------------------------------------

class InferenceEngine:
    """Classifies candidate responses using baselines from a :class:`ScanTree`.

    The engine does not own the baseline tree — it reads from the ``ScanTree``
    passed at construction.  The tree handles route ordering, prefix probing,
    and baseline storage.

    ``send_fn`` signature::

        async (method: str, url: str, headers: dict | None, body: str | None)
            -> ResponseSignature
    """

    def __init__(
        self,
        tree: ScanTree,
        status_blacklist: set[int] | None = None,
        status_whitelist: set[int] | None = None,
        on_filtered=None,
    ) -> None:
        self._tree = tree
        self._status_blacklist = status_blacklist
        self._status_whitelist = status_whitelist
        self._on_filtered_cb = on_filtered

    def _on_filtered(self, route: Route, path: str, sig: ResponseSignature, reason: str) -> None:
        if self._on_filtered_cb:
            self._on_filtered_cb(route, path, sig, reason)

    def _filter_status(self, status: int) -> bool:
        if self._status_whitelist and status not in self._status_whitelist:
            return True
        if self._status_blacklist and status in self._status_blacklist:
            return True
        return False

    async def process(
        self,
        route: Route,
        sig: ResponseSignature,
        path: str,
        send_fn,
    ) -> Finding | None:
        """Classify a candidate response. Returns a :class:`Finding` or ``None``."""
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
        node = self._tree.lookup_baseline(path, method)
        if node is not None:
            prefix, baseline = node
            # Consume fresh boundary flag for this prefix — whether the route
            # matches or deviates.  If it deviates, it'll be reported as a
            # normal finding.  If it matches, report it as a boundary finding.
            is_fresh = self._tree.consume_fresh_boundary(prefix, method)
            match_reason = matches_baseline(sig, baseline, path_len)
            if match_reason is not None:
                if is_fresh:
                    # First route at a new handler boundary — report the
                    # boundary itself as a finding (e.g. "403 forbidden on
                    # a protected resource") even though children will be filtered.
                    baseline_ref = baseline.signatures[0]
                    reason_parts = _build_reason(sig, baseline_ref)
                    if not reason_parts:
                        reason_parts = [f"handler boundary at {prefix}"]
                    return Finding(
                        route=route, signature=sig,
                        reason=", ".join(reason_parts),
                        confidence="medium",
                    )
                self._on_filtered(route, path, sig, f"baseline match at {prefix}: {match_reason}")
                return None
            baseline_ref = baseline.signatures[0]
        else:
            baseline_ref = None

        # --- Verification phase ---
        if baseline_ref is None:
            return Finding(
                route=route, signature=sig,
                reason="no baseline available", confidence="low",
            )

        # Method change probe
        method_probe_status: int | None = None
        alt_method = _pick_alternate_method(route.method)
        try:
            method_sig = await send_fn(alt_method, path, None, None)
            method_probe_status = method_sig.status_code
        except Exception:
            pass

        # New headers check
        ref_headers = baseline_ref.header_names
        new_headers = sig.header_names - ref_headers
        new_headers -= {"date", "content-length", "transfer-encoding", "connection"}

        # --- Classification ---
        reason_parts = _build_reason(
            sig, baseline_ref,
            method_probe_status=method_probe_status,
            new_headers=new_headers if new_headers else None,
        )

        if not reason_parts:
            reason_parts = ["response differs from baseline"]

        confidence = _score_confidence(reason_parts)
        reason = ", ".join(reason_parts)

        return Finding(
            route=route, signature=sig,
            reason=reason, confidence=confidence,
        )
