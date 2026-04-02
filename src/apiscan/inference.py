"""Inference-based API discovery engine.

Classifies HTTP responses by actively verifying handler behaviour under
perturbation.  This module has **no HTTP knowledge** — it receives response
data and emits probe requests via a caller-supplied ``send_fn`` callback.

The ``InferenceEngine`` reads baselines from a :class:`~apiscan.scantree.ScanTree`
and classifies both route responses and boundary probe discoveries through
the same pipeline.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING
from uuid import uuid4

logger = logging.getLogger(__name__)

from apiscan.kite import Route

if TYPE_CHECKING:
    from apiscan.scantree import BoundaryProbe, ScanTree


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ResponseSignature:
    """Captured signals from a single HTTP response."""

    status_code: int
    content_type: str
    content_length: int
    adjusted_content_length: int
    adjustment_scale: int
    word_count: int
    line_count: int
    header_names: frozenset[str]
    allow: str = ""


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
    reason: str
    confidence: str


# ---------------------------------------------------------------------------
# Signal extraction
# ---------------------------------------------------------------------------

def compute_signature(
    status_code: int,
    headers: dict[str, str],
    body: bytes,
    path: str,
) -> ResponseSignature:
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

    return ResponseSignature(
        status_code=status_code,
        content_type=content_type,
        content_length=content_length,
        adjusted_content_length=adjusted_content_length,
        adjustment_scale=adjustment_scale,
        word_count=word_count,
        line_count=line_count,
        header_names=frozenset(k.lower() for k in headers),
        allow=headers.get("allow", headers.get("Allow", "")),
    )


# ---------------------------------------------------------------------------
# Baseline construction & matching
# ---------------------------------------------------------------------------

_BASELINE_COMPARABLE = (
    "status_code", "content_type", "content_length",
    "adjusted_content_length", "word_count", "line_count",
)


def build_baseline(signatures: list[ResponseSignature]) -> Baseline:
    if not signatures:
        return Baseline()
    if len(signatures) == 1:
        return Baseline(signatures=list(signatures), stable_fields=set(_BASELINE_COMPARABLE))

    stable: set[str] = set()
    for f in _BASELINE_COMPARABLE:
        vals = {getattr(s, f) for s in signatures}
        if len(vals) == 1:
            stable.add(f)
    return Baseline(signatures=list(signatures), stable_fields=stable)


def matches_baseline(
    sig: ResponseSignature,
    baseline: Baseline,
    path_len: int,
) -> str | None:
    """Return a match reason string, or ``None`` if no match."""
    if not baseline.signatures:
        return None

    ref = baseline.signatures[0]
    stable = baseline.stable_fields

    if "status_code" in stable and sig.status_code != ref.status_code:
        return None
    if "content_type" in stable and sig.content_type != ref.content_type:
        return None

    if "content_length" in stable and sig.content_length == ref.content_length:
        return f"status={ref.status_code}, exact length={sig.content_length}"
    if "adjusted_content_length" in stable:
        expected = ref.adjusted_content_length + (ref.adjustment_scale * path_len)
        if sig.content_length == expected:
            return f"status={ref.status_code}, scaled length={sig.content_length}"

    if ("word_count" in stable and "line_count" in stable
            and sig.word_count == ref.word_count and sig.line_count == ref.line_count):
        return f"status={ref.status_code}, words={sig.word_count}, lines={sig.line_count}"

    return None


# ---------------------------------------------------------------------------
# Known bad-site detection
# ---------------------------------------------------------------------------

def is_known_bad_site(sig: ResponseSignature) -> bool:
    if (sig.status_code == 400 and sig.content_length == 1555
            and sig.word_count == 82 and sig.line_count == 12):
        return True
    if sig.status_code == 403:
        is_aws = "x-amzn-requestid" in sig.header_names
        if is_aws or (sig.line_count == 1 and sig.word_count == 6 and sig.content_length == 54):
            if sig.line_count == 1 and sig.word_count in (6, 13, 28):
                return True
    return False


# ---------------------------------------------------------------------------
# Reason building & confidence
# ---------------------------------------------------------------------------

def _build_reason(
    sig: ResponseSignature,
    baseline_ref: ResponseSignature,
    *,
    method_probe_status: int | None = None,
    allow_header: str = "",
    new_headers: frozenset[str] | None = None,
) -> list[str]:
    parts: list[str] = []
    if sig.content_type != baseline_ref.content_type:
        parts.append(f"content-type: {baseline_ref.content_type} -> {sig.content_type}")
    if method_probe_status == 405:
        label = f"method-sensitive: 405 Method Not Allowed"
        if allow_header:
            label += f" (allow: {allow_header})"
        parts.append(label)
    elif method_probe_status is not None and method_probe_status != sig.status_code:
        parts.append(f"method-sensitive: {method_probe_status} on alternate verb")
    if sig.status_code != baseline_ref.status_code:
        parts.append(f"status: {baseline_ref.status_code} -> {sig.status_code}{_status_label(sig.status_code)}")
    if new_headers:
        parts.append(f"new headers: {', '.join(sorted(new_headers)[:5])}")
    return parts


def _status_label(code: int) -> str:
    return {
        200: "", 201: " (created)", 204: " (no content)",
        301: " (moved)", 302: " (redirect)",
        400: " (bad request)", 401: " (auth required)", 403: " (forbidden)",
        405: " (method not allowed)", 422: " (validation error)",
        429: " (rate limited)", 500: " (server error)",
    }.get(code, "")


def _score_confidence(reason_parts: list[str]) -> str:
    for part in reason_parts:
        if part.startswith("method-sensitive: 405") or part.startswith("content-type:"):
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

DEFAULT_METHODS = ["GET", "POST"]


def _random_segment() -> str:
    return uuid4().hex[:16]


# ---------------------------------------------------------------------------
# Inference engine
# ---------------------------------------------------------------------------

class InferenceEngine:
    """Classifies route responses and boundary probes using baselines from a ScanTree."""

    def __init__(
        self,
        tree: ScanTree,
        status_blacklist: set[int] | None = None,
        status_whitelist: set[int] | None = None,
        on_filtered=None,
        tracker=None,
        methods: list[str] | None = None,
    ) -> None:
        self._tree = tree
        self._methods = methods or DEFAULT_METHODS
        self._status_blacklist = status_blacklist
        self._status_whitelist = status_whitelist
        self._on_filtered_cb = on_filtered
        self._tracker = tracker

    def _on_filtered(self, route: Route, path: str, sig: ResponseSignature, reason: str) -> None:
        if self._on_filtered_cb:
            self._on_filtered_cb(route, path, sig, reason)

    def _filter_status(self, status: int) -> bool:
        if self._status_whitelist and status not in self._status_whitelist:
            return True
        if self._status_blacklist and status in self._status_blacklist:
            return True
        return False

    # ------------------------------------------------------------------
    # Classify a boundary probe (from tree walk)
    # ------------------------------------------------------------------

    def classify_boundary(self, probe: BoundaryProbe) -> Finding | None:
        """Classify a handler boundary discovered during prefix probing."""
        if self._filter_status(probe.signature.status_code):
            return None
        if is_known_bad_site(probe.signature):
            return None

        reason_parts = _build_reason(probe.signature, probe.ancestor_signature)
        if not reason_parts:
            reason_parts = [f"handler boundary at {probe.prefix}"]

        return Finding(
            route=Route(template_path=probe.prefix, method=probe.method),
            signature=probe.signature,
            reason=f"probe: {', '.join(reason_parts)}",
            confidence=_score_confidence(reason_parts),
        )

    # ------------------------------------------------------------------
    # Classify a route response
    # ------------------------------------------------------------------

    def _matches_any_ancestor(
        self, sig: ResponseSignature, path: str, method: str, path_len: int,
    ) -> bool:
        """True if sig matches any baseline in the ancestor chain."""
        for bl in self._tree.ancestor_baselines(path, method):
            if matches_baseline(sig, bl, path_len) is not None:
                return True
        return False

    async def process(
        self,
        route: Route,
        sig: ResponseSignature,
        path: str,
        send_fn,
    ) -> list[Finding]:
        """Classify a candidate response.

        Returns a list of findings (empty if filtered).  Safe for
        concurrent calls from multiple workers.
        """
        # Pre-filters
        if self._filter_status(sig.status_code):
            self._on_filtered(route, path, sig, f"status filter: {sig.status_code}")
            return []
        if is_known_bad_site(sig):
            self._on_filtered(route, path, sig, f"known bad site: {sig.status_code}, length={sig.content_length}")
            return []

        # Baseline lookup
        path_len = len(path.lstrip("/"))
        node = self._tree.lookup_baseline(path, route.method)

        if node is None:
            logger.debug("%s %s: no baseline available", route.method, path)
            return [Finding(route=route, signature=sig,
                            reason="no baseline available", confidence="low")]

        prefix, baseline = node
        baseline_ref = baseline.signatures[0]
        logger.debug("%s %s: baseline at %s (status=%d, ct=%s, len=%d)",
                     route.method, path, prefix, baseline_ref.status_code,
                     baseline_ref.content_type, baseline_ref.content_length)

        # Check nearest baseline, then ancestors.
        # Nearest match → try alternate methods before filtering.
        # Ancestor match → filter (default handler leaking through).
        match_reason = matches_baseline(sig, baseline, path_len)
        if match_reason is not None:
            logger.debug("%s %s: matches nearest baseline (%s), trying alt methods",
                         route.method, path, match_reason)
            alt_findings = await self._try_alternate_methods(
                route, path, path_len, prefix, send_fn)
            if alt_findings:
                logger.debug("%s %s: alt methods found %d findings",
                             route.method, path, len(alt_findings))
                return alt_findings
            self._on_filtered(route, path, sig, f"baseline match at {prefix}: {match_reason}")
            return []

        if self._matches_any_ancestor(sig, path, route.method, path_len):
            logger.debug("%s %s: matches ancestor baseline, filtering", route.method, path)
            self._on_filtered(route, path, sig, "matches ancestor baseline")
            return []

        # Verification: method change probe
        if self._tracker:
            self._tracker.plan(1)
        method_probe_status: int | None = None
        method_allow: str = ""
        alt_method = [m for m in self._methods if m != route.method][0]
        try:
            method_sig = await send_fn(alt_method, path, None, None)
            method_probe_status = method_sig.status_code
            method_allow = method_sig.allow
            logger.debug("%s %s: verification %s -> status=%d, allow=%s",
                         route.method, path, alt_method, method_probe_status, method_allow)
        except Exception:
            logger.debug("%s %s: verification %s failed", route.method, path, alt_method)

        # Check for new headers
        new_headers = sig.header_names - baseline_ref.header_names
        new_headers -= {"date", "content-length", "transfer-encoding", "connection"}

        # Classification
        reason_parts = _build_reason(
            sig, baseline_ref,
            method_probe_status=method_probe_status,
            allow_header=method_allow,
            new_headers=new_headers if new_headers else None,
        )
        if not reason_parts:
            reason_parts = ["response differs from baseline"]

        confidence = _score_confidence(reason_parts)
        logger.debug("%s %s: finding -> reason=%s, confidence=%s",
                     route.method, path, ", ".join(reason_parts), confidence)

        return [Finding(
            route=route, signature=sig,
            reason=", ".join(reason_parts),
            confidence=confidence,
        )]

    # ------------------------------------------------------------------
    # Parallel alternate method probing
    # ------------------------------------------------------------------

    async def _try_alternate_methods(
        self,
        route: Route,
        path: str,
        path_len: int,
        match_prefix: str,
        send_fn,
    ) -> list[Finding]:
        """Probe all alternate HTTP methods in parallel.

        Returns findings grouped by distinct response: if POST and PUT both
        return 400, that's one finding with both methods in the reason.
        """
        alt_methods = [m for m in self._methods if m != route.method]
        if self._tracker:
            self._tracker.plan(len(alt_methods))

        async def _probe(method: str) -> tuple[str, ResponseSignature | None]:
            try:
                return method, await send_fn(method, path, None, None)
            except Exception:
                return method, None

        results = await asyncio.gather(*[_probe(m) for m in alt_methods])

        # Filter and check each against its method's baseline.
        # Skip methods whose baseline is more distant than the original
        # route's match — a root fallback means nothing new to discover.
        deviations: list[tuple[str, ResponseSignature, Baseline]] = []
        for method, sig in results:
            if sig is None:
                logger.debug("alt %s %s: probe failed", method, path)
                continue
            if self._filter_status(sig.status_code):
                logger.debug("alt %s %s: status-filtered (%d)", method, path, sig.status_code)
                continue
            if is_known_bad_site(sig):
                logger.debug("alt %s %s: known bad site", method, path)
                continue
            if self._matches_any_ancestor(sig, path, method, path_len):
                logger.debug("alt %s %s: matches ancestor baseline", method, path)
                continue

            node = self._tree.lookup_baseline(path, method)
            if node is None:
                logger.debug("alt %s %s: no baseline", method, path)
                continue
            bl_prefix, method_baseline = node
            if len(bl_prefix) < len(match_prefix):
                logger.debug("alt %s %s: baseline at %s more distant than match at %s",
                             method, path, bl_prefix, match_prefix)
                continue
            if matches_baseline(sig, method_baseline, path_len) is not None:
                logger.debug("alt %s %s: matches its own baseline at %s", method, path, bl_prefix)
                continue

            logger.debug("alt %s %s: deviation (status=%d, ct=%s, len=%d)",
                         method, path, sig.status_code, sig.content_type, sig.content_length)
            deviations.append((method, sig, method_baseline))

        if not deviations:
            return []

        # Group deviations by response fingerprint
        groups: dict[tuple[int, str, int], list[tuple[str, ResponseSignature, Baseline]]] = {}
        for method, sig, bl in deviations:
            key = (sig.status_code, sig.content_type, sig.content_length)
            groups.setdefault(key, []).append((method, sig, bl))

        # Build one finding per distinct response
        findings: list[Finding] = []
        for _, group in groups.items():
            methods_found = [m for m, _, _ in group]
            sig = group[0][1]
            baseline_ref = group[0][2].signatures[0]
            reason_parts = _build_reason(sig, baseline_ref)
            if not reason_parts:
                reason_parts = ["responds differently"]
            findings.append(Finding(
                route=replace(route, method=methods_found[0]),
                signature=sig,
                reason=f"via {', '.join(methods_found)}: {', '.join(reason_parts)}",
                confidence=_score_confidence(reason_parts),
            ))

        return findings
