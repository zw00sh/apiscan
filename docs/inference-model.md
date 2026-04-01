# Inference-Based API Discovery Model

## Core Principle

Instead of "learn what bad looks like, discard matches" (kiterunner model),
we **actively verify candidates by testing handler behaviour under perturbation**.

A real handler reacts differently to variations in method, parameters, and body.
A wildcard returns the same response regardless.

## Architecture

Three modules with clear responsibilities:

| Module | Owns | Reads |
|---|---|---|
| `scantree.py` | Route tree, baselines, prefix probing | — |
| `inference.py` | Response classification, verification | Baselines from ScanTree |
| `scanner.py` | HTTP transport, concurrency, rate limiting | — |

A shared `RequestTracker` object tracks planned/completed HTTP requests
across all three modules for accurate progress display.

## How It Works

### 1. Initialization

Root baselines established by probing `/{random}` × 2 for each HTTP method
(GET, POST, PUT, DELETE, PATCH) — 10 parallel requests. Captures the
default handler response per verb.

### 2. Priority Queue Scheduling

All work goes through a single priority queue, ordered by expected value:

1. **Original routes** (priority 0) — direct wordlist hits, processed first.
2. **Prefix probes** (priority 1) — send `/{prefix}/{random}` per method.
   If the response differs from ancestor baselines, register a new baseline
   and emit a `BoundaryGroup` finding. Routes are parked until their prefix
   probe completes (baseline invariant).
3. **Recursive routes** (priority 2, if `--recurse` enabled) — when a
   boundary is found, re-apply the entire wordlist under that prefix.
   Controlled by `--max-depth`.
4. **Lookahead probes** (priority 3+i, if `--lookahead` enabled) — probe
   common path segments one level deeper at leaf nodes to discover hidden
   N+1 boundaries. Ordered by segment popularity (`api` first, then `v1`,
   etc.).

Workers pull the highest-priority item available. The operator sees original
route findings before recursive or exploratory results.

### 3. Route Classification

For each route response, the inference engine:

1. **Pre-filters**: status blacklist/whitelist, known bad-site patterns
2. **Baseline comparison**: lookup nearest ancestor baseline for this
   (path, method). If match → try alternate methods before discarding.
3. **Alternate method probing**: fire all 4 alternate methods in parallel.
   Compare each against that method's baseline at the same prefix. Group
   deviations by response fingerprint. Only probe methods with a baseline
   at the route's prefix (not distant root fallbacks).
4. **Verification**: for routes that deviate from baseline, send one
   alternate method probe for method-sensitivity detection (405 = high
   confidence). Check for new response headers.
5. **Classification**: build reason from accumulated signals, score
   confidence (high/medium/low).

### 4. Signal Tiers

**Tier 1 — Baseline comparison (always checked):**
- Status code (exact match, no range tolerance)
- Content-Type change (handler boundary signal)
- Content-Length (exact or path-scaled)
- Word + line count (fallback)

**Tier 2 — Verification (on deviations):**
- 405 Method Not Allowed (definitive)
- New response headers vs baseline
- Alternate method status change

**Tier 3 — Pre-filters (before pipeline):**
- Status blacklist/whitelist
- Google Cloud 400 pattern
- AWS Gateway 403 pattern

### 5. Baseline Stability

Each baseline tracks `stable_fields` — which response characteristics were
identical across multiple probes. Only stable fields are used for
comparison. If content-length varied between probes, it's excluded from
matching.

Method fallback: only at root (where all methods are explicitly probed).
Intermediate nodes don't fall back to GET — different methods may have
different handler behaviour.

## Comparison with Kiterunner

| Aspect | Kiterunner | apiscan |
|---|---|---|
| Baseline construction | Upfront preflight per prefix | Lazy, depth-first tree walk |
| Baseline granularity | Per depth-1 prefix | Per handler boundary (tree) |
| Method handling | Safe mode (GET only) or all | Always sends schema method |
| Method awareness | None | Per-method baselines + alternate method probing |
| Soft 404 handling | Length/word/line heuristics | Content-type + status as first-class signals |
| Gateway/multi-service | Single baseline | Tree adapts to handler boundaries |
| Classification output | Binary (finding or not) | Finding with reason + confidence |
| Request tracking | None | RequestTracker with planned/sent counts |

## See Also

- `docs/inference-pipeline.md` — detailed pipeline diagram with all code paths
