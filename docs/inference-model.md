# Inference-Based API Discovery Model

## Core Principle

Instead of "learn what bad looks like, discard matches" (kiterunner model),
we **actively verify candidates by testing handler behaviour under perturbation**.

A real handler reacts differently to variations in method, parameters, and body.
A wildcard returns the same response regardless.

## Implementation

The inference engine is implemented in `src/apiscan/inference.py` with no HTTP
knowledge — it receives `ResponseSignature` objects and emits probe requests
via a caller-supplied `send_fn` callback.

### Data Structures

```python
ResponseSignature           # captured signals from one HTTP response
  status_code: int
  content_type: str         # parsed, lowercase, no params (e.g. "application/json")
  content_length: int
  adjusted_content_length   # body with path string removed
  adjustment_scale          # times path appears in body
  word_count: int
  line_count: int
  header_names: frozenset   # lowercase header names present

Baseline                    # stable response characteristics for a handler boundary
  signatures: list          # from multiple probes
  stable_fields: set        # which fields were consistent across probes

Finding                     # a verified route discovery
  route: Route
  signature: ResponseSignature
  reason: str               # human-readable explanation
  confidence: str           # "high", "medium", "low"
```

## Architecture

```
.kite routes (seeds)
       |
       v
+-----------------+
|  Initial Probe  |  Send candidate request with schema method
+-----------------+
       |
       v
+--------------------+
|  Pre-filters       |  Status blacklist/whitelist, known bad sites
+--------------------+
       |
  filtered? ----------> discard
       |
       v
+-----------------------+
|  Baseline Tree Lookup |  Compare against nearest ancestor baseline
+-----------------------+
       |
  matches baseline? -----> discard (wildcard)
       |
  no match
       |
       v
+------------------------+
|  Verification Phase    |
+------------------------+
  |                  |
  v                  v
random             method
sibling            change
  |                  |
  v                  v
+-----------------------------------+
|  Classify: sibling similar to     |
|  candidate? -> new handler        |
|  boundary, re-compare.            |
|  Method probe -> 405? high conf.  |
|  Accumulate reason + confidence.  |
+-----------------------------------+
       |            |
   reasons      no reasons
   found        found
       |            |
       v            v
   FINDING     FINDING (low conf,
   with          "response differs
   reason        from baseline")
```

## Inference Rules (as implemented)

### Step 1: Pre-filters

Applied before baseline comparison. Any match -> discard immediately.

| Filter                  | Rule                                                    |
|-------------------------|---------------------------------------------------------|
| Status blacklist        | `status_code in blacklist` -> discard                   |
| Status whitelist        | `status_code not in whitelist` -> discard               |
| Google Cloud bad request | status=400, length=1555, words=82, lines=12            |
| AWS API Gateway         | status=403, `x-amzn-requestid` header, words in {6,13,28} |

### Step 2: Baseline comparison

Compare candidate `ResponseSignature` against the nearest ancestor in
the `BaselineTree`. Only **stable fields** (consistent across multiple
probes) are used for comparison.

| Check                    | Logic                                                   | Result          |
|--------------------------|---------------------------------------------------------|-----------------|
| Status out of range      | `abs(candidate - baseline) >= 50`                       | Skip baseline   |
| Content-Type changed     | `candidate.content_type != baseline.content_type`       | Not a match     |
| Exact length match       | `candidate.length == baseline.length`                   | Match (discard) |
| Scaled length match      | `length == adjusted + (scale * path_len)`               | Match (discard) |
| Word+line count match    | Both word and line count equal                          | Match (discard) |
| None of the above        | Falls through all checks                                | Not a match     |

**Key rule**: Content-Type change *prevents* matching even if lengths are
identical. This is the primary mechanism for detecting handler boundaries
(gateway returns `text/html`, API service returns `application/json`).

### Step 3: Verification probes

When a candidate deviates from baseline, two probes are sent:

#### 3a. Random sibling probe

Send `GET /{parent_prefix}/{random_hex}` to test if the parent path is a
new handler boundary.

| Sibling result         | Action                                                   |
|------------------------|----------------------------------------------------------|
| Similar to candidate   | Register new handler boundary at parent prefix.          |
|                        | Send a second random probe for variance detection.       |
|                        | Re-compare candidate against new baseline.               |
|                        | If still deviates -> continue to step 3b.                |
|                        | If matches -> discard.                                   |
| Different from candidate | Candidate is likely a real route.                       |
|                        | Also check if sibling reveals a previously unknown       |
|                        | handler boundary (differs from existing baseline).       |

"Similar" is defined as: same status code, same content-type, and
content-length within `path_len * 3` of each other.

#### 3b. Method change probe

Send an alternate HTTP method to the same path (randomly selected from
GET/POST/PUT/DELETE/PATCH, excluding the original method).

| Method probe result    | Signal                                                   |
|------------------------|----------------------------------------------------------|
| 405 response           | **Definitive** — method-aware routing, high confidence   |
| Different status       | Supporting evidence for real handler                     |
| Same as original       | No additional signal                                     |

### Step 4: Classification

Reason strings are accumulated from all signals that fired:

| Signal                          | Reason string format                                |
|---------------------------------|-----------------------------------------------------|
| Content-Type change             | `"content-type: text/html -> application/json"`     |
| Method sensitivity (405)        | `"method-sensitive: 405 Method Not Allowed"`        |
| Method sensitivity (other)      | `"method-sensitive: {status} on alternate verb"`    |
| Status divergence               | `"status: 404 -> 200"` (with label if known)       |
| New response headers            | `"new headers: x-request-id, x-ratelimit-remaining"` |

Status labels: `(created)`, `(no content)`, `(moved)`, `(redirect)`,
`(bad request)`, `(auth required)`, `(forbidden)`, `(method not allowed)`,
`(validation error)`, `(rate limited)`, `(server error)`.

Common variable headers (`date`, `content-length`, `transfer-encoding`,
`connection`) are excluded from the new-headers check.

If no specific reasons are identified but the response still differs from
baseline, the fallback reason is `"response differs from baseline"`.

### Confidence scoring

| Condition                                      | Confidence |
|------------------------------------------------|------------|
| 405 on method change                           | high       |
| Content-type change from baseline              | high       |
| Two or more reason parts                       | high       |
| Status divergence to 200, 201, 204, 401, 403   | medium     |
| Everything else                                | low        |

## Baseline Tree

Baselines are discovered lazily, driven by findings rather than upfront
preflighting. The tree (`BaselineTree`) is a dict keyed by path prefix.

### Initialization

At scan start, 3 probes are sent to `/{random_hex}` to establish the root
baseline at `/`. Variance across these probes determines which fields are
stable.

### Lazy growth

New nodes are added when verification probes reveal handler boundaries:

```
1. Scan starts
   Root baseline: GET /{random} x3 -> 404 text/html
   Tree: { "/" : Baseline(404, text/html, stable={all}) }

2. Candidate GET /api/v1/users -> 200 application/json
   Doesn't match "/" baseline (content-type differs)

   Sibling: GET /api/v1/{random} -> 404 application/json
   Sibling NOT similar to candidate (status differs)
   But sibling differs from "/" baseline -> new handler boundary

   Tree: { "/": ..., "/api/v1": Baseline(404, application/json, ...) }

   Re-compare candidate against /api/v1: status 200 vs 404, out of range
   -> continues to verification -> FINDING

3. Candidate GET /api/v1/orders -> 404 application/json
   Matches /api/v1 baseline -> discard
```

### Lookup

`BaselineTree.lookup(path)` walks from the longest matching prefix to
the shortest. For `/api/v1/users/123`, it checks:
`/api/v1/users/123` -> `/api/v1/users` -> `/api/v1` -> `/api` -> `/`

### Baseline stability

Each `Baseline` tracks `stable_fields` — the set of field names that
were identical across all probe responses. Only stable fields participate
in `matches_baseline()`. If content-length varied between probes, it's
excluded, preventing false matches on targets with non-deterministic responses.

```
Comparable fields: status_code, content_type, content_length,
                   adjusted_content_length, word_count, line_count
```

## Module Boundaries

| Module        | Responsibility                                    |
|---------------|---------------------------------------------------|
| `inference.py` | Baseline tree, signal evaluation, classification. No HTTP. |
| `scanner.py`  | Async HTTP transport, concurrency, rate limiting.  |
| `kite.py`     | .kite parsing, crumb rendering, keyword filter.    |
| `output.py`   | Terminal formatting, CSV, progress tracking.       |

The bridge between scanner and inference is `send_fn`:
```
async (method: str, url: str, headers: dict | None, body: str | None)
    -> ResponseSignature
```

Scanner wraps `httpx.AsyncClient.request` + semaphore + rate limiter behind
this callback. Inference calls it for verification probes without knowing
anything about the HTTP layer.

## Comparison with Kiterunner Model

| Aspect                  | Kiterunner (static baseline)         | Inference (active verification)      |
|-------------------------|--------------------------------------|--------------------------------------|
| Baseline construction   | Upfront preflight per prefix         | Lazy, discovered during scan         |
| Baseline granularity    | Per depth-1 prefix                   | Per handler boundary (tree)          |
| Method handling         | Safe mode downgrades to GET          | Always sends schema method           |
| Method awareness        | None (baselines merge all methods)   | Method variation is a probe signal   |
| Soft 404 handling       | Length/word/line heuristics           | Content-type + perturbation testing  |
| Gateway/multi-service   | Single baseline, high false positive | Tree adapts to handler boundaries    |
| Requests per route      | 1 (plus preflight overhead)          | 1-4 (but only ~20% need >1)         |
| Classification output   | Binary: finding or not               | Finding with reason + confidence     |
| False positive rate     | High on complex targets              | Low (verified by behaviour)          |
| False negative rate     | High for method-routed endpoints     | Low (tests method sensitivity)       |
