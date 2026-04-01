# Scanner Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              CLI (__main__.py)                          │
│                                                                        │
│  Parses args, loads routes (.kite or wordlist), creates RequestTracker, │
│  ProgressTracker, calls scan().                                        │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                           scan() — scanner.py                          │
│                                                                        │
│  Creates: ScanTree, InferenceEngine, httpx.AsyncClient, worker pool    │
│  Owns:    priority queue, send_fn, rate limiter, scheduling            │
│                                                                        │
│  ┌──────────┐   ┌───────────────────┐   ┌────────────┐                │
│  │ ScanTree │   │ PriorityQueue     │──>│ Worker Pool│──> Results     │
│  │ (data)   │   │                   │   │ (N tasks)  │                │
│  │ baselines│   │ probes → routes   │   │            │                │
│  │ prefixes │   │ → recursive       │   │ feedback   │                │
│  └──────────┘   │ → lookahead       │   │ → queue    │                │
│                 └───────────────────┘   └────────────┘                │
└─────────────────────────────────────────────────────────────────────────┘
```

## Priority Queue Model

All work goes through a single `asyncio.PriorityQueue`:

```
PRIORITY    ITEM TYPE           DESCRIPTION
────────    ─────────           ───────────
0           Route (original)    Direct wordlist routes — highest value
1           ProbePrefix         Prefix probing for boundary detection
2           Route (recursive)   Routes injected under discovered boundaries
3+i         LookaheadProbe      Common segment probes, ordered by popularity
                                (api=3, v1=4, user=5, ... search=22)
```

Workers pull items in priority order. Original routes are processed first,
giving the operator results immediately. Recursive routes and lookahead
probes run at lower priority without blocking.

## Scheduling Flow

```
STARTUP
  1. tree.initialize(send_fn)     Root baselines (10 parallel probes)
  2. _seed_queue()                Synchronous tree traversal:
                                  - Depth-1 prefix probes enqueued at priority 1
                                  - Deeper probes parked in pending_children
                                  - Routes parked in pending_routes
                                  - Root routes enqueued at priority 0

WORKER PULLS ProbePrefix(prefix, depth)
  1. tree.probe_prefix()          Probes all methods, stores baselines
  2. If boundary found:
     - Emit collapsed boundary finding
     - If --recurse: enqueue recursive routes at priority 2
     - Enqueue child prefix probes at priority 1
  3. If no boundary + --lookahead + leaf node:
     - Enqueue lookahead probes at priority 3+i
  4. Release parked routes for this prefix at priority 0
  5. Release parked child probes

WORKER PULLS Route
  1. Render path/headers/body
  2. Send HTTP request
  3. Classify via InferenceEngine
  4. If finding: reactive probe_prefix (inline, idempotent)
  5. If redirect in scope: enqueue target at priority 0
  6. Emit findings

WORKER PULLS LookaheadProbe(prefix, segment)
  1. Send GET {prefix}/{segment}/{random}
  2. Check against all ancestor baselines
  3. If hit: enqueue ProbePrefix at priority 1
```

## Baseline Invariant

Routes are only enqueued AFTER their prefix probe completes. Child probes
are only enqueued AFTER their parent probe completes. This guarantees
`lookup_baseline()` finds the correct baseline when a route is classified.

```
ProbePrefix("/api")  completes → baseline stored
  ├── releases Route("/api/users")     → worker can classify
  ├── releases Route("/api/health")    → worker can classify
  └── releases ProbePrefix("/api/v1")  → child can now probe
        completes → baseline stored
          └── releases Route("/api/v1/login")
```

## Shared State

```
┌─────────────────────────────────────────────────────────────────────┐
│                       SHARED OBJECTS                                │
│                                                                    │
│  ┌──────────────────┐    All producers call plan()/tick():         │
│  │  RequestTracker   │                                             │
│  │  .plan(n)         │    tree.initialize()  ─── plan(10)          │
│  │  .plan_routes(n)  │    probe_prefix()     ─── plan(N)           │
│  │  .tick()          │    InferenceEngine     ── plan(N)           │
│  │  .sent/.planned   │    send_fn()          ─── tick()            │
│  └──────────────────┘                                              │
│                                                                    │
│  ┌──────────────────┐                                              │
│  │  ScanTree         │    Data only — no walk, no scheduling       │
│  │                   │                                             │
│  │  Written by:      │    .initialize()  (root baselines)          │
│  │                   │    .probe_prefix() (prefix baselines)       │
│  │  Read by:         │    InferenceEngine.process()                │
│  │                   │     └─ .lookup_baseline(path, method)       │
│  └──────────────────┘                                              │
│                                                                    │
│  ┌──────────────────┐                                              │
│  │  RateLimiter      │    asyncio.Lock serializes acquire()        │
│  │                   │    Called by send_fn() and _handle_route()  │
│  └──────────────────┘                                              │
└─────────────────────────────────────────────────────────────────────┘
```

## Concurrency

```
PARALLEL                                 SEQUENTIAL / ORDERED
────────                                 ────────────────────

Root init: 10 probes at once             Prefix probes before child probes
                                         (parent baseline needed for children)
Prefix probing: 5 methods per prefix
  all fired in parallel                  Routes after their prefix probe
                                         (baseline needed for classification)
Worker pool: N tasks process items
  concurrently from priority queue       Rate limiter serializes HTTP requests
                                         when --rate is set
All priority levels interleave:
  workers pull whatever is highest
  priority at any given moment
```
