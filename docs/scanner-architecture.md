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
│  Owns:    send_fn (HTTP bridge), rate limiter, connection tracking      │
│                                                                        │
│  ┌──────────┐   ┌──────────────┐   ┌────────────┐   ┌──────────────┐  │
│  │ ScanTree │──>│ asyncio.Queue│──>│ Worker Pool│──>│ Results      │  │
│  │ (walk)   │   │ (bounded)    │   │ (N tasks)  │   │ (on_result)  │  │
│  │ pushes   │   │              │   │            │   │              │  │
│  │ directly │   │              │   │            │   │              │  │
│  └──────────┘   └──────────────┘   └────────────┘   └──────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

## Concurrency Model

```
                    ┌─────────────────────────────────────┐
                    │      TREE WALK (concurrent tasks)   │
                    │                                     │
                    │  await tree.walk(send_fn, queue)    │
                    │                                     │
                    │  Pushes: Route | BoundaryProbe      │
                    │  Order:  depth-first per branch,    │
                    │          siblings concurrent         │
                    │          (asyncio.gather)            │
                    └────────────────┬────────────────────┘
                                     │
                          ┌──────────▼──────────┐
                          │   asyncio.Queue     │
                          │   maxsize = N × 2   │
                          │                     │
                          │   Backpressure:     │
                          │   put() blocks      │
                          │   branch walkers    │
                          │   when full         │
                          └──┬──┬──┬──┬──┬──┬───┘
                             │  │  │  │  │  │
              ┌──────────────┘  │  │  │  │  └──────────────┐
              ▼                 ▼  ▼  ▼  ▼                 ▼
        ┌──────────┐    ┌──────────────────────┐    ┌──────────┐
        │ Worker 1 │    │     Workers 2..N-1   │    │ Worker N │
        │          │    │                      │    │          │
        │ get()    │    │  (identical logic)    │    │ get()    │
        │ classify │    │                      │    │ classify │
        │ emit     │    │                      │    │ emit     │
        └──────────┘    └──────────────────────┘    └──────────┘
              │                                           │
              │         All workers share:                │
              │         • send_fn (HTTP via httpx)        │
              │         • RateLimiter (if --rate set)     │
              │         • InferenceEngine                 │
              │         • RequestTracker                  │
              └─────────────────┬─────────────────────────┘
                                ▼
                        ┌───────────────┐
                        │   on_result() │──> terminal, CSV, proxy replay
                        │  on_progress()│──> progress bar
                        └───────────────┘
```

## IPC / Shared State

```
┌─────────────────────────────────────────────────────────────────────┐
│                       SHARED OBJECTS                                │
│                                                                    │
│  ┌──────────────────┐    All three producers call plan()/tick():   │
│  │  RequestTracker   │                                             │
│  │                   │    ScanTree.initialize()  ─── plan(10)      │
│  │  .plan(n)  ◄──────┤    ScanTree._probe_node() ── plan(N)       │
│  │  .tick()   ◄──────┤    InferenceEngine ────────── plan(N)       │
│  │  .sent     ───────┤──> ProgressTracker reads sent/planned       │
│  │  .planned  ───────┤                                             │
│  │  .on_tick  ──────►│──> ProgressTracker.tick_request()           │
│  └──────────────────┘                                              │
│                                                                    │
│  ┌──────────────────┐                                              │
│  │  ScanTree         │    Owns: route tree + per-node baselines    │
│  │                   │                                             │
│  │  Written by:      │    .initialize()  (root baselines)          │
│  │                   │    ._probe_node() (intermediate baselines)  │
│  │  Read by:         │    InferenceEngine.process()                │
│  │                   │     └─ .lookup_baseline(path, method)       │
│  └──────────────────┘                                              │
│                                                                    │
│  ┌──────────────────┐                                              │
│  │  RateLimiter      │    asyncio.Lock serializes acquire()        │
│  │                   │                                             │
│  │  Called by:       │    send_fn() in every HTTP request          │
│  │                   │    (tree probes + route requests +          │
│  │                   │     verification probes)                    │
│  └──────────────────┘                                              │
│                                                                    │
│  ┌──────────────────┐                                              │
│  │  httpx.AsyncClient│    Single connection pool shared by all     │
│  │                   │    workers via send_fn closure               │
│  └──────────────────┘                                              │
└─────────────────────────────────────────────────────────────────────┘
```

## Parallelism Points

```
PARALLEL (asyncio.gather)                    SEQUENTIAL (awaited in order)
─────────────────────────                    ──────────────────────────────

Root init: 10 probes at once                 Prefix probing blocks branch:
  2 random × 5 methods                        node probed before children
                                               start (baseline invariant)
Prefix probing: 5 methods per node
  all fired in parallel                      Rate limiter lock: serializes
                                               all HTTP through one lock
Variance probes: N methods per node
  all fired in parallel

Sibling branches: walked concurrently
  via asyncio.gather — /api/v1/* and
  /api/v2/* explored in parallel

Alternate method probing: 4 methods
  per baseline-matched route

Worker pool: N routes processed
  concurrently from queue
```

## Data Flow Per Route

```
          Route from queue
               │
               ▼
    ┌─────────────────────┐
    │ render_path/query/   │
    │ headers/body         │   kite.py: expand crumbs to concrete values
    └──────────┬──────────┘
               │
               ▼
    ┌─────────────────────┐
    │ client.request()     │   httpx: actual HTTP call
    │ (via rate limiter)   │   tracker.tick() on completion
    └──────────┬──────────┘
               │
               ▼
    ┌─────────────────────┐
    │ compute_signature()  │   inference.py: extract status, content-type,
    │                      │   content-length, word/line count, headers
    └──────────┬──────────┘
               │
               ▼
    ┌─────────────────────┐
    │ engine.process()     │   inference.py: classify against baselines
    │                      │
    │  ┌─ pre-filter ─────┐│   status blacklist, known bad sites
    │  ├─ baseline match ─┤│   lookup_baseline() → matches_baseline()
    │  │   └─ alt methods ┤│   4 parallel probes (may add findings)
    │  ├─ verification ───┤│   method sensitivity, new headers
    │  └─ classification ─┘│   build reason, score confidence
    └──────────┬──────────┘
               │
          Finding | None
               │
               ▼
    ┌─────────────────────┐
    │ _finding_to_result() │   scanner.py: Finding → ScanResult
    │ _emit() → on_result()│   terminal output, CSV, proxy replay
    └─────────────────────┘
```

## Bottlenecks

```
BOTTLENECK                          WHERE                    WHY
──────────────────────────────────  ───────────────────────  ──────────────────────────
Prefix probing blocks branch        scantree.py:_probe_node  5-10 HTTP round-trips per
                                                             interior node before any
                                                             routes from that subtree
                                                             reach workers. Required by
                                                             baseline invariant.

Rate limiter lock contention        scanner.py:34            asyncio.Lock serializes all
                                                             rate-limited requests across
                                                             all workers + tree probes
```
