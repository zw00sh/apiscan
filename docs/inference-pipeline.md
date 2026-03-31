# Inference Pipeline

## Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                          SCAN TREE                                  │
│                                                                     │
│  Routes organised by path segments, depth-first iteration.          │
│  At each node: probe for baselines, yield events, recurse.          │
│                                                                     │
│  ┌─────────────┐    ┌──────────────────┐    ┌────────────────────┐  │
│  │ initialize()│───>│ Root baselines   │    │ Per-method probes  │  │
│  │             │    │ 5 methods × 2    │    │ at each prefix     │  │
│  │ 10 parallel │    │ random probes    │    │ (parallel)         │  │
│  │ probes      │    │                  │    │                    │  │
│  └─────────────┘    │ /{random} × 2   │    │ /{prefix}/{random} │  │
│                     │ per method       │    │ for GET/POST/PUT/  │  │
│                     │                  │    │ DELETE/PATCH        │  │
│                     │                  │    │                    │  │
│                     └──────────────────┘    └────────┬───────────┘  │
│                                                       │             │
│                                              differs from ancestor? │
│                                              no ──> skip            │
│                                              yes ──> store baseline │
│                                                       │             │
│                          depth-first walk             │             │
│                              │                        │             │
│                    ┌─────────┴──────────┐             │             │
│                    ▼                    ▼             ▼             │
│             BoundaryProbe          Route          (next node)       │
└─────────────┬──────────────────────┬────────────────────────────────┘
              │                      │
              ▼                      ▼
┌─────────────────────┐   ┌──────────────────────────────────────────┐
│ classify_boundary() │   │              process()                   │
│                     │   │                                          │
│ Pre-filters:        │   │ ┌──────────────────────────────────┐     │
│ • status blacklist  │   │ │         PRE-FILTERS              │     │
│ • known bad sites   │   │ │                                  │     │
│                     │   │ │ • Status blacklist/whitelist     │     │
│ Build reason from   │   │ │ • Known bad site patterns        │     │
│ sig vs ancestor:    │   │ │   (Google Cloud, AWS Gateway)    │     │
│ • content-type      │   │ │                                  │     │
│ • status change     │   │ │ filtered ──> on_filtered()       │     │
│ • new headers       │   │ └──────────────┬───────────────────┘     │
│                     │   │                │                         │
│ ──> Finding         │   │                ▼                         │
│   (probe: reason)   │   │ ┌──────────────────────────────────┐     │
│                     │   │ │      BASELINE COMPARISON         │     │
└──────────┬──────────┘   │ │                                  │     │
           │              │ │ lookup nearest ancestor baseline │     │
           │              │ │ for this (path, method)          │     │
           │              │ │                                  │     │
           │              │ │ match? ───────────┐              │     │
           │              │ │                   ▼              │     │
           │              │ │          ┌─────────────────┐     │     │
           │              │ │          │ TRY ALTERNATE   │     │     │
           │              │ │          │ METHODS         │     │     │
           │              │ │          │                 │     │     │
           │              │ │          │ Fire all 4 alt  │     │     │
           │              │ │          │ methods parallel│     │     │
           │              │ │          │                 │     │     │
           │              │ │          │ For each:       │     │     │
           │              │ │          │ • pre-filter    │     │     │
           │              │ │          │ • compare vs    │     │     │
           │              │ │          │   method's own  │     │     │
           │              │ │          │   baseline      │     │     │
           │              │ │          │                 │     │     │
           │              │ │          │ Group by        │     │     │
           │              │ │          │ (status, ct,    │     │     │
           │              │ │          │  length)        │     │     │
           │              │ │          │                 │     │     │
           │              │ │          │ deviations? ────┼──> [Finding]
           │              │ │          │ none? ──────────┼──> on_filtered()
           │              │ │          └─────────────────┘     │     │
           │              │ │                                  │     │
           │              │ │ no match                         │     │
           │              │ │    │                             │     │
           │              │ └────┼─────────────────────────────┘     │
           │              │      ▼                                   │
           │              │ ┌──────────────────────────────────┐     │
           │              │ │       VERIFICATION               │     │
           │              │ │                                  │     │
           │              │ │ Method change probe:             │     │
           │              │ │   send alt method to same path   │     │
           │              │ │   405 ──> high confidence        │     │
           │              │ │                                  │     │
           │              │ │ Header comparison:               │     │
           │              │ │   new headers vs baseline        │     │
           │              │ │   (excl date, content-length,    │     │
           │              │ │    transfer-encoding, connection)│     │
           │              │ └──────────────┬───────────────────┘     │
           │              │                │                         │
           │              │                ▼                         │
           │              │ ┌──────────────────────────────────┐     │
           │              │ │       CLASSIFICATION             │     │
           │              │ │                                  │     │
           │              │ │ Build reason from signals:       │     │
           │              │ │ • content-type change    (high)  │     │
           │              │ │ • 405 method not allowed (high)  │     │
           │              │ │ • alt method status diff         │     │
           │              │ │ • status code deviation          │     │
           │              │ │ • new response headers           │     │
           │              │ │                                  │     │
           │              │ │ Confidence:                      │     │
           │              │ │ • high: 405, content-type, 2+    │     │
           │              │ │ • medium: 200/201/204/401/403    │     │
           │              │ │ • low: everything else           │     │
           │              │ └──────────────┬───────────────────┘     │
           │              │                │                         │
           │              │                ▼                         │
           │              │           Finding                        │
           │              └──────────────┬───────────────────────────┘
           │                             │
           ▼                             ▼
┌────────────────────────────────────────────────────────────────────┐
│                          SCANNER                                   │
│                                                                    │
│  _finding_to_result(finding) ──> ScanResult                        │
│                                                                    │
│  ──> on_result()    (terminal output, CSV, proxy replay)           │
│  ──> on_progress()  (progress bar update)                          │
└────────────────────────────────────────────────────────────────────┘
```

## Signal Tiers

```
TIER 1 — Always checked (baseline comparison)
┌────────────────────────────┬───────────────────────────────────┐
│ Status code match          │ Different code = different handler│
│ Content-Type match         │ html → json = handler boundary    │
│ Content-Length exact       │ Same bytes = same handler         │
│ Content-Length scaled      │ Adjusted for path echo in body    │
│ Word + line count          │ Fallback body shape comparison    │
└────────────────────────────┴───────────────────────────────────┘

TIER 2 — Checked during verification
┌────────────────────────────┬──────────────────────────────────┐
│ 405 Method Not Allowed     │ Definitive method-aware routing  │
│ New response headers       │ Different service/middleware     │
│ Alt method status change   │ Supporting evidence              │
└────────────────────────────┴──────────────────────────────────┘

TIER 3 — Filtered before reaching pipeline
┌────────────────────────────┬──────────────────────────────────┐
│ Status blacklist/whitelist │ User-configured filtering        │
│ Google Cloud 400 pattern   │ 400/1555B/82W/12L                │
│ AWS Gateway 403 pattern    │ 403 + x-amzn-requestid header    │
└────────────────────────────┴──────────────────────────────────┘
```

## Module Responsibilities

```
scantree.py     Route ordering, baseline storage, prefix probing
                Yields: Route | BoundaryProbe
                Owns: tree structure, baselines, initialization probes

inference.py    Response classification (stateless w.r.t. HTTP)
                Reads: baselines from ScanTree
                Produces: Finding | None
                Methods: classify_boundary(), process()

scanner.py      HTTP transport, concurrency, rate limiting
                Consumes: Route | BoundaryProbe from tree walk
                Produces: ScanResult via _finding_to_result()
                Owns: httpx client, worker pool, send_fn
```
