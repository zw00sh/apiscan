#!/usr/bin/env python3
"""Build ranked API wordlists from multiple sources.

Sources:
  - routes-large.json  (kiterunner Swagger/OpenAPI specs)
  - httparchive_apiroutes_*.txt
  - unique.txt
  - raft-small-directories.txt

Output:
  kites/api-top-1k.txt
  kites/api-top-10k.txt
  kites/api-top-100k.txt

Ranking: paths are scored by how many independent sources they appear in,
then by total frequency across all sources.  Cross-source hits are weighted
heavily — a path in 3 sources ranks above a path seen 1000 times in 1 source.
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

KITES_DIR = Path(__file__).resolve().parent.parent / "kites"

# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

# Segments that look like IDs / values rather than route names
_NUMERIC_RE = re.compile(r"^\d+$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEX_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)
_PARAM_RE = re.compile(r"^\{[^}]+\}$")  # Swagger {param}
_COLON_PARAM_RE = re.compile(r"^:[a-zA-Z]")  # Express :param
_VERSION_RE = re.compile(r"^v?\d+(\.\d+)*(-\w+)?$", re.I)  # v1, 0.1.6-SNAPSHOT

# Paths to skip entirely
_SKIP_PATTERNS = [
    re.compile(r"\.\.", re.I),           # traversal
    re.compile(r"^/%[0-9a-f]{2}", re.I), # encoded traversal
    re.compile(r"^\$"),                   # $BASEPATH$ etc.
    re.compile(r"\.(jpg|jpeg|png|gif|ico|svg|woff2?|ttf|eot|css|map)$", re.I),  # static assets
]

# Max path depth — anything deeper than 8 segments is almost certainly noise
_MAX_DEPTH = 8


def _is_id_segment(seg: str) -> bool:
    """True if this path segment looks like a dynamic value."""
    if _PARAM_RE.match(seg):
        return True
    if _COLON_PARAM_RE.match(seg):
        return True
    if _NUMERIC_RE.match(seg) and len(seg) >= 2:
        return True  # single digits (0, 1, 2) kept — often version prefixes
    if _UUID_RE.match(seg):
        return True
    if _HEX_RE.match(seg):
        return True
    return False


def _should_skip(path: str) -> bool:
    for pat in _SKIP_PATTERNS:
        if pat.search(path):
            return True
    return False


def normalize_path(raw: str) -> str | None:
    """Normalize a path: strip params, lowercase, deduplicate slashes.

    Returns None if the path should be skipped entirely.
    """
    path = raw.strip()
    if not path:
        return None

    # Ensure leading slash
    if not path.startswith("/"):
        path = "/" + path

    # Strip query string and fragment
    path = path.split("?")[0].split("#")[0]

    # Skip junk
    if _should_skip(path):
        return None

    # Split, normalize segments
    parts = path.strip("/").split("/")
    if len(parts) > _MAX_DEPTH:
        return None

    normalized: list[str] = []
    for seg in parts:
        seg = seg.strip()
        if not seg:
            continue
        if _is_id_segment(seg):
            # Replace with placeholder — we'll generate both versions
            normalized.append(":id")
        else:
            normalized.append(seg.lower())

    if not normalized:
        return None

    return "/" + "/".join(normalized)


def expand_path(path: str) -> list[str]:
    """Expand a normalized path into variants for ranking.

    A path like /api/v1/users/:id/posts produces:
      /api
      /api/v1
      /api/v1/users
      /api/v1/users/:id/posts   (full path with placeholder)

    Intermediate prefixes get partial credit (they're real route prefixes).
    The full path gets full credit.
    """
    parts = path.strip("/").split("/")
    results: list[str] = []

    # Full path always included
    results.append(path)

    # Static prefixes (stop at first :id, skip single-char segments)
    prefix_parts: list[str] = []
    for part in parts:
        if part == ":id":
            break
        prefix_parts.append(part)
        prefix = "/" + "/".join(prefix_parts)
        if prefix != path and len(prefix) > 2:  # skip /<single-char> prefixes
            results.append(prefix)

    return results


# ---------------------------------------------------------------------------
# Source loaders
# ---------------------------------------------------------------------------

def load_routes_large_json(path: Path) -> Counter[str]:
    """Extract paths from kiterunner's Swagger/OpenAPI JSON dump."""
    counts: Counter[str] = Counter()
    with open(path) as f:
        data = json.load(f)

    for spec in data:
        spec_paths = spec.get("paths", {})
        for raw_path in spec_paths:
            norm = normalize_path(raw_path)
            if norm:
                for variant in expand_path(norm):
                    counts[variant] += 1

    return counts


def load_flat_wordlist(path: Path) -> Counter[str]:
    """Load a flat wordlist (one path per line)."""
    counts: Counter[str] = Counter()
    with open(path) as f:
        for line in f:
            norm = normalize_path(line)
            if norm:
                for variant in expand_path(norm):
                    counts[variant] += 1
    return counts


def load_raft(path: Path) -> Counter[str]:
    """Load RAFT directory names (no leading slash, single segments)."""
    counts: Counter[str] = Counter()
    with open(path) as f:
        for line in f:
            seg = line.strip().lower()
            if not seg or seg.startswith("#"):
                continue
            if _should_skip(seg):
                continue
            norm = "/" + seg
            counts[norm] += 1
    return counts


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def merge_and_rank(
    source_counts: list[tuple[str, Counter[str]]],
) -> list[tuple[str, float, int]]:
    """Merge sources and rank paths.

    Scoring:
      score = (num_sources ** 2) * 1000 + log_frequency

    Cross-source appearance dominates. Within a source tier, higher
    frequency wins.

    Returns sorted list of (path, score, num_sources).
    """
    import math

    # Collect per-path data
    path_sources: dict[str, set[str]] = {}
    path_total: Counter[str] = Counter()

    for source_name, counts in source_counts:
        for path, count in counts.items():
            path_sources.setdefault(path, set()).add(source_name)
            path_total[path] += count

    # Score
    scored: list[tuple[str, float, int]] = []
    for path, sources in path_sources.items():
        n_sources = len(sources)
        freq = path_total[path]
        score = (n_sources ** 2) * 10000 + math.log1p(freq) * 100
        scored.append((path, score, n_sources))

    scored.sort(key=lambda x: (-x[1], x[0]))
    return scored


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------

def _is_api_relevant(path: str) -> bool:
    """Filter out paths that are clearly not API routes."""
    parts = path.strip("/").split("/")

    # Skip single-char paths (noise from prefix expansion)
    if len(parts) == 1 and len(parts[0]) <= 1:
        return False

    # Skip paths that are clearly static file patterns
    last = parts[-1] if parts else ""
    if "." in last:
        ext = last.rsplit(".", 1)[-1].lower()
        # Allow API-like extensions
        if ext not in ("json", "xml", "yaml", "yml", "graphql", "gql", "php",
                        "asp", "aspx", "jsp", "do", "action", "cgi", "pl",
                        "py", "rb", "go", "rs", "ts", "js"):
            # Most other extensions are static files
            if ext in ("html", "htm", "txt", "md", "pdf", "doc", "docx",
                       "xls", "xlsx", "csv", "zip", "tar", "gz", "bz2",
                       "rar", "7z", "exe", "dll", "so", "bin", "dat",
                       "log", "bak", "old", "tmp", "swp", "swo"):
                return False

    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("Loading sources...", file=sys.stderr)

    sources: list[tuple[str, Counter[str]]] = []

    # 1. routes-large.json
    json_tar = KITES_DIR / "routes-large.json.tar.gz"
    json_path = Path("/tmp/routes-large.json")
    if json_path.exists():
        print(f"  routes-large.json: loading...", file=sys.stderr, end="", flush=True)
        counts = load_routes_large_json(json_path)
        print(f" {len(counts)} paths", file=sys.stderr)
        sources.append(("swagger", counts))
    elif json_tar.exists():
        import subprocess
        subprocess.run(["tar", "-xzf", str(json_tar), "-C", "/tmp/"], check=True)
        print(f"  routes-large.json: loading...", file=sys.stderr, end="", flush=True)
        counts = load_routes_large_json(json_path)
        print(f" {len(counts)} paths", file=sys.stderr)
        sources.append(("swagger", counts))
    else:
        print("  routes-large.json: not found, skipping", file=sys.stderr)

    # 2. httparchive
    for p in sorted(KITES_DIR.glob("httparchive_apiroutes_*.txt")):
        print(f"  {p.name}: loading...", file=sys.stderr, end="", flush=True)
        counts = load_flat_wordlist(p)
        print(f" {len(counts)} paths", file=sys.stderr)
        sources.append(("httparchive", counts))

    # 3. unique.txt
    unique_path = KITES_DIR / "unique.txt"
    if unique_path.exists():
        print(f"  unique.txt: loading...", file=sys.stderr, end="", flush=True)
        counts = load_flat_wordlist(unique_path)
        print(f" {len(counts)} paths", file=sys.stderr)
        sources.append(("unique", counts))

    # 4. raft-small-directories
    raft_path = KITES_DIR / "raft-small-directories.txt"
    if raft_path.exists():
        print(f"  raft-small-directories.txt: loading...", file=sys.stderr, end="", flush=True)
        counts = load_raft(raft_path)
        print(f" {len(counts)} paths", file=sys.stderr)
        sources.append(("raft", counts))

    # 5. SecLists API wordlists
    seclists_files = [
        ("seclists-endpoints", "api-endpoints.txt"),
        ("seclists-wild", "api-seen-in-wild.txt"),
    ]
    for source_name, filename in seclists_files:
        p = KITES_DIR / filename
        if p.exists():
            print(f"  {filename}: loading...", file=sys.stderr, end="", flush=True)
            counts = load_flat_wordlist(p)
            print(f" {len(counts)} paths", file=sys.stderr)
            sources.append((source_name, counts))

    if not sources:
        print("No sources found!", file=sys.stderr)
        sys.exit(1)

    # Merge and rank
    print(f"\nMerging {len(sources)} sources...", file=sys.stderr)
    ranked = merge_and_rank(sources)
    print(f"Total unique paths: {len(ranked)}", file=sys.stderr)

    # Filter to API-relevant
    ranked = [(p, s, n) for p, s, n in ranked if _is_api_relevant(p)]
    print(f"After API-relevance filter: {len(ranked)}", file=sys.stderr)

    # Remove :id paths for the output wordlists (apiscan doesn't fuzz params)
    # but keep paths that have :id in the middle with static suffixes
    # e.g. /api/v1/users/:id/posts → keep (the static suffix matters)
    #       /api/v1/users/:id → drop (nothing useful after the param)
    def _useful_path(path: str) -> bool:
        parts = path.strip("/").split("/")
        if not parts:
            return False
        # Drop if last segment is :id (terminal param)
        if parts[-1] == ":id":
            return False
        return True

    ranked = [(p, s, n) for p, s, n in ranked if _useful_path(p)]
    print(f"After param-terminal filter: {len(ranked)}", file=sys.stderr)

    # Source distribution
    for threshold in [1, 2, 3, 4]:
        count = sum(1 for _, _, n in ranked if n >= threshold)
        print(f"  In {threshold}+ sources: {count}", file=sys.stderr)

    # Write tiers
    tiers = [
        ("api-top-1k.txt", 1000),
        ("api-top-10k.txt", 10000),
        ("api-top-100k.txt", 100000),
    ]

    for filename, limit in tiers:
        out_path = KITES_DIR / filename
        paths = [p for p, _, _ in ranked[:limit]]
        # Sort alphabetically within each tier for deterministic output
        # (ranking determines inclusion, not line order)
        paths.sort()
        with open(out_path, "w") as f:
            for p in paths:
                f.write(p + "\n")
        print(f"\nWrote {out_path.name}: {len(paths)} paths", file=sys.stderr)

    # Print top-50 for sanity check
    print(f"\nTop 50 paths by score:", file=sys.stderr)
    for i, (path, score, n_sources) in enumerate(ranked[:50]):
        print(f"  {i+1:3}. [{n_sources}src] {path}", file=sys.stderr)


if __name__ == "__main__":
    main()
