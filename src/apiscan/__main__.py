"""CLI entry point for apiscan."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import sys
import tarfile
import time
import warnings
from pathlib import Path
from urllib.request import Request, urlopen

from apiscan.kite import Route, apply_safety_filter, load_kite
from apiscan.output import (
    BOLD,
    CYAN,
    DIM,
    RESET,
    CSVWriter,
    ProgressTracker,
    ScanResult,
    format_result,
    print_banner,
    print_summary,
    supports_color,
)
from apiscan.scanner import scan

# ---------------------------------------------------------------------------
# Wordlist download + fast index
# ---------------------------------------------------------------------------

# We only use routes-large.kite (958k routes, 18k APIs). routes-small.kite is a naive
# subset with no path param type info and no deduplication — we derive a better "fast"
# wordlist at runtime by keeping only routes that appear across multiple independent APIs.
CDN_BASE = "https://wordlists-cdn.assetnote.io/data/kiterunner"
CDN_TARBALL = "routes-large.kite.tar.gz"
CDN_KITE = "routes-large.kite"
CDN_DESC = "~35 MB download, ~183 MB extracted"

# The fast index is a precomputed list of (path, method) pairs that appear in >= N
# distinct API specs. At threshold=2 this yields ~30k routes — similar size to routes-small
# but every route has been independently validated by appearing in 2+ Swagger specs.
# The top routes are exactly what you'd expect: /login, /api/register, /users, /api/auth/login.
FAST_INDEX_NAME = "routes-fast.json"
FAST_MIN_APIS = 2


def _default_cache_dir() -> Path:
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        base = Path(xdg)
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Caches"
    else:
        base = Path.home() / ".cache"
    return base / "apiscan"


def _download_kite(cache_dir: Path, force: bool = False, use_color: bool = True) -> Path:
    """Download routes-large.kite from CDN. Returns path to the .kite file."""
    b = BOLD if use_color else ""
    d = DIM if use_color else ""
    c = CYAN if use_color else ""
    r = RESET if use_color else ""

    cache_dir.mkdir(parents=True, exist_ok=True)
    kite_path = cache_dir / CDN_KITE

    if kite_path.exists() and not force:
        print(f"  {b}{CDN_KITE}{r} already exists at {kite_path}")
        print(f"  {d}use --force to re-download{r}")
        return kite_path

    url = f"{CDN_BASE}/{CDN_TARBALL}"
    tarball_path = cache_dir / CDN_TARBALL

    print(f"  {c}downloading{r} {CDN_TARBALL} ({CDN_DESC})")
    req = Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"})
    with urlopen(req) as resp, open(tarball_path, "wb") as f:
        total = int(resp.headers.get("Content-Length", 0))
        downloaded = 0
        while chunk := resp.read(1024 * 64):
            f.write(chunk)
            downloaded += len(chunk)
            if total:
                pct = downloaded * 100 // total
                print(f"\r  {d}[{pct:>3}%] {downloaded:,} / {total:,} bytes{r}", end="", flush=True)
        print()

    print(f"  {c}extracting{r} {CDN_TARBALL}")
    with tarfile.open(tarball_path, "r:gz") as tf:
        for member in tf.getmembers():
            if member.name == CDN_KITE or member.name.endswith(f"/{CDN_KITE}"):
                member.name = CDN_KITE
                tf.extract(member, cache_dir)
                break
        else:
            tf.extractall(cache_dir)

    tarball_path.unlink()
    print(f"  {b}{CDN_KITE}{r} -> {kite_path}")
    return kite_path


def _build_fast_index(kite_path: str, cache_dir: Path, use_color: bool = True) -> Path:
    """Build the fast-scan index: deduplicated routes appearing in >= FAST_MIN_APIS APIs.

    Stores a JSON set of (template_path, method) pairs. Cached as routes-fast.json.
    """
    d = DIM if use_color else ""
    c = CYAN if use_color else ""
    r = RESET if use_color else ""

    index_path = cache_dir / FAST_INDEX_NAME

    def _index_progress(parsed: int, total: int) -> None:
        pct = parsed * 100 // total if total else 0
        print(f"\r  {c}building fast index{r} {d}[{pct:>3}%]{r}", end="", flush=True)

    print(f"  {c}building fast index{r} {d}[  0%]{r}", end="", flush=True)
    routes = load_kite(kite_path, on_progress=_index_progress)

    # Count how many distinct source APIs each (path, method) appears in
    route_apis: dict[tuple[str, str], set[str]] = {}
    total = len(routes)
    for i, route in enumerate(routes):
        key = (route.template_path, route.method)
        if key not in route_apis:
            route_apis[key] = set()
        route_apis[key].add(route.source_api_url)
        if i % 50_000 == 0:
            pct = 100 + (i * 100 // total) if total else 100  # 100-199% for dedup phase
            print(f"\r  {c}building fast index{r} {d}[dedup {i * 100 // total:>3}%]{r}", end="", flush=True)

    # Keep routes appearing in >= FAST_MIN_APIS distinct APIs
    fast_keys = [list(k) for k, apis in route_apis.items() if len(apis) >= FAST_MIN_APIS]

    with open(index_path, "w") as f:
        json.dump(fast_keys, f)

    print(f"\r  {c}fast index:{r} {len(fast_keys):,} routes (from {len(route_apis):,} unique, threshold >={FAST_MIN_APIS} APIs){' ' * 10}")
    return index_path


def _apply_fast_filter(routes: list[Route], index_path: Path) -> list[Route]:
    """Filter routes to only those in the fast index."""
    with open(index_path) as f:
        fast_keys = {(p, m) for p, m in json.load(f)}
    return [r for r in routes if (r.template_path, r.method) in fast_keys]


# ---------------------------------------------------------------------------
# Download subcommand
# ---------------------------------------------------------------------------

def _download(args: argparse.Namespace) -> None:
    use_color = supports_color() and not getattr(args, "no_color", False)
    cache_dir = Path(args.dir) if args.dir else _default_cache_dir()
    kite_path = _download_kite(cache_dir, force=args.force, use_color=use_color)

    # Also build fast index if it doesn't exist
    index_path = cache_dir / FAST_INDEX_NAME
    if not index_path.exists() or args.force:
        _build_fast_index(str(kite_path), cache_dir, use_color=use_color)

    print(f"\n  use with: apiscan scan --url <target>")


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="apiscan",
        description="API content discovery using Kiterunner .kite wordlists",
    )
    sub = p.add_subparsers(dest="command")

    # -- download --
    dl = sub.add_parser("download", help="Download routes-large.kite from Assetnote CDN")
    dl.add_argument("--dir", default=None,
                    help=f"Download directory (default: {_default_cache_dir()})")
    dl.add_argument("--force", action="store_true",
                    help="Re-download even if file exists")
    dl.add_argument("--no-color", action="store_true")

    # -- scan --
    sc = sub.add_parser("scan", help="Scan a target using a .kite wordlist")
    sc.add_argument("--kite", default=None,
                    help="Path to .kite wordlist file (default: cached routes-large.kite)")
    sc.add_argument("--url", required=True, help="Target base URL")
    sc.add_argument("--fast", action="store_true",
                    help="Use deduplicated subset (~30k routes appearing in 2+ APIs)")

    safety = sc.add_argument_group("safety")
    safety.add_argument("--unsafe-all", action="store_true",
                        help="Enable all HTTP methods and disable keyword filtering")
    safety.add_argument("--unsafe-methods", action="store_true",
                        help="Enable all HTTP methods (keep keyword filtering)")
    safety.add_argument("--unsafe-keywords", action="store_true",
                        help="Disable keyword filtering (keep GET-only)")

    http = sc.add_argument_group("http")
    http.add_argument("--concurrency", type=int, default=10,
                      help="Max concurrent requests (default: 10)")
    http.add_argument("--rate", type=float, default=None,
                      help="Global requests per second cap")
    http.add_argument("--timeout", type=float, default=10.0,
                      help="Request timeout in seconds (default: 10)")
    http.add_argument("--max-redirects", type=int, default=3,
                      help="Max redirects to follow (default: 3)")
    http.add_argument("--header", action="append", default=[], metavar="K:V",
                      help="Extra header (repeatable)")

    filtering = sc.add_argument_group("filtering")
    filtering.add_argument("--status-codes", default=None,
                           help="Whitelist status codes, comma-separated (e.g. 200,301,403)")
    filtering.add_argument("--blacklist-codes", default=None,
                           help="Blacklist status codes, comma-separated (e.g. 404,500)")

    output = sc.add_argument_group("output")
    output.add_argument("--output", default=None, metavar="PATH",
                        help="Write CSV results to file (includes curl replay column)")
    output.add_argument("--replay-proxy", default=None, metavar="URL",
                        help="Replay findings through a proxy (e.g. http://127.0.0.1:8080 for Burp)")
    output.add_argument("--verbose", action="store_true",
                        help="Show additional details")
    output.add_argument("--no-color", action="store_true",
                        help="Disable ANSI colors")
    output.add_argument("--quiet", action="store_true",
                        help="Suppress banner and progress")

    return p


def _parse_headers(raw: list[str]) -> dict[str, str]:
    headers = {}
    for h in raw:
        if ":" not in h:
            print(f"warning: ignoring malformed header '{h}' (expected K:V)", file=sys.stderr)
            continue
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()
    return headers


def _parse_codes(raw: str | None) -> set[int] | None:
    if not raw:
        return None
    return {int(c.strip()) for c in raw.split(",") if c.strip().isdigit()}


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

def _ensure_kite(args: argparse.Namespace, use_color: bool) -> str:
    """Ensure routes-large.kite is available. Returns path."""
    if args.kite:
        return args.kite

    cache_dir = _default_cache_dir()
    kite_path = cache_dir / CDN_KITE

    if not kite_path.exists():
        c = CYAN if use_color else ""
        r = RESET if use_color else ""
        print(f"  {c}first run:{r} downloading {CDN_KITE}...")
        _download_kite(cache_dir, use_color=use_color)
        print()

    return str(kite_path)


def _ensure_fast_index(kite_path: str, use_color: bool) -> Path:
    """Ensure fast index exists. Builds it if needed."""
    cache_dir = _default_cache_dir()
    index_path = cache_dir / FAST_INDEX_NAME
    if not index_path.exists():
        _build_fast_index(kite_path, cache_dir, use_color=use_color)
    return index_path


async def _scan(args: argparse.Namespace) -> None:
    use_color = supports_color() and not args.no_color

    d = DIM if use_color else ""
    r = RESET if use_color else ""

    kite_path = _ensure_kite(args, use_color)

    def _load_progress(parsed: int, total: int) -> None:
        pct = parsed * 100 // total if total else 0
        print(f"\r  {d}loading {kite_path} [{pct:>3}%]{r}", end="", flush=True)

    if not args.quiet:
        print(f"  {d}loading {kite_path} [  0%]{r}", end="", flush=True)
    routes = load_kite(kite_path, on_progress=_load_progress if not args.quiet else None)

    # Apply --fast filter if requested (before safety filter)
    if args.fast and not args.kite:
        if not args.quiet:
            print(f"\r  {d}applying fast filter...{' ' * 30}{r}", end="", flush=True)
        index_path = _ensure_fast_index(kite_path, use_color)
        routes = _apply_fast_filter(routes, index_path)

    if not args.quiet:
        print(f"\r  {d}loaded {len(routes):,} routes, applying filters...{' ' * 20}{r}", end="", flush=True)
    unsafe_methods = args.unsafe_all or args.unsafe_methods
    unsafe_keywords = args.unsafe_all or args.unsafe_keywords
    filtered_routes, stats = apply_safety_filter(
        routes, unsafe_methods=unsafe_methods, unsafe_keywords=unsafe_keywords,
    )

    # Shuffle routes so we spread across path prefixes rather than hammering one API
    # at a time. Seeded for deterministic re-runs.
    random.Random(42).shuffle(filtered_routes)

    if not args.quiet:
        print(f"\r{' ' * 80}\r", end="")  # clear the status line
        print_banner(args.url, len(filtered_routes), unsafe_methods, unsafe_keywords, stats, use_color)

    csv_writer = CSVWriter(args.output, replay_proxy=args.replay_proxy) if args.output else None
    progress = ProgressTracker(len(filtered_routes), use_color) if not args.quiet else None

    # Replay proxy: re-send findings through a proxy (e.g. Burp) so they appear
    # in the proxy history for manual inspection and modification.
    import httpx as _httpx
    replay_client: _httpx.AsyncClient | None = None
    if args.replay_proxy:
        replay_client = _httpx.AsyncClient(
            proxy=args.replay_proxy, verify=False, follow_redirects=False,
        )

    # Deduplicate output — same (status, method, path, size) shown once.
    # All results still go to CSV; only terminal display is deduped.
    seen_results: set[tuple[int, str, str, int]] = set()

    async def _replay(result: ScanResult) -> None:
        """Re-send the finding through the replay proxy."""
        if not replay_client:
            return
        try:
            await replay_client.request(
                result.method, result.url,
                headers=result.request_headers or {},
                content=result.request_body.encode() if result.request_body else None,
                timeout=args.timeout,
            )
        except Exception:
            pass  # best-effort replay, don't break the scan

    def on_result(result: ScanResult) -> None:
        if csv_writer:
            csv_writer.write_result(result)
        if replay_client:
            asyncio.create_task(_replay(result))
        display_key = (result.status_code, result.method, result.path, result.content_length)
        if display_key in seen_results:
            return
        seen_results.add(display_key)
        if progress:
            print(f"\r{' ' * 60}\r", end="", file=sys.stderr, flush=True)
        print(format_result(result, use_color))

    def on_progress(findings_delta: int) -> None:
        if progress:
            progress.update(findings_delta)

    start = time.monotonic()
    warnings.filterwarnings("ignore", message="Unverified HTTPS request")

    findings = await scan(
        target_url=args.url,
        routes=filtered_routes,
        concurrency=args.concurrency,
        rate_limit=args.rate,
        timeout=args.timeout,
        max_redirects=args.max_redirects,
        status_blacklist=_parse_codes(args.blacklist_codes),
        status_whitelist=_parse_codes(args.status_codes),
        unsafe=unsafe_methods,
        extra_headers=_parse_headers(args.header),
        on_result=on_result,
        on_progress=on_progress,
    )

    elapsed = time.monotonic() - start

    if replay_client:
        await replay_client.aclose()

    if csv_writer:
        csv_writer.close()

    if not args.quiet:
        print_summary(len(findings), len(filtered_routes), elapsed, use_color)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def cli() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    try:
        if args.command == "download":
            _download(args)
        elif args.command == "scan":
            asyncio.run(_scan(args))
        else:
            parser.print_help()
            sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n\n  interrupted", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    cli()
