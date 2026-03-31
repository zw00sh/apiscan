"""CLI entry point for apiscan."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import tarfile
import time
import warnings
from pathlib import Path
from urllib.request import Request, urlopen

from apiscan.kite import apply_safety_filter, load_kite
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
# Wordlist download
# ---------------------------------------------------------------------------

CDN_BASE = "https://wordlists-cdn.assetnote.io/data/kiterunner"
AVAILABLE_KITES = {
    "routes-large": ("routes-large.kite.tar.gz", "routes-large.kite", "~35 MB download, ~183 MB extracted"),
    "routes-small": ("routes-small.kite.tar.gz", "routes-small.kite", "~430 KB download, ~1.7 MB extracted"),
}


def _default_cache_dir() -> Path:
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        base = Path(xdg)
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Caches"
    else:
        base = Path.home() / ".cache"
    return base / "apiscan"


def _download(args: argparse.Namespace) -> None:
    use_color = supports_color() and not getattr(args, "no_color", False)
    b = BOLD if use_color else ""
    d = DIM if use_color else ""
    c = CYAN if use_color else ""
    r = RESET if use_color else ""

    cache_dir = Path(args.dir) if args.dir else _default_cache_dir()
    cache_dir.mkdir(parents=True, exist_ok=True)

    names = args.wordlists if args.wordlists else list(AVAILABLE_KITES.keys())

    for name in names:
        if name not in AVAILABLE_KITES:
            print(f"unknown wordlist '{name}'. available: {', '.join(AVAILABLE_KITES)}", file=sys.stderr)
            sys.exit(1)

        tarball_name, kite_name, desc = AVAILABLE_KITES[name]
        kite_path = cache_dir / kite_name

        if kite_path.exists() and not args.force:
            print(f"  {b}{kite_name}{r} already exists at {kite_path}")
            print(f"  {d}use --force to re-download{r}")
            continue

        url = f"{CDN_BASE}/{tarball_name}"
        tarball_path = cache_dir / tarball_name

        print(f"  {c}downloading{r} {tarball_name} ({desc})")
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

        print(f"  {c}extracting{r} {tarball_name}")
        with tarfile.open(tarball_path, "r:gz") as tf:
            # Extract only the expected .kite file, safely
            for member in tf.getmembers():
                if member.name == kite_name or member.name.endswith(f"/{kite_name}"):
                    member.name = kite_name  # flatten any directory prefix
                    tf.extract(member, cache_dir)
                    break
            else:
                # Fallback: extract everything
                tf.extractall(cache_dir)

        tarball_path.unlink()
        print(f"  {b}{kite_name}{r} -> {kite_path}")

    print(f"\n  use with: apiscan scan --kite {cache_dir / '<name>.kite'}")


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
    dl = sub.add_parser("download", help="Download .kite wordlists from Assetnote CDN")
    dl.add_argument("wordlists", nargs="*", default=[],
                    help=f"Wordlists to download (default: all). Options: {', '.join(AVAILABLE_KITES)}")
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
                    help="Use routes-small.kite instead of routes-large.kite")

    safety = sc.add_argument_group("safety")
    safety.add_argument("--unsafe", action="store_true",
                        help="Enable all HTTP methods and disable keyword filtering")

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
                        help="Write CSV results to file")
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

def _resolve_kite(args: argparse.Namespace) -> str:
    """Resolve the .kite file path: explicit --kite, --fast, or default (routes-large)."""
    if args.kite:
        return args.kite

    name = "routes-small" if args.fast else "routes-large"
    _, kite_name, _ = AVAILABLE_KITES[name]
    kite_path = _default_cache_dir() / kite_name

    if not kite_path.exists():
        use_color = supports_color() and not args.no_color
        c = CYAN if use_color else ""
        r = RESET if use_color else ""
        print(f"  {c}first run:{r} downloading {kite_name}...")
        # Build a minimal args namespace for _download
        dl_args = argparse.Namespace(
            wordlists=[name], dir=None, force=False, no_color=getattr(args, "no_color", False),
        )
        _download(dl_args)
        print()

    return str(kite_path)


async def _scan(args: argparse.Namespace) -> None:
    use_color = supports_color() and not args.no_color

    d = DIM if use_color else ""
    r = RESET if use_color else ""

    kite_path = _resolve_kite(args)

    if not args.quiet:
        print(f"  {d}loading {kite_path}...{r}", end="", flush=True)
    routes = load_kite(kite_path)
    if not args.quiet:
        print(f"\r  {d}loaded {len(routes):,} routes, applying filters...{r}", end="", flush=True)
    filtered_routes, stats = apply_safety_filter(routes, args.unsafe)
    if not args.quiet:
        print(f"\r{' ' * 60}\r", end="")  # clear the status line
        print_banner(args.url, len(filtered_routes), args.unsafe, stats, use_color)

    csv_writer = CSVWriter(args.output) if args.output else None
    progress = ProgressTracker(len(filtered_routes), use_color) if not args.quiet else None

    def on_result(result: ScanResult) -> None:
        if progress:
            # Clear the progress line before printing a finding
            print(f"\r{' ' * 60}\r", end="", file=sys.stderr, flush=True)
        print(format_result(result, use_color))
        if csv_writer:
            csv_writer.write_result(result)

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
        unsafe=args.unsafe,
        extra_headers=_parse_headers(args.header),
        on_result=on_result,
        on_progress=on_progress,
    )

    elapsed = time.monotonic() - start

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

    if args.command == "download":
        _download(args)
    elif args.command == "scan":
        asyncio.run(_scan(args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    cli()
