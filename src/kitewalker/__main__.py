"""CLI entry point for kitewalker."""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
import warnings

from kitewalker.kite import apply_safety_filter, load_kite
from kitewalker.output import (
    CSVWriter,
    ProgressTracker,
    ScanResult,
    format_result,
    print_banner,
    print_summary,
    supports_color,
)
from kitewalker.scanner import scan


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="kitewalker",
        description="API content discovery using Kiterunner .kite wordlists",
    )
    p.add_argument("--kite", required=True, help="Path to .kite wordlist file")
    p.add_argument("--url", required=True, help="Target base URL")

    safety = p.add_argument_group("safety")
    safety.add_argument("--unsafe", action="store_true",
                        help="Enable all HTTP methods and disable keyword filtering")

    http = p.add_argument_group("http")
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

    filtering = p.add_argument_group("filtering")
    filtering.add_argument("--status-codes", default=None,
                           help="Whitelist status codes, comma-separated (e.g. 200,301,403)")
    filtering.add_argument("--blacklist-codes", default=None,
                           help="Blacklist status codes, comma-separated (e.g. 404,500)")

    output = p.add_argument_group("output")
    output.add_argument("--output", default=None, metavar="PATH",
                        help="Write CSV results to file")
    output.add_argument("--verbose", action="store_true",
                        help="Show additional details")
    output.add_argument("--no-color", action="store_true",
                        help="Disable ANSI colors")
    output.add_argument("--quiet", action="store_true",
                        help="Suppress banner and progress")

    return p.parse_args(argv)


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


async def _main(args: argparse.Namespace) -> None:
    use_color = supports_color() and not args.no_color

    # Load routes
    routes = load_kite(args.kite)
    filtered_routes, stats = apply_safety_filter(routes, args.unsafe)

    if not args.quiet:
        print_banner(args.url, len(filtered_routes), args.unsafe, stats, use_color)

    # CSV writer
    csv_writer = CSVWriter(args.output) if args.output else None

    # Progress
    progress = ProgressTracker(len(filtered_routes), use_color) if not args.quiet else None

    def on_result(result: ScanResult) -> None:
        print(format_result(result, use_color))
        if csv_writer:
            csv_writer.write_result(result)

    def on_progress(findings_delta: int) -> None:
        if progress:
            progress.update(findings_delta)

    start = time.monotonic()

    # Suppress TLS verification warnings
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


def cli() -> None:
    args = _parse_args()
    asyncio.run(_main(args))


if __name__ == "__main__":
    cli()
