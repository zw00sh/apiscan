"""CLI entry point for apiscan."""

from __future__ import annotations

import argparse
import asyncio
import importlib.resources
import json as _json
import os
import sys
import time
import warnings

from apiscan.kite import Route
from apiscan.wordlist import load_wordlist
from apiscan.output import (
    BOLD,
    CYAN,
    DIM,
    GREEN,
    RESET,
    CSVWriter,
    ProgressTracker,
    ScanResult,
    format_findings_tree,
    format_result,
    print_banner,
    print_hints,
    print_summary,
    supports_color,
)
from apiscan.scanner import scan


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="apiscan",
        description="Method-aware API content discovery (default: built-in 10k wordlist)",
    )
    p.add_argument("-u", "--url", required=True, help="Target base URL")

    wordlist = p.add_argument_group("wordlist (default: built-in 10k)")
    wl_mutex = wordlist.add_mutually_exclusive_group()
    wl_mutex.add_argument("-w", "--wordlist", default=None, metavar="PATH",
                          help="Custom wordlist file (one path per line)")
    wl_mutex.add_argument("--short", action="store_true",
                          help="Built-in top 1k wordlist (fast)")
    wl_mutex.add_argument("--long", action="store_true",
                          help="Built-in top 100k wordlist (thorough)")

    recursion = p.add_argument_group("recursion")
    recurse_mode = recursion.add_mutually_exclusive_group()
    recurse_mode.add_argument("--recurse", action="store_true",
                              help="Recurse into discovered boundaries with smart dedup (strips structural prefixes from wordlist)")
    recurse_mode.add_argument("--recurse-all", action="store_true",
                              help="Recurse into discovered boundaries using the full wordlist (no dedup)")
    recursion.add_argument("--max-depth", type=int, default=2,
                           help="Max recursion depth (default: 2)")
    recursion.add_argument("--no-lookahead", action="store_true", default=False,
                           help="Disable lookahead probing. Lookahead tests common path segments "
                                "(api, v1, admin, …) one level deeper at leaf nodes to find hidden "
                                "boundaries. Adds ~30 extra requests but can discover routes that "
                                "wordlists miss. Disable to reduce noise or request count")

    http = p.add_argument_group("http")
    method_group = http.add_mutually_exclusive_group()
    method_group.add_argument("-m", "--methods", default="GET,POST",
                              help="HTTP methods to probe, comma-separated (default: GET,POST)")
    method_group.add_argument("--all-methods", action="store_true", default=False,
                              help="Probe all methods (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)")
    http.add_argument("-c", "--concurrency", type=int, default=10,
                      help="Max concurrent requests (default: 10)")
    http.add_argument("-r", "--rate", type=float, default=None,
                      help="Global requests per second cap")
    http.add_argument("-t", "--timeout", type=float, default=10.0,
                      help="Request timeout in seconds (default: 10)")
    http.add_argument("--max-redirects", type=int, default=3,
                      help="Max redirects to follow (default: 3)")
    http.add_argument("-H", "--header", action="append", default=[], metavar="K:V",
                      help="Extra header (repeatable, e.g. -H 'Authorization: Bearer TOKEN')")

    filtering = p.add_argument_group("filtering")
    filtering.add_argument("-i", "--include", default=None, metavar="CODES",
                           help="Only report these status codes, comma-separated (e.g. 200,301,403)")
    filtering.add_argument("-e", "--exclude", default=None, metavar="CODES",
                           help="Never report these status codes, comma-separated (e.g. 429,500)")
    filtering.add_argument("--no-skip-wildcard-siblings", action="store_true",
                           help="Probe all segment-prefix siblings individually instead of skipping them when a wildcard handler is detected")

    output = p.add_argument_group("output")
    output.add_argument("-o", "--output", default=None, metavar="PATH",
                        help="Write CSV results to file (includes curl replay column)")
    output.add_argument("--replay-proxy", default=None, metavar="URL",
                        help="Replay findings through a proxy (e.g. http://127.0.0.1:8080 for Burp)")
    output.add_argument("-v", "--verbose", action="store_true",
                        help="Show additional details")
    output.add_argument("--show-headers", action="store_true",
                        help="Show newly-discovered response headers for each finding")
    output.add_argument("--debug", action="store_true",
                        help="Show why routes are filtered (noisy)")
    output.add_argument("--no-color", action="store_true",
                        help="Disable ANSI colors")
    output_mode = output.add_mutually_exclusive_group()
    output_mode.add_argument("-q", "--quiet", action="store_true",
                             help="Suppress banner, progress, and summary — output only discovered URLs")
    output_mode.add_argument("-j", "--json", action="store_true",
                             help="Output findings as JSON Lines (one object per line)")

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

def _resolve_wordlist(args: argparse.Namespace) -> str:
    """Return the wordlist path from args, defaulting to the built-in 10k list."""
    if args.wordlist:
        return args.wordlist
    if args.short:
        name = "api-top-1k.txt"
    elif args.long:
        name = "api-top-100k.txt"
    else:
        name = "api-top-10k.txt"
    ref = importlib.resources.files("apiscan") / "wordlists" / name
    with importlib.resources.as_file(ref) as p:
        return str(p)


async def _scan(args: argparse.Namespace) -> None:
    suppress_ui = args.quiet or args.json
    use_color = supports_color() and not args.no_color and not suppress_ui

    d = DIM if use_color else ""
    r = RESET if use_color else ""
    c2 = CYAN if use_color else ""

    if args.all_methods:
        scan_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
    else:
        scan_methods = [m.strip().upper() for m in args.methods.split(",") if m.strip()]
    valid = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
    for m in scan_methods:
        if m not in valid:
            print(f"error: unknown method '{m}' (valid: {', '.join(sorted(valid))})", file=sys.stderr)
            sys.exit(1)

    wordlist_path = _resolve_wordlist(args)
    routes = load_wordlist(wordlist_path)

    if not suppress_ui:
        print_banner(args.url, len(routes), scan_methods, use_color,
                     concurrency=args.concurrency, rate_limit=args.rate,
                     timeout=args.timeout,
                     recurse=args.recurse or args.recurse_all,
                     lookahead=not args.no_lookahead,
                     max_depth=args.max_depth)

    from apiscan.scanner import RequestTracker
    req_tracker = RequestTracker(
        on_tick=lambda: progress.tick_request() if progress else None,
    )

    csv_writer = CSVWriter(args.output, replay_proxy=args.replay_proxy) if args.output else None
    progress = ProgressTracker(len(routes), use_color, tracker=req_tracker) if not suppress_ui else None
    # Re-bind the tick callback now that progress exists
    req_tracker._on_tick = progress.tick_request if progress else None

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
        if args.json:
            print(_json.dumps({
                "url": result.url,
                "method": result.method,
                "path": result.path,
                "status_code": result.status_code,
                "content_length": result.content_length,
                "word_count": result.word_count,
                "line_count": result.line_count,
                "redirect_location": result.redirect_location,
                "is_boundary": result.is_boundary,
                "boundary_info": result.boundary_info,
                "new_headers": dict(result.new_headers) if result.new_headers else {},
                "reason": result.reason,
                "confidence": result.confidence,
                "timestamp": result.timestamp,
            }), flush=True)
            return
        if args.quiet:
            print(result.url)
            return
        display_key = (result.status_code, result.method, result.path, result.content_length)
        if display_key in seen_results:
            # Mutation of an already-shown route — sent to CSV/proxy but not printed
            if progress:
                progress.hidden += 1
            return
        seen_results.add(display_key)
        if progress:
            print(f"\r{' ' * 120}\r", end="", file=sys.stderr, flush=True)
        print(format_result(result, use_color, verbose=args.verbose or args.debug,
                            show_headers=args.show_headers))

    def on_progress(findings_delta: int) -> None:
        if progress:
            progress.update(findings_delta)

    def _debug_print(msg: str) -> None:
        d2 = DIM if use_color else ""
        r2 = RESET if use_color else ""
        if progress:
            print(f"\r{' ' * 120}\r", end="", file=sys.stderr, flush=True)
        print(f"{d2}  {msg}{r2}", file=sys.stderr)

    def on_filtered(method: str, path: str, status: int, reason: str) -> None:
        if not args.debug:
            return
        _debug_print(f"filtered {method:<7} {status:>3} {path} -- {reason}")

    def on_debug(msg: str) -> None:
        _debug_print(msg)

    # Track results via callback so partial results survive Ctrl+C
    all_findings: list[ScanResult] = []
    _orig_on_result = on_result

    def on_result_tracking(result: ScanResult) -> None:
        all_findings.append(result)
        _orig_on_result(result)

    start = time.monotonic()
    warnings.filterwarnings("ignore", message="Unverified HTTPS request")

    interrupted = False
    scan_tree = None
    try:
        findings, scan_tree = await scan(
            target_url=args.url,
            routes=routes,
            concurrency=args.concurrency,
            rate_limit=args.rate,
            timeout=args.timeout,
            max_redirects=args.max_redirects,
            status_blacklist=_parse_codes(args.exclude),
            status_whitelist=_parse_codes(args.include),
            extra_headers=_parse_headers(args.header),
            on_result=on_result_tracking,
            on_progress=on_progress,
            on_filtered=on_filtered,
            on_debug=on_debug if args.debug else None,
            tracker=req_tracker,
            recurse=args.recurse or args.recurse_all,
            recurse_all=args.recurse_all,
            max_depth=args.max_depth,
            lookahead=not args.no_lookahead,
            methods=scan_methods,
            skip_wildcard_siblings=not args.no_skip_wildcard_siblings,
        )
    except (asyncio.CancelledError, KeyboardInterrupt):
        interrupted = True
        findings = all_findings

    elapsed = time.monotonic() - start

    if progress:
        progress.finish()

    if replay_client:
        await replay_client.aclose()

    if csv_writer:
        csv_writer.close()

    if args.debug and scan_tree is not None:
        print(f"\n{d}--- scan tree ---{r}", file=sys.stderr)
        print(scan_tree.format_tree(debug=True), file=sys.stderr)
        print(f"{d}--- end tree ---{r}\n", file=sys.stderr)

    if not suppress_ui:
        if interrupted:
            print(f"\n  {d}interrupted{r}", file=sys.stderr)
        print_summary(len(findings), req_tracker.routes_planned, req_tracker.sent, elapsed, use_color,
                      errors=req_tracker.errors)
        if findings:
            tree_str = format_findings_tree(findings, use_color)
            if tree_str:
                print(f"\n{tree_str}")
        boundary_count = sum(1 for f in findings if f.is_boundary)
        if args.short:
            wl_tier = "short"
        elif getattr(args, "long"):
            wl_tier = "long"
        elif args.wordlist:
            wl_tier = "custom"
        else:
            wl_tier = "default"
        print_hints(
            recurse=args.recurse or args.recurse_all, lookahead=not args.no_lookahead,
            methods=scan_methods, boundaries_found=boundary_count,
            wildcard_skipped=req_tracker.skipped_fn() if req_tracker.skipped_fn else 0,
            wordlist_tier=wl_tier,
            use_color=use_color,
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def cli() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    try:
        asyncio.run(_scan(args))
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    cli()
