"""Terminal output with ANSI colors, CSV writer, and progress tracking."""

from __future__ import annotations

import csv
import sys
import time
from collections import deque
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apiscan.kite import FilterStats

# ---------------------------------------------------------------------------
# ANSI colors
# ---------------------------------------------------------------------------

GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"
BLUE = "\033[34m"
WHITE = "\033[37m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

# 256-color helpers
def _c256(n: int) -> str:
    return f"\033[38;5;{n}m"

def _bg256(n: int) -> str:
    return f"\033[48;5;{n}m"

# Per-status-code colors (256-color)
_STATUS_COLORS: dict[int, str] = {
    200: _c256(82),    # bright green
    201: _c256(36),    # teal
    204: _c256(65),    # dim green
    301: _c256(220),   # yellow
    302: _c256(214),   # amber
    304: _c256(178),   # dark yellow
    400: _c256(208),   # dark orange
    401: _c256(214),   # bright orange — needs auth, actionable
    403: _c256(170),   # magenta/pink — forbidden
    404: _c256(245),   # dim grey — noise
    405: f"{BOLD}{_c256(196)}",  # bright red bold — discovery signal
    429: f"{_bg256(52)}{_c256(255)}",   # white on dark red bg — scan in trouble
    500: _c256(196),   # red
    502: f"{_bg256(52)}{_c256(255)}",   # white on dark red bg — scan in trouble
    503: f"{_bg256(52)}{_c256(255)}",   # white on dark red bg — scan in trouble
}

# Fallback colors by range
_STATUS_RANGE_COLORS: list[tuple[int, int, str]] = [
    (200, 300, _c256(82)),   # green
    (300, 400, _c256(220)),  # yellow
    (400, 500, _c256(245)),  # dim grey
    (500, 600, _c256(196)),  # red
]

# Magnitude colors for size (B, K, M)
_SIZE_COLORS = [_c256(245), _c256(214), _c256(208)]  # dim, yellow, orange
# Magnitude colors for word count (purple shades)
_WORD_COLORS = [_c256(96), _c256(134), _c256(171)]   # dim, medium, bright purple
# Magnitude colors for line count (blue shades)
_LINE_COLORS = [_c256(60), _c256(69), _c256(111)]    # dim, medium, bright blue


def supports_color() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


# ---------------------------------------------------------------------------
# Scan result (shared with scanner)
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    url: str
    method: str
    path: str
    status_code: int
    content_length: int
    word_count: int
    line_count: int
    redirect_location: str | None = None
    reason: str = ""
    confidence: str = ""
    timestamp: str = ""
    request_headers: dict[str, str] | None = None
    request_body: str | None = None


def build_curl(result: ScanResult, proxy: str | None = None) -> str:
    """Build a curl command that replays the request."""
    parts = ["curl", "-s", "-k"]
    if result.method != "GET":
        parts += ["-X", result.method]
    if proxy:
        parts += ["-x", proxy]
    for k, v in (result.request_headers or {}).items():
        parts += ["-H", f"'{k}: {v}'"]
    if result.request_body:
        parts += ["-d", f"'{result.request_body}'"]
    parts.append(f"'{result.url}'")
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Terminal formatting
# ---------------------------------------------------------------------------

def _status_color(status: int) -> str:
    if status in _STATUS_COLORS:
        return _STATUS_COLORS[status]
    for lo, hi, color in _STATUS_RANGE_COLORS:
        if lo <= status < hi:
            return color
    return ""


def _fmt_magnitude(value: int, suffix: str, colors: list[str], use_color: bool) -> str:
    """Format a value with unit suffix and magnitude-appropriate color.

    Always shows the suffix (e.g. '  42B', ' 1.5K', ' 2.3M').
    Returns a string right-aligned to 5 chars + 1 char suffix.
    """
    if value >= 1_000_000:
        text = f"{value / 1_000_000:.1f}M"
        color = colors[2] if use_color else ""
    elif value >= 1_000:
        text = f"{value / 1_000:.1f}K"
        color = colors[1] if use_color else ""
    else:
        text = f"{value}{suffix}"
        color = colors[0] if use_color else ""
    r = RESET if use_color else ""
    return f"{color}{text:>6}{r}"


def format_result(result: ScanResult, use_color: bool = True, verbose: bool = False) -> str:
    r = RESET if use_color else ""

    # Status code — per-code color
    sc_color = _status_color(result.status_code) if use_color else ""
    sc = f"{sc_color}{result.status_code:>3}{r}" if use_color else f"{result.status_code:>3}"

    # Method
    method = f"{CYAN}{result.method:<7}{r}" if use_color else f"{result.method:<7}"

    # Magnitude-colored columns (size lines words, no separators between them)
    size = _fmt_magnitude(result.content_length, "B", _SIZE_COLORS, use_color)
    lines = _fmt_magnitude(result.line_count, "L", _LINE_COLORS, use_color)
    words = _fmt_magnitude(result.word_count, "W", _WORD_COLORS, use_color)

    # Path
    path = f"{WHITE}{result.path}{r}" if use_color else result.path

    line = f"{sc} | {method} | {size} {lines} {words} | {path}"

    if verbose and result.reason:
        hint = f" {DIM}({result.reason}){r}" if use_color else f" ({result.reason})"
        line += hint
    if result.redirect_location:
        redir = f" -> {result.redirect_location}"
        line += f" {DIM}{redir}{r}" if use_color else redir
    return line


BANNER = " ▄▀█ █▀█ █ █▀ █▀▀ ▄▀█ █▄ █\n █▀█ █▀▀ █ ▄█ █▄▄ █▀█ █ ▀█"


def print_banner(target: str, route_count: int,
                 unsafe_keywords: bool,
                 stats: FilterStats, use_color: bool = True) -> None:
    b = BOLD if use_color else ""
    r = RESET if use_color else ""
    d = DIM if use_color else ""
    c = CYAN if use_color else ""
    y = YELLOW if use_color else ""
    g = GREEN if use_color else ""
    print(f"\n{c}{BANNER}{r}")
    print(f" {d}api content discovery · v0.15.0{r}\n")
    print(f"  target:  {target}")
    print(f"  routes:  {route_count}")

    if unsafe_keywords:
        print(f"  filter:  {y}{b}keywords disabled{r} {d}-- no keyword filter{r}")
    elif stats.keyword_filtered:
        print(f"  filter:  {g}{b}keywords active{r} {d}-- {stats.keyword_filtered} routes filtered by keyword{r}")
    print()


# ---------------------------------------------------------------------------
# CSV writer
# ---------------------------------------------------------------------------

_CSV_COLUMNS = [
    "timestamp", "url", "method", "path", "status_code",
    "content_length", "word_count", "line_count",
    "redirect_location", "reason", "confidence", "curl",
]


class CSVWriter:
    def __init__(self, path: str, replay_proxy: str | None = None) -> None:
        self._file = open(path, "w", newline="")
        self._writer = csv.writer(self._file)
        self._writer.writerow(_CSV_COLUMNS)
        self._proxy = replay_proxy

    def write_result(self, result: ScanResult) -> None:
        self._writer.writerow([
            result.timestamp, result.url, result.method, result.path,
            result.status_code, result.content_length, result.word_count,
            result.line_count, result.redirect_location or "",
            result.reason, result.confidence, build_curl(result, self._proxy),
        ])

    def close(self) -> None:
        self._file.close()


# ---------------------------------------------------------------------------
# Braille progress bar
# ---------------------------------------------------------------------------

# 8 cells × 8 fill levels = 64 steps. Each cell fills bottom-left to full
# before the next one starts.
_BRAILLE = " ⡀⡄⡆⡇⣇⣧⣷⣿"


def braille_bar(pct: float) -> str:
    steps = int(pct * 64 / 100)
    full_cells = steps // 8
    partial = steps % 8
    bar = "⣿" * full_cells
    if full_cells < 8:
        bar += _BRAILLE[partial]
        bar += " " * (7 - full_cells)
    return bar


# ---------------------------------------------------------------------------
# Progress tracker
# ---------------------------------------------------------------------------

class ProgressTracker:
    def __init__(self, route_total: int, use_color: bool = True, tracker=None) -> None:
        self._initial_route_total = route_total
        self.routes_completed = 0
        self.findings = 0
        self.hidden = 0
        self._tracker = tracker  # RequestTracker from scanner
        self._use_color = use_color
        self._last_print = 0.0
        self._start = time.monotonic()
        self._window: deque[float] = deque()

    @property
    def route_total(self) -> int:
        """Dynamic total — grows when recursion adds routes."""
        if self._tracker and hasattr(self._tracker, 'routes_planned'):
            return self._tracker.routes_planned
        return self._initial_route_total

    def set_phase(self, phase: str, phase_total: int) -> None:
        pass  # kept for API compat

    def tick_request(self) -> None:
        """Record a completed HTTP request for req/s calculation."""
        now = time.monotonic()
        self._window.append(now)
        cutoff = now - 3.0
        while self._window and self._window[0] <= cutoff:
            self._window.popleft()
        if now - self._last_print >= 0.25:
            self._print(now)
            self._last_print = now

    def update(self, findings_delta: int = 0) -> None:
        """Record a completed route."""
        self.routes_completed += 1
        self.findings += findings_delta
        now = time.monotonic()
        if now - self._last_print >= 0.25 or self.routes_completed == self.route_total:
            self._print(now)
            self._last_print = now

    def _print(self, now: float) -> None:
        d = DIM if self._use_color else ""
        c = CYAN if self._use_color else ""
        g = GREEN if self._use_color else ""
        r = RESET if self._use_color else ""

        # Route progress with braille bar
        route_pct = self.routes_completed * 100 / self.route_total if self.route_total else 0
        route_bar = braille_bar(route_pct)

        # Request counts from tracker
        reqs_sent = self._tracker.sent if self._tracker else 0
        reqs_total = self._tracker.planned if self._tracker else 0

        # Request rate from sliding window
        if len(self._window) > 1:
            span = self._window[-1] - self._window[0]
            rps = (len(self._window) - 1) / span if span > 0 else 0
        else:
            rps = 0

        hidden_str = f" {d}| {self.hidden} hidden{r}" if self.hidden else ""

        # Show if route total grew from recursion
        recurse_str = ""
        if self._tracker and hasattr(self._tracker, 'routes_planned'):
            if self._tracker.routes_planned > self._initial_route_total:
                added = self._tracker.routes_planned - self._initial_route_total
                recurse_str = f" {d}| +{added} recursive{r}"

        print(f"\r{' ' * 120}\r", end="", file=sys.stderr, flush=True)
        line = (f"[{g}{route_bar}{r}{d}{route_pct:02.0f}%{r}] "
                f"|   {d}{self.routes_completed}/{self.route_total} routes{r} "
                f"| {d}{reqs_sent}/{reqs_total} reqs{r} "
                f"{d}({rps:.0f} req/s){r} "
                f"| {c}{self.findings} found{r}"
                f"{recurse_str}"
                f"{hidden_str}")
        print(f"\r{line}", end="", flush=True, file=sys.stderr)
        if self.routes_completed == self.route_total:
            print(file=sys.stderr)


def print_summary(findings: int, total_candidates: int, total_requests: int,
                  elapsed: float, use_color: bool = True) -> None:
    d = DIM if use_color else ""
    r = RESET if use_color else ""
    b = BOLD if use_color else ""
    avg_rps = total_requests / elapsed if elapsed > 0 else 0
    print(f"\n{b}{findings} findings{r} from {total_candidates} candidates in {total_requests} requests {d}({elapsed:.1f}s, {avg_rps:.0f} avg req/s){r}")
