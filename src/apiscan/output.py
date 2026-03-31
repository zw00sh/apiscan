"""Terminal output with ANSI colors, CSV writer, and progress tracking."""

from __future__ import annotations

import csv
import sys
import time
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
    original_method: str = ""
    timestamp: str = ""


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


def format_result(result: ScanResult, use_color: bool = True) -> str:
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

    if result.original_method and result.original_method != result.method:
        hint = f" {DIM}(original: {result.original_method}){r}" if use_color else f" (original: {result.original_method})"
        line += hint
    if result.redirect_location:
        redir = f" -> {result.redirect_location}"
        line += f" {DIM}{redir}{r}" if use_color else redir
    return line


BANNER = " ▄▀█ █▀█ █ █▀ █▀▀ ▄▀█ █▄ █\n █▀█ █▀▀ █ ▄█ █▄▄ █▀█ █ ▀█"


def print_banner(target: str, route_count: int,
                 unsafe_methods: bool, unsafe_keywords: bool,
                 stats: FilterStats, use_color: bool = True) -> None:
    b = BOLD if use_color else ""
    r = RESET if use_color else ""
    d = DIM if use_color else ""
    c = CYAN if use_color else ""
    y = YELLOW if use_color else ""
    g = GREEN if use_color else ""
    rd = RED if use_color else ""
    print(f"\n{c}{BANNER}{r}")
    print(f" {d}api content discovery · v0.5.0{r}\n")
    print(f"  target:  {target}")
    print(f"  routes:  {route_count}")

    if unsafe_methods and unsafe_keywords:
        sc = sum(v for m, v in stats.method_breakdown.items() if m != "GET")
        print(f"  mode:    {rd}{b}unsafe-all{r} {d}-- all methods, no keyword filter. {sc} state-changing routes{r}")
    elif unsafe_methods:
        sc = sum(v for m, v in stats.method_breakdown.items() if m != "GET")
        print(f"  mode:    {y}{b}unsafe-methods{r} {d}-- all methods, keyword filter active. "
              f"{stats.keyword_filtered} keyword-filtered, {sc} state-changing routes{r}")
    elif unsafe_keywords:
        print(f"  mode:    {y}{b}unsafe-keywords{r} {d}-- GET-only, no keyword filter. "
              f"{stats.method_filtered} method-filtered{r}")
    else:
        print(f"  mode:    {g}{b}safe{r} {d}-- GET-only, keyword filter. "
              f"{stats.method_filtered} filtered by method, "
              f"{stats.keyword_filtered} by keyword{r}")
    print()


# ---------------------------------------------------------------------------
# CSV writer
# ---------------------------------------------------------------------------

_CSV_COLUMNS = [
    "timestamp", "url", "method", "path", "status_code",
    "content_length", "word_count", "line_count",
    "redirect_location", "original_method",
]


class CSVWriter:
    def __init__(self, path: str) -> None:
        self._file = open(path, "w", newline="")
        self._writer = csv.writer(self._file)
        self._writer.writerow(_CSV_COLUMNS)

    def write_result(self, result: ScanResult) -> None:
        self._writer.writerow([
            result.timestamp, result.url, result.method, result.path,
            result.status_code, result.content_length, result.word_count,
            result.line_count, result.redirect_location or "",
            result.original_method,
        ])

    def close(self) -> None:
        self._file.close()


# ---------------------------------------------------------------------------
# Progress tracker
# ---------------------------------------------------------------------------

class ProgressTracker:
    def __init__(self, total: int, use_color: bool = True) -> None:
        self.total = total
        self.completed = 0
        self.findings = 0
        self._use_color = use_color
        self._last_print = 0.0
        self._start = time.monotonic()
        self._window: list[float] = []  # timestamps for RPS calculation

    def update(self, findings_delta: int = 0) -> None:
        self.completed += 1
        self.findings += findings_delta
        now = time.monotonic()
        self._window.append(now)
        # Keep only last 3 seconds for rolling RPS
        cutoff = now - 3.0
        self._window = [t for t in self._window if t > cutoff]
        if now - self._last_print >= 0.25 or self.completed == self.total:
            self._print(now)
            self._last_print = now

    def _print(self, now: float) -> None:
        d = DIM if self._use_color else ""
        c = CYAN if self._use_color else ""
        r = RESET if self._use_color else ""
        elapsed = now - self._start
        if elapsed > 0 and len(self._window) > 1:
            window_span = self._window[-1] - self._window[0]
            rps = (len(self._window) - 1) / window_span if window_span > 0 else 0
        else:
            rps = 0
        pct = self.completed * 100 // self.total if self.total else 0
        line = f"\r{d}[{pct:>3}%] {self.completed}/{self.total} | {c}{self.findings} findings{r} {d}| {rps:.0f} req/s{r}"
        print(f"{line:<60}", end="", flush=True, file=sys.stderr)
        if self.completed == self.total:
            print(file=sys.stderr)


def print_summary(findings: int, total_requests: int, elapsed: float,
                  use_color: bool = True) -> None:
    d = DIM if use_color else ""
    r = RESET if use_color else ""
    b = BOLD if use_color else ""
    print(f"\n{b}{findings} findings{r} from {total_requests} requests in {elapsed:.1f}s")
