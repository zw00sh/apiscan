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

def _status_color(status: int, use_color: bool) -> tuple[str, str]:
    if not use_color:
        return "", ""
    if status == 405:
        return RED, RESET
    if 200 <= status < 300:
        return GREEN, RESET
    if 300 <= status < 400:
        return YELLOW, RESET
    if 400 <= status < 500:
        return DIM, RESET
    return "", ""


def format_result(result: ScanResult, use_color: bool = True) -> str:
    sc_on, sc_off = _status_color(result.status_code, use_color)
    if use_color:
        d, r = DIM, RESET
        parts = [
            f"{sc_on}{result.status_code:>3}{sc_off}",
            f"{CYAN}{result.method:<7}{RESET}",
            f"{YELLOW}{result.content_length:>7}B{RESET}",
            f"{MAGENTA}{result.word_count:>5}W{RESET}",
            f"{d}{result.line_count:>5}L{r}",
            f"{WHITE}{result.path}{RESET}",
        ]
    else:
        parts = [
            f"{result.status_code:>3}",
            f"{result.method:<7}",
            f"{result.content_length:>7}B",
            f"{result.word_count:>5}W",
            f"{result.line_count:>5}L",
            f"{result.path}",
        ]
    line = " | ".join(parts)
    if result.original_method and result.original_method != result.method:
        hint = f" {DIM}(original: {result.original_method}){RESET}" if use_color else f" (original: {result.original_method})"
        line += hint
    if result.redirect_location:
        redir = f" -> {result.redirect_location}"
        line += f" {DIM}{redir}{RESET}" if use_color else redir
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
    print(f" {d}api content discovery · v0.3.0{r}\n")
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
