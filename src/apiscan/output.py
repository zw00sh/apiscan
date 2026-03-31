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
    c_on, c_off = _status_color(result.status_code, use_color)
    parts = [
        f"{c_on}{result.status_code:>3}{c_off}",
        f"{result.method:<7}",
        f"{result.path}",
        f"{result.content_length}B",
        f"{result.word_count}W",
        f"{result.line_count}L",
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


def print_banner(target: str, route_count: int, unsafe: bool,
                 stats: FilterStats, use_color: bool = True) -> None:
    b = BOLD if use_color else ""
    r = RESET if use_color else ""
    d = DIM if use_color else ""
    c = CYAN if use_color else ""
    print(f"\n{c}{BANNER}{r}")
    print(f" {d}api content discovery · v0.1.0{r}\n")
    print(f"  target:  {target}")
    print(f"  routes:  {route_count}")

    if unsafe:
        sc = sum(v for m, v in stats.method_breakdown.items() if m != "GET")
        print(f"  {YELLOW if use_color else ''}mode:    unsafe -- sending {sc} state-changing routes (POST/PUT/DELETE/PATCH){r}")
    else:
        print(f"  {d}mode:    safe (GET-only, keyword filter). "
              f"{stats.method_filtered} routes filtered by method, "
              f"{stats.keyword_filtered} by keyword. Use --unsafe for full scan.{r}")
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

    def update(self, findings_delta: int = 0) -> None:
        self.completed += 1
        self.findings += findings_delta
        now = time.monotonic()
        if now - self._last_print >= 0.5 or self.completed == self.total:
            self._print()
            self._last_print = now

    def _print(self) -> None:
        d = DIM if self._use_color else ""
        r = RESET if self._use_color else ""
        print(
            f"\r{d}[{self.completed}/{self.total}] {self.findings} findings{r}",
            end="", flush=True, file=sys.stderr,
        )
        if self.completed == self.total:
            print(file=sys.stderr)


def print_summary(findings: int, total_requests: int, elapsed: float,
                  use_color: bool = True) -> None:
    d = DIM if use_color else ""
    r = RESET if use_color else ""
    b = BOLD if use_color else ""
    print(f"\n{b}{findings} findings{r} from {total_requests} requests in {elapsed:.1f}s")
