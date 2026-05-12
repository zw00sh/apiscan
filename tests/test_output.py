"""Tests for output.py: CSV writer and ANSI formatting."""

from __future__ import annotations

import csv
import os
import tempfile

from apiscan.output import (
    CSVWriter,
    LogWriter,
    ProgressTracker,
    ScanResult,
    build_curl,
    format_findings_tree,
    format_result,
    print_banner,
    print_hints,
)


def _make_result(**overrides) -> ScanResult:
    defaults = dict(
        url="http://example.com/api/users",
        method="GET",
        path="/api/users",
        status_code=200,
        content_length=42,
        word_count=5,
        line_count=1,
        redirect_location=None,
        reason="",
        confidence="",
        timestamp="2026-03-31T12:00:00",
    )
    defaults.update(overrides)
    return ScanResult(**defaults)


class TestFormatResult:
    def test_200_has_color(self):
        r = _make_result(status_code=200)
        line = format_result(r, use_color=True)
        assert "\033[38;5;82m" in line  # 256-color bright green
        assert "200" in line

    def test_301_has_color(self):
        r = _make_result(status_code=301, redirect_location="http://example.com/new")
        line = format_result(r, use_color=True)
        assert "\033[38;5;220m" in line  # 256-color yellow
        assert "301" in line
        assert "/new" in line

    def test_405_bold_red(self):
        r = _make_result(status_code=405)
        line = format_result(r, use_color=True)
        assert "\033[1m" in line  # BOLD
        assert "\033[38;5;196m" in line  # bright red

    def test_404_dim_grey(self):
        r = _make_result(status_code=404)
        line = format_result(r, use_color=True)
        assert "\033[38;5;245m" in line  # dim grey

    def test_401_distinct_from_404(self):
        r401 = format_result(_make_result(status_code=401), use_color=True)
        r404 = format_result(_make_result(status_code=404), use_color=True)
        # 401 should use bright orange (214), 404 dim grey (245) — visually distinct
        assert "\033[38;5;214m" in r401
        assert "\033[38;5;245m" in r404

    def test_429_background_shaded(self):
        r = _make_result(status_code=429)
        line = format_result(r, use_color=True)
        assert "\033[48;5;" in line  # has background color

    def test_502_background_shaded(self):
        r = _make_result(status_code=502)
        line = format_result(r, use_color=True)
        assert "\033[48;5;" in line  # has background color

    def test_no_color(self):
        r = _make_result(status_code=200)
        line = format_result(r, use_color=False)
        assert "\033[" not in line
        assert "200" in line

    def test_reason_shown_when_verbose(self):
        r = _make_result(reason="status: 404 -> 200")
        line = format_result(r, use_color=False, verbose=True)
        assert "(status: 404 -> 200)" in line

    def test_reason_hidden_without_verbose(self):
        r = _make_result(reason="status: 404 -> 200")
        line = format_result(r, use_color=False, verbose=False)
        assert "status: 404 -> 200" not in line

    def test_reason_hidden_when_empty(self):
        r = _make_result(reason="")
        line = format_result(r, use_color=False, verbose=True)
        assert "(" not in line or "redirect" in line.lower() or "->" in line

    def test_magnitude_bytes(self):
        r = _make_result(content_length=500)
        line = format_result(r, use_color=False)
        assert "500" in line

    def test_magnitude_kilobytes(self):
        r = _make_result(content_length=1500)
        line = format_result(r, use_color=False)
        assert "1.5K" in line

    def test_magnitude_megabytes(self):
        r = _make_result(content_length=2_500_000)
        line = format_result(r, use_color=False)
        assert "2.5M" in line

    def test_columns_aligned(self):
        """Fixed-width columns should produce consistent line lengths up to the path."""
        r1 = format_result(_make_result(content_length=42, word_count=5, line_count=1), use_color=False)
        r2 = format_result(_make_result(content_length=150_000, word_count=25_000, line_count=3_000), use_color=False)
        # Everything before the path should be the same width
        pre1 = r1.split("/api")[0]
        pre2 = r2.split("/api")[0]
        assert len(pre1) == len(pre2)


    def test_show_headers_multiline(self):
        r = _make_result(new_headers=(("x-powered-by", "Express"), ("x-request-id", "abc-123")))
        output = format_result(r, use_color=False, show_headers=True)
        lines = output.split("\n")
        assert len(lines) == 3  # main line + 2 header lines
        assert "x-powered-by: Express" in lines[1]
        assert "x-request-id: abc-123" in lines[2]

    def test_show_headers_hidden_by_default(self):
        r = _make_result(new_headers=(("x-request-id", "abc"),))
        line = format_result(r, use_color=False)
        assert "x-request-id" not in line

    def test_show_headers_empty_no_extra_lines(self):
        r = _make_result(new_headers=())
        output = format_result(r, use_color=False, show_headers=True)
        assert "\n" not in output

    def test_boundary_info_shown_without_verbose(self):
        r = _make_result(boundary_info="GET=403, POST=404")
        line = format_result(r, use_color=False, verbose=False)
        assert "GET=403, POST=404" in line

    def test_boundary_info_not_shown_when_none(self):
        r = _make_result()
        line = format_result(r, use_color=False, verbose=False)
        assert "boundary" not in line.lower()


class TestBuildCurl:
    def test_get_omits_x_flag(self):
        cmd = build_curl(_make_result(method="GET"))
        assert "-X" not in cmd.split()

    def test_post_includes_x_flag(self):
        cmd = build_curl(_make_result(method="POST"))
        assert "-X POST" in cmd

    def test_wildcard_method_does_not_leak_asterisk(self):
        """Boundary findings use method='*' as a display marker. build_curl must
        not produce '-X *', which is an invalid HTTP method."""
        cmd = build_curl(_make_result(method="*"))
        assert "-X *" not in cmd
        assert "*" not in cmd.split()


class TestCSVWriter:
    def test_write_and_read(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            path = f.name

        try:
            writer = CSVWriter(path)
            writer.write_result(_make_result())
            writer.write_result(_make_result(status_code=301, path="/other"))
            writer.close()

            with open(path, newline="") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                assert len(rows) == 2
                assert rows[0]["status_code"] == "200"
                assert rows[0]["path"] == "/api/users"
                assert rows[1]["status_code"] == "301"
                assert rows[1]["path"] == "/other"
                assert "timestamp" in rows[0]
                assert "reason" in rows[0]
                assert "confidence" in rows[0]
        finally:
            os.unlink(path)

    def test_csv_columns(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            path = f.name

        try:
            writer = CSVWriter(path)
            writer.close()

            with open(path, newline="") as f:
                reader = csv.reader(f)
                header = next(reader)
                expected = [
                    "timestamp", "url", "method", "path", "status_code",
                    "content_length", "word_count", "line_count",
                    "redirect_location", "is_boundary", "boundary_info",
                    "new_headers", "reason", "confidence", "curl",
                ]
                assert header == expected
        finally:
            os.unlink(path)


class TestLogWriter:
    def test_writes_header_and_entries(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            path = f.name
        try:
            writer = LogWriter(path, target="https://example.com", argv=["apiscan", "-u", "https://example.com"])
            writer.write_result(_make_result(status_code=200, method="GET",
                                              path="/api/users", content_length=1024,
                                              timestamp="2026-05-12T14:30:01"))
            writer.write_result(_make_result(status_code=405, method="POST",
                                              path="/api/admin", content_length=42,
                                              timestamp="2026-05-12T14:30:02"))
            writer.close()
            with open(path) as f:
                content = f.read()
            # Header
            assert "apiscan" in content
            assert "https://example.com" in content
            # Entries — dirsearch style: [time] STATUS - METHOD - SIZE - PATH
            assert "14:30:01" in content
            assert "200" in content
            assert "GET" in content
            assert "/api/users" in content
            assert "405" in content
            assert "POST" in content
            assert "/api/admin" in content
        finally:
            os.unlink(path)

    def test_entry_format_dirsearch_style(self):
        """Each line should follow dirsearch convention: bracketed time, status, size, path."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            path = f.name
        try:
            writer = LogWriter(path, target="https://example.com", argv=["apiscan"])
            writer.write_result(_make_result(status_code=200, method="GET",
                                              path="/x", content_length=1500,
                                              timestamp="2026-05-12T09:00:00"))
            writer.close()
            with open(path) as f:
                lines = [ln for ln in f.read().splitlines() if ln and not ln.startswith("#")]
            assert len(lines) == 1
            line = lines[0]
            assert line.startswith("[09:00:00]")
            assert "200" in line
            assert "/x" in line
            assert "1.5KB" in line or "1500B" in line or "1.5K" in line
        finally:
            os.unlink(path)

    def test_redirect_location_included(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            path = f.name
        try:
            writer = LogWriter(path, target="https://example.com", argv=["apiscan"])
            writer.write_result(_make_result(status_code=301, method="GET",
                                              path="/old", redirect_location="/new",
                                              timestamp="2026-05-12T09:00:00"))
            writer.close()
            with open(path) as f:
                content = f.read()
            assert "/old" in content
            assert "/new" in content
        finally:
            os.unlink(path)


class TestBanner:
    def test_banner_shows_methods(self, capsys):
        print_banner("http://example.com", 90, ["GET", "POST"], use_color=False)
        output = capsys.readouterr().out
        assert "target:" in output
        assert "routes:" in output
        assert "methods:" in output
        assert "GET, POST" in output

    def test_banner_custom_methods(self, capsys):
        print_banner("http://example.com", 100, ["GET", "POST", "PUT"], use_color=False)
        output = capsys.readouterr().out
        assert "GET, POST, PUT" in output

    def test_banner_shows_http_config(self, capsys):
        print_banner("http://example.com", 90, ["GET"], use_color=False,
                     concurrency=20, rate_limit=50.0, timeout=5.0)
        output = capsys.readouterr().out
        assert "20 workers" in output
        assert "50 req/s" in output
        assert "5.0s timeout" in output

    def test_banner_unlimited_rate(self, capsys):
        print_banner("http://example.com", 90, ["GET"], use_color=False)
        output = capsys.readouterr().out
        assert "unlimited" in output

    def test_banner_features_natural_language(self, capsys):
        print_banner("http://example.com", 90, ["GET"], use_color=False,
                     recurse=True, lookahead=True, max_depth=3)
        output = capsys.readouterr().out
        assert "recursion to depth 3" in output
        assert "lookahead" in output

    def test_banner_lookahead_default(self, capsys):
        print_banner("http://example.com", 90, ["GET"], use_color=False,
                     lookahead=True)
        output = capsys.readouterr().out
        assert "features: lookahead" in output

    def test_banner_no_lookahead(self, capsys):
        print_banner("http://example.com", 90, ["GET"], use_color=False,
                     lookahead=False)
        output = capsys.readouterr().out
        assert "lookahead disabled" in output


class TestProgressTracker:
    def test_status_bar_shows_sent_count(self, capsys):
        """The status bar should display how many HTTP requests have been sent."""

        class FakeTracker:
            sent = 42
            planned = 100
            routes_planned = 50
            queue_size = None
            skipped_fn = None
            blocked_fn = None

        progress = ProgressTracker(50, use_color=False, tracker=FakeTracker())
        progress.findings = 3
        progress._print(progress._start + 1.0)
        output = capsys.readouterr().err
        assert "42 sent" in output

    def test_status_bar_sent_count_is_exact_no_rounding(self, capsys):
        """The sent counter must show the exact integer, not '1.5k' style truncation."""

        class FakeTracker:
            sent = 1523
            planned = 5000
            routes_planned = 2000
            queue_size = None
            skipped_fn = None
            blocked_fn = None

        progress = ProgressTracker(2000, use_color=False, tracker=FakeTracker())
        progress._print(progress._start + 1.0)
        output = capsys.readouterr().err
        assert "1523 sent" in output or "1,523 sent" in output
        assert "1.5k sent" not in output

    def test_status_bar_sent_count_large_value(self, capsys):
        """A million sent requests still displays exactly."""

        class FakeTracker:
            sent = 1_234_567
            planned = 2_000_000
            routes_planned = 1_000_000
            queue_size = None
            skipped_fn = None
            blocked_fn = None

        progress = ProgressTracker(1_000_000, use_color=False, tracker=FakeTracker())
        progress._print(progress._start + 1.0)
        output = capsys.readouterr().err
        # Either bare or with thousands separators — anything but a truncated form
        assert ("1234567" in output) or ("1,234,567" in output)
        assert "1.2M" not in output and "1234.6k" not in output


class TestFindingsTree:
    def test_empty_results(self):
        assert format_findings_tree([], use_color=False) == ""

    def test_single_result(self):
        results = [_make_result(path="/api/users", status_code=200, method="GET")]
        tree = format_findings_tree(results, use_color=False)
        assert "api/users" in tree
        assert "200 GET" in tree

    def test_multiple_methods_same_path(self):
        results = [
            _make_result(path="/api/users", status_code=200, method="GET"),
            _make_result(path="/api/users", status_code=201, method="POST"),
        ]
        tree = format_findings_tree(results, use_color=False)
        assert "200 GET" in tree
        assert "201 POST" in tree

    def test_tree_structure(self):
        results = [
            _make_result(path="/api/v1/users", status_code=200, method="GET"),
            _make_result(path="/api/v1/health", status_code=200, method="GET"),
            _make_result(path="/admin/dashboard", status_code=401, method="GET"),
        ]
        tree = format_findings_tree(results, use_color=False)
        assert "api/v1" in tree  # collapsed chain
        assert "users" in tree
        assert "health" in tree
        assert "admin" in tree
        assert "dashboard" in tree

    def test_tree_connectors(self):
        results = [
            _make_result(path="/a/x"),
            _make_result(path="/b/y"),
        ]
        tree = format_findings_tree(results, use_color=False)
        assert "├──" in tree or "└──" in tree


class TestHints:
    def test_recurse_hint_when_boundaries(self, capsys):
        print_hints(recurse=False, lookahead=True, methods=["GET", "POST", "PUT"],
                    boundaries_found=3, use_color=False)
        output = capsys.readouterr().err
        assert "3 handler boundaries" in output
        assert "--recurse" in output

    def test_recurse_all_hint_when_recurse_set(self, capsys):
        print_hints(recurse=True, lookahead=True, methods=["GET", "POST", "PUT"],
                    boundaries_found=3, use_color=False)
        output = capsys.readouterr().err
        assert "--recurse-all" in output
        assert "re-run with --recurse" not in output

    def test_no_lookahead_hint(self, capsys):
        """Lookahead is now default — no hint to enable it."""
        print_hints(recurse=True, lookahead=True, methods=["GET", "POST", "PUT"],
                    boundaries_found=0, use_color=False)
        output = capsys.readouterr().err
        assert "--lookahead" not in output

    def test_methods_hint_for_default(self, capsys):
        print_hints(recurse=True, lookahead=True, methods=["GET", "POST"],
                    boundaries_found=0, use_color=False)
        output = capsys.readouterr().err
        assert "broader method coverage" in output

    def test_no_methods_hint_for_custom(self, capsys):
        print_hints(recurse=True, lookahead=True, methods=["GET", "POST", "PUT"],
                    boundaries_found=0, use_color=False)
        output = capsys.readouterr().err
        assert "method coverage" not in output

    def test_no_hints_when_all_enabled(self, capsys):
        print_hints(recurse=True, lookahead=True, methods=["GET", "POST", "PUT"],
                    boundaries_found=0, wordlist_tier="long", use_color=False)
        output = capsys.readouterr().err
        assert output.strip() == ""

    def test_short_wordlist_hint(self, capsys):
        print_hints(recurse=True, lookahead=True, methods=["GET", "POST", "PUT"],
                    boundaries_found=0, wordlist_tier="short", use_color=False)
        output = capsys.readouterr().err
        assert "--short" in output
        assert "10k" in output

    def test_default_wordlist_hint(self, capsys):
        print_hints(recurse=True, lookahead=True, methods=["GET", "POST", "PUT"],
                    boundaries_found=0, wordlist_tier="default", use_color=False)
        output = capsys.readouterr().err
        assert "--long" in output
