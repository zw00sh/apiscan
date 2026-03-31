"""Tests for output.py: CSV writer and ANSI formatting."""

from __future__ import annotations

import csv
import os
import tempfile

from apiscan.kite import FilterStats
from apiscan.output import (
    CSVWriter,
    ScanResult,
    format_result,
    print_banner,
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
        original_method="GET",
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

    def test_original_method_shown(self):
        r = _make_result(method="GET", original_method="POST")
        line = format_result(r, use_color=False)
        assert "(original: POST)" in line

    def test_original_method_hidden_when_same(self):
        r = _make_result(method="GET", original_method="GET")
        line = format_result(r, use_color=False)
        assert "original" not in line

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
                assert "original_method" in rows[0]
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
                    "redirect_location", "original_method", "curl",
                ]
                assert header == expected
        finally:
            os.unlink(path)


class TestFilterStatsMessage:
    def test_safe_mode_banner(self, capsys):
        stats = FilterStats(
            total=100, kept=60, method_filtered=30, keyword_filtered=10,
            method_breakdown={"GET": 60, "POST": 25, "DELETE": 15},
        )
        print_banner("http://example.com", 60, False, False, stats=stats, use_color=False)
        output = capsys.readouterr().out
        assert "safe" in output.lower()
        assert "30 filtered by method" in output
        assert "10 by keyword" in output

    def test_unsafe_all_banner(self, capsys):
        stats = FilterStats(
            total=100, kept=100, method_filtered=0, keyword_filtered=0,
            method_breakdown={"GET": 60, "POST": 25, "DELETE": 15},
        )
        print_banner("http://example.com", 100, True, True, stats=stats, use_color=False)
        output = capsys.readouterr().out
        assert "unsafe-all" in output.lower()
        assert "40 state-changing" in output

    def test_unsafe_methods_banner(self, capsys):
        stats = FilterStats(
            total=100, kept=90, method_filtered=0, keyword_filtered=10,
            method_breakdown={"GET": 60, "POST": 25, "DELETE": 15},
        )
        print_banner("http://example.com", 90, True, False, stats=stats, use_color=False)
        output = capsys.readouterr().out
        assert "unsafe-methods" in output.lower()

    def test_unsafe_keywords_banner(self, capsys):
        stats = FilterStats(
            total=100, kept=60, method_filtered=30, keyword_filtered=0,
            method_breakdown={"GET": 60, "POST": 25, "DELETE": 15},
        )
        print_banner("http://example.com", 60, False, True, stats=stats, use_color=False)
        output = capsys.readouterr().out
        assert "unsafe-keywords" in output.lower()
