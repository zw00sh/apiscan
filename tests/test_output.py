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
    def test_200_green(self):
        r = _make_result(status_code=200)
        line = format_result(r, use_color=True)
        assert "\033[32m" in line  # GREEN
        assert "200" in line

    def test_301_yellow(self):
        r = _make_result(status_code=301, redirect_location="http://example.com/new")
        line = format_result(r, use_color=True)
        assert "\033[33m" in line  # YELLOW
        assert "301" in line
        assert "/new" in line

    def test_405_red(self):
        r = _make_result(status_code=405)
        line = format_result(r, use_color=True)
        assert "\033[31m" in line  # RED

    def test_404_dim(self):
        r = _make_result(status_code=404)
        line = format_result(r, use_color=True)
        assert "\033[2m" in line  # DIM

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
                    "redirect_location", "original_method",
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
        print_banner("http://example.com", 60, unsafe=False, stats=stats, use_color=False)
        output = capsys.readouterr().out
        assert "safe" in output.lower()
        assert "30 routes filtered by method" in output
        assert "10 by keyword" in output
        assert "--unsafe" in output

    def test_unsafe_mode_banner(self, capsys):
        stats = FilterStats(
            total=100, kept=100, method_filtered=0, keyword_filtered=0,
            method_breakdown={"GET": 60, "POST": 25, "DELETE": 15},
        )
        print_banner("http://example.com", 100, unsafe=True, stats=stats, use_color=False)
        output = capsys.readouterr().out
        assert "unsafe" in output.lower()
        assert "40 state-changing" in output
