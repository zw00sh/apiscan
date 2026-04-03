"""Unit tests for the dependency-aware work queue."""

from __future__ import annotations

import asyncio

import pytest

from apiscan.workqueue import WorkQueue


class TestWorkQueue:
    @pytest.mark.asyncio
    async def test_basic_ordering(self):
        wq = WorkQueue()
        wq.add("a", "item_a")
        wq.add("b", "item_b", "a")
        wq.prepare()
        key, item = await wq.get()
        assert key == "a"
        wq.item_done("a")
        key, item = await wq.get()
        assert key == "b"
        wq.item_done("b")

    @pytest.mark.asyncio
    async def test_parallel_no_deps(self):
        wq = WorkQueue()
        wq.add("a", "A")
        wq.add("b", "B")
        wq.prepare()
        keys = set()
        keys.add((await wq.get())[0])
        keys.add((await wq.get())[0])
        assert keys == {"a", "b"}

    @pytest.mark.asyncio
    async def test_dynamic_add(self):
        wq = WorkQueue()
        wq.add("a", "A")
        wq.prepare()
        await wq.get()
        wq.enqueue_dynamic("d", "dynamic")
        key, item = await wq.get()
        assert key == "d"
        assert item == "dynamic"

    @pytest.mark.asyncio
    async def test_recursive_batch_with_deps(self):
        wq = WorkQueue()
        wq.add("a", "A")
        wq.prepare()
        k, _ = await wq.get()
        wq.item_done(k)
        # Add batch where c depends on b
        wq.enqueue_recursive_batch([
            ("b", "B", []),
            ("c", "C", ["b"]),
        ])
        key, item = await wq.get()
        assert key == "b"
        wq.item_done("b")
        key, item = await wq.get()
        assert key == "c"
        wq.item_done("c")

    @pytest.mark.asyncio
    async def test_skip_fn_releases_dependents(self):
        wq = WorkQueue()
        wq.skip_fn = lambda k, i: k == "a"
        wq.add("a", "A")
        wq.add("b", "B", "a")
        wq.prepare()
        # a is skipped, so b should become ready
        key, item = await wq.get()
        assert key == "b"
        assert wq.skipped == 1

    @pytest.mark.asyncio
    async def test_manual_gate(self):
        wq = WorkQueue()
        wq.add_manual_gate("gate")
        wq.add("a", "A", "gate")
        wq.prepare()
        # Gate is ready but doesn't go to worker queue — a is blocked
        assert wq.ready_count == 0
        assert wq.blocked_count > 0
        wq.item_done("gate")
        key, item = await wq.get()
        assert key == "a"

    @pytest.mark.asyncio
    async def test_completed_deps_stripped_in_batch(self):
        wq = WorkQueue()
        wq.add("a", "A")
        wq.prepare()
        k, _ = await wq.get()
        wq.item_done(k)
        # Batch where b depends on already-completed a
        wq.enqueue_recursive_batch([
            ("b", "B", ["a"]),
        ])
        key, item = await wq.get()
        assert key == "b"

    @pytest.mark.asyncio
    async def test_wait_completes(self):
        wq = WorkQueue()
        wq.add("a", "A")
        wq.prepare()
        k, _ = await wq.get()
        wq.item_done(k)
        # Should not hang
        await asyncio.wait_for(wq.wait(), timeout=1.0)

    @pytest.mark.asyncio
    async def test_skip_fn_in_recursive_batch(self):
        wq = WorkQueue()
        wq.skip_fn = lambda k, i: k == "skip_me"
        wq.add("a", "A")
        wq.prepare()
        k, _ = await wq.get()
        wq.item_done(k)
        wq.enqueue_recursive_batch([
            ("skip_me", "X", []),
            ("after_skip", "Y", ["skip_me"]),
        ])
        # skip_me is skipped, after_skip should be released
        key, item = await wq.get()
        assert key == "after_skip"
        assert wq.skipped == 1
