"""Incremental catalog reads, invalidation, and disposable-cache failure paths."""

import os
import sqlite3
from datetime import date, datetime, timezone
from pathlib import Path
from unittest.mock import Mock

import pytest

from hecate_agent.core.catalog_index import CatalogIndex


def word_data(path, text):
    return {"word": [text]}


def index_files(root, parser, **kwargs):
    index = CatalogIndex(root, "test-v1")
    index.refresh(root.glob("*.md"), parser, tokens=lambda data: [("word", data["word"][0])], **kwargs)
    return index


@pytest.fixture
def catalog(tmp_path):
    root = tmp_path / "hunts"
    root.mkdir()
    for number in range(3):
        (root / f"H-{number:04}.md").write_text(f"value-{number}")
    return root


def test_warm_index_survives_new_instances_without_rereading_files(catalog, monkeypatch):
    parser = Mock(side_effect=lambda path, text: {"word": [text]})
    index_files(catalog, parser)
    parser.reset_mock()
    monkeypatch.setattr(Path, "read_text", Mock(side_effect=AssertionError("Unexpected source read")))
    index = index_files(catalog, parser)
    assert len(index.entries()) == 3
    assert index.lookup("word", "value-1") == [catalog / "H-0001.md"]
    parser.assert_not_called()


def test_only_edited_file_is_read_and_parsed(catalog, monkeypatch):
    parser = Mock(side_effect=lambda path, text: {"word": [text]})
    index_files(catalog, parser)
    path = catalog / "H-0001.md"
    path.write_text("updated")
    parser.reset_mock()
    original = Path.read_text
    reads = []

    def read(path, *args, **kwargs):
        reads.append(path)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    index = index_files(catalog, parser)
    assert reads == [path]
    assert parser.call_count == 1
    assert index.lookup("word", "value-1") == []
    assert index.lookup("word", "updated") == [path]


def test_touch_reuses_parsed_data_but_updates_recency(catalog):
    parser = Mock(side_effect=lambda path, text: {"word": [text]})
    index_files(catalog, parser)
    path = catalog / "H-0000.md"
    stat = path.stat()
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 10_000_000_000))
    parser.reset_mock()
    index = index_files(catalog, parser)
    parser.assert_not_called()
    assert index.lookup("word", "value-0", since_ns=stat.st_mtime_ns + 1) == [path]


@pytest.mark.parametrize("replace", [False, True])
def test_same_size_restored_mtime_edits_are_detected(catalog, replace):
    parser = word_data
    index_files(catalog, parser)
    path = catalog / "H-0000.md"
    stat = path.stat()
    target = catalog / "replacement.tmp" if replace else path
    target.write_text("newword")
    os.utime(target, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    if replace:
        target.replace(path)
    index = index_files(catalog, parser)
    assert index.lookup("word", "newword") == [path]
    assert index.lookup("word", "value-0") == []


def test_add_delete_and_rename_remove_stale_membership(catalog):
    parser = word_data
    index_files(catalog, parser)
    (catalog / "H-0000.md").unlink()
    (catalog / "H-0001.md").rename(catalog / "H-0004.md")
    (catalog / "H-0005.md").write_text("added")
    index = index_files(catalog, parser)
    assert index.lookup("word", "value-0") == []
    assert index.lookup("word", "value-1") == [catalog / "H-0004.md"]
    assert index.lookup("word", "added") == [catalog / "H-0005.md"]


def test_parser_failure_never_keeps_old_data_and_is_retryable(catalog):
    parser = word_data
    index_files(catalog, parser)
    (catalog / "H-0001.md").write_text("changed")
    failing = Mock(side_effect=ValueError("temporary parser failure"))
    failed = index_files(catalog, failing)
    assert failed.lookup("word", "value-1") == []
    assert len(failed.entries()) == 2
    repaired = index_files(catalog, parser)
    assert repaired.lookup("word", "changed") == [catalog / "H-0001.md"]


def test_read_only_cache_uses_fresh_file_data(catalog, monkeypatch):
    parser = word_data
    index_files(catalog, parser)
    (catalog / "H-0000.md").write_text("changed")
    original = CatalogIndex._connect

    def read_only(self):
        conn = original(self)
        conn.execute("PRAGMA query_only=ON")
        return conn

    monkeypatch.setattr(CatalogIndex, "_connect", read_only)
    index = index_files(catalog, parser)
    assert index.lookup("word", "changed") == [catalog / "H-0000.md"]
    assert index.lookup("word", "value-0") == []


@pytest.mark.parametrize("failure", ["unavailable", "database", "payload"])
def test_bad_cache_falls_back_to_files(catalog, monkeypatch, failure):
    parser = word_data
    index = index_files(catalog, parser)
    if failure == "unavailable":
        monkeypatch.setattr(CatalogIndex, "_connect", Mock(side_effect=OSError("read-only workspace")))
    elif failure == "database":
        index.database.write_bytes(b"corrupt database")
    else:
        with sqlite3.connect(index.database) as conn:
            conn.execute("UPDATE documents SET payload='broken JSON'")
    refreshed = index_files(catalog, parser)
    assert refreshed.lookup("word", "value-1") == [catalog / "H-0001.md"]


def test_change_during_read_is_not_cached_under_the_wrong_fingerprint(catalog, monkeypatch):
    original = Path.read_text
    path = catalog / "H-0000.md"
    changed = False

    def read(file, *args, **kwargs):
        nonlocal changed
        content = original(file, *args, **kwargs)
        if file == path and not changed:
            changed = True
            path.write_text("after edit")
        return content

    monkeypatch.setattr(Path, "read_text", read)
    parser = word_data
    index = index_files(catalog, parser)
    assert index.lookup("word", "after edit") == [path]
    assert index.lookup("word", "value-0") == []


def test_dates_round_trip_and_uncacheable_fields_do_not_hide_documents(catalog):
    value = {"date": date(2026, 1, 2), "datetime": datetime(2026, 1, 2, tzinfo=timezone.utc)}
    index = CatalogIndex(catalog, "dates")
    index.refresh(catalog.glob("*.md"), lambda path, text: value)
    other = CatalogIndex(catalog, "dates")
    other.refresh(catalog.glob("*.md"), Mock(side_effect=AssertionError("Unexpected parse")))
    assert other.entries()[0].data == value
    index = CatalogIndex(catalog, "custom")
    index.refresh(catalog.glob("*.md"), lambda path, text: {"custom": {1, 2}, "word": {"uncached"}})
    assert index.entries()[0].data == {"custom": {1, 2}, "word": {"uncached"}}
    assert len(index.lookup("word", "uncached")) == 3


def test_parser_does_not_hold_sqlite_write_lock(catalog):
    index = CatalogIndex(catalog, "locks")

    def parse(path, text):
        with sqlite3.connect(index.database, timeout=0) as other:
            other.execute("BEGIN IMMEDIATE")
        return {"value": text}

    index.refresh(catalog.glob("*.md"), parse)
    assert len(index.entries()) == 3
