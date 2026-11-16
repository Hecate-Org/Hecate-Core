"""Bounded, unambiguous inputs and exclusive private artifacts for model evals."""

from __future__ import annotations

import json
import math
import os
import signal
import stat
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, TextIO

import yaml

MAX_SUITE_BYTES = 1024 * 1024
MAX_REPORT_BYTES = 64 * 1024 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
MAX_TOTAL_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_CASES = 1000
MAX_DEPTH = 32


def read_bounded(path: Path, limit: int) -> str:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Evaluation input must be a regular file")
        if info.st_size > limit:
            raise ValueError("Evaluation input exceeds its size limit")
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("Evaluation input exceeds its size limit")
    try:
        return raw.decode("utf-8")
    except UnicodeError:
        raise ValueError("Evaluation input must be UTF-8") from None


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def invalid_constant(value: str) -> None:
    raise ValueError("Non-finite JSON number")


def finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("Non-finite JSON number")
    return number


def parse_json(text: str) -> Any:
    return json.loads(text, object_pairs_hook=unique_object, parse_constant=invalid_constant, parse_float=finite_float)


def load_report(path: Path) -> dict[str, Any]:
    try:
        report = parse_json(read_bounded(path, MAX_REPORT_BYTES))
    except (UnicodeError, RecursionError, ValueError):
        raise ValueError("Invalid or oversized evaluation report") from None
    if not isinstance(report, dict):
        raise ValueError("Evaluation report must be an object")
    return report


class UniqueLoader(yaml.SafeLoader):
    def construct_mapping(self, node: Any, deep: bool = False) -> dict[Any, Any]:
        keys: set[Any] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in keys:
                raise ValueError("Duplicate YAML key")
            keys.add(key)
        return super().construct_mapping(node, deep=deep)


def load_suite_yaml(path: Path) -> Any:
    text = read_bounded(path, MAX_SUITE_BYTES)
    try:
        depth = 0
        for index, event in enumerate(yaml.parse(text)):
            if index > 100_000 or isinstance(event, yaml.AliasEvent):
                raise ValueError("YAML aliases or excessive node counts are not supported")
            if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
                depth += 1
                if depth > MAX_DEPTH:
                    raise ValueError("Suite nesting exceeds its depth limit")
            elif isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
                depth -= 1
        loader = UniqueLoader(text)
        try:
            return loader.get_single_data()
        finally:
            loader.dispose()
    except (yaml.YAMLError, RecursionError, TypeError):
        raise ValueError("Invalid suite YAML") from None


def validate_json_value(value: Any, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise ValueError("Expected answer exceeds its nesting limit")
    if value is None or type(value) in (bool, int):
        return
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeError:
            raise ValueError("Expected answer contains invalid Unicode") from None
        return
    if type(value) is float and math.isfinite(value):
        return
    if isinstance(value, list):
        for item in value:
            validate_json_value(item, depth + 1)
        return
    if isinstance(value, dict) and all(isinstance(k, str) for k in value):
        for key, item in value.items():
            validate_json_value(key, depth + 1)
            validate_json_value(item, depth + 1)
        return
    raise ValueError("Expected answers must contain finite, JSON-compatible values")


def strict_equal(actual: Any, expected: Any) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(strict_equal(actual[k], v) for k, v in expected.items())
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(strict_equal(a, b) for a, b in zip(actual, expected))
    return bool(actual == expected)


@contextmanager
def reserve_report(path: Path | None) -> Iterator[tuple[TextIO | None, TextIO | None]]:
    """Claim both artifacts before any provider is constructed or called."""
    if path is None:
        yield None, None
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as report:
        progress_fd = os.open(path.with_name(path.name + ".progress.jsonl"), flags, 0o600)
        with os.fdopen(progress_fd, "w", encoding="utf-8") as progress:
            yield report, progress


def write_checkpoint(handle: TextIO | None, value: dict[str, Any]) -> None:
    if handle is not None:
        handle.write(json.dumps(value, allow_nan=False) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


@contextmanager
def interruptible() -> Iterator[None]:
    """Let a normal termination save a failed/partial report, like Ctrl+C."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    previous = signal.getsignal(signal.SIGTERM)

    def terminate(signum: int, frame: Any) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, terminate)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)
