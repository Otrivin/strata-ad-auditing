"""In-memory log capture used to fold scan-time log records into scan.log."""
from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Iterator


class _ListHandler(logging.Handler):
    """Buffer log records in a list; cheap, thread-safe via the GIL on append."""

    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@contextmanager
def capture_scan_log(level: int = logging.DEBUG) -> Iterator[list[logging.LogRecord]]:
    """
    Capture all log records emitted under the `strata` logger tree at DEBUG level
    (or whatever level you pass) for the duration of the with-block.

    Yields the underlying list of records so the caller can pass it on to write_scan_log().

    Existing console handlers are left alone — this only adds a parallel sink.
    """
    handler = _ListHandler()
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter("%(message)s"))

    root = logging.getLogger("strata")
    prev_level = root.level
    # Make sure records actually reach the handler — root may be at WARNING by default
    if root.level > level or root.level == 0:
        root.setLevel(level)
    root.addHandler(handler)

    try:
        yield handler.records
    finally:
        root.removeHandler(handler)
        root.setLevel(prev_level)
