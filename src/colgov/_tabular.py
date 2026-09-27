"""Tabular files for the ``colgov`` command: CSV, or Parquet with pyarrow.

A file's format comes from its extension: ``.parquet`` or ``.pq`` is
Parquet, anything else is CSV. CSV values are text and an empty cell is a
null. Parquet keeps its column types and nulls, and is read and written in
batches so memory stays bounded.
"""

from __future__ import annotations

import contextlib
import csv
import os
import sys
import tempfile
from collections.abc import Callable, Iterator, Sequence
from typing import Any

PARQUET_SUFFIXES = (".parquet", ".pq")
BATCH_ROWS = 10_000

Row = list[Any]


class TabularError(Exception):
    """A file can't be read or written as a table."""


def is_parquet(path: str) -> bool:
    return path.lower().endswith(PARQUET_SUFFIXES)


def _pyarrow() -> Any:
    try:
        import pyarrow
        import pyarrow.parquet
    except ImportError:
        raise TabularError('reading and writing Parquet needs pyarrow: pip install "colgov[parquet]"') from None
    return pyarrow


class Source:
    """A table to read: its header, column types, and rows."""

    path: str
    header: list[str]

    def rows(self, columns: Sequence[str] | None = None) -> Iterator[tuple[str, Row]]:
        """Yield (location, values) per row: all columns, or just ``columns`` in that order."""
        raise NotImplementedError  # pragma: no cover

    def is_string(self, column: str) -> bool:
        raise NotImplementedError  # pragma: no cover

    def type_name(self, column: str) -> str:
        raise NotImplementedError  # pragma: no cover

    def arrow_type(self, column: str) -> Any:
        """The column's pyarrow type, or None for text."""
        return None

    def sample(self, limit: int) -> dict[str, list[Any]]:
        """The first ``limit`` rows, as columns."""
        data: dict[str, list[Any]] = {c: [] for c in self.header}
        for n, (_, row) in enumerate(self.rows()):
            if n >= limit:
                break
            for column, value in zip(self.header, row, strict=True):
                data[column].append(value)
        return data


def _check_header(path: str, header: list[str]) -> list[str]:
    if not header:
        raise TabularError(f"{path}: no header row")
    if len(set(header)) != len(header) or not all(header):
        raise TabularError(f"{path}: column names must be unique and non-empty")
    return header


class CsvSource(Source):
    def __init__(self, path: str) -> None:
        self.path = path
        with open(path, newline="", encoding="utf-8-sig") as f:
            header = next(csv.reader(f), None) or []
        self.header = _check_header(path, header)

    def rows(self, columns: Sequence[str] | None = None) -> Iterator[tuple[str, Row]]:
        positions = None if columns is None else [self.header.index(c) for c in columns]
        with open(self.path, newline="", encoding="utf-8-sig") as f:
            reader = csv.reader(f)
            next(reader, None)
            for lineno, row in enumerate(reader, start=2):
                if len(row) != len(self.header):
                    raise TabularError(
                        f"{self.path}, line {lineno}: expected {len(self.header)} fields, got {len(row)}"
                    )
                values: Row = [v if v != "" else None for v in row]
                yield f"line {lineno}", values if positions is None else [values[i] for i in positions]

    def is_string(self, column: str) -> bool:
        return True

    def type_name(self, column: str) -> str:
        return "string"


class ParquetSource(Source):
    def __init__(self, path: str) -> None:
        self.path = path
        pa = _pyarrow()
        try:
            self._file = pa.parquet.ParquetFile(path)
        except (pa.ArrowException, ValueError) as exc:
            raise TabularError(f"{path}: not a readable Parquet file: {exc}") from None
        self._schema = self._file.schema_arrow
        self._pa = pa
        self.header = _check_header(path, list(self._schema.names))

    def rows(self, columns: Sequence[str] | None = None) -> Iterator[tuple[str, Row]]:
        names = list(self.header if columns is None else columns)
        n = 0
        for batch in self._file.iter_batches(batch_size=BATCH_ROWS, columns=names):
            for row in zip(*(batch.column(i).to_pylist() for i in range(batch.num_columns)), strict=True):
                n += 1
                yield f"row {n}", list(row)
        if not names:  # no columns asked for: still report every row
            for _ in range(self._file.metadata.num_rows):
                n += 1
                yield f"row {n}", []

    def _type(self, column: str) -> Any:
        t = self._schema.field(column).type
        types = self._pa.types
        return t.value_type if types.is_dictionary(t) else t

    def is_string(self, column: str) -> bool:
        t = self._type(column)
        types = self._pa.types
        is_string_view = getattr(types, "is_string_view", None)  # pyarrow >= 16
        if is_string_view is not None and is_string_view(t):
            return True
        return bool(types.is_string(t) or types.is_large_string(t))

    def type_name(self, column: str) -> str:
        return str(self._type(column))

    def arrow_type(self, column: str) -> Any:
        return self._type(column)


def open_source(path: str) -> Source:
    return ParquetSource(path) if is_parquet(path) else CsvSource(path)


@contextlib.contextmanager
def open_sink(path: str, columns: list[str], types: dict[str, Any]) -> Iterator[Callable[[Row], None]]:
    """Yield a function that writes one row.

    ``-`` writes CSV to stdout. Otherwise the file is written to a temporary
    name and renamed into place only if everything succeeds. ``types`` gives
    Parquet column types (None means text); CSV ignores them.
    """
    if path == "-":
        writer = csv.writer(sys.stdout)
        writer.writerow(columns)
        yield writer.writerow
        return
    parquet = is_parquet(path)
    pa = _pyarrow() if parquet else None
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".colgov-", suffix=".tmp")
    try:
        if pa is None:
            with os.fdopen(fd, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(columns)
                yield writer.writerow
        else:
            os.close(fd)
            schema = pa.schema([(c, types.get(c) or pa.string()) for c in columns])
            with pa.parquet.ParquetWriter(tmp, schema) as pq_writer:
                buffer: list[Row] = []

                def flush() -> None:
                    arrays = [pa.array([r[i] for r in buffer], type=f.type) for i, f in enumerate(schema)]
                    pq_writer.write_table(pa.Table.from_arrays(arrays, schema=schema))
                    buffer.clear()

                def write(row: Row) -> None:
                    buffer.append(row)
                    if len(buffer) >= BATCH_ROWS:
                        flush()

                yield write
                if buffer:
                    flush()
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
