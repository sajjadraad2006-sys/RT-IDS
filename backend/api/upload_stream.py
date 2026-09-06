"""Bounded parsers for supported uploaded flow-record containers."""
from __future__ import annotations

from dataclasses import dataclass
import csv
import io
import itertools
import json
from pathlib import Path
from typing import Any, BinaryIO, Iterator
import unicodedata

from ..detection.input_schema import FlowSchemaValidator


SUPPORTED_UPLOAD_EXTENSIONS = {".csv", ".tsv", ".json", ".ndjson", ".jsonl"}
READ_CHUNK_BYTES = 1024 * 1024
JSON_CHUNK_CHARS = 64 * 1024
MAX_JSON_VALUE_CHARS = 2 * 1024 * 1024


class UploadParseError(ValueError):
    """A supported container is malformed or violates a bounded parser rule."""


class DuplicateJsonKeyError(ValueError):
    """A JSON object repeated the same raw member name."""


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    normalized_keys: set[str] = set()
    for key, value in pairs:
        normalized = unicodedata.normalize("NFC", key)
        if normalized in normalized_keys:
            raise DuplicateJsonKeyError("duplicate_json_key")
        normalized_keys.add(normalized)
        result[key] = value
    return result


@dataclass(frozen=True)
class RejectedRow:
    reason: str


@dataclass
class PreparedUpload:
    input_format: str
    validator: FlowSchemaValidator
    rows: Iterator[dict[str, Any] | RejectedRow]
    bytes_read: int

    def close(self) -> None:
        """Release parser wrappers without closing Starlette's upload stream."""
        close_rows = getattr(self.rows, "close", None)
        if callable(close_rows):
            close_rows()


def enforce_byte_limit(stream: BinaryIO, max_bytes: int) -> int:
    """Scan a seekable spooled upload without retaining a second byte copy."""
    stream.seek(0)
    total = 0
    while True:
        chunk = stream.read(READ_CHUNK_BYTES)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            stream.seek(0)
            raise UploadParseError("upload_byte_limit_exceeded")
        if b"\x00" in chunk:
            stream.seek(0)
            raise UploadParseError("binary_content_not_supported")
    stream.seek(0)
    if total == 0:
        raise UploadParseError("empty_upload")
    return total


def _text_wrapper(stream: BinaryIO) -> io.TextIOWrapper:
    return io.TextIOWrapper(
        stream, encoding="utf-8-sig", errors="strict", newline="",
        write_through=False,
    )


def _csv_upload(stream: BinaryIO, extension: str, bytes_read: int) -> PreparedUpload:
    text = _text_wrapper(stream)
    try:
        sample = text.read(64 * 1024)
        text.seek(0)
        if extension == ".tsv":
            delimiter = "\t"
            input_format = "tsv"
        else:
            input_format = "csv"
            try:
                delimiter = csv.Sniffer().sniff(sample, delimiters=",;\t").delimiter
            except csv.Error:
                delimiter = ","
        reader = csv.reader(text, delimiter=delimiter)
        try:
            header = next(reader)
        except StopIteration as exc:
            raise UploadParseError("missing_header") from exc
        header = [str(item).strip().lstrip("\ufeff") for item in header]
        validator = FlowSchemaValidator(header, input_format=input_format)

        def rows() -> Iterator[dict[str, Any] | RejectedRow]:
            try:
                for values in reader:
                    if not values or not any(str(value).strip() for value in values):
                        continue
                    if len(values) != len(header):
                        yield RejectedRow("column_count_mismatch")
                    else:
                        yield dict(zip(header, values))
            except (csv.Error, UnicodeDecodeError) as exc:
                raise UploadParseError(f"malformed_{input_format}") from exc
            finally:
                # Detach so TextIOWrapper does not close Starlette's upload.
                try:
                    text.detach()
                except (ValueError, OSError):
                    pass

        return PreparedUpload(input_format, validator, rows(), bytes_read)
    except Exception:
        try:
            text.detach()
        except (ValueError, OSError):
            pass
        raise


def _iter_ndjson(text: io.TextIOWrapper) -> Iterator[Any | RejectedRow]:
    try:
        for line in text:
            stripped = line.strip()
            if not stripped:
                continue
            if len(stripped) > MAX_JSON_VALUE_CHARS:
                yield RejectedRow("json_row_too_large")
                continue
            try:
                yield json.loads(
                    stripped, object_pairs_hook=_reject_duplicate_json_keys
                )
            except DuplicateJsonKeyError:
                yield RejectedRow("duplicate_json_key")
            except json.JSONDecodeError:
                yield RejectedRow("invalid_ndjson_line")
    except UnicodeDecodeError as exc:
        raise UploadParseError("invalid_utf8") from exc


def _iter_json_values(text: io.TextIOWrapper) -> Iterator[Any]:
    """Incrementally decode a top-level JSON object or array."""
    decoder = json.JSONDecoder(object_pairs_hook=_reject_duplicate_json_keys)
    buffer = ""
    position = 0
    eof = False

    def compact_and_fill() -> bool:
        nonlocal buffer, position, eof
        if position:
            buffer = buffer[position:]
            position = 0
        chunk = text.read(JSON_CHUNK_CHARS)
        if chunk:
            buffer += chunk
            return True
        eof = True
        return False

    def skip_space() -> None:
        nonlocal position
        while True:
            while position < len(buffer) and buffer[position].isspace():
                position += 1
            if position < len(buffer) or eof:
                return
            compact_and_fill()

    compact_and_fill()
    skip_space()
    if position >= len(buffer):
        raise UploadParseError("empty_json")
    is_array = buffer[position] == "["
    if is_array:
        position += 1
    first = True

    while True:
        skip_space()
        if is_array:
            if position < len(buffer) and buffer[position] == "]":
                position += 1
                break
            if not first:
                if position >= len(buffer) and not eof:
                    compact_and_fill()
                    skip_space()
                if position >= len(buffer) or buffer[position] != ",":
                    raise UploadParseError("malformed_json_array")
                position += 1
                skip_space()
        elif not first:
            break

        value_start = position
        while True:
            try:
                value, end = decoder.raw_decode(buffer, position)
                position = end
                yield value
                first = False
                break
            except DuplicateJsonKeyError as exc:
                raise UploadParseError("duplicate_json_key") from exc
            except json.JSONDecodeError as exc:
                if eof:
                    raise UploadParseError("malformed_json") from exc
                if len(buffer) - value_start > MAX_JSON_VALUE_CHARS:
                    raise UploadParseError("json_row_too_large") from exc
                # Keep the incomplete value, discard already-consumed prefix.
                if value_start:
                    buffer = buffer[value_start:]
                    position = 0
                    value_start = 0
                compact_and_fill()

        if not is_array:
            break

    skip_space()
    if position < len(buffer):
        raise UploadParseError("trailing_json_content")


def _json_upload(stream: BinaryIO, extension: str, bytes_read: int) -> PreparedUpload:
    text = _text_wrapper(stream)
    input_format = "ndjson" if extension in {".ndjson", ".jsonl"} else "json"
    values = _iter_ndjson(text) if input_format == "ndjson" else _iter_json_values(text)
    buffered: list[Any | RejectedRow] = []
    first_mapping: dict[str, Any] | None = None
    try:
        # The first record defines the homogeneous JSON schema. Do not scan or
        # retain an arbitrary primitive prefix looking for a later object.
        try:
            value = next(values)
            buffered.append(value)
            if isinstance(value, dict):
                first_mapping = value
        except StopIteration:
            pass
        validator = FlowSchemaValidator(
            first_mapping.keys() if first_mapping is not None else [],
            input_format=input_format,
        )

        def rows() -> Iterator[dict[str, Any] | RejectedRow]:
            try:
                for value in itertools.chain(buffered, values):
                    if isinstance(value, RejectedRow):
                        yield value
                    elif isinstance(value, dict):
                        yield value
                    else:
                        yield RejectedRow("json_row_must_be_object")
            except UnicodeDecodeError as exc:
                raise UploadParseError("invalid_utf8") from exc
            finally:
                try:
                    text.detach()
                except (ValueError, OSError):
                    pass

        return PreparedUpload(input_format, validator, rows(), bytes_read)
    except Exception:
        try:
            text.detach()
        except (ValueError, OSError):
            pass
        raise


def prepare_upload(stream: BinaryIO, filename: str, *, max_bytes: int) -> PreparedUpload:
    """Validate extension/bytes and return a lazy record stream."""
    extension = Path(filename).suffix.lower()
    if extension not in SUPPORTED_UPLOAD_EXTENSIONS:
        raise UploadParseError("unsupported_file_extension")
    bytes_read = enforce_byte_limit(stream, max_bytes)
    try:
        if extension in {".csv", ".tsv"}:
            return _csv_upload(stream, extension, bytes_read)
        return _json_upload(stream, extension, bytes_read)
    except UnicodeDecodeError as exc:
        raise UploadParseError("invalid_utf8") from exc
