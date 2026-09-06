"""Bounded upload parser behavior for supported containers."""
from io import BytesIO
import json

import pytest

from backend.api.upload_stream import RejectedRow, UploadParseError, prepare_upload
from tests.helpers import canonical_flow, canonical_json


def test_json_array_is_iterated_in_input_order_without_full_row_list():
    rows = [canonical_flow(flow_duration=value) for value in (1, 2, 3)]
    prepared = prepare_upload(
        BytesIO(canonical_json(*rows)), "flows.json", max_bytes=10_000_000
    )
    parsed = list(prepared.rows)
    assert [int(item["flow_duration"]) for item in parsed] == [1, 2, 3]
    assert prepared.validator.report.detected_input_profile == (
        "cyberguard-canonical-json-v1"
    )


def test_ndjson_is_streamed_and_keeps_order():
    lines = b"\n".join(
        canonical_json(canonical_flow(flow_duration=value))[1:-1]
        for value in (4, 5, 6)
    )
    prepared = prepare_upload(
        BytesIO(lines), "flows.jsonl", max_bytes=10_000_000
    )
    parsed = list(prepared.rows)
    assert [int(item["flow_duration"]) for item in parsed] == [4, 5, 6]
    assert prepared.input_format == "ndjson"


def test_byte_limit_is_applied_before_parsing_without_accepting_prefix():
    with pytest.raises(UploadParseError, match="upload_byte_limit_exceeded"):
        prepare_upload(BytesIO(b"a,b\n1,2\n"), "flows.csv", max_bytes=4)


def test_headerless_text_container_is_not_a_supported_adapter():
    with pytest.raises(UploadParseError, match="unsupported_file_extension"):
        prepare_upload(BytesIO(b"failed login\n"), "events.log", max_bytes=100)


def _json_object_with_duplicate(row, key, second_value):
    encoded = json.dumps(row, separators=(",", ":"))
    return (encoded[:-1] + f",{json.dumps(key)}:{json.dumps(second_value)}}}").encode()


def test_top_level_json_object_rejects_duplicate_canonical_key():
    payload = _json_object_with_duplicate(canonical_flow(flow_duration=1), "flow_duration", 2)
    with pytest.raises(UploadParseError, match="duplicate_json_key"):
        prepare_upload(BytesIO(payload), "flow.json", max_bytes=10_000_000)


def test_json_array_rejects_duplicate_key_in_member_object():
    duplicate = _json_object_with_duplicate(canonical_flow(), "syn_flag_count", 3)
    prepared = prepare_upload(
        BytesIO(b"[" + canonical_json(canonical_flow())[1:-1] + b"," + duplicate + b"]"),
        "flows.json",
        max_bytes=10_000_000,
    )
    rows = iter(prepared.rows)
    assert next(rows)["flow_duration"] == 0
    with pytest.raises(UploadParseError, match="duplicate_json_key"):
        next(rows)


def test_ndjson_reports_duplicate_cicflowmeter_alias_key_as_rejected_row():
    canonical = canonical_flow()
    canonical.pop("flow_duration")
    aliased = {"Flow Duration": 1, **canonical}
    duplicate = _json_object_with_duplicate(aliased, "Flow Duration", 2)
    content = canonical_json(aliased)[1:-1] + b"\n" + duplicate
    prepared = prepare_upload(
        BytesIO(content), "flows.ndjson", max_bytes=10_000_000
    )
    rows = list(prepared.rows)
    assert isinstance(rows[0], dict)
    assert rows[1] == RejectedRow("duplicate_json_key")


def test_escaped_equivalent_json_member_names_are_duplicates():
    row = json.dumps(canonical_flow(), separators=(",", ":"))[1:-1]
    payload = ("{" + row + ',"flow\\u005fduration":2}').encode()
    with pytest.raises(UploadParseError, match="duplicate_json_key"):
        prepare_upload(BytesIO(payload), "escaped.json", max_bytes=10_000_000)


def test_unicode_normalization_equivalent_member_names_fail_closed():
    payload = '{"méta":1,"me\\u0301ta":2}'.encode()
    with pytest.raises(UploadParseError, match="duplicate_json_key"):
        prepare_upload(BytesIO(payload), "unicode.json", max_bytes=10_000_000)


def test_duplicate_key_in_nested_object_is_fatal_for_json_container():
    row = json.dumps(canonical_flow(), separators=(",", ":"))[1:-1]
    payload = ("{" + row + ',"metadata":{"x":1,"x":2}}').encode()
    with pytest.raises(UploadParseError, match="duplicate_json_key"):
        prepare_upload(BytesIO(payload), "nested.json", max_bytes=10_000_000)


def test_ndjson_duplicate_line_is_recoverable_and_surrounding_order_is_stable():
    first = canonical_flow(flow_duration=10)
    middle = _json_object_with_duplicate(canonical_flow(flow_duration=20), "flow_duration", 21)
    last = canonical_flow(flow_duration=30)
    content = b"\n".join((
        canonical_json(first)[1:-1],
        middle,
        canonical_json(last)[1:-1],
    ))
    prepared = prepare_upload(
        BytesIO(content), "ordered.ndjson", max_bytes=10_000_000
    )
    rows = list(prepared.rows)
    assert rows[0]["flow_duration"] == 10
    assert rows[1] == RejectedRow("duplicate_json_key")
    assert rows[2]["flow_duration"] == 30


@pytest.mark.parametrize(("extension", "delimiter"), [(".csv", ","), (".tsv", "\t")])
def test_normalization_equivalent_duplicate_tabular_headers_are_unsupported(
    extension, delimiter,
):
    headers = list(canonical_flow()) + [" flow_duration "]
    values = ["0"] * len(headers)
    payload = (delimiter.join(headers) + "\n" + delimiter.join(values) + "\n").encode()
    prepared = prepare_upload(
        BytesIO(payload), "duplicate" + extension, max_bytes=10_000_000
    )
    assert prepared.validator.report.supported is False
    assert prepared.validator.report.duplicate_columns == ["flow_duration"]
