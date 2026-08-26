"""Bounded upload parser behavior for supported containers."""
from io import BytesIO

import pytest

from backend.api.upload_stream import UploadParseError, prepare_upload
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
