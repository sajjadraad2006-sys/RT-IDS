"""Fail-closed input-schema regression tests."""
from backend.detection.features import FEATURE_NAMES
from backend.detection.input_schema import FlowSchemaValidator, validate_records
from tests.helpers import canonical_flow


def _rename(row, replacements):
    return {replacements.get(name, name): value for name, value in row.items()}


def test_verified_init_window_fwd_alias_maps_correctly():
    row = _rename(
        canonical_flow(init_win_bytes_fwd=4096),
        {"init_win_bytes_fwd": "Init_Win_bytes_fwd"},
    )
    accepted, report = validate_records([row])
    assert report["supported"] is True
    assert report["recognized_aliases"]["Init_Win_bytes_fwd"] == (
        "init_win_bytes_fwd"
    )
    assert accepted[0]["init_win_bytes_fwd"] == 4096


def test_supported_cicflowmeter_profiles_are_accepted():
    cic2017 = _rename(
        canonical_flow(),
        {
            "flow_duration": "Flow Duration",
            "total_fwd_packets": "Total Fwd Packets",
            "init_win_bytes_fwd": "Init_Win_bytes_fwd",
        },
    )
    cse2018 = _rename(
        canonical_flow(),
        {
            "flow_duration": "Flow Duration",
            "total_fwd_packets": "Tot Fwd Pkts",
            "bytes_per_sec": "Flow Byts/s",
            "packet_length_mean": "Pkt Len Mean",
            "init_win_bytes_fwd": "Init Fwd Win Byts",
        },
    )
    _, cic_report = validate_records([cic2017], input_format="csv")
    _, cse_report = validate_records([cse2018], input_format="csv")
    assert cic_report["detected_input_profile"] == "cicids2017-cicflowmeter"
    assert cse_report["detected_input_profile"] == (
        "cse-cic-ids2018-cicflowmeter-v3"
    )
    assert cic_report["feature_coverage_percentage"] == 100.0
    assert cse_report["feature_coverage_percentage"] == 100.0
    assert cic_report["usable_row_count"] == cse_report["usable_row_count"] == 1


def test_zero_values_count_as_present_schema_features():
    accepted, report = validate_records([canonical_flow()])
    assert len(accepted) == 1
    assert report["recognized_direct_features"] == sorted(FEATURE_NAMES)
    assert report["missing_required_features"] == []
    assert report["feature_coverage_percentage"] == 100.0


def test_invalid_numeric_row_cannot_silently_become_benign():
    row = canonical_flow(flow_duration="not-a-number")
    accepted, report = validate_records([row])
    assert accepted == []
    assert report["invalid_numeric_cells"] == 1
    assert report["rows_rejected"] == 1
    assert report["usable_row_count"] == 0


def test_single_and_batch_schema_accounting_match():
    good = canonical_flow(flow_duration=0)
    bad = canonical_flow(flow_duration="NaN")
    batch_rows, batch_report = validate_records([good, bad])

    validator = FlowSchemaValidator(good.keys(), input_format="json")
    single_rows = [
        item for row in (good, bad)
        if (item := validator.validate_row(row)) is not None
    ]
    assert batch_rows == single_rows
    assert batch_report == validator.report.to_dict()


def test_conflicting_alias_values_reject_the_row_and_are_reported():
    row = canonical_flow(init_win_bytes_fwd=100)
    row["Init_Win_bytes_fwd"] = 200
    accepted, report = validate_records([row])
    assert accepted == []
    assert report["alias_conflicts"]["init_win_bytes_fwd"] == [
        "init_win_bytes_fwd", "Init_Win_bytes_fwd"
    ]
    assert report["invalid_numeric_cell_counts"]["ambiguous_alias_values"] == 1


def test_equal_canonical_and_alias_values_are_explicitly_accepted():
    row = canonical_flow(init_win_bytes_fwd=100)
    row["Init_Win_bytes_fwd"] = 100
    accepted, report = validate_records([row])
    assert accepted[0]["init_win_bytes_fwd"] == 100
    assert report["alias_conflicts"]["init_win_bytes_fwd"] == [
        "init_win_bytes_fwd", "Init_Win_bytes_fwd"
    ]
    assert report["rows_rejected"] == 0


def test_equal_two_alias_representations_are_accepted_without_first_last_choice():
    row = canonical_flow()
    row.pop("init_win_bytes_fwd")
    row["Init_Win_bytes_fwd"] = 0
    row["Init Fwd Win Byts"] = 0
    accepted, report = validate_records([row])
    assert accepted[0]["init_win_bytes_fwd"] == 0
    assert report["rows_rejected"] == 0


def test_two_aliases_with_different_values_fail_closed():
    row = canonical_flow()
    row.pop("init_win_bytes_fwd")
    row["Init_Win_bytes_fwd"] = 0
    row["Init Fwd Win Byts"] = 1
    accepted, report = validate_records([row])
    assert accepted == []
    assert report["invalid_numeric_cell_counts"]["ambiguous_alias_values"] == 1


def test_zero_and_missing_alias_values_are_not_treated_as_equal():
    row = canonical_flow(init_win_bytes_fwd=0)
    row["Init_Win_bytes_fwd"] = ""
    accepted, report = validate_records([row])
    assert accepted == []
    assert report["invalid_numeric_cell_counts"]["missing_numeric_value"] == 1
    assert report["rows_rejected"] == 1


def test_normalized_duplicate_column_names_make_schema_unsupported():
    columns = list(FEATURE_NAMES) + [" flow_duration "]
    validator = FlowSchemaValidator(columns, input_format="csv")
    assert validator.report.supported is False
    assert validator.report.duplicate_columns == ["flow_duration"]
    assert validator.report.rejection_reasons["duplicate_column_names"] == 1


def test_bounded_sanitization_is_reported_not_hidden():
    row = canonical_flow(flow_duration="1e20")
    accepted, report = validate_records([row])
    assert accepted[0]["flow_duration"] == 1e15
    assert report["sanitization_counts"]["clipped_above_max"] == 1
