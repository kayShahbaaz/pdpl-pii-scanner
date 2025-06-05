"""
test_compliance_checks.py
----------------------------
Unit tests for compliance_checks.py: consent/retention column detection
and cross-border transfer flagging.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from file_readers import Table
from compliance_checks import (
    check_consent_and_retention,
    check_cross_border_transfer,
    run_compliance_checks,
)


def make_table(columns, rows, file_path="test.csv", sheet_name=None):
    return Table(file_path=file_path, sheet_name=sheet_name, columns=columns, rows=rows)


class TestConsentAndRetentionCheck:
    def test_missing_both_columns_flags_two_gaps(self):
        table = make_table(["name", "email"], [{"name": "A", "email": "a@x.com"}])
        result = check_consent_and_retention(table)
        assert result["has_consent_column"] is False
        assert result["has_retention_column"] is False
        assert len(result["gaps"]) == 2

    def test_consent_column_present_removes_that_gap(self):
        table = make_table(
            ["name", "consent_given"],
            [{"name": "A", "consent_given": "Yes"}],
        )
        result = check_consent_and_retention(table)
        assert result["has_consent_column"] is True
        assert len(result["gaps"]) == 1  # only retention gap remains

    def test_both_columns_present_no_gaps(self):
        table = make_table(
            ["name", "opt_in", "retention_date"],
            [{"name": "A", "opt_in": "Yes", "retention_date": "2027-01-01"}],
        )
        result = check_consent_and_retention(table)
        assert result["gaps"] == []

    def test_case_insensitive_column_matching(self):
        table = make_table(["Consent_Date", "Retention"], [{}])
        result = check_consent_and_retention(table)
        assert result["has_consent_column"] is True
        assert result["has_retention_column"] is True


class TestCrossBorderTransferCheck:
    def test_no_location_column_returns_empty(self):
        table = make_table(["name", "email"], [{"name": "A", "email": "a@x.com"}])
        result = check_cross_border_transfer(table)
        assert result["location_columns_found"] == []
        assert result["non_saudi_values_found"] == []

    def test_non_saudi_value_is_flagged(self):
        table = make_table(
            ["server_location"],
            [{"server_location": "AWS Frankfurt, Germany"}],
        )
        result = check_cross_border_transfer(table)
        assert result["location_columns_found"] == ["server_location"]
        assert len(result["non_saudi_values_found"]) == 1

    def test_saudi_value_in_location_column_not_flagged_as_foreign(self):
        table = make_table(
            ["server_location"],
            [{"server_location": "AWS Riyadh, KSA"}],
        )
        result = check_cross_border_transfer(table)
        # The column is recognized as a location column, but the value
        # itself doesn't match a non-Saudi keyword.
        assert result["non_saudi_values_found"] == []

    def test_multiple_rows_multiple_foreign_locations(self):
        table = make_table(
            ["server_location"],
            [
                {"server_location": "AWS Frankfurt, Germany"},
                {"server_location": "AWS Riyadh, KSA"},
                {"server_location": "Azure US-East"},
            ],
        )
        result = check_cross_border_transfer(table)
        assert len(result["non_saudi_values_found"]) == 2

    def test_none_value_does_not_crash(self):
        table = make_table(["country"], [{"country": None}])
        result = check_cross_border_transfer(table)
        assert result["non_saudi_values_found"] == []


class TestRunComplianceChecks:
    def test_returns_both_check_results(self):
        table = make_table(
            ["name", "country"],
            [{"name": "A", "country": "USA"}],
        )
        result = run_compliance_checks(table)
        assert "consent_retention" in result
        assert "cross_border" in result
        assert result["table_label"] == table.label
