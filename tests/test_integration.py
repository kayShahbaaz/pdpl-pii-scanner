"""
test_integration.py
----------------------
End-to-end integration tests for the full PDPL Checker pipeline:
scan_table -> risk scoring, and the redaction round-trip. These catch
wiring bugs that unit tests on individual modules can miss.
"""

import sys
import os
import csv
import tempfile
import shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from file_readers import read_csv_table
from pdpl_checker import scan_table, compute_file_risk_score, mask_value
from redactor import redact_csv


@pytest.fixture
def tmp_dir():
    d = tempfile.mkdtemp()
    yield d
    shutil.rmtree(d, ignore_errors=True)


def write_csv(path, rows):
    fieldnames = list(rows[0].keys())
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# mask_value
# ---------------------------------------------------------------------------

class TestMaskValue:
    def test_long_value_keeps_first_four_last_three(self):
        assert mask_value("1023456789") == "1023***789"

    def test_short_value_masks_middle_only(self):
        masked = mask_value("12345")
        assert masked.startswith("1")
        assert masked.endswith("5")
        assert "***" in masked

    def test_never_returns_the_original_value(self):
        original = "ahmed.s@example.com"
        masked = mask_value(original)
        assert masked != original


# ---------------------------------------------------------------------------
# scan_table -> findings + flagged_cells wiring
# ---------------------------------------------------------------------------

class TestScanTable:
    def test_finds_national_id_and_mobile_in_same_row(self, tmp_dir):
        path = os.path.join(tmp_dir, "test.csv")
        write_csv(path, [
            {"national_id": "1023456789", "mobile": "0512345678", "name": "Ahmed"},
        ])
        table = read_csv_table(path)
        findings, flagged_cells = scan_table(table)

        pii_types = {f["pii_type"] for f in findings}
        assert "National ID" in pii_types
        assert "Mobile Number" in pii_types
        assert ("name" not in [f["column"] for f in findings])

    def test_every_finding_has_pdpl_category_and_risk_weight(self, tmp_dir):
        path = os.path.join(tmp_dir, "test.csv")
        write_csv(path, [{"iban": "SA0380000000608010167519"}])
        table = read_csv_table(path)
        findings, _ = scan_table(table)

        assert len(findings) >= 1
        for f in findings:
            assert "pdpl_category" in f
            assert "risk_weight" in f
            assert f["risk_weight"] > 0

    def test_masked_value_never_equals_raw_value_in_findings(self, tmp_dir):
        path = os.path.join(tmp_dir, "test.csv")
        write_csv(path, [{"national_id": "1023456789"}])
        table = read_csv_table(path)
        findings, _ = scan_table(table)

        for f in findings:
            assert f["masked_value"] != "1023456789"

    def test_blank_row_produces_no_findings(self, tmp_dir):
        path = os.path.join(tmp_dir, "test.csv")
        write_csv(path, [{"national_id": "", "mobile": ""}])
        table = read_csv_table(path)
        findings, flagged_cells = scan_table(table)
        assert findings == []
        assert flagged_cells == set()


# ---------------------------------------------------------------------------
# compute_file_risk_score
# ---------------------------------------------------------------------------

class TestComputeFileRiskScore:
    def test_no_findings_gives_none_band(self):
        result = compute_file_risk_score([])
        assert result["band"] == "None"
        assert result["total_weight"] == 0

    def test_sensitive_data_findings_are_counted_separately(self):
        findings = [
            {"risk_weight": 5.0, "pdpl_category": "Sensitive Data"},
            {"risk_weight": 1.0, "pdpl_category": "Personal Data"},
        ]
        result = compute_file_risk_score(findings)
        assert result["sensitive_data_hits"] == 1
        assert result["total_weight"] == 6.0

    def test_band_thresholds_are_monotonic(self):
        # Low total weight -> Low band; higher weight -> higher band.
        low = compute_file_risk_score([{"risk_weight": 2, "pdpl_category": "Personal Data"}])
        high = compute_file_risk_score([{"risk_weight": 150, "pdpl_category": "Sensitive Data"}])
        band_order = ["None", "Low", "Medium", "High", "Critical"]
        assert band_order.index(low["band"]) < band_order.index(high["band"])


# ---------------------------------------------------------------------------
# Redaction round-trip
# ---------------------------------------------------------------------------

class TestRedactionRoundTrip:
    def test_flagged_cells_are_redacted_unflagged_are_preserved(self, tmp_dir):
        input_path = os.path.join(tmp_dir, "input.csv")
        output_path = os.path.join(tmp_dir, "output.csv")
        write_csv(input_path, [
            {"name": "Ahmed", "national_id": "1023456789"},
            {"name": "Sara", "national_id": "2034567891"},
        ])
        table = read_csv_table(input_path)
        findings, flagged_cells = scan_table(table)
        redact_csv(table, flagged_cells, output_path)

        with open(output_path, newline="") as f:
            reader = list(csv.DictReader(f))

        assert reader[0]["name"] == "Ahmed"  # untouched
        assert reader[0]["national_id"] == "[REDACTED]"
        assert reader[1]["name"] == "Sara"  # untouched
        assert reader[1]["national_id"] == "[REDACTED]"

    def test_blank_cells_stay_blank_after_redaction(self, tmp_dir):
        input_path = os.path.join(tmp_dir, "input.csv")
        output_path = os.path.join(tmp_dir, "output.csv")
        write_csv(input_path, [{"name": "Omar", "national_id": ""}])
        table = read_csv_table(input_path)
        findings, flagged_cells = scan_table(table)
        redact_csv(table, flagged_cells, output_path)

        with open(output_path, newline="") as f:
            reader = list(csv.DictReader(f))

        assert reader[0]["national_id"] == ""  # never flagged, stays blank


# ---------------------------------------------------------------------------
# Full end-to-end: realistic mixed dataset
# ---------------------------------------------------------------------------

class TestEndToEndRealisticDataset:
    def test_full_pipeline_on_mixed_sensitive_and_personal_data(self, tmp_dir):
        input_path = os.path.join(tmp_dir, "patients.csv")
        write_csv(input_path, [
            {
                "patient_id": "P001",
                "national_id": "1067891234",
                "medical_condition": "Type 2 Diabetes",
                "server_location": "AWS Frankfurt, Germany",
            },
        ])
        table = read_csv_table(input_path)
        findings, flagged_cells = scan_table(table)
        risk = compute_file_risk_score(findings)

        # Should detect at least National ID + Health Data.
        pii_types = {f["pii_type"] for f in findings}
        assert "National ID" in pii_types
        assert "Health Data" in pii_types

        # server_location must NOT be flagged as an Address (regression
        # check for the false positive found during manual testing).
        assert "server_location" not in [f["column"] for f in findings]

        # Sensitive Data should push the risk band up.
        assert risk["sensitive_data_hits"] >= 1
        assert risk["band"] in {"Low", "Medium", "High", "Critical"}
