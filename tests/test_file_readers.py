"""
test_file_readers.py
-----------------------
Unit tests for file_readers.py: CSV reading, XLSX multi-sheet reading,
folder discovery, and the NaN/missing-value sanitization that was added
after a real bug (empty Excel cells producing phantom "nan" string matches).
"""

import sys
import os
import csv
import tempfile
import shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pandas as pd
import pytest

from file_readers import (
    read_csv_table,
    read_xlsx_tables,
    read_tables,
    discover_files,
    _sanitize_cell,
)


@pytest.fixture
def tmp_dir():
    d = tempfile.mkdtemp()
    yield d
    shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# CSV reading
# ---------------------------------------------------------------------------

class TestReadCsvTable:
    def test_reads_columns_and_rows(self, tmp_dir):
        path = os.path.join(tmp_dir, "test.csv")
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["name", "email"])
            writer.writerow(["Ahmed", "ahmed@example.com"])
            writer.writerow(["Sara", "sara@example.com"])

        table = read_csv_table(path)
        assert table.columns == ["name", "email"]
        assert len(table.rows) == 2
        assert table.rows[0]["name"] == "Ahmed"
        assert table.sheet_name is None

    def test_empty_csv_raises_value_error(self, tmp_dir):
        path = os.path.join(tmp_dir, "empty.csv")
        with open(path, "w") as f:
            pass  # truly empty, no header

        with pytest.raises(ValueError):
            read_csv_table(path)

    def test_table_label_for_csv_has_no_sheet_suffix(self, tmp_dir):
        path = os.path.join(tmp_dir, "customers.csv")
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["name"])
            writer.writerow(["Ahmed"])

        table = read_csv_table(path)
        assert table.label == "customers.csv"


# ---------------------------------------------------------------------------
# XLSX reading -- including the NaN regression
# ---------------------------------------------------------------------------

class TestReadXlsxTables:
    def test_reads_multiple_sheets(self, tmp_dir):
        path = os.path.join(tmp_dir, "test.xlsx")
        with pd.ExcelWriter(path, engine="openpyxl") as writer:
            pd.DataFrame({"a": [1, 2]}).to_excel(writer, sheet_name="Sheet1", index=False)
            pd.DataFrame({"b": [3, 4]}).to_excel(writer, sheet_name="Sheet2", index=False)

        tables = read_xlsx_tables(path)
        assert len(tables) == 2
        sheet_names = {t.sheet_name for t in tables}
        assert sheet_names == {"Sheet1", "Sheet2"}

    def test_empty_cells_become_none_not_nan_string(self, tmp_dir):
        """
        Regression test: empty Excel cells previously produced the literal
        string 'nan' (or float NaN) in table.rows, which slipped past the
        scanner's "is this cell empty" check and produced phantom matches.
        """
        path = os.path.join(tmp_dir, "test.xlsx")
        df = pd.DataFrame({
            "name": ["Ahmed", "Sara"],
            "iban": ["SA0380000000608010167519", None],
        })
        with pd.ExcelWriter(path, engine="openpyxl") as writer:
            df.to_excel(writer, sheet_name="Sheet1", index=False)

        tables = read_xlsx_tables(path)
        table = tables[0]

        empty_cell = table.rows[1]["iban"]
        assert empty_cell is None
        assert empty_cell != "nan"

    def test_table_label_includes_sheet_name(self, tmp_dir):
        path = os.path.join(tmp_dir, "employees.xlsx")
        with pd.ExcelWriter(path, engine="openpyxl") as writer:
            pd.DataFrame({"a": [1]}).to_excel(writer, sheet_name="BankInfo", index=False)

        tables = read_xlsx_tables(path)
        assert tables[0].label == "employees.xlsx [BankInfo]"


class TestSanitizeCell:
    def test_none_stays_none(self):
        assert _sanitize_cell(None) is None

    def test_float_nan_becomes_none(self):
        assert _sanitize_cell(float("nan")) is None

    def test_literal_nan_string_becomes_none(self):
        assert _sanitize_cell("nan") is None
        assert _sanitize_cell("NaN") is None
        assert _sanitize_cell("  nan  ") is None

    def test_real_value_passes_through_unchanged(self):
        assert _sanitize_cell("SA0380000000608010167519") == "SA0380000000608010167519"

    def test_zero_is_not_treated_as_missing(self):
        # 0 is a legitimate value, not a missing one -- must not be
        # accidentally caught by NaN-like sanitization.
        assert _sanitize_cell("0") == "0"


# ---------------------------------------------------------------------------
# Unified read_tables dispatch
# ---------------------------------------------------------------------------

class TestReadTables:
    def test_csv_extension_dispatches_to_csv_reader(self, tmp_dir):
        path = os.path.join(tmp_dir, "test.csv")
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["a"])
            writer.writerow(["1"])

        tables = read_tables(path)
        assert len(tables) == 1
        assert tables[0].sheet_name is None

    def test_unsupported_extension_raises(self, tmp_dir):
        path = os.path.join(tmp_dir, "test.txt")
        with open(path, "w") as f:
            f.write("hello")

        with pytest.raises(ValueError):
            read_tables(path)


# ---------------------------------------------------------------------------
# Folder discovery
# ---------------------------------------------------------------------------

class TestDiscoverFiles:
    def test_single_file_returns_list_of_one(self, tmp_dir):
        path = os.path.join(tmp_dir, "test.csv")
        open(path, "w").close()
        result = discover_files(path)
        assert result == [path]

    def test_directory_finds_csv_and_xlsx_only(self, tmp_dir):
        open(os.path.join(tmp_dir, "a.csv"), "w").close()
        open(os.path.join(tmp_dir, "b.xlsx"), "w").close()
        open(os.path.join(tmp_dir, "c.txt"), "w").close()

        result = discover_files(tmp_dir)
        basenames = sorted(os.path.basename(p) for p in result)
        assert basenames == ["a.csv", "b.xlsx"]

    def test_recursive_directory_scan(self, tmp_dir):
        sub = os.path.join(tmp_dir, "subfolder")
        os.makedirs(sub)
        open(os.path.join(tmp_dir, "top.csv"), "w").close()
        open(os.path.join(sub, "nested.csv"), "w").close()

        result = discover_files(tmp_dir)
        assert len(result) == 2

    def test_nonexistent_path_raises_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            discover_files("/this/path/does/not/exist")

    def test_unsupported_single_file_raises_value_error(self, tmp_dir):
        path = os.path.join(tmp_dir, "test.txt")
        open(path, "w").close()
        with pytest.raises(ValueError):
            discover_files(path)
