"""
file_readers.py
-----------------
Unified file reading for the PDPL Checker.

Supports .csv and .xlsx files. Each "table" read from a file is normalized
into the same shape: a list of dict rows plus the column names, regardless
of whether it came from a CSV or a specific Excel sheet.

This lets the scanner treat every (file, sheet) pair the same way.
"""

import csv
import os
from dataclasses import dataclass

import pandas as pd

SUPPORTED_EXTENSIONS = {".csv", ".xlsx"}


@dataclass
class Table:
    """A single scannable table: one CSV file, or one sheet within an XLSX."""
    file_path: str
    sheet_name: str | None  # None for CSV; sheet name for XLSX
    columns: list[str]
    rows: list[dict]  # list of {column_name: value}

    @property
    def label(self) -> str:
        """Human-readable identifier, e.g. 'employees.xlsx [Sheet1]' or 'customers.csv'."""
        base = os.path.basename(self.file_path)
        if self.sheet_name:
            return f"{base} [{self.sheet_name}]"
        return base


def read_csv_table(filepath: str) -> Table:
    with open(filepath, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            raise ValueError(f"'{filepath}' appears to be empty or has no header row.")
        columns = list(reader.fieldnames)
        rows = [dict(row) for row in reader]
    return Table(file_path=filepath, sheet_name=None, columns=columns, rows=rows)


def _sanitize_cell(value):
    """
    Normalizes a pandas cell value so missing data is always None, never the
    float NaN or the literal string 'nan' -- both of which pandas can
    produce depending on dtype/version, and both of which would otherwise
    slip past the "is this cell empty" check in the scanner.
    """
    if value is None:
        return None
    if isinstance(value, float) and pd.isna(value):
        return None
    if isinstance(value, str) and value.strip().lower() == "nan":
        return None
    return value


def read_xlsx_tables(filepath: str) -> list[Table]:
    """Reads every sheet in an XLSX file as its own Table."""
    sheets = pd.read_excel(filepath, sheet_name=None, dtype=str)
    tables = []
    for sheet_name, df in sheets.items():
        columns = list(df.columns)
        rows = [
            {col: _sanitize_cell(row[col]) for col in columns}
            for row in df.to_dict(orient="records")
        ]
        tables.append(Table(file_path=filepath, sheet_name=sheet_name, columns=columns, rows=rows))
    return tables


def read_tables(filepath: str) -> list[Table]:
    """
    Reads any supported file into a list of Tables.
    CSV files produce exactly one Table; XLSX files produce one per sheet.
    """
    ext = os.path.splitext(filepath)[1].lower()
    if ext == ".csv":
        return [read_csv_table(filepath)]
    elif ext == ".xlsx":
        return read_xlsx_tables(filepath)
    else:
        raise ValueError(f"Unsupported file type: '{ext}'. Supported: {sorted(SUPPORTED_EXTENSIONS)}")


def discover_files(path: str) -> list[str]:
    """
    Given a file or directory path, returns a sorted list of scannable
    file paths (.csv / .xlsx). Directories are scanned recursively.
    """
    if os.path.isfile(path):
        ext = os.path.splitext(path)[1].lower()
        if ext not in SUPPORTED_EXTENSIONS:
            raise ValueError(f"Unsupported file type: '{ext}'. Supported: {sorted(SUPPORTED_EXTENSIONS)}")
        return [path]

    if os.path.isdir(path):
        found = []
        for root, _dirs, files in os.walk(path):
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext in SUPPORTED_EXTENSIONS:
                    found.append(os.path.join(root, fname))
        return sorted(found)

    raise FileNotFoundError(f"Path not found: '{path}'")
