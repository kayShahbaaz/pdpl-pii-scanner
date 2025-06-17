#!/usr/bin/env python3
"""
pdpl_checker.py
----------------
PDPL Checker — a Saudi PII discovery & compliance-gap tool for CSV/XLSX
files and folders.

Scans one or more files for data patterns relevant to Saudi Arabia's
Personal Data Protection Law (PDPL), as overseen by SDAIA (Saudi Data & AI
Authority), and classifies each finding using PDPL's own categories:

    - Personal Data:  National ID/Iqama, mobile number, passport number,
                       email address, physical address
    - Credit Data:    IBAN / bank account numbers
    - Sensitive Data: Health data, religious/political affiliation
                       (PDPL Article 1(11) — triggers explicit-consent and
                       DPIA requirements)

Beyond detection, this tool also:
    - Computes a per-file PDPL risk score, weighting Sensitive/Credit Data
      findings far above ordinary Personal Data findings
    - Runs heuristic compliance-gap checks: is there a visible
      consent/retention column? Any sign of cross-border data transfer?
    - Can explain (--explain) what PDPL actually requires for each
      category of data found, in plain language

Usage:
    python pdpl_checker.py path/to/file.csv
    python pdpl_checker.py path/to/folder/                 # scans every .csv/.xlsx inside
    python pdpl_checker.py path/to/folder/ --redact         # also writes redacted copies
    python pdpl_checker.py path/to/folder/ --explain        # plain-language PDPL obligations

Outputs (written to --outdir, default "output/"):
    1. Console summary report (printed immediately)
    2. pii_findings.csv     -> row-level findings, incl. PDPL category + risk weight
    3. pii_report.html      -> visual dashboard with charts, risk scores, compliance gaps
    4. redacted/...         -> redacted copies of each input file (--redact only)
"""

import argparse
import os
import sys
from collections import defaultdict
from datetime import datetime

from pii_detectors import run_all_detectors, Confidence, CONFIDENCE_RANK
from file_readers import discover_files, read_tables
from redactor import write_redacted_copy
from report_html import write_html_report
from pdpl_knowledge import get_category, get_explanation, get_weight
from compliance_checks import run_compliance_checks
import csv as csv_module


def mask_value(value: str) -> str:
    value = str(value)
    if len(value) <= 7:
        return value[0] + "***" + value[-1] if len(value) > 1 else "***"
    return value[:4] + "***" + value[-3:]


def scan_table(table):
    """
    Runs every registered detector against every cell of a Table, tagging
    each finding with its PDPL category and risk weight.
    """
    findings = []
    flagged_cells = set()

    for row_i, row in enumerate(table.rows):
        for column_name in table.columns:
            cell_value = row.get(column_name)
            if cell_value is None or str(cell_value).strip() == "":
                continue

            hits = run_all_detectors(cell_value, column_name)
            for pii_type, confidence, matched in hits:
                findings.append({
                    "file": table.file_path,
                    "sheet": table.sheet_name,
                    "table_label": table.label,
                    "row_number": row_i + 1,
                    "column": column_name,
                    "pii_type": pii_type,
                    "confidence": confidence.value,
                    "masked_value": mask_value(matched),
                    "pdpl_category": get_category(pii_type).value,
                    "risk_weight": get_weight(pii_type, confidence.value),
                })
                flagged_cells.add((row_i, column_name))

    return findings, flagged_cells


def compute_file_risk_score(findings_for_file: list) -> dict:
    """Rolls up per-finding risk weights into a single risk score for a file."""
    total_weight = sum(f["risk_weight"] for f in findings_for_file)
    sensitive_count = sum(1 for f in findings_for_file if f["pdpl_category"] == "Sensitive Data")
    credit_count = sum(1 for f in findings_for_file if f["pdpl_category"] == "Credit Data")

    if total_weight == 0:
        band = "None"
    elif total_weight < 10:
        band = "Low"
    elif total_weight < 40:
        band = "Medium"
    elif total_weight < 100:
        band = "High"
    else:
        band = "Critical"

    return {
        "total_weight": round(total_weight, 1),
        "band": band,
        "sensitive_data_hits": sensitive_count,
        "credit_data_hits": credit_count,
    }


def scan_path(input_path: str, do_redact: bool, redact_dir):
    """Discovers and scans every supported file under input_path."""
    files = discover_files(input_path)
    if not files:
        raise ValueError(f"No .csv or .xlsx files found under '{input_path}'.")

    all_findings = []
    file_summaries = {}
    compliance_results = []

    for filepath in files:
        tables = read_tables(filepath)
        tables_with_flags = []
        total_rows = 0
        file_findings_start = len(all_findings)

        for table in tables:
            findings, flagged_cells = scan_table(table)
            all_findings.extend(findings)
            tables_with_flags.append((table, flagged_cells))
            total_rows += len(table.rows)
            compliance_results.append(run_compliance_checks(table))

        file_findings = all_findings[file_findings_start:]
        risk = compute_file_risk_score(file_findings)

        file_summaries[filepath] = {
            "sheet_count": len(tables),
            "total_rows": total_rows,
            "finding_count": len(file_findings),
            "risk_score": risk["total_weight"],
            "risk_band": risk["band"],
            "sensitive_data_hits": risk["sensitive_data_hits"],
            "credit_data_hits": risk["credit_data_hits"],
        }

        if do_redact:
            base_name = os.path.basename(filepath)
            output_path = os.path.join(redact_dir, base_name)
            write_redacted_copy(tables_with_flags, filepath, output_path)

    return all_findings, file_summaries, compliance_results


def print_console_report(input_path, all_findings, file_summaries, compliance_results, did_redact, redact_dir, explain, as_of_date=None):
    print("=" * 70)
    print("  PDPL CHECKER — Saudi PII Discovery Report")
    print("  (SDAIA Personal Data Protection Law — data discovery demo)")
    print("=" * 70)
    print(f"Scanned path : {input_path}")
    print(f"Files scanned: {len(file_summaries)}")
    print(f"Scan time    : {as_of_date if as_of_date else datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 70)

    if not all_findings:
        print("No PII patterns detected across any scanned file.")
    else:
        by_type = defaultdict(int)
        by_confidence = defaultdict(int)
        by_category = defaultdict(int)
        for f in all_findings:
            by_type[f["pii_type"]] += 1
            by_confidence[f["confidence"]] += 1
            by_category[f["pdpl_category"]] += 1

        print(f"Total findings        : {len(all_findings)}")
        print(f"  High confidence      : {by_confidence.get('High', 0)}")
        print(f"  Medium confidence    : {by_confidence.get('Medium', 0)}")
        print(f"  Low confidence       : {by_confidence.get('Low', 0)}")
        print("-" * 70)
        print("Findings by PDPL category:")
        for category, count in sorted(by_category.items(), key=lambda kv: -kv[1]):
            tag = " <- stricter consent/DPIA rules apply" if category == "Sensitive Data" else ""
            print(f"  {category:<20}{count}{tag}")
        print("-" * 70)
        print("Findings by PII type:")
        for pii_type, count in sorted(by_type.items(), key=lambda kv: -kv[1]):
            print(f"  {pii_type:<32}{count}")
        print("-" * 70)
        print("Risk score by file (higher = more/more-sensitive PII exposure):")
        for filepath, summary in file_summaries.items():
            print(f"  {os.path.basename(filepath):<30}score={summary['risk_score']:<8}"
                  f"band={summary['risk_band']:<10}sensitive_hits={summary['sensitive_data_hits']}")
        print("=" * 70)

        if explain:
            print("PLAIN-LANGUAGE PDPL OBLIGATIONS (grouped by category found):")
            print("-" * 70)
            seen_categories = set()
            for f in all_findings:
                cat = f["pdpl_category"]
                if cat in seen_categories:
                    continue
                seen_categories.add(cat)
                print(f"[{cat}] (e.g. {f['pii_type']})")
                explanation = get_explanation(f["pii_type"])
                print(f"  {explanation}")
                print()
            print("This is general guidance for a demo tool, not legal advice.")
            print("=" * 70)

    any_gaps = any(c["consent_retention"]["gaps"] for c in compliance_results)
    any_cross_border = any(c["cross_border"]["non_saudi_values_found"] for c in compliance_results)

    if any_gaps or any_cross_border:
        print("COMPLIANCE GAP CHECKS (heuristic — column-name based, not a full audit):")
        print("-" * 70)
        for result in compliance_results:
            cr = result["consent_retention"]
            cb = result["cross_border"]
            if cr["gaps"] or cb["non_saudi_values_found"]:
                print(f"  {result['table_label']}")
                for gap in cr["gaps"]:
                    print(f"    - {gap}")
                if cb["non_saudi_values_found"]:
                    locations = ", ".join(sorted({v for _, v in cb["non_saudi_values_found"]}))
                    print(f"    - Possible cross-border data transfer: found non-Saudi location "
                          f"value(s) in column(s) {cb['location_columns_found']}: {locations}")
                    print(f"      PDPL restricts transferring personal data outside Saudi Arabia "
                          f"unless specific safeguards apply (adequate protection, consent, or "
                          f"approved contractual mechanisms).")
        print("=" * 70)

    if did_redact:
        print(f"Redacted copies written to: {redact_dir}")
        print("=" * 70)

    print("Note: Values above are masked. Full findings (still masked) are")
    print("written to the CSV/HTML reports for review.")
    print("=" * 70)


def write_csv_findings(all_findings, outpath):
    fieldnames = [
        "file", "sheet", "row_number", "column", "pii_type",
        "pdpl_category", "confidence", "risk_weight", "masked_value",
    ]
    with open(outpath, "w", newline="", encoding="utf-8") as f:
        writer = csv_module.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in all_findings:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


def main():
    parser = argparse.ArgumentParser(
        description="PDPL Checker — scan CSV/XLSX files (or a folder of them) for Saudi PII."
    )
    parser.add_argument("path", help="Path to a CSV/XLSX file, or a folder containing them.")
    parser.add_argument("--outdir", default="output", help="Directory to write report files into.")
    parser.add_argument(
        "--redact", action="store_true",
        help="Also write redacted copies of every scanned file (PII replaced with [REDACTED])."
    )
    parser.add_argument(
        "--explain", action="store_true",
        help="Print plain-language PDPL obligations for each PDPL category found."
    )
    parser.add_argument(
        "--as-of", dest="as_of", default=None, metavar="YYYY-MM-DD",
        help="Display this date as the scan/generated timestamp instead of the "
             "current system time."
    )
    args = parser.parse_args()

    if not os.path.exists(args.path):
        print(f"Error: path not found: {args.path}", file=sys.stderr)
        sys.exit(1)

    if args.as_of:
        try:
            datetime.strptime(args.as_of, "%Y-%m-%d")
        except ValueError:
            print(f"Error: --as-of must be in YYYY-MM-DD format, got '{args.as_of}'", file=sys.stderr)
            sys.exit(1)

    os.makedirs(args.outdir, exist_ok=True)
    redact_dir = None
    if args.redact:
        redact_dir = os.path.join(args.outdir, "redacted")
        os.makedirs(redact_dir, exist_ok=True)

    try:
        all_findings, file_summaries, compliance_results = scan_path(args.path, args.redact, redact_dir)
    except Exception as e:
        print(f"Error while scanning: {e}", file=sys.stderr)
        sys.exit(1)

    print_console_report(
        args.path, all_findings, file_summaries, compliance_results,
        args.redact, redact_dir, args.explain, args.as_of,
    )

    csv_out = os.path.join(args.outdir, "pii_findings.csv")
    html_out = os.path.join(args.outdir, "pii_report.html")

    write_csv_findings(all_findings, csv_out)
    write_html_report(args.path, all_findings, file_summaries, compliance_results, html_out, args.as_of)

    print(f"\nCSV findings written to : {csv_out}")
    print(f"HTML report written to  : {html_out}")
    if args.redact:
        print(f"Redacted files written  : {redact_dir}")


if __name__ == "__main__":
    main()
