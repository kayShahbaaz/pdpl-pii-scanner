"""
compliance_checks.py
----------------------
Heuristic, file-level compliance checks that go beyond "did we find PII?"
and toward "does this dataset show signs of the governance PDPL expects
around that PII?"

These are intentionally lightweight, column-name-driven heuristics -- not a
substitute for an actual compliance audit. They exist to demonstrate the
*kind* of question a PDPL-aware reviewer would ask about a dataset:

    1. Is there any visible record of consent or a retention/expiry date
       for the personal data in this file? (PDPL requires a lawful basis
       and discourages indefinite retention without purpose.)
    2. Does this file contain any column suggesting data may be stored or
       processed outside Saudi Arabia? (PDPL restricts cross-border
       transfers of personal data unless specific conditions are met.)
"""

import re


CONSENT_COLUMN_HINTS = [
    "consent", "opt_in", "opt-in", "optin", "agreed_to", "permission",
    "consent_date", "consent_given",
]

RETENTION_COLUMN_HINTS = [
    "retention", "expiry", "expiration", "delete_after", "delete_by",
    "retention_date", "data_expiry",
]

CROSS_BORDER_COLUMN_HINTS = [
    "country", "region", "server_location", "hosted_in", "data_center",
    "datacenter", "storage_location", "processing_location",
]

# Countries/regions outside Saudi Arabia that, if found as *values* in a
# cross-border-hinted column, are worth flagging. This is intentionally a
# short illustrative list, not exhaustive -- the point is to demonstrate
# the check, not to replace a real data residency audit.
NON_SAUDI_LOCATION_KEYWORDS = [
    "usa", "united states", "us-east", "us-west", "uk", "united kingdom",
    "europe", "eu-", "germany", "ireland", "singapore", "india", "uae",
    "dubai", "china", "frankfurt", "virginia", "ohio", "london",
]

SAUDI_LOCATION_KEYWORDS = ["saudi", "ksa", "riyadh", "jeddah", "dammam", "sa-"]


def _has_matching_column(columns, hints):
    return any(
        any(hint in col.lower() for hint in hints)
        for col in columns
    )


def check_consent_and_retention(table) -> dict:
    """
    Checks whether a table has any column suggesting consent tracking or a
    retention/expiry policy. Returns a dict describing what was (not) found.
    """
    has_consent_column = _has_matching_column(table.columns, CONSENT_COLUMN_HINTS)
    has_retention_column = _has_matching_column(table.columns, RETENTION_COLUMN_HINTS)

    gaps = []
    if not has_consent_column:
        gaps.append(
            "No consent-tracking column found (e.g. 'consent', 'opt_in'). "
            "PDPL generally requires a documented lawful basis -- usually "
            "consent -- before processing personal data."
        )
    if not has_retention_column:
        gaps.append(
            "No retention/expiry column found (e.g. 'retention_date', "
            "'delete_after'). PDPL discourages keeping personal data longer "
            "than necessary for its stated purpose."
        )

    return {
        "table_label": table.label,
        "has_consent_column": has_consent_column,
        "has_retention_column": has_retention_column,
        "gaps": gaps,
    }


def check_cross_border_transfer(table) -> dict:
    """
    Checks for columns that hint at data location/residency, and scans
    their values for non-Saudi location keywords.
    """
    location_columns = [
        col for col in table.columns
        if any(hint in col.lower() for hint in CROSS_BORDER_COLUMN_HINTS)
    ]

    flagged_values = []
    if location_columns:
        for row in table.rows:
            for col in location_columns:
                value = row.get(col)
                if value is None:
                    continue
                text = str(value).lower()
                if any(kw in text for kw in NON_SAUDI_LOCATION_KEYWORDS):
                    flagged_values.append((col, str(value)))

    return {
        "table_label": table.label,
        "location_columns_found": location_columns,
        "non_saudi_values_found": flagged_values,
    }


def run_compliance_checks(table) -> dict:
    """Runs all heuristic compliance checks for a single Table."""
    return {
        "table_label": table.label,
        "consent_retention": check_consent_and_retention(table),
        "cross_border": check_cross_border_transfer(table),
    }
