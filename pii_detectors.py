"""
pii_detectors.py
-----------------
PII detection registry for the PDPL Checker.

Each detector is a small class implementing a common interface:
    - regex pattern
    - optional extra validation
    - column-name hints
    - a confidence score: HIGH, MEDIUM, or LOW

Detectors covered so far:
    - Saudi National ID / Iqama number
    - Saudi mobile number
    - IBAN (Saudi format, with general fallback)
    - Passport number (heuristic — no universal format)
    - Email address
    - Physical address (heuristic, column-hint driven — addresses have no
      reliable regex, so this one leans on column names + light content cues)
"""

import re
from enum import Enum


class Confidence(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    NONE = "None"


CONFIDENCE_RANK = {
    Confidence.HIGH: 3,
    Confidence.MEDIUM: 2,
    Confidence.LOW: 1,
    Confidence.NONE: 0,
}


def _clean(value: str) -> str:
    """Strip whitespace/dashes/parentheses so formatted numbers still match."""
    return re.sub(r"[\s\-\(\)]", "", value)


class BaseDetector:
    """Common interface for all PII detectors."""
    name = "base"
    column_hints: list = []

    def detect(self, value, column_name=""):
        raise NotImplementedError

    def _column_hint_matches(self, column_name: str) -> bool:
        col = column_name.lower()
        return any(hint in col for hint in self.column_hints)


# ---------------------------------------------------------------------------
# Saudi National ID / Iqama
# ---------------------------------------------------------------------------

class NationalIdDetector(BaseDetector):
    name = "National ID"
    regex = re.compile(r"\b[12]\d{9}\b")
    column_hints = [
        "national_id", "national id", "nationalid", "iqama", "id_number",
        "id number", "saudi_id", "civil_id", "nid",
    ]

    def detect(self, value, column_name=""):
        if value is None:
            value = ""
        cleaned = _clean(str(value))
        match = self.regex.search(cleaned)
        hint = self._column_hint_matches(column_name)

        if match:
            digits = match.group()
            is_placeholder = len(set(digits)) <= 2
            if not is_placeholder:
                return Confidence.HIGH, digits
            return Confidence.MEDIUM, digits

        if hint and str(value).strip() != "":
            return Confidence.LOW, str(value)

        return Confidence.NONE, None


# ---------------------------------------------------------------------------
# Saudi mobile number
# ---------------------------------------------------------------------------

class MobileNumberDetector(BaseDetector):
    name = "Mobile Number"
    regex = re.compile(r"\b(?:\+?966|0)5\d{8}\b")
    column_hints = [
        "mobile", "phone", "cell", "contact_number", "contact number",
        "tel", "telephone", "whatsapp",
    ]

    def detect(self, value, column_name=""):
        if value is None:
            value = ""
        cleaned = _clean(str(value))
        match = self.regex.search(cleaned)
        hint = self._column_hint_matches(column_name)

        if match:
            return Confidence.HIGH, match.group()

        if hint and str(value).strip() != "":
            return Confidence.LOW, str(value)

        return Confidence.NONE, None


# ---------------------------------------------------------------------------
# IBAN (Saudi format SAxx + 22 digits, with general IBAN fallback)
# ---------------------------------------------------------------------------

class IbanDetector(BaseDetector):
    name = "IBAN"
    saudi_regex = re.compile(r"\bSA\d{22}\b", re.IGNORECASE)
    general_regex = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b", re.IGNORECASE)
    column_hints = ["iban", "bank_account", "bank account", "account_number", "account number"]

    def _mod97_check(self, iban: str) -> bool:
        """Standard IBAN checksum validation (mod-97)."""
        iban = iban.upper()
        rearranged = iban[4:] + iban[:4]
        numeric = "".join(str(int(c, 36)) for c in rearranged)
        try:
            return int(numeric) % 97 == 1
        except ValueError:
            return False

    def detect(self, value, column_name=""):
        if value is None:
            value = ""
        cleaned = _clean(str(value)).upper()
        hint = self._column_hint_matches(column_name)

        saudi_match = self.saudi_regex.search(cleaned)
        if saudi_match:
            candidate = saudi_match.group()
            if self._mod97_check(candidate):
                return Confidence.HIGH, candidate
            return Confidence.MEDIUM, candidate

        general_match = self.general_regex.search(cleaned)
        if general_match:
            candidate = general_match.group()
            if self._mod97_check(candidate):
                return Confidence.MEDIUM, candidate
            if hint:
                return Confidence.LOW, candidate

        if hint and str(value).strip() != "":
            return Confidence.LOW, str(value)

        return Confidence.NONE, None


# ---------------------------------------------------------------------------
# Passport number (heuristic — formats vary widely by country)
# ---------------------------------------------------------------------------

class PassportDetector(BaseDetector):
    name = "Passport Number"
    regex = re.compile(r"\b[A-Z]{1,2}\d{6,8}\b", re.IGNORECASE)
    column_hints = ["passport", "passport_no", "passport number", "passport_number"]

    def detect(self, value, column_name=""):
        if value is None:
            value = ""
        cleaned = _clean(str(value))
        hint = self._column_hint_matches(column_name)
        match = self.regex.search(cleaned)

        if match:
            if hint:
                return Confidence.HIGH, match.group()
            return Confidence.MEDIUM, match.group()

        if hint and str(value).strip() != "":
            return Confidence.LOW, str(value)

        return Confidence.NONE, None


# ---------------------------------------------------------------------------
# Email address
# ---------------------------------------------------------------------------

class EmailDetector(BaseDetector):
    name = "Email"
    regex = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    column_hints = ["email", "e-mail", "mail"]

    def detect(self, value, column_name=""):
        if value is None:
            value = ""
        match = self.regex.search(str(value))
        hint = self._column_hint_matches(column_name)

        if match:
            return Confidence.HIGH, match.group()

        if hint and str(value).strip() != "":
            return Confidence.LOW, str(value)

        return Confidence.NONE, None


# ---------------------------------------------------------------------------
# Physical address (heuristic — no reliable regex, relies on column hints
# plus light content cues like digit+street-word patterns)
# ---------------------------------------------------------------------------

class AddressDetector(BaseDetector):
    name = "Address"
    column_hints = ["address", "street", "addr", "home_address", "mailing_address", "residential"]
    # "location" alone is too broad (matches server_location, data center
    # fields, etc.) -- only treat it as an address hint if it's not paired
    # with an infrastructure-sounding qualifier.
    infra_location_terms = ["server", "data_center", "datacenter", "hosted", "region", "cluster"]
    # Light content cue: a number followed by 0-4 words and then a common
    # street/area keyword (e.g. "123 King Fahd Road", "45 Tahlia Street").
    content_cue_regex = re.compile(
        r"\d+\s+(?:\w+\s+){0,4}(street|st\.|road|rd\.|avenue|ave\.|district|building|"
        r"شارع|طريق|حي|مبنى)",
        re.IGNORECASE,
    )

    def _column_hint_matches(self, column_name: str) -> bool:
        col = column_name.lower()
        if any(term in col for term in self.infra_location_terms):
            return False
        if "location" in col:
            # Plain "location" still counts, but only on its own --
            # e.g. "location" or "customer_location", not "server_location"
            return True
        return any(hint in col for hint in self.column_hints)

    def detect(self, value, column_name=""):
        if value is None:
            value = ""
        text = str(value)
        hint = self._column_hint_matches(column_name)
        content_cue = bool(self.content_cue_regex.search(text))

        if text.strip() == "":
            return Confidence.NONE, None

        if hint and content_cue:
            return Confidence.HIGH, text
        if hint:
            return Confidence.MEDIUM, text
        if content_cue:
            return Confidence.LOW, text

        return Confidence.NONE, None


# ---------------------------------------------------------------------------
# Health Data (PDPL Sensitive Data — Article 1(11))
# ---------------------------------------------------------------------------

class HealthDataDetector(BaseDetector):
    name = "Health Data"
    column_hints = [
        "health", "medical", "diagnosis", "condition", "disability",
        "blood_type", "blood type", "medication", "treatment", "illness",
    ]
    content_cue_regex = re.compile(
        r"\b(diabetes|cancer|hiv|aids|hepatitis|asthma|disability|disabled|"
        r"chronic|diagnosis|diagnosed|medication|surgery|covid|tumou?r|"
        r"mental health|depression|anxiety disorder|pregnan(t|cy))\b",
        re.IGNORECASE,
    )

    def detect(self, value, column_name=""):
        if value is None:
            value = ""
        text = str(value)
        if text.strip() == "":
            return Confidence.NONE, None

        hint = self._column_hint_matches(column_name)
        content_cue = bool(self.content_cue_regex.search(text))

        if hint and content_cue:
            return Confidence.HIGH, text
        if content_cue:
            return Confidence.MEDIUM, text
        if hint:
            return Confidence.LOW, text

        return Confidence.NONE, None


# ---------------------------------------------------------------------------
# Religious or Political Affiliation (PDPL Sensitive Data — Article 1(11))
# ---------------------------------------------------------------------------

class ReligiousPoliticalDetector(BaseDetector):
    name = "Religious or Political Affiliation"
    column_hints = [
        "religion", "religious", "faith", "sect", "political", "party_affiliation",
        "party affiliation", "ideology",
    ]
    content_cue_regex = re.compile(
        r"\b(muslim|christian|jewish|hindu|buddhist|atheist|sunni|shia|"
        r"catholic|protestant|orthodox church|secular|"
        r"conservative party|liberal party|socialist|communist)\b",
        re.IGNORECASE,
    )

    def detect(self, value, column_name=""):
        if value is None:
            value = ""
        text = str(value)
        if text.strip() == "":
            return Confidence.NONE, None

        hint = self._column_hint_matches(column_name)
        content_cue = bool(self.content_cue_regex.search(text))

        if hint and content_cue:
            return Confidence.HIGH, text
        if hint:
            return Confidence.MEDIUM, text
        if content_cue:
            return Confidence.LOW, text

        return Confidence.NONE, None


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

DETECTOR_REGISTRY = [
    NationalIdDetector(),
    MobileNumberDetector(),
    IbanDetector(),
    PassportDetector(),
    EmailDetector(),
    AddressDetector(),
    HealthDataDetector(),
    ReligiousPoliticalDetector(),
]


def run_all_detectors(value, column_name=""):
    """
    Run every registered detector against a single cell value.

    Returns a list of (detector_name, confidence, matched_value) for every
    detector that produced a hit (confidence != NONE).
    """
    hits = []
    for detector in DETECTOR_REGISTRY:
        confidence, matched = detector.detect(value, column_name)
        if confidence != Confidence.NONE:
            hits.append((detector.name, confidence, matched))
    return hits
