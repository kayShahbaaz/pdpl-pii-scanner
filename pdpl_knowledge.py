"""
pdpl_knowledge.py
-------------------
A small, grounded reference of how Saudi PDPL (Personal Data Protection Law)
classifies data, used to tag scanner findings and power the --explain flag.

IMPORTANT — accuracy note:
This is a best-effort summary for an educational/portfolio tool, built from
PDPL Article 1 definitions and public guidance from SDAIA and several law
firms (see SOURCES below). It is NOT legal advice, and article numbers
beyond Article 1's defined terms should be treated as general guidance
rather than a verified citation. Always confirm against the official PDPL
text and Implementing Regulations published by SDAIA before relying on this
for real compliance decisions.

SOURCES consulted while building this module:
    - SDAIA's own "Guide to the Saudi Personal Data Protection Law"
      (dgp.sdaia.gov.sa)
    - PDPL Article 1, Definitions (saudiprivacylaw.com mirror of the
      official text)
    - Multiple law-firm summaries (King & Spalding, Akin, Hala Privacy,
      Cleary Gottlieb, TermsFeed, GetTerms) cross-checked for consistency
"""

from enum import Enum


class PdplCategory(str, Enum):
    PERSONAL_DATA = "Personal Data"
    SENSITIVE_DATA = "Sensitive Data"
    CREDIT_DATA = "Credit Data"  # PDPL gives this its own special category too


# ---------------------------------------------------------------------------
# Per-detector PDPL classification
# ---------------------------------------------------------------------------
# PDPL Article 1(11) defines Sensitive Data narrowly: data revealing racial/
# ethnic origin, religious/intellectual/political belief, security-related
# criminal records, biometric/genetic data used to identify someone, health
# data, or data indicating a parent is unknown. Everything else that
# identifies a person (names, ID numbers, contact info, financial records)
# is ordinary Personal Data -- still protected, but without the extra
# consent/DPIA requirements that apply to Sensitive Data.

DETECTOR_CLASSIFICATION = {
    "National ID": PdplCategory.PERSONAL_DATA,
    "Mobile Number": PdplCategory.PERSONAL_DATA,
    "Passport Number": PdplCategory.PERSONAL_DATA,
    "Email": PdplCategory.PERSONAL_DATA,
    "Address": PdplCategory.PERSONAL_DATA,
    "IBAN": PdplCategory.CREDIT_DATA,  # financial/credit-adjacent, special protections under Art. 24
    "Health Data": PdplCategory.SENSITIVE_DATA,
    "Religious or Political Affiliation": PdplCategory.SENSITIVE_DATA,
}

# Relative severity weight used for risk scoring. Sensitive Data and Credit
# Data both carry extra legal obligations under PDPL, so a single hit there
# is weighted well above an ordinary Personal Data hit.
CATEGORY_WEIGHT = {
    PdplCategory.PERSONAL_DATA: 1,
    PdplCategory.CREDIT_DATA: 3,
    PdplCategory.SENSITIVE_DATA: 5,
}

# Confidence further scales the weight -- a Low-confidence guess shouldn't
# move the score as much as a High-confidence hit of the same category.
CONFIDENCE_MULTIPLIER = {
    "High": 1.0,
    "Medium": 0.6,
    "Low": 0.3,
}


# ---------------------------------------------------------------------------
# Plain-language obligation text, keyed by category -- powers --explain
# ---------------------------------------------------------------------------

CATEGORY_EXPLANATIONS = {
    PdplCategory.PERSONAL_DATA: (
        "Under PDPL, this is ordinary Personal Data: information that can identify "
        "a person (e.g. an ID number, phone number, or address). PDPL still requires "
        "a lawful basis to process it (typically consent), data minimization, and "
        "reasonable security measures -- but it does not trigger PDPL's stricter "
        "Sensitive Data rules."
    ),
    PdplCategory.CREDIT_DATA: (
        "PDPL gives Credit Data its own special protections (Art. 24): information "
        "related to a person's financing, debt, or credit history. Processing it "
        "generally requires the data subject's explicit consent, and the law "
        "specifically requires controllers to notify individuals before disclosing "
        "their credit data."
    ),
    PdplCategory.SENSITIVE_DATA: (
        "Under PDPL Article 1(11), this qualifies as Sensitive Data -- a special "
        "category covering things like health, biometric/genetic, racial/ethnic, "
        "or religious/political information. PDPL requires EXPLICIT consent (not "
        "just implied consent) before processing this kind of data, restricts using "
        "it for marketing even with consent, and high-risk processing of it may "
        "require a Data Protection Impact Assessment (DPIA) before you start."
    ),
}

DETECTOR_NOTES = {
    "IBAN": (
        "Flagged as Credit/financial data rather than ordinary Personal Data, since "
        "bank account identifiers are closely tied to PDPL's Credit Data protections."
    ),
    "Health Data": (
        "Detected via keyword/condition matching, not medical-record parsing -- "
        "treat hits as 'worth a human review' rather than a certainty."
    ),
    "Religious or Political Affiliation": (
        "Detected via keyword matching on explicit religious/political terms. "
        "This is a coarse heuristic; it will miss indirect references and may "
        "over-trigger on neutral mentions (e.g. discussing a holiday by name)."
    ),
}


def get_category(pii_type: str) -> PdplCategory:
    return DETECTOR_CLASSIFICATION.get(pii_type, PdplCategory.PERSONAL_DATA)


def get_explanation(pii_type: str) -> str:
    category = get_category(pii_type)
    text = CATEGORY_EXPLANATIONS[category]
    note = DETECTOR_NOTES.get(pii_type)
    if note:
        text = text + " Note: " + note
    return text


def get_weight(pii_type: str, confidence: str) -> float:
    category = get_category(pii_type)
    base = CATEGORY_WEIGHT[category]
    multiplier = CONFIDENCE_MULTIPLIER.get(confidence, 0.3)
    return base * multiplier
