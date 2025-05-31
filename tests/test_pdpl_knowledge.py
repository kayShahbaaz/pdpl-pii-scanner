"""
test_pdpl_knowledge.py
-------------------------
Unit tests for pdpl_knowledge.py: classification mapping, risk weighting,
and explanation text generation.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pdpl_knowledge import (
    PdplCategory,
    get_category,
    get_explanation,
    get_weight,
)


class TestClassificationMapping:
    def test_national_id_is_personal_data(self):
        assert get_category("National ID") == PdplCategory.PERSONAL_DATA

    def test_mobile_is_personal_data(self):
        assert get_category("Mobile Number") == PdplCategory.PERSONAL_DATA

    def test_iban_is_credit_data(self):
        assert get_category("IBAN") == PdplCategory.CREDIT_DATA

    def test_health_data_is_sensitive(self):
        assert get_category("Health Data") == PdplCategory.SENSITIVE_DATA

    def test_religious_political_is_sensitive(self):
        assert get_category("Religious or Political Affiliation") == PdplCategory.SENSITIVE_DATA

    def test_unknown_pii_type_defaults_to_personal_data(self):
        # New/unregistered detector names should fail safe to Personal Data
        # rather than raising, so the pipeline never crashes on a typo.
        assert get_category("Some New Detector") == PdplCategory.PERSONAL_DATA


class TestRiskWeighting:
    def test_sensitive_data_high_confidence_is_heaviest(self):
        weight = get_weight("Health Data", "High")
        assert weight == 5.0  # base weight 5 * multiplier 1.0

    def test_sensitive_data_low_confidence_is_discounted(self):
        weight = get_weight("Health Data", "Low")
        assert weight == 1.5  # base weight 5 * multiplier 0.3

    def test_personal_data_high_confidence(self):
        weight = get_weight("National ID", "High")
        assert weight == 1.0  # base weight 1 * multiplier 1.0

    def test_credit_data_high_confidence(self):
        weight = get_weight("IBAN", "High")
        assert weight == 3.0  # base weight 3 * multiplier 1.0

    def test_sensitive_data_outweighs_few_personal_data_hits(self):
        # A single high-confidence Sensitive Data hit (5.0) should weigh
        # more than a few Personal Data hits (1.0 each) -- this is the
        # entire point of category-aware risk scoring.
        sensitive_hit = get_weight("Health Data", "High")
        three_personal_hits = sum(get_weight("National ID", "High") for _ in range(3))
        assert sensitive_hit > three_personal_hits

    def test_weight_scales_linearly_with_repeated_hits(self):
        # Confirms the scoring is a straightforward additive weight, not
        # some hidden non-linear curve -- important since the file-level
        # risk score is just a sum of these.
        ten_personal_hits = sum(get_weight("National ID", "High") for _ in range(10))
        assert ten_personal_hits == 10.0


class TestExplanationText:
    def test_sensitive_data_explanation_mentions_explicit_consent(self):
        text = get_explanation("Health Data")
        assert "explicit consent" in text.lower() or "explicit" in text.lower()

    def test_personal_data_explanation_does_not_overclaim_sensitivity(self):
        text = get_explanation("National ID")
        assert "sensitive data" not in text.lower().split(".")[0].lower() or "does not trigger" in text.lower()

    def test_credit_data_explanation_mentions_article_24_concept(self):
        text = get_explanation("IBAN")
        assert "credit" in text.lower()

    def test_detector_specific_note_is_appended(self):
        text = get_explanation("Health Data")
        assert "keyword" in text.lower()  # from DETECTOR_NOTES
