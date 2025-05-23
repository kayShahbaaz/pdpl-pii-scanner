"""
test_pii_detectors.py
-----------------------
Unit tests for each PII detector in pii_detectors.py.

Covers: correct High-confidence matches, validation logic downgrading
suspect matches, column-hint fallback behavior, and known false-positive
cases that were caught and fixed during development (e.g. server_location
incorrectly matching the Address detector).
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pii_detectors import (
    Confidence,
    NationalIdDetector,
    MobileNumberDetector,
    IbanDetector,
    PassportDetector,
    EmailDetector,
    AddressDetector,
    HealthDataDetector,
    ReligiousPoliticalDetector,
    run_all_detectors,
)


# ---------------------------------------------------------------------------
# National ID
# ---------------------------------------------------------------------------

class TestNationalIdDetector:
    def setup_method(self):
        self.detector = NationalIdDetector()

    def test_valid_citizen_id_high_confidence(self):
        conf, match = self.detector.detect("1023456789", "national_id")
        assert conf == Confidence.HIGH
        assert match == "1023456789"

    def test_valid_resident_id_high_confidence(self):
        conf, match = self.detector.detect("2034567891", "national_id")
        assert conf == Confidence.HIGH

    def test_placeholder_repeated_digits_downgraded(self):
        # Starts with neither 1 nor 2's valid range issue -- but even if it
        # matched the prefix, all-repeated-digit strings should not be HIGH.
        conf, match = self.detector.detect("1111111111", "national_id")
        assert conf == Confidence.MEDIUM

    def test_wrong_prefix_falls_back_to_column_hint(self):
        # Starts with 9 -- not a valid National ID prefix at all.
        conf, match = self.detector.detect("9999999999", "national_id")
        assert conf == Confidence.LOW

    def test_no_match_no_hint_returns_none(self):
        conf, match = self.detector.detect("hello world", "notes")
        assert conf == Confidence.NONE
        assert match is None

    def test_blank_value_returns_none(self):
        conf, match = self.detector.detect("", "national_id")
        assert conf == Confidence.NONE

    def test_formatted_with_dashes_still_matches(self):
        conf, match = self.detector.detect("102-345-6789", "national_id")
        assert conf == Confidence.HIGH
        assert match == "1023456789"

    def test_column_hint_with_malformed_value(self):
        conf, match = self.detector.detect("ABC123", "iqama")
        assert conf == Confidence.LOW


# ---------------------------------------------------------------------------
# Mobile Number
# ---------------------------------------------------------------------------

class TestMobileNumberDetector:
    def setup_method(self):
        self.detector = MobileNumberDetector()

    def test_local_format_high_confidence(self):
        conf, match = self.detector.detect("0512345678", "mobile")
        assert conf == Confidence.HIGH
        assert match == "0512345678"

    def test_international_plus_format(self):
        conf, match = self.detector.detect("+966512345678", "mobile_number")
        assert conf == Confidence.HIGH

    def test_international_no_plus_format(self):
        conf, match = self.detector.detect("966512345678", "phone")
        assert conf == Confidence.HIGH

    def test_malformed_number_falls_back_to_low_via_hint(self):
        conf, match = self.detector.detect("123456", "mobile")
        assert conf == Confidence.LOW

    def test_no_hint_no_match_is_none(self):
        conf, match = self.detector.detect("123456", "notes")
        assert conf == Confidence.NONE

    def test_non_saudi_mobile_prefix_not_matched(self):
        # Doesn't start with 5 after the country/leading-zero prefix.
        conf, match = self.detector.detect("0612345678", "mobile")
        assert conf == Confidence.LOW  # caught only via column hint, not regex


# ---------------------------------------------------------------------------
# IBAN
# ---------------------------------------------------------------------------

class TestIbanDetector:
    def setup_method(self):
        self.detector = IbanDetector()

    def test_valid_saudi_iban_passes_checksum_high_confidence(self):
        # Known-valid-format Saudi IBAN used in public documentation examples.
        conf, match = self.detector.detect("SA0380000000608010167519", "iban")
        assert conf == Confidence.HIGH

    def test_saudi_format_but_bad_checksum_is_medium(self):
        conf, match = self.detector.detect("SA1234567890123456789012", "iban")
        assert conf == Confidence.MEDIUM

    def test_non_iban_text_with_hint_is_low(self):
        conf, match = self.detector.detect("not-an-iban", "iban")
        assert conf == Confidence.LOW

    def test_no_hint_no_match_is_none(self):
        conf, match = self.detector.detect("not-an-iban", "notes")
        assert conf == Confidence.NONE

    def test_lowercase_iban_still_matches(self):
        conf, match = self.detector.detect("sa0380000000608010167519", "account_number")
        assert conf == Confidence.HIGH


# ---------------------------------------------------------------------------
# Passport
# ---------------------------------------------------------------------------

class TestPassportDetector:
    def setup_method(self):
        self.detector = PassportDetector()

    def test_valid_shape_with_hint_high_confidence(self):
        conf, match = self.detector.detect("A12345678", "passport_no")
        assert conf == Confidence.HIGH

    def test_valid_shape_without_hint_medium_confidence(self):
        # Same shape, but column name gives no passport-specific signal.
        conf, match = self.detector.detect("A12345678", "notes")
        assert conf == Confidence.MEDIUM

    def test_empty_with_hint_returns_none(self):
        conf, match = self.detector.detect("", "passport_no")
        assert conf == Confidence.NONE


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

class TestEmailDetector:
    def setup_method(self):
        self.detector = EmailDetector()

    def test_valid_email_high_confidence(self):
        conf, match = self.detector.detect("ahmed.s@example.com", "email")
        assert conf == Confidence.HIGH
        assert match == "ahmed.s@example.com"

    def test_invalid_email_with_hint_is_low(self):
        conf, match = self.detector.detect("not_an_email", "email")
        assert conf == Confidence.LOW

    def test_email_found_in_unrelated_column(self):
        # Even without a hint, a real email shape should still be HIGH.
        conf, match = self.detector.detect("contact me at ahmed@example.com", "notes")
        assert conf == Confidence.HIGH


# ---------------------------------------------------------------------------
# Address -- includes regression tests for the server_location false positive
# ---------------------------------------------------------------------------

class TestAddressDetector:
    def setup_method(self):
        self.detector = AddressDetector()

    def test_home_address_with_street_cue_high_confidence(self):
        conf, match = self.detector.detect("123 King Fahd Road, Riyadh", "home_address")
        assert conf == Confidence.HIGH

    def test_home_address_hint_without_content_cue_medium(self):
        conf, match = self.detector.detect("Some descriptive text", "home_address")
        assert conf == Confidence.MEDIUM

    def test_street_cue_without_hint_is_low(self):
        conf, match = self.detector.detect("123 Main Street area", "notes")
        assert conf == Confidence.LOW

    def test_server_location_is_not_flagged_as_address(self):
        """
        Regression test: server_location previously matched the Address
        detector's 'location' column hint, producing a false positive.
        Infrastructure-sounding location columns must be excluded.
        """
        conf, match = self.detector.detect("AWS Frankfurt, Germany", "server_location")
        assert conf == Confidence.NONE

    def test_data_center_column_not_flagged(self):
        conf, match = self.detector.detect("us-east-1", "data_center")
        assert conf == Confidence.NONE

    def test_plain_location_column_still_flagged(self):
        conf, match = self.detector.detect("123 Main St", "location")
        assert conf == Confidence.MEDIUM

    def test_customer_location_column_still_flagged(self):
        conf, match = self.detector.detect("some text", "customer_location")
        assert conf == Confidence.MEDIUM


# ---------------------------------------------------------------------------
# Health Data
# ---------------------------------------------------------------------------

class TestHealthDataDetector:
    def setup_method(self):
        self.detector = HealthDataDetector()

    def test_medical_column_with_condition_keyword_high_confidence(self):
        conf, match = self.detector.detect("Type 2 Diabetes", "medical_condition")
        assert conf == Confidence.HIGH

    def test_condition_keyword_in_unrelated_column_medium(self):
        conf, match = self.detector.detect("Patient has diabetes", "notes")
        assert conf == Confidence.MEDIUM

    def test_medical_column_no_keyword_low(self):
        conf, match = self.detector.detect("No issues reported", "medical_condition")
        assert conf == Confidence.LOW

    def test_unrelated_text_no_hint_is_none(self):
        conf, match = self.detector.detect("Everything is fine", "notes")
        assert conf == Confidence.NONE


# ---------------------------------------------------------------------------
# Religious / Political Affiliation
# ---------------------------------------------------------------------------

class TestReligiousPoliticalDetector:
    def setup_method(self):
        self.detector = ReligiousPoliticalDetector()

    def test_religion_column_with_keyword_high_confidence(self):
        conf, match = self.detector.detect("Sunni", "religion")
        assert conf == Confidence.HIGH

    def test_religion_column_no_keyword_medium(self):
        conf, match = self.detector.detect("Prefer not to say", "religion")
        assert conf == Confidence.MEDIUM

    def test_keyword_in_unrelated_column_low(self):
        conf, match = self.detector.detect("Shia", "notes")
        assert conf == Confidence.LOW

    def test_incidental_holiday_mention_not_flagged(self):
        """
        A casual mention of a holiday name (not in our keyword list) should
        not be treated as a religious-affiliation disclosure.
        """
        conf, match = self.detector.detect("Mentioned Eid in passing", "notes")
        assert conf == Confidence.NONE


# ---------------------------------------------------------------------------
# run_all_detectors -- integration across the full registry
# ---------------------------------------------------------------------------

class TestRunAllDetectors:
    def test_single_cell_can_match_multiple_detectors(self):
        # A cell could plausibly match more than one detector; the function
        # should return every hit, not just the first.
        hits = run_all_detectors("ahmed.s@example.com", "email")
        names = [h[0] for h in hits]
        assert "Email" in names

    def test_blank_cell_returns_no_hits(self):
        hits = run_all_detectors("", "national_id")
        assert hits == []

    def test_none_value_returns_no_hits(self):
        hits = run_all_detectors(None, "mobile")
        assert hits == []

    def test_clean_unrelated_text_returns_no_hits(self):
        hits = run_all_detectors("Regular customer", "notes")
        assert hits == []
