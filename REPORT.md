# PDPL PII Scanner — Project Report

**Project:** pdpl-pii-scanner
**Type:** Personal data discovery & compliance-readiness tool for Saudi Arabia's PDPL
**Scan date:** Run against included `sample_data/` on 2025-06-21

---

## 1. Summary

This project is a Python tool that scans CSV and Excel files for personal data regulated under Saudi Arabia's **Personal Data Protection Law (PDPL)**, enforced by **SDAIA** (Saudi Data & AI Authority). It goes beyond simple pattern matching: every finding is classified into PDPL's own legal categories, scored for risk, and checked against basic governance expectations (consent tracking, data retention, cross-border transfer).

The goal was to demonstrate practical understanding of **PDPL data discovery** — the first step any organization must take before it can apply real compliance controls (consent management, access restriction, encryption, breach response). A tool can't protect personal data it doesn't know it has.

This report covers two things: **what the project does and how it's built** (Sections 2–5), and **the actual results from running it against the included sample data** (Section 6).

---

## 2. What it detects

| PII Type | PDPL Category | Basis |
|---|---|---|
| Saudi National ID / Iqama | Personal Data | Identifies a person |
| Saudi Mobile Number | Personal Data | Identifies a person |
| Passport Number | Personal Data | Identifies a person |
| Email Address | Personal Data | Identifies a person |
| Physical Address | Personal Data | Identifies a person |
| IBAN / Bank Account | **Credit Data** | PDPL Article 24 — special protections for financial/credit data |
| Health / Medical Data | **Sensitive Data** | PDPL Article 1(11) — explicitly listed |
| Religious or Political Affiliation | **Sensitive Data** | PDPL Article 1(11) — explicitly listed |

The Personal Data / Credit Data / Sensitive Data split is not arbitrary — it mirrors how PDPL itself defines these terms. Sensitive Data is the narrowest and most consequential category: under Article 1(11) it covers data revealing racial or ethnic origin, religious or political belief, health, biometric/genetic identifiers, security-related criminal records, or unknown parentage. PDPL requires **explicit consent** (not implied) before processing Sensitive Data, restricts its use for marketing even with consent, and may require a Data Protection Impact Assessment (DPIA) for high-risk processing.

> This classification is built from PDPL's Article 1 definitions and public SDAIA/law-firm guidance. It's an educational summary, not legal advice — see `pdpl_knowledge.py` for sources and caveats.

## 3. How detection works

Each detector combines three signals into a confidence score (**High / Medium / Low**) instead of a flat yes/no:

1. **Regex pattern match** — does the value's format match the PII type?
2. **Validation** — does it pass extra checks (IBAN mod-97 checksum, rejection of placeholder/repeated-digit National IDs, medical/religious keyword cues)?
3. **Column-name hints** — does the header itself suggest PII, even if the cell content doesn't cleanly match?

This three-signal approach exists because pure regex matching produces too many false positives and false negatives on its own. For example, a 10-digit number starting with `9` should never be treated as a Saudi National ID regardless of format, while a malformed phone number sitting in a column literally named `mobile` is still worth flagging for human review — just at lower confidence.

## 4. Risk scoring

Every finding gets a **risk weight**: `category_weight × confidence_multiplier`.

- Category weight: Personal Data = 1, Credit Data = 3, Sensitive Data = 5
- Confidence multiplier: High = ×1.0, Medium = ×0.6, Low = ×0.3

These sum into a **per-file risk score**, banded as None / Low / Medium / High / Critical. The weighting means a file with a handful of Sensitive Data hits can outrank a file with many more ordinary Personal Data hits — which is the correct behavior, since that's also how PDPL's own obligations scale.

## 5. Compliance gap checks

Beyond detecting PII, the tool runs two heuristic governance checks per file:

- **Consent / retention tracking** — is there a column suggesting consent was recorded (`consent`, `opt_in`), or that data has a retention/expiry policy (`retention_date`, `delete_after`)? PDPL requires a lawful basis for processing and discourages indefinite retention.
- **Cross-border transfer indicators** — is there a location-type column (`country`, `server_location`, `hosted_in`), and do any values point outside Saudi Arabia? PDPL restricts transferring personal data abroad without specific safeguards.

These are column-name-driven heuristics, not a substitute for a real audit — but they demonstrate the kind of governance question a PDPL-aware reviewer asks beyond "does PII exist."

---

## 6. Findings from the sample data scan

The tool was run against the three files in `sample_data/` (a customer CSV, an employee/banking XLSX with two sheets, and a patient CSV) using:

```bash
python pdpl_checker.py sample_data --outdir output --redact --explain
```

### 6.1 Overall results

| Metric | Value |
|---|---|
| Files scanned | 3 |
| Total findings | 62 |
| High confidence | 55 |
| Medium confidence | 2 |
| Low confidence | 5 |

### 6.2 Findings by PDPL category

| Category | Count | Note |
|---|---|---|
| Personal Data | 53 | Standard consent/security obligations apply |
| Sensitive Data | 5 | Triggers stricter explicit-consent and DPIA requirements |
| Credit Data | 4 | Triggers PDPL Article 24 disclosure-notification requirements |

### 6.3 Findings by PII type

| PII Type | Count |
|---|---|
| National ID | 16 |
| Mobile Number | 15 |
| Email | 15 |
| IBAN | 4 |
| Address | 4 |
| Passport Number | 3 |
| Health Data | 3 |
| Religious or Political Affiliation | 2 |

### 6.4 Risk score by file

| File | Risk Score | Band | Sensitive Hits |
|---|---|---|---|
| sample_customers.csv | 27.6 | Medium | 0 |
| sample_employees.xlsx | 28.6 | Medium | 0 |
| sample_patients.csv | 24.5 | Medium | 5 |

Note that `sample_patients.csv` reaches a comparable risk score to the other two files **despite having fewer total findings** — this is the risk-weighting design working as intended: its 5 Sensitive Data hits (health and religious data) carry more weight than a larger number of ordinary Personal Data hits.

### 6.5 Compliance gaps identified

- **All three files** lack a retention/expiry tracking column.
- **`sample_customers.csv`, `sample_employees.xlsx`** (both sheets) also lack any consent-tracking column.
- **`sample_patients.csv`** shows a likely **cross-border data transfer**: its `server_location` column contains values pointing to Germany (AWS Frankfurt) and the US (Azure US-East), alongside one Saudi-based entry (AWS Riyadh) — a pattern PDPL restricts without specific safeguards in place.

### 6.6 Output artifacts produced

- `output/pii_report.html` — bilingual (EN/AR) interactive dashboard with charts and hover tooltips
- `output/pii_findings.csv` — full row-level findings list
- `output/redacted/` — sanitized copies of all three input files with flagged cells replaced by `[REDACTED]`

---

## 7. Testing

The project includes a pytest suite of **101 tests** covering every module: detectors, PDPL classification/risk weighting, compliance checks, file reading (CSV/XLSX), and full pipeline integration. All 101 currently pass.

Two real bugs were found and fixed during development via this test suite — both are kept as permanent regression tests:

1. A pandas behavior where empty Excel cells could read as the literal string `"nan"` rather than a true empty value, which would have produced phantom PII matches.
2. An Address detector false positive where infrastructure columns like `server_location` were being flagged as physical addresses purely because of the substring `"location"` in the column name.

## 8. Limitations

- PDPL article citations beyond Article 1's defined terms (e.g. the Credit Data/Article 24 reference) are based on secondary legal sources, not independently verified against primary legislative text.
- Health, religious, and political affiliation detection is keyword-based; it will miss indirect references and may over-trigger on neutral mentions.
- Compliance gap checks are column-name heuristics and cannot detect consent or retention processes tracked outside the scanned file.
- Risk scores are a simple weighted sum, not a calibrated estimate of actual harm or regulatory exposure.

## 9. Possible extensions

- Custom column-hint/regex configuration per organization via a config file, instead of hardcoded detectors.
- Format-preserving pseudonymization instead of full `[REDACTED]` replacement, for datasets that need to remain structurally realistic.
- A "diff" mode comparing two scans of the same dataset over time to track whether PII/Sensitive Data exposure is growing or shrinking.
- Support for JSON input/output or a simple database connector.

---

*This report and the underlying tool are educational/portfolio work demonstrating PDPL data-discovery concepts. Nothing here constitutes legal advice; consult PDPL's official text and Implementing Regulations, or a qualified advisor, for real compliance decisions.*

---

## Author

**kayShahbaaz** **خ شهباز**
