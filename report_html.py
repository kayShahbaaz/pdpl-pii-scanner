"""
report_html.py
----------------
Generates the visual HTML dashboard for the PDPL Checker.

Handles both single-file and multi-file/folder scans: the report shows an
overall summary plus a per-file breakdown table, charts for PII type and
confidence distribution, and a detailed (masked) findings table.
"""

import os
import json
import html as html_lib
from collections import defaultdict
from datetime import datetime

from pii_detectors import Confidence, CONFIDENCE_RANK


RISK_BAND_COLOR = {
    "None": "#4a90c9",
    "Low": "#4a90c9",
    "Medium": "#d9a13a",
    "High": "#e0556f",
    "Critical": "#b13354",
}

# Bilingual labels (English / Arabic) for every heading, stat card, and
# table column used in the report. Keeping these in one dict makes it easy
# to extend to other languages later without hunting through f-strings.
AR = {
    "report_kicker": "نموذج اكتشاف البيانات وفق نظام حماية البيانات الشخصية السعودي (سدايا)",
    "report_title": "تقرير فحص البيانات الشخصية",
    "scanned": "تم فحص",
    "files": "الملفات",
    "rows": "الصفوف",
    "generated": "تاريخ الإنشاء",
    "files_scanned": "الملفات التي تم فحصها",
    "total_rows": "إجمالي الصفوف",
    "total_pii_hits": "إجمالي نتائج البيانات الشخصية",
    "sensitive_hits": "نتائج البيانات الحساسة (المادة ١-١١)",
    "pii_by_type": "نتائج البيانات الشخصية حسب النوع",
    "pdpl_category": "التصنيف وفق نظام حماية البيانات",
    "confidence_breakdown": "توزيع مستوى الثقة",
    "top_pii_types": "أكثر أنواع البيانات الشخصية تكرارًا",
    "files_risk_score": "درجة الخطورة لكل ملف",
    "file_col": "الملف",
    "sheets_col": "الأوراق",
    "rows_col": "الصفوف",
    "findings_col": "النتائج",
    "sensitive_hits_col": "نتائج حساسة",
    "risk_score_col": "درجة الخطورة",
    "risk_band_col": "مستوى الخطورة",
    "compliance_checks": "فحوصات الامتثال (تقديرية، ليست تدقيقًا كاملاً)",
    "gaps_found_col": "الثغرات المكتشفة",
    "detailed_findings": "النتائج التفصيلية (مقنّعة)",
    "row_col": "الصف",
    "column_col": "العمود",
    "pii_type_col": "نوع البيانات",
    "confidence_col": "مستوى الثقة",
    "value_col": "القيمة (مقنّعة)",
    "footer": "تم إنشاؤه بواسطة PDPL Checker — نموذج لاكتشاف البيانات الشخصية السعودية متوافق مع نظام حماية البيانات الشخصية. جميع القيم المعروضة مقنّعة؛ لا يخزن هذا التقرير بيانات شخصية كاملة.",
}

# Arabic names for each PII type, used both in chart labels and the
# detailed findings table so the bilingual labeling is consistent
# throughout, not just in the static headings.
PII_TYPE_AR = {
    "National ID": "الهوية الوطنية",
    "Mobile Number": "رقم الجوال",
    "IBAN": "رقم الآيبان",
    "Passport Number": "رقم الجواز",
    "Email": "البريد الإلكتروني",
    "Address": "العنوان",
    "Health Data": "بيانات صحية",
    "Religious or Political Affiliation": "الانتماء الديني أو السياسي",
}

PDPL_CATEGORY_AR = {
    "Personal Data": "بيانات شخصية",
    "Credit Data": "بيانات ائتمانية",
    "Sensitive Data": "بيانات حساسة",
}

CONFIDENCE_AR = {
    "High": "مرتفعة",
    "Medium": "متوسطة",
    "Low": "منخفضة",
}

# Hover tooltip explanations shown on each chart, so a viewer unfamiliar
# with the tool understands what they're looking at without leaving the
# page. These appear as the Chart.js tooltip title (one-time context, not
# per-data-point) via an afterTitle callback registered per chart in JS.
CHART_HELP_EN = {
    "typeChart": "Each slice is a PII type the scanner detected (e.g. National ID, Mobile Number). Hover a slice to see its exact count.",
    "categoryChart": "Groups findings by PDPL's own categories: Personal Data, Credit Data, or Sensitive Data. Sensitive Data triggers stricter consent/DPIA rules under PDPL Art. 1(11).",
    "confidenceChart": "How sure the scanner is about each match: High (pattern + validation passed), Medium (pattern matched but flagged as suspect), Low (only a column-name hint, worth a human review).",
    "columnChart": "Total hits per PII type, broken down by which file it came from (one color per file). Bars are grouped so you can compare files at a glance.",
}
CHART_HELP_AR = {
    "typeChart": "كل قطاع يمثل نوع بيانات شخصية تم رصده (مثل الهوية الوطنية أو رقم الجوال). مرّر الفأرة لرؤية العدد الدقيق.",
    "categoryChart": "تصنيف النتائج حسب فئات نظام حماية البيانات: بيانات شخصية، بيانات ائتمانية، أو بيانات حساسة. البيانات الحساسة تتطلب موافقة صريحة وتقييم أثر أشد وفق المادة ١-١١.",
    "confidenceChart": "مدى ثقة الأداة بكل نتيجة: مرتفعة (تطابق ونجاح التحقق)، متوسطة (تطابق مع شك)، منخفضة (إشارة من اسم العمود فقط، تحتاج مراجعة بشرية).",
    "columnChart": "إجمالي النتائج لكل نوع بيانات، موزعة حسب الملف المصدر (لون لكل ملف). الأعمدة مجمّعة لتسهيل المقارنة بين الملفات.",
}


def esc(s):
    return html_lib.escape(str(s))


def bilingual(en_key, ar_key=None):
    """Returns 'English / العربية' for a heading, given an AR dict key."""
    ar_text = AR.get(ar_key or en_key, "")
    return f"{en_key} / {ar_text}" if ar_text else en_key


def write_html_report(scanned_path, all_findings, file_summaries, compliance_results, outpath, as_of_date=None):
    total_rows = sum(s["total_rows"] for s in file_summaries.values())
    total_files = len(file_summaries)
    total_findings = len(all_findings)

    by_type_counts = defaultdict(int)
    by_confidence_counts = defaultdict(int)
    by_category_counts = defaultdict(int)
    # type_by_file[pii_type][file_basename] = hit count -- groups by the
    # PII type the scanner detected (e.g. "Mobile Number"), not the raw
    # column name. Raw column names vary across files/orgs ("mobile" vs
    # "mobile_number" vs "phone") and would otherwise fragment the chart
    # into near-duplicate bars for the same underlying PII type.
    type_by_file = defaultdict(lambda: defaultdict(int))
    for f in all_findings:
        by_type_counts[f["pii_type"]] += 1
        by_confidence_counts[f["confidence"]] += 1
        by_category_counts[f.get("pdpl_category", "Personal Data")] += 1
        file_base = os.path.basename(f["file"])
        type_by_file[f["pii_type"]][file_base] += 1

    high_conf = by_confidence_counts.get("High", 0)
    sensitive_total = sum(s.get("sensitive_data_hits", 0) for s in file_summaries.values())

    # ---- Per-file summary table (now with risk score) ----
    file_rows_html = ""
    for filepath, summary in file_summaries.items():
        band = summary.get("risk_band", "None")
        band_color = RISK_BAND_COLOR.get(band, "#8a97a8")
        file_rows_html += f"""
        <tr>
            <td>{esc(os.path.basename(filepath))}</td>
            <td>{summary['sheet_count']}</td>
            <td>{summary['total_rows']}</td>
            <td>{summary['finding_count']}</td>
            <td>{summary.get('sensitive_data_hits', 0)}</td>
            <td>{summary.get('risk_score', 0)}</td>
            <td><span class="badge" style="background:{band_color}22;color:{band_color}">{esc(band)}</span></td>
        </tr>"""
    if not file_summaries:
        file_rows_html = '<tr><td colspan="7" class="empty-state">No files scanned.</td></tr>'

    # ---- Compliance gap panel ----
    compliance_rows_html = ""
    for result in compliance_results:
        cr = result["consent_retention"]
        cb = result["cross_border"]
        gap_items = "".join(f"<li>{esc(g)}</li>" for g in cr["gaps"])
        cross_border_item = ""
        if cb["non_saudi_values_found"]:
            locations = ", ".join(sorted({v for _, v in cb["non_saudi_values_found"]}))
            cross_border_item = (
                f"<li>Possible cross-border transfer: non-Saudi location value(s) found "
                f"in {esc(', '.join(cb['location_columns_found']))} — {esc(locations)}</li>"
            )
        if gap_items or cross_border_item:
            compliance_rows_html += f"""
            <tr>
                <td>{esc(result['table_label'])}</td>
                <td><ul class="gap-list">{gap_items}{cross_border_item}</ul></td>
            </tr>"""
    if not compliance_rows_html:
        compliance_rows_html = '<tr><td colspan="2" class="empty-state">No compliance gaps flagged.</td></tr>'

    # ---- Detailed findings table (capped for performance, note total) ----
    MAX_DETAIL_ROWS = 500
    sorted_findings = sorted(
        all_findings,
        key=lambda x: -CONFIDENCE_RANK[Confidence(x["confidence"])],
    )
    detail_rows_html = ""
    for f in sorted_findings[:MAX_DETAIL_ROWS]:
        badge_class = {
            "High": "badge-high",
            "Medium": "badge-medium",
            "Low": "badge-low",
        }.get(f["confidence"], "badge-low")
        category = f.get("pdpl_category", "Personal Data")
        cat_class = "cat-sensitive" if category == "Sensitive Data" else (
            "cat-credit" if category == "Credit Data" else "cat-personal"
        )
        sheet_label = f" [{esc(f['sheet'])}]" if f.get("sheet") else ""
        pii_type_ar = PII_TYPE_AR.get(f["pii_type"], "")
        category_ar = PDPL_CATEGORY_AR.get(category, "")
        confidence_ar = CONFIDENCE_AR.get(f["confidence"], "")
        detail_rows_html += f"""
        <tr>
            <td>{esc(os.path.basename(f['file']))}{sheet_label}</td>
            <td>{f['row_number']}</td>
            <td>{esc(f['column'])}</td>
            <td>{esc(f['pii_type'])}<br><span class="ar">{esc(pii_type_ar)}</span></td>
            <td><span class="cat-badge {cat_class}">{esc(category)}</span><br><span class="ar">{esc(category_ar)}</span></td>
            <td><span class="badge {badge_class}">{esc(f['confidence'])}</span><br><span class="ar">{esc(confidence_ar)}</span></td>
            <td><code>{esc(f['masked_value'])}</code></td>
        </tr>"""
    if not all_findings:
        detail_rows_html = '<tr><td colspan="7" class="empty-state">No PII detected.</td></tr>'

    truncation_note = ""
    if len(sorted_findings) > MAX_DETAIL_ROWS:
        truncation_note = (
            f'<p class="note">Showing top {MAX_DETAIL_ROWS} of {len(sorted_findings)} findings '
            f'(sorted by confidence). See pii_findings.csv for the full list.</p>'
        )

    type_label_list = list(by_type_counts.keys())
    type_labels_bilingual = [
        f"{t} / {PII_TYPE_AR.get(t, '')}" if PII_TYPE_AR.get(t) else t
        for t in type_label_list
    ]
    type_labels = json.dumps(type_labels_bilingual)
    type_values = json.dumps(list(by_type_counts.values()))

    confidence_order = ["High", "Medium", "Low"]
    confidence_labels = json.dumps([f"{c} / {CONFIDENCE_AR[c]}" for c in confidence_order])
    confidence_values = json.dumps([by_confidence_counts.get(c, 0) for c in confidence_order])

    category_order = ["Personal Data", "Credit Data", "Sensitive Data"]
    category_labels = json.dumps([f"{c} / {PDPL_CATEGORY_AR[c]}" for c in category_order])
    category_values = json.dumps([by_category_counts.get(c, 0) for c in category_order])

    # Top-PII-type chart, grouped by file: x-axis = PII type (not raw column
    # name, which varies across files/orgs -- "mobile" vs "mobile_number"
    # would otherwise fragment into separate near-duplicate bars for the
    # same underlying PII type). One dataset per file, color-coded.
    type_totals = {t: sum(counts.values()) for t, counts in type_by_file.items()}
    top_types = [t for t, _ in sorted(type_totals.items(), key=lambda kv: -kv[1])[:12]]
    top_type_labels_bilingual = [
        f"{t} / {PII_TYPE_AR.get(t, '')}" if PII_TYPE_AR.get(t) else t
        for t in top_types
    ]

    file_basenames = sorted({os.path.basename(f["file"]) for f in all_findings})
    column_chart_palette = ['#2f9e6e', '#4a90c9', '#d9a13a', '#9b6fd6', '#e0556f', '#5bc0c0']

    column_chart_labels = json.dumps(top_type_labels_bilingual)
    column_chart_datasets = json.dumps([
        {
            "label": file_base,
            "data": [type_by_file[t].get(file_base, 0) for t in top_types],
            "backgroundColor": column_chart_palette[i % len(column_chart_palette)],
            "borderRadius": 4,
            "maxBarThickness": 28,
        }
        for i, file_base in enumerate(file_basenames)
    ])

    scan_time = as_of_date if as_of_date else datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>PDPL Checker Report</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
    :root {{
        --bg: #0f1419;
        --panel: #161c24;
        --panel-border: #232b36;
        --text: #e6ebf2;
        --text-dim: #8a97a8;
        --accent: #2f9e6e;
        --high: #e0556f;
        --high-soft: rgba(224, 85, 111, 0.15);
        --medium: #d9a13a;
        --medium-soft: rgba(217, 161, 58, 0.15);
        --low: #4a90c9;
        --low-soft: rgba(74, 144, 201, 0.15);
    }}
    * {{ box-sizing: border-box; }}
    body {{
        margin: 0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        background: var(--bg);
        color: var(--text);
        padding: 32px 24px 64px;
    }}
    .container {{ max-width: 1150px; margin: 0 auto; }}
    header {{
        margin-bottom: 28px;
        border-bottom: 1px solid var(--panel-border);
        padding-bottom: 20px;
    }}
    header .label {{
        color: var(--accent);
        font-size: 13px;
        font-weight: 600;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        margin-bottom: 6px;
    }}
    header h1 {{ margin: 0 0 8px; font-size: 26px; font-weight: 650; }}
    header .meta {{
        color: var(--text-dim);
        font-size: 13px;
        display: flex;
        gap: 20px;
        flex-wrap: wrap;
    }}
    .stat-grid {{
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 14px;
        margin-bottom: 28px;
    }}
    .stat-card {{
        background: var(--panel);
        border: 1px solid var(--panel-border);
        border-radius: 10px;
        padding: 16px 18px;
    }}
    .stat-card .num {{ font-size: 28px; font-weight: 650; line-height: 1.1; }}
    .stat-card .lbl {{ color: var(--text-dim); font-size: 12.5px; margin-top: 4px; }}
    .stat-card.warn .num {{ color: var(--high); }}
    .charts-grid {{
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 16px;
        margin-bottom: 28px;
    }}
    .panel {{
        background: var(--panel);
        border: 1px solid var(--panel-border);
        border-radius: 10px;
        padding: 20px;
    }}
    .panel h2 {{ margin: 0 0 16px; font-size: 15px; font-weight: 600; color: var(--text); }}
    .panel.full {{ grid-column: 1 / -1; }}
    .chart-box {{ position: relative; height: 260px; width: 100%; }}
    .chart-box.tall {{ height: 320px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13.5px; }}
    th {{
        text-align: left;
        color: var(--text-dim);
        font-weight: 600;
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.03em;
        padding: 8px 10px;
        border-bottom: 1px solid var(--panel-border);
    }}
    td {{ padding: 9px 10px; border-bottom: 1px solid rgba(255,255,255,0.04); }}
    tr:last-child td {{ border-bottom: none; }}
    code {{
        background: rgba(255,255,255,0.06);
        padding: 2px 6px;
        border-radius: 4px;
        font-size: 12.5px;
    }}
    .badge {{
        display: inline-block;
        padding: 3px 9px;
        border-radius: 20px;
        font-size: 11.5px;
        font-weight: 600;
    }}
    .badge-high {{ background: var(--high-soft); color: var(--high); }}
    .badge-medium {{ background: var(--medium-soft); color: var(--medium); }}
    .badge-low {{ background: var(--low-soft); color: var(--low); }}
    .cat-badge {{
        display: inline-block;
        padding: 3px 9px;
        border-radius: 6px;
        font-size: 11px;
        font-weight: 600;
        white-space: nowrap;
    }}
    .cat-personal {{ background: rgba(74, 144, 201, 0.15); color: var(--low); }}
    .cat-credit {{ background: rgba(217, 161, 58, 0.15); color: var(--medium); }}
    .cat-sensitive {{ background: rgba(224, 85, 111, 0.18); color: var(--high); font-weight: 700; }}
    .gap-list {{ margin: 0; padding-left: 18px; color: var(--text-dim); font-size: 12.5px; }}
    .gap-list li {{ margin-bottom: 4px; }}
    .empty-state {{ text-align: center; color: var(--text-dim); padding: 24px; }}
    .table-scroll {{ max-height: 460px; overflow-y: auto; }}
    .note {{ color: var(--text-dim); font-size: 12.5px; margin: 10px 2px 0; }}
    footer {{ margin-top: 32px; color: var(--text-dim); font-size: 12px; text-align: center; }}
    .ar {{
        direction: rtl;
        unicode-bidi: embed;
        font-family: "Tahoma", "Segoe UI", "Noto Sans Arabic", sans-serif;
        color: var(--text-dim);
        font-weight: 400;
    }}
    header .label .ar {{ display: block; margin-top: 4px; font-size: 12px; letter-spacing: normal; text-transform: none; }}
    h1 .ar.h1-ar {{ font-size: 16px; font-weight: 500; color: var(--text-dim); }}
    .lbl .ar {{ font-size: 11.5px; }}
    th .ar {{ font-size: 10.5px; display: inline-block; }}
    h2 .ar {{ font-size: 12.5px; font-weight: 500; }}
    footer .ar {{ display: block; margin-top: 6px; font-size: 11.5px; }}
    .info-icon {{
        display: inline-block;
        color: var(--text-dim);
        font-size: 13px;
        cursor: help;
        position: relative;
        margin-left: 4px;
    }}
    .info-icon:hover {{ color: var(--accent); }}
    .info-icon::after {{
        content: attr(data-tip);
        direction: ltr;
        position: absolute;
        bottom: 130%;
        left: 0;
        z-index: 20;
        width: 260px;
        max-width: 60vw;
        background: #1f2630;
        border: 1px solid var(--panel-border);
        color: var(--text);
        font-size: 11.5px;
        font-weight: 400;
        line-height: 1.5;
        padding: 10px 12px;
        border-radius: 8px;
        box-shadow: 0 6px 18px rgba(0,0,0,0.4);
        opacity: 0;
        visibility: hidden;
        transition: opacity 0.15s ease;
        white-space: normal;
        pointer-events: none;
    }}
    .info-icon:hover::after {{ opacity: 1; visibility: visible; }}
    @media (max-width: 800px) {{
        .stat-grid {{ grid-template-columns: repeat(2, 1fr); }}
        .charts-grid {{ grid-template-columns: 1fr; }}
        .info-icon::after {{ width: 200px; left: auto; right: 0; }}
    }}
</style>
</head>
<body>
<div class="container">

    <header>
        <div class="label">PDPL Checker · SDAIA Data Discovery Demo<br><span class="ar">{AR['report_kicker']}</span></div>
        <h1>PII Scan Report <span class="ar h1-ar">/ {AR['report_title']}</span></h1>
        <div class="meta">
            <span>Scanned / {AR['scanned']}: <strong style="color:var(--text)">{esc(scanned_path)}</strong></span>
            <span>Files / {AR['files']}: <strong style="color:var(--text)">{total_files}</strong></span>
            <span>Rows / {AR['rows']}: <strong style="color:var(--text)">{total_rows}</strong></span>
            <span>Generated / {AR['generated']}: {scan_time}</span>
        </div>
    </header>

    <div class="stat-grid">
        <div class="stat-card">
            <div class="num">{total_files}</div>
            <div class="lbl">Files Scanned <span class="ar">/ {AR['files_scanned']}</span></div>
        </div>
        <div class="stat-card">
            <div class="num">{total_rows}</div>
            <div class="lbl">Total Rows <span class="ar">/ {AR['total_rows']}</span></div>
        </div>
        <div class="stat-card {'warn' if total_findings else ''}">
            <div class="num">{total_findings}</div>
            <div class="lbl">Total PII Hits <span class="ar">/ {AR['total_pii_hits']}</span></div>
        </div>
        <div class="stat-card {'warn' if sensitive_total else ''}">
            <div class="num">{sensitive_total}</div>
            <div class="lbl">Sensitive Data Hits (PDPL Art. 1(11)) <span class="ar">/ {AR['sensitive_hits']}</span></div>
        </div>
    </div>

    <div class="charts-grid">
        <div class="panel">
            <h2>PII Hits by Type <span class="ar">/ {AR['pii_by_type']}</span> <span class="info-icon" data-tip="{esc(CHART_HELP_EN['typeChart'])} {esc(CHART_HELP_AR['typeChart'])}">ⓘ</span></h2>
            <div class="chart-box"><canvas id="typeChart"></canvas></div>
        </div>
        <div class="panel">
            <h2>PDPL Category Breakdown <span class="ar">/ {AR['pdpl_category']}</span> <span class="info-icon" data-tip="{esc(CHART_HELP_EN['categoryChart'])} {esc(CHART_HELP_AR['categoryChart'])}">ⓘ</span></h2>
            <div class="chart-box"><canvas id="categoryChart"></canvas></div>
        </div>
        <div class="panel">
            <h2>Confidence Breakdown <span class="ar">/ {AR['confidence_breakdown']}</span> <span class="info-icon" data-tip="{esc(CHART_HELP_EN['confidenceChart'])} {esc(CHART_HELP_AR['confidenceChart'])}">ⓘ</span></h2>
            <div class="chart-box"><canvas id="confidenceChart"></canvas></div>
        </div>
        <div class="panel">
            <h2>Top PII Types by Hit Count <span class="ar">/ {AR['top_pii_types']}</span> <span class="info-icon" data-tip="{esc(CHART_HELP_EN['columnChart'])} {esc(CHART_HELP_AR['columnChart'])}">ⓘ</span></h2>
            <div class="chart-box tall"><canvas id="columnChart"></canvas></div>
        </div>
    </div>

    <div class="panel full" style="margin-bottom:16px;">
        <h2>Files Scanned — PDPL Risk Score <span class="ar">/ {AR['files_risk_score']}</span></h2>
        <div class="table-scroll">
        <table>
            <thead>
                <tr>
                    <th>File <span class="ar">/ {AR['file_col']}</span></th>
                    <th>Sheets <span class="ar">/ {AR['sheets_col']}</span></th>
                    <th>Rows <span class="ar">/ {AR['rows_col']}</span></th>
                    <th>Findings <span class="ar">/ {AR['findings_col']}</span></th>
                    <th>Sensitive Hits <span class="ar">/ {AR['sensitive_hits_col']}</span></th>
                    <th>Risk Score <span class="ar">/ {AR['risk_score_col']}</span></th>
                    <th>Risk Band <span class="ar">/ {AR['risk_band_col']}</span></th>
                </tr>
            </thead>
            <tbody>{file_rows_html}</tbody>
        </table>
        </div>
    </div>

    <div class="panel full" style="margin-bottom:16px;">
        <h2>Compliance Gap Checks <span class="ar">/ {AR['compliance_checks']}</span></h2>
        <div class="table-scroll">
        <table>
            <thead>
                <tr>
                    <th style="width:220px">File / Sheet</th>
                    <th>Gaps Found <span class="ar">/ {AR['gaps_found_col']}</span></th>
                </tr>
            </thead>
            <tbody>{compliance_rows_html}</tbody>
        </table>
        </div>
    </div>

    <div class="panel full">
        <h2>Detailed Findings (masked) <span class="ar">/ {AR['detailed_findings']}</span></h2>
        <div class="table-scroll">
        <table>
            <thead>
                <tr>
                    <th>File <span class="ar">/ {AR['file_col']}</span></th>
                    <th>Row # <span class="ar">/ {AR['row_col']}</span></th>
                    <th>Column <span class="ar">/ {AR['column_col']}</span></th>
                    <th>PII Type <span class="ar">/ {AR['pii_type_col']}</span></th>
                    <th>PDPL Category <span class="ar">/ {AR['pdpl_category']}</span></th>
                    <th>Confidence <span class="ar">/ {AR['confidence_col']}</span></th>
                    <th>Value (masked) <span class="ar">/ {AR['value_col']}</span></th>
                </tr>
            </thead>
            <tbody>{detail_rows_html}</tbody>
        </table>
        </div>
        {truncation_note}
    </div>

    <footer>
        Generated by PDPL Checker — a Saudi PII discovery demo aligned with SDAIA's Personal Data Protection Law.
        All values shown are masked; this report does not store full PII.
        <br><span class="ar">{AR['footer']}</span>
    </footer>

</div>

<script>
const chartTextColor = '#8a97a8';
const gridColor = 'rgba(255,255,255,0.06)';
Chart.defaults.color = chartTextColor;
Chart.defaults.borderColor = gridColor;
Chart.defaults.font.family = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";

new Chart(document.getElementById('typeChart'), {{
    type: 'doughnut',
    data: {{
        labels: {type_labels},
        datasets: [{{
            data: {type_values},
            backgroundColor: ['#2f9e6e', '#4a90c9', '#d9a13a', '#9b6fd6', '#e0556f', '#5bc0c0'],
            borderColor: '#161c24',
            borderWidth: 2,
        }}]
    }},
    options: {{
        responsive: true,
        maintainAspectRatio: false,
        plugins: {{
            legend: {{ position: 'bottom' }},
            tooltip: {{
                callbacks: {{
                    label: function(ctx) {{
                        const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
                        const pct = total ? Math.round((ctx.parsed / total) * 100) : 0;
                        return ' ' + ctx.label + ': ' + ctx.parsed + ' hits (' + pct + '%)';
                    }}
                }}
            }}
        }},
        cutout: '65%'
    }}
}});

new Chart(document.getElementById('confidenceChart'), {{
    type: 'doughnut',
    data: {{
        labels: {confidence_labels},
        datasets: [{{
            data: {confidence_values},
            backgroundColor: ['#e0556f', '#d9a13a', '#4a90c9'],
            borderColor: '#161c24',
            borderWidth: 2,
        }}]
    }},
    options: {{
        responsive: true,
        maintainAspectRatio: false,
        plugins: {{
            legend: {{ position: 'bottom' }},
            tooltip: {{
                callbacks: {{
                    label: function(ctx) {{ return ' ' + ctx.label + ': ' + ctx.parsed + ' findings'; }}
                }}
            }}
        }},
        cutout: '65%'
    }}
}});

new Chart(document.getElementById('categoryChart'), {{
    type: 'doughnut',
    data: {{
        labels: {category_labels},
        datasets: [{{
            data: {category_values},
            backgroundColor: ['#4a90c9', '#d9a13a', '#e0556f'],
            borderColor: '#161c24',
            borderWidth: 2,
        }}]
    }},
    options: {{
        responsive: true,
        maintainAspectRatio: false,
        plugins: {{
            legend: {{ position: 'bottom' }},
            tooltip: {{
                callbacks: {{
                    label: function(ctx) {{ return ' ' + ctx.label + ': ' + ctx.parsed + ' findings'; }}
                }}
            }}
        }},
        cutout: '65%'
    }}
}});

new Chart(document.getElementById('columnChart'), {{
    type: 'bar',
    data: {{
        labels: {column_chart_labels},
        datasets: {column_chart_datasets}
    }},
    options: {{
        responsive: true,
        maintainAspectRatio: false,
        plugins: {{
            legend: {{ display: true, position: 'bottom' }},
            tooltip: {{
                callbacks: {{
                    title: function(items) {{ return items[0].label; }},
                    label: function(ctx) {{
                        return ' ' + ctx.dataset.label + ': ' + ctx.parsed.y + ' hit(s)';
                    }}
                }}
            }}
        }},
        scales: {{
            y: {{ beginAtZero: true, ticks: {{ precision: 0 }}, grid: {{ color: gridColor }} }},
            x: {{ grid: {{ display: false }}, ticks: {{ autoSkip: false, maxRotation: 45, minRotation: 0 }} }}
        }}
    }}
}});
</script>

</body>
</html>
"""

    with open(outpath, "w", encoding="utf-8") as f:
        f.write(html_content)
