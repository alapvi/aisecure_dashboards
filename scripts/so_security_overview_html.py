#!/usr/bin/env python3
import sys
import os
import html
import base64
import mimetypes
from pathlib import Path
from datetime import datetime

import requests
import urllib3


# ============================================================
# CONFIGURATION
# ============================================================

ES_URL = os.getenv("SO_ES_URL", "https://localhost:9200")
ES_INDEX = os.getenv("SO_ES_INDEX", "logs-*")

ES_USER = os.getenv("SO_ES_USER", "")
ES_PASS = os.getenv("SO_ES_PASS", "")

VERIFY_TLS = os.getenv("SO_VERIFY_TLS", "false").lower() in ("1", "true", "yes", "on")

TIME_FROM = os.getenv("SO_TIME_FROM", "now-24h")
TIME_TO = os.getenv("SO_TIME_TO", "now")
TIME_ZONE = os.getenv("SO_TIME_ZONE", "Europe/Madrid")

OUTPUT_HTML = os.getenv("SO_OUTPUT_HTML", "security_overview.html")
HTML_REFRESH_SECONDS = int(os.getenv("SO_HTML_REFRESH_SECONDS", "600"))

LOGO_FILE = os.getenv("SO_LOGO_FILE", "logo_institut.png")

DASHBOARD_TITLE = os.getenv("SO_DASHBOARD_TITLE", "AI Secure Campus - Security overview")
DASHBOARD_SUBTITLE = os.getenv("SO_DASHBOARD_SUBTITLE", "Security detections, protocol activity, DNS queries and external organization visibility")

TIME_FIELD = "@timestamp"
TOP_TERMS_SIZE = int(os.getenv("SO_TOP_TERMS_SIZE", "20"))


# ============================================================
# FIELD CANDIDATES
# ============================================================

RULE_NAME_FIELDS = [
    "rule.name",
    "alert.signature",
    "suricata.eve.alert.signature",
    "event.reason",
]

DNS_QUERY_FIELDS = [
    "dns.query.name",
    "dns.question.name",
    "dns.question.registered_domain",
    "dns.question.top_level_domain",
]

PROTOCOL_FIELDS = [
    "network.protocol",
    "network.transport",
    "zeek.proto",
]

ORGANIZATION_FIELDS = [
    "destination.as.organization.name",
    "server.as.organization.name",
    "source.as.organization.name",
    "client.as.organization.name",
    "as.organization.name",
]


# ============================================================
# INTERNAL SETTINGS
# ============================================================

if not VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ============================================================
# FORMAT FUNCTIONS
# ============================================================

def fmt_int(value):
    try:
        return f"{int(value):,}"
    except Exception:
        return "0"


def short_label(value, max_len=48):
    value = str(value)
    if len(value) <= max_len:
        return value
    return value[:max_len - 1] + "…"


# ============================================================
# LOGO
# ============================================================

def logo_data_uri():
    logo_path = Path(LOGO_FILE)

    if not logo_path.exists():
        return ""

    mime_type, _ = mimetypes.guess_type(str(logo_path))
    if not mime_type:
        mime_type = "image/png"

    with open(logo_path, "rb") as f:
        encoded = base64.b64encode(f.read()).decode("ascii")

    return f"data:{mime_type};base64,{encoded}"


# ============================================================
# ELASTICSEARCH FUNCTIONS
# ============================================================

def check_config():
    if not ES_USER:
        print("ERROR: SO_ES_USER is not configured.")
        sys.exit(1)

    if not ES_PASS:
        print("ERROR: SO_ES_PASS is not configured.")
        sys.exit(1)


def es_post(path, payload):
    url = f"{ES_URL.rstrip('/')}/{path.lstrip('/')}"

    try:
        response = requests.post(
            url,
            auth=(ES_USER, ES_PASS),
            headers={"Content-Type": "application/json"},
            json=payload,
            verify=VERIFY_TLS,
            timeout=60,
        )
    except requests.exceptions.RequestException as e:
        print("ERROR connecting to Elasticsearch:")
        print(e)
        sys.exit(1)

    if response.status_code >= 400:
        raise RuntimeError(f"Elasticsearch error {response.status_code}: {response.text}")

    return response.json()


def range_filter():
    return {
        "range": {
            TIME_FIELD: {
                "gte": TIME_FROM,
                "lte": TIME_TO
            }
        }
    }


def count_docs_with_field(field):
    payload = {
        "query": {
            "bool": {
                "filter": [
                    range_filter(),
                    {
                        "exists": {
                            "field": field
                        }
                    }
                ]
            }
        }
    }

    try:
        data = es_post(f"{ES_INDEX}/_count", payload)
        return int(data.get("count", 0))
    except Exception:
        return 0


def query_terms(field, size=TOP_TERMS_SIZE):
    return {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    range_filter(),
                    {
                        "exists": {
                            "field": field
                        }
                    }
                ]
            }
        },
        "aggs": {
            "top": {
                "terms": {
                    "field": field,
                    "size": size,
                    "order": {
                        "_count": "desc"
                    }
                }
            }
        }
    }


def choose_terms_field(candidates, label):
    print(f"Detecting {label} field...")

    expanded_candidates = []
    for field in candidates:
        expanded_candidates.append(field)
        expanded_candidates.append(f"{field}.keyword")

    seen = set()
    expanded_candidates = [x for x in expanded_candidates if not (x in seen or seen.add(x))]

    for field in expanded_candidates:
        count = count_docs_with_field(field)
        print(f"  {field}: {count} documents")

        if count <= 0:
            continue

        try:
            data = es_post(f"{ES_INDEX}/_search", query_terms(field, 1))
            buckets = data.get("aggregations", {}).get("top", {}).get("buckets", [])
            if buckets:
                print(f"  Selected: {field}")
                print("")
                return field
        except Exception as e:
            print(f"  Not aggregatable or failed: {field}")
            print(f"  {e}")

    print(f"  No usable {label} field found. Falling back to {candidates[0]}")
    print("")
    return candidates[0]


# ============================================================
# HTML COMPONENTS
# ============================================================

def make_word_cloud(items):
    if not items:
        return "<p class='nodata'>No protocol data available.</p>"

    width = 680
    height = 300

    max_count = max([item["doc_count"] for item in items]) if items else 1
    min_count = min([item["doc_count"] for item in items]) if items else 0

    if max_count <= 0:
        max_count = 1

    positions = [
        (340, 145), (245, 150), (430, 150), (315, 95), (375, 95),
        (250, 95), (445, 95), (200, 180), (500, 180), (300, 205),
        (390, 205), (185, 120), (520, 120), (255, 225), (455, 225),
        (145, 160), (555, 160), (330, 245), (380, 60), (290, 60),
    ]

    colors = [
        "#17a9d6", "#26c6b8", "#8da2ff", "#ff9cc3", "#f2a516",
        "#2d77c7", "#33b7c2", "#ff8c7a", "#73c9a9", "#9f8cff",
    ]

    texts = []

    for idx, item in enumerate(items[:20]):
        label = str(item["key"])
        count = int(item["doc_count"])

        if max_count == min_count:
            weight = 1.0
        else:
            weight = (count - min_count) / max(1, max_count - min_count)

        font_size = 15 + weight * 42
        x, y = positions[idx % len(positions)]
        color = colors[idx % len(colors)]
        delay = idx * 0.055

        texts.append(f"""
        <text
          class="cloud-word"
          style="animation-delay:{delay:.2f}s"
          x="{x}"
          y="{y}"
          text-anchor="middle"
          dominant-baseline="middle"
          font-size="{font_size:.1f}"
          font-weight="{700 if idx < 3 else 500}"
          fill="{color}">
          {html.escape(label)}
          <title>{html.escape(label)} · {fmt_int(count)} records</title>
        </text>
        """)

    return f"""
    <svg viewBox="0 0 {width} {height}" class="word-cloud" preserveAspectRatio="xMidYMid meet" role="img" aria-label="Protocol word cloud">
      <rect x="0" y="0" width="{width}" height="{height}" rx="16" class="cloud-bg"></rect>
      {''.join(texts)}
    </svg>
    """


def make_org_bar_chart(items):
    if not items:
        return "<p class='nodata'>No organization data available.</p>"

    width = 720
    height = 310
    padding_left = 58
    padding_right = 190
    padding_top = 24
    padding_bottom = 40

    chart_w = width - padding_left - padding_right
    chart_h = height - padding_top - padding_bottom

    max_count = max([item["doc_count"] for item in items]) if items else 1
    if max_count <= 0:
        max_count = 1

    bars = []
    labels = []
    legend = []

    visible_items = items[:10]
    bar_gap = 6
    bar_w = max(18, (chart_w / max(1, len(visible_items))) - bar_gap)

    palette = [
        "#16bfc5", "#9de8e5", "#6ca8ff", "#ff8cab", "#f2b44b",
        "#65c3a5", "#9c8cff", "#ff9f6e", "#59b8e8", "#d278ff",
    ]

    for i, item in enumerate(visible_items):
        count = int(item["doc_count"])
        label = str(item["key"])

        x = padding_left + i * (bar_w + bar_gap)
        bar_h = (count / max_count) * chart_h
        y = padding_top + chart_h - bar_h
        color = palette[i % len(palette)]
        delay = i * 0.075

        bars.append(f"""
        <rect
          class="org-bar"
          style="animation-delay:{delay:.2f}s"
          x="{x:.2f}"
          y="{y:.2f}"
          width="{bar_w:.2f}"
          height="{bar_h:.2f}"
          rx="4"
          fill="{color}">
          <title>{html.escape(label)} · {fmt_int(count)} records</title>
        </rect>
        """)

        labels.append(f"""
        <text x="{x + bar_w / 2:.2f}" y="{height - 18}" text-anchor="middle" class="chart-x-label">{i + 1}</text>
        """)

        legend_y = padding_top + i * 24
        legend.append(f"""
        <g>
          <circle cx="{width - padding_right + 24}" cy="{legend_y + 5}" r="5" fill="{color}"></circle>
          <text x="{width - padding_right + 38}" y="{legend_y + 9}" class="legend-text">{html.escape(short_label(label, 28))}</text>
        </g>
        """)

    grid = []
    for frac in [0, 0.25, 0.5, 0.75, 1]:
        value = max_count * frac
        y = padding_top + chart_h - frac * chart_h
        grid.append(f"""
        <line x1="{padding_left}" y1="{y:.2f}" x2="{padding_left + chart_w}" y2="{y:.2f}" class="chart-grid"></line>
        <text x="8" y="{y + 4:.2f}" class="chart-axis">{fmt_int(value)}</text>
        """)

    return f"""
    <svg viewBox="0 0 {width} {height}" class="bar-chart" preserveAspectRatio="xMidYMid meet" role="img" aria-label="Organization bar chart">
      {''.join(grid)}
      <line x1="{padding_left}" y1="{padding_top + chart_h}" x2="{padding_left + chart_w}" y2="{padding_top + chart_h}" class="chart-axis-line"></line>
      {''.join(bars)}
      {''.join(labels)}
      {''.join(legend)}
      <text x="{padding_left}" y="{height - 2}" class="chart-axis">Top organizations by event count</text>
    </svg>
    """


def make_bar_table(items, value_title="Count"):
    if not items:
        return "<p class='nodata'>No data available.</p>"

    max_count = max([item["doc_count"] for item in items]) if items else 1
    if max_count <= 0:
        max_count = 1

    rows = []

    for item in items:
        label = html.escape(str(item["key"]))
        count = int(item["doc_count"])
        pct = (count / max_count) * 100

        rows.append(f"""
        <tr>
          <td class="name-cell">
            <div class="heat" style="width:{pct:.2f}%"></div>
            <span>{label}</span>
          </td>
          <td class="count-cell">{fmt_int(count)}</td>
        </tr>
        """)

    return f"""
    <table class="data-table">
      <thead>
        <tr>
          <th>Value</th>
          <th>{html.escape(value_title)}</th>
        </tr>
      </thead>
      <tbody>
        {''.join(rows)}
      </tbody>
    </table>
    """


def generate_html(
    top_rules,
    top_dns,
    top_protocols,
    top_orgs,
    rule_field,
    dns_field,
    protocol_field,
    organization_field
):
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logo_uri = logo_data_uri()

    if logo_uri:
        logo_html = f'<img class="brand-logo" src="{logo_uri}" alt="Institute logo">'
    else:
        logo_html = """
        <div class="brand-logo-fallback">
          <div class="fallback-main">IES</div>
          <div class="fallback-sub">Dr. Simarro</div>
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{html.escape(DASHBOARD_TITLE)}</title>
  <meta http-equiv="refresh" content="{HTML_REFRESH_SECONDS}">
  <style>
    * {{
      box-sizing: border-box;
    }}

    :root {{
      --bg: #eef7fd;
      --bg-grid: rgba(27, 150, 210, 0.12);
      --bg-dot: rgba(243, 171, 98, 0.35);
      --card: rgba(255, 255, 255, 0.94);
      --border: rgba(78, 188, 232, 0.32);
      --border-strong: rgba(78, 188, 232, 0.58);
      --blue-dark: #164d82;
      --blue: #167db4;
      --cyan: #17a9d6;
      --cyan-soft: #dff7ff;
      --text: #102033;
      --muted: #60748a;
      --danger-soft: rgba(255, 116, 116, 0.20);
      --shadow: 0 14px 35px rgba(14, 64, 98, 0.10);
    }}

    html {{
      width: 100%;
      min-height: 100%;
    }}

    body {{
      margin: 0;
      min-height: 100vh;
      padding: clamp(12px, 2vw, 32px);
      font-family: Arial, Helvetica, sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle, var(--bg-dot) 1px, transparent 1.3px),
        linear-gradient(var(--bg-grid) 1px, transparent 1px),
        linear-gradient(90deg, var(--bg-grid) 1px, transparent 1px),
        linear-gradient(180deg, #f7fbff 0%, var(--bg) 100%);
      background-size: 28px 28px, 54px 54px, 54px 54px, auto;
      overflow-x: hidden;
      animation: pageFadeIn 0.65s ease-out both;
    }}

    .page {{
      width: 100%;
      max-width: 1800px;
      margin: 0 auto;
    }}

    .header {{
      display: grid;
      grid-template-columns: minmax(120px, 240px) 1fr minmax(120px, 240px);
      gap: clamp(12px, 2vw, 24px);
      align-items: center;
      margin-bottom: clamp(16px, 2vw, 28px);
    }}

    .brand-side {{
      display: flex;
      align-items: center;
      justify-content: flex-start;
      min-width: 0;
    }}

    .brand-logo {{
      width: min(220px, 100%);
      max-height: 95px;
      object-fit: contain;
      filter: drop-shadow(0 8px 18px rgba(10, 60, 90, 0.10));
    }}

    .brand-logo-fallback {{
      width: min(210px, 100%);
      border-radius: 16px;
      background: rgba(255,255,255,0.82);
      border: 1px solid var(--border);
      padding: 16px 18px;
      box-shadow: var(--shadow);
    }}

    .fallback-main {{
      font-weight: 800;
      font-size: 28px;
      letter-spacing: 0.12em;
      color: var(--blue-dark);
    }}

    .fallback-sub {{
      margin-top: 4px;
      color: var(--muted);
      font-size: 13px;
    }}

    .title-block {{
      text-align: center;
      min-width: 0;
    }}

    h1 {{
      margin: 0;
      font-size: clamp(26px, 3vw, 42px);
      line-height: 1.1;
      letter-spacing: -0.03em;
      color: var(--blue-dark);
    }}

    .title-accent {{
      color: var(--cyan);
    }}

    .subtitle {{
      max-width: 920px;
      margin: 12px auto 0 auto;
      color: var(--muted);
      font-size: clamp(13px, 1.1vw, 16px);
      line-height: 1.45;
    }}

    .status-pill {{
      justify-self: end;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 9px 14px;
      border-radius: 999px;
      background: rgba(255,255,255,0.80);
      border: 1px solid var(--border);
      color: var(--blue-dark);
      font-size: 13px;
      font-weight: 700;
      box-shadow: var(--shadow);
      white-space: nowrap;
    }}

    .status-dot {{
      width: 9px;
      height: 9px;
      border-radius: 50%;
      background: var(--cyan);
      box-shadow: 0 0 0 5px rgba(23,169,214,0.16);
    }}

    .dashboard-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(min(100%, 620px), 1fr));
      gap: clamp(12px, 1.4vw, 18px);
      align-items: stretch;
    }}

    .panel {{
      background: var(--card);
      backdrop-filter: blur(6px);
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: clamp(12px, 1.4vw, 20px);
      box-shadow: var(--shadow);
      min-height: clamp(320px, 40vh, 460px);
      display: flex;
      flex-direction: column;
      min-width: 0;
      overflow: hidden;
      animation: panelRise 0.75s ease-out both;
    }}

    .panel:nth-child(1) {{ animation-delay: 0.05s; }}
    .panel:nth-child(2) {{ animation-delay: 0.12s; }}
    .panel:nth-child(3) {{ animation-delay: 0.19s; }}
    .panel:nth-child(4) {{ animation-delay: 0.26s; }}

    .panel-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      margin-bottom: 12px;
    }}

    h2 {{
      margin: 0;
      color: var(--blue-dark);
      font-size: clamp(17px, 1.4vw, 22px);
      letter-spacing: -0.02em;
    }}

    .panel-tag {{
      padding: 5px 10px;
      border-radius: 999px;
      background: var(--cyan-soft);
      border: 1px solid var(--border-strong);
      color: var(--blue-dark);
      font-size: 11px;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      white-space: nowrap;
    }}

    .word-cloud {{
      width: 100%;
      height: clamp(250px, 34vh, 370px);
      display: block;
      flex: 1;
    }}

    .cloud-bg {{
      fill: rgba(255, 255, 255, 0.10);
      stroke: rgba(78, 188, 232, 0.18);
    }}

    .cloud-word {{
      opacity: 0;
      transform-box: fill-box;
      transform-origin: center;
      animation: wordPop 0.55s ease-out forwards;
    }}

    .bar-chart {{
      width: 100%;
      height: clamp(250px, 34vh, 370px);
      display: block;
      flex: 1;
    }}

    .org-bar {{
      transform-box: fill-box;
      transform-origin: bottom;
      animation: growSvgBar 0.9s ease-out both;
    }}

    .chart-grid {{
      stroke: rgba(108, 137, 160, 0.18);
      stroke-width: 1;
    }}

    .chart-axis {{
      fill: #617084;
      font-size: 11px;
    }}

    .chart-axis-line {{
      stroke: rgba(108, 137, 160, 0.28);
      stroke-width: 1;
    }}

    .chart-x-label {{
      fill: #617084;
      font-size: 11px;
    }}

    .legend-text {{
      fill: #24394f;
      font-size: 12px;
    }}

    .data-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: clamp(12px, 0.95vw, 14px);
      overflow: hidden;
      border-radius: 12px;
      table-layout: fixed;
    }}

    .data-table thead th {{
      text-align: left;
      padding: 10px 12px;
      color: var(--blue-dark);
      background: #eaf3fb;
      border-bottom: 1px solid rgba(78, 188, 232, 0.22);
      font-size: clamp(12px, 0.95vw, 13px);
    }}

    .data-table thead th:last-child {{
      text-align: right;
      width: clamp(90px, 10vw, 140px);
    }}

    .data-table tbody td {{
      padding: 9px 12px;
      border-bottom: 1px solid rgba(78, 188, 232, 0.14);
    }}

    .name-cell {{
      position: relative;
      overflow: hidden;
      min-width: 0;
    }}

    .name-cell span {{
      position: relative;
      z-index: 2;
      display: block;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      color: #172c42;
    }}

    .heat {{
      position: absolute;
      z-index: 1;
      left: 0;
      top: 0;
      bottom: 0;
      background: var(--danger-soft);
      border-radius: 0 999px 999px 0;
      transform-origin: left center;
      animation: growBar 0.9s ease-out both;
    }}

    .count-cell {{
      text-align: right;
      font-family: monospace;
      color: #24394f;
    }}

    .nodata {{
      color: #718096;
      font-style: italic;
    }}

    .footer {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      color: var(--muted);
      font-size: 12px;
      margin-top: 12px;
      padding: 12px 2px 0 2px;
    }}

    .footer span {{
      padding: 5px 9px;
      border-radius: 999px;
      background: rgba(255,255,255,0.65);
      border: 1px solid rgba(78, 188, 232, 0.18);
    }}

    @keyframes pageFadeIn {{
      from {{ opacity: 0; }}
      to {{ opacity: 1; }}
    }}

    @keyframes panelRise {{
      from {{ opacity: 0; transform: translateY(14px); }}
      to {{ opacity: 1; transform: translateY(0); }}
    }}

    @keyframes growBar {{
      from {{ transform: scaleX(0); }}
      to {{ transform: scaleX(1); }}
    }}

    @keyframes growSvgBar {{
      from {{ transform: scaleY(0); }}
      to {{ transform: scaleY(1); }}
    }}

    @keyframes wordPop {{
      from {{ opacity: 0; transform: scale(0.72); }}
      to {{ opacity: 1; transform: scale(1); }}
    }}

    @media (prefers-reduced-motion: reduce) {{
      *, *::before, *::after {{
        animation-duration: 0.001ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: 0.001ms !important;
        scroll-behavior: auto !important;
      }}
    }}

    @media (max-width: 1200px) {{
      .header {{
        grid-template-columns: 1fr;
        text-align: center;
      }}

      .brand-side {{
        justify-content: center;
      }}

      .status-pill {{
        justify-self: center;
      }}
    }}

    @media (max-width: 800px) {{
      body {{
        padding: 14px;
      }}

      .panel-header {{
        align-items: flex-start;
        flex-direction: column;
      }}

      .panel-tag {{
        align-self: flex-start;
      }}

      .footer {{
        font-size: 11px;
      }}
    }}

    @media (max-width: 520px) {{
      h1 {{
        font-size: 26px;
      }}

      .subtitle {{
        font-size: 13px;
      }}

      .brand-logo {{
        max-height: 70px;
      }}

      .status-pill {{
        font-size: 12px;
      }}

      .panel {{
        border-radius: 14px;
      }}
    }}
  </style>
</head>
<body>
  <div class="page">

    <header class="header">
      <div class="brand-side">
        {logo_html}
      </div>

      <div class="title-block">
        <h1>{html.escape(DASHBOARD_TITLE)}</h1>
        <div class="subtitle">
          {html.escape(DASHBOARD_SUBTITLE)}
        </div>
      </div>

      <div class="status-pill">
        <span class="status-dot"></span>
        Last 24 hours · refresh {HTML_REFRESH_SECONDS}s
      </div>
    </header>

    <main class="dashboard-grid">

      <section class="panel">
        <div class="panel-header">
          <h2>Protocols</h2>
          <span class="panel-tag">network.protocol</span>
        </div>
        {make_word_cloud(top_protocols)}
      </section>

      <section class="panel">
        <div class="panel-header">
          <h2>Organization name</h2>
          <span class="panel-tag">ASN organization</span>
        </div>
        {make_org_bar_chart(top_orgs)}
      </section>

      <section class="panel">
        <div class="panel-header">
          <h2>Top detections</h2>
          <span class="panel-tag">Rule name</span>
        </div>
        {make_bar_table(top_rules, "Count")}
      </section>

      <section class="panel">
        <div class="panel-header">
          <h2>Top DNS queries</h2>
          <span class="panel-tag">DNS</span>
        </div>
        {make_bar_table(top_dns, "Count")}
      </section>

    </main>

    <footer class="footer">
      <span>Generated: {html.escape(generated_at)}</span>
      <span>Elasticsearch: {html.escape(ES_URL)}</span>
      <span>Index: {html.escape(ES_INDEX)}</span>
      <span>Rule field: {html.escape(rule_field)}</span>
      <span>DNS field: {html.escape(dns_field)}</span>
      <span>Protocol field: {html.escape(protocol_field)}</span>
      <span>Organization field: {html.escape(organization_field)}</span>
    </footer>

  </div>
</body>
</html>
"""


# ============================================================
# MAIN
# ============================================================

def main():
    check_config()

    print("Querying Elasticsearch...")
    print(f"URL: {ES_URL}")
    print(f"Index: {ES_INDEX}")
    print(f"Time range: {TIME_FROM} → {TIME_TO}")
    print("")

    rule_field = choose_terms_field(RULE_NAME_FIELDS, "rule name")
    dns_field = choose_terms_field(DNS_QUERY_FIELDS, "DNS query")
    protocol_field = choose_terms_field(PROTOCOL_FIELDS, "network protocol")
    organization_field = choose_terms_field(ORGANIZATION_FIELDS, "organization name")

    top_rules_data = es_post(f"{ES_INDEX}/_search", query_terms(rule_field, TOP_TERMS_SIZE))
    top_dns_data = es_post(f"{ES_INDEX}/_search", query_terms(dns_field, TOP_TERMS_SIZE))
    top_protocols_data = es_post(f"{ES_INDEX}/_search", query_terms(protocol_field, TOP_TERMS_SIZE))
    top_orgs_data = es_post(f"{ES_INDEX}/_search", query_terms(organization_field, TOP_TERMS_SIZE))

    top_rules = top_rules_data.get("aggregations", {}).get("top", {}).get("buckets", [])
    top_dns = top_dns_data.get("aggregations", {}).get("top", {}).get("buckets", [])
    top_protocols = top_protocols_data.get("aggregations", {}).get("top", {}).get("buckets", [])
    top_orgs = top_orgs_data.get("aggregations", {}).get("top", {}).get("buckets", [])

    html_doc = generate_html(
        top_rules=top_rules,
        top_dns=top_dns,
        top_protocols=top_protocols,
        top_orgs=top_orgs,
        rule_field=rule_field,
        dns_field=dns_field,
        protocol_field=protocol_field,
        organization_field=organization_field
    )

    with open(OUTPUT_HTML, "w", encoding="utf-8") as f:
        f.write(html_doc)

    print("")
    print("Results:")
    print(f"  Top detections:    {len(top_rules)} rows")
    print(f"  Top DNS queries:   {len(top_dns)} rows")
    print(f"  Top protocols:     {len(top_protocols)} rows")
    print(f"  Top organizations: {len(top_orgs)} rows")
    print("")
    print(f"HTML generated successfully: {OUTPUT_HTML}")


if __name__ == "__main__":
    main()
