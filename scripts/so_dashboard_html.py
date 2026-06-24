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

OUTPUT_HTML = os.getenv("SO_OUTPUT_HTML", "dashboard_so.html")
HTML_REFRESH_SECONDS = int(os.getenv("SO_HTML_REFRESH_SECONDS", "600"))

LOGO_FILE = os.getenv("SO_LOGO_FILE", "logo_institut.png")

DASHBOARD_TITLE = os.getenv("SO_DASHBOARD_TITLE", "AI Secure Campus - Network traffic")
DASHBOARD_SUBTITLE = os.getenv("SO_DASHBOARD_SUBTITLE", "Real-time network visibility for the AI Secure Campus ecosystem")

TIME_FIELD = "@timestamp"
CONNECTION_FIELD = "network.community_id"

BYTE_FIELD_PAIRS = [
    ("client.bytes", "server.bytes"),
    ("source.bytes", "destination.bytes"),
    ("network.bytes", None),
]

SOURCE_IP_FIELDS = [
    "client.ip",
    "source.ip",
]

DESTINATION_IP_FIELDS = [
    "server.ip",
    "destination.ip",
]

TREND_INTERVAL = "1m"
CARDINALITY_PRECISION = 40000
TOP_TERMS_SIZE = int(os.getenv("SO_TOP_TERMS_SIZE", "10"))


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


def fmt_gb(value):
    try:
        gb = float(value) / (1000 ** 3)
        return f"{gb:,.2f} GB"
    except Exception:
        return "0.00 GB"


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
        print("ERROR Elasticsearch:", response.status_code)
        print(response.text)
        sys.exit(1)

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

    data = es_post(f"{ES_INDEX}/_count", payload)
    return int(data.get("count", 0))


def choose_first_available_field(candidates, label):
    print(f"Detecting {label} field...")

    for field in candidates:
        count = count_docs_with_field(field)
        print(f"  {field}: {count} documents")

        if count > 0:
            print(f"  Selected: {field}")
            print("")
            return field

    print(f"  No candidate field found. Falling back to: {candidates[0]}")
    print("")
    return candidates[0]


def choose_bytes_fields():
    print("Detecting traffic byte fields...")

    for field_a, field_b in BYTE_FIELD_PAIRS:
        count_a = count_docs_with_field(field_a)
        print(f"  {field_a}: {count_a} documents")

        count_b = 0
        if field_b:
            count_b = count_docs_with_field(field_b)
            print(f"  {field_b}: {count_b} documents")

        if count_a > 0 or count_b > 0:
            print(f"  Selected: {field_a}" + (f", {field_b}" if field_b else ""))
            print("")
            return field_a, field_b

    fallback_a, fallback_b = BYTE_FIELD_PAIRS[0]
    print(f"  No byte fields found. Falling back to: {fallback_a}, {fallback_b}")
    print("")
    return fallback_a, fallback_b


# ============================================================
# QUERY BUILDERS
# ============================================================

def query_connections():
    return {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    range_filter(),
                    {
                        "exists": {
                            "field": CONNECTION_FIELD
                        }
                    }
                ]
            }
        },
        "aggs": {
            "unique_connections": {
                "cardinality": {
                    "field": CONNECTION_FIELD,
                    "precision_threshold": CARDINALITY_PRECISION
                }
            }
        }
    }


def query_bytes(field_a, field_b):
    should = [
        {
            "exists": {
                "field": field_a
            }
        }
    ]

    aggs = {
        "bytes_a": {
            "sum": {
                "field": field_a
            }
        }
    }

    if field_b:
        should.append({
            "exists": {
                "field": field_b
            }
        })

        aggs["bytes_b"] = {
            "sum": {
                "field": field_b
            }
        }

    return {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    range_filter()
                ],
                "should": should,
                "minimum_should_match": 1
            }
        },
        "aggs": aggs
    }


def query_trend():
    return {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    range_filter(),
                    {
                        "exists": {
                            "field": CONNECTION_FIELD
                        }
                    }
                ]
            }
        },
        "aggs": {
            "connections_per_minute": {
                "date_histogram": {
                    "field": TIME_FIELD,
                    "fixed_interval": TREND_INTERVAL,
                    "min_doc_count": 0,
                    "time_zone": TIME_ZONE,
                    "extended_bounds": {
                        "min": TIME_FROM,
                        "max": TIME_TO
                    }
                },
                "aggs": {
                    "unique_connections": {
                        "cardinality": {
                            "field": CONNECTION_FIELD,
                            "precision_threshold": CARDINALITY_PRECISION
                        }
                    }
                }
            }
        }
    }


def query_top_terms(field, size=TOP_TERMS_SIZE):
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


# ============================================================
# HTML / SVG COMPONENTS
# ============================================================

def make_svg_line(points):
    width = 1200
    height = 360

    if not points:
        return "<p class='nodata'>No data available for the chart.</p>"

    values = [p["value"] for p in points]
    max_value = max(values) if values else 0

    if max_value <= 0:
        return "<p class='nodata'>No data available for the chart.</p>"

    padding_left = 60
    padding_right = 25
    padding_top = 25
    padding_bottom = 65

    chart_w = width - padding_left - padding_right
    chart_h = height - padding_top - padding_bottom

    coords = []

    for i, point in enumerate(points):
        x = padding_left + (i / max(1, len(points) - 1)) * chart_w
        y = padding_top + chart_h - (point["value"] / max_value) * chart_h
        coords.append((x, y))

    polyline = " ".join(f"{x:.2f},{y:.2f}" for x, y in coords)

    grid = []

    for frac in [0, 0.25, 0.5, 0.75, 1]:
        val = max_value * frac
        y = padding_top + chart_h - frac * chart_h

        grid.append(
            f'<line x1="{padding_left}" y1="{y:.2f}" '
            f'x2="{width-padding_right}" y2="{y:.2f}" class="grid"/>'
            f'<text x="8" y="{y+4:.2f}" class="axis">{int(val)}</text>'
        )

    x_labels = []
    last_hour = None

    for i, point in enumerate(points):
        label = point.get("label", "")

        if len(label) >= 5 and label[2] == ":":
            hour = label[:2]
            minute = label[3:5]

            if minute == "00" and hour != last_hour:
                x = padding_left + (i / max(1, len(points) - 1)) * chart_w
                last_hour = hour

                x_labels.append(
                    f'<line x1="{x:.2f}" y1="{padding_top}" '
                    f'x2="{x:.2f}" y2="{padding_top + chart_h}" class="grid-vertical"/>'
                    f'<text x="{x:.2f}" y="{height-30}" '
                    f'class="axis x-axis" text-anchor="middle">{html.escape(label)}</text>'
                )

    return f"""
    <svg viewBox="0 0 {width} {height}" class="chart" preserveAspectRatio="xMidYMid meet">
      {''.join(grid)}
      {''.join(x_labels)}
      <polyline points="{polyline}" class="line" fill="none"/>
      <text x="{padding_left}" y="{height-10}" class="axis">Time, one-hour intervals</text>
    </svg>
    """


def make_bar_list(items):
    if not items:
        return "<p class='nodata'>No data available.</p>"

    max_value = max([i["doc_count"] for i in items]) if items else 1
    if max_value <= 0:
        max_value = 1

    rows = []

    for idx, item in enumerate(items):
        key = html.escape(str(item["key"]))
        count = int(item["doc_count"])
        pct = (count / max_value) * 100
        delay = idx * 0.08

        rows.append(f"""
        <div class="bar-row">
          <div class="bar-label">{key}</div>
          <div class="bar-track">
            <div class="bar-fill" style="width:{pct:.2f}%; animation-delay:{delay:.2f}s"></div>
          </div>
          <div class="bar-value" style="animation-delay:{delay + 0.18:.2f}s">{fmt_int(count)}</div>
        </div>
        """)

    return "\n".join(rows)


def generate_html(
    unique_connections,
    total_bytes,
    egress_bytes,
    ingress_bytes,
    trend_points,
    top_src,
    top_dst,
    bytes_field_a,
    bytes_field_b,
    src_field,
    dst_field
):
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    chart = make_svg_line(trend_points)
    logo_uri = logo_data_uri()

    bytes_fields_text = bytes_field_a if not bytes_field_b else f"{bytes_field_a}, {bytes_field_b}"

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

    .cards {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(min(100%, 260px), 1fr));
      gap: clamp(10px, 1.4vw, 18px);
      margin-bottom: 18px;
    }}

    .card {{
      position: relative;
      overflow: hidden;
      background: linear-gradient(135deg, rgba(255,255,255,0.96), rgba(232,248,255,0.90));
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: clamp(14px, 1.4vw, 22px);
      min-height: clamp(105px, 13vh, 145px);
      box-shadow: var(--shadow);
    }}

    .card::before {{
      content: "";
      position: absolute;
      left: 0;
      top: 0;
      bottom: 0;
      width: 5px;
      background: linear-gradient(180deg, var(--cyan), var(--blue-dark));
    }}

    .card-title {{
      display: flex;
      align-items: center;
      gap: 8px;
      font-weight: 800;
      font-size: clamp(12px, 1vw, 15px);
      color: var(--blue-dark);
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }}

    .card-title::before {{
      content: "";
      width: 9px;
      height: 9px;
      border-radius: 3px;
      background: var(--cyan);
      opacity: 0.85;
    }}

    .card-value {{
      margin-top: clamp(14px, 2vh, 26px);
      text-align: right;
      font-size: clamp(26px, 3vw, 42px);
      font-weight: 800;
      color: #071a2c;
      letter-spacing: -0.04em;
    }}

    .panel {{
      background: var(--card);
      backdrop-filter: blur(6px);
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: clamp(12px, 1.4vw, 20px);
      box-shadow: var(--shadow);
      min-width: 0;
      overflow: hidden;
      margin-bottom: 18px;
    }}

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

    .chart {{
      width: 100%;
      height: clamp(260px, 36vh, 420px);
      display: block;
    }}

    .line {{
      stroke: var(--blue);
      stroke-width: 2.8;
      filter: drop-shadow(0 4px 8px rgba(22, 125, 180, 0.25));
    }}

    .grid {{
      stroke: rgba(108, 137, 160, 0.18);
      stroke-width: 1;
    }}

    .grid-vertical {{
      stroke: rgba(23, 169, 214, 0.14);
      stroke-width: 1;
    }}

    .axis {{
      fill: #617084;
      font-size: 12px;
    }}

    .x-axis {{
      font-size: 11px;
    }}

    .two-cols {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(min(100%, 520px), 1fr));
      gap: clamp(12px, 1.4vw, 18px);
    }}

    @keyframes topIpBarGrow {{
      from {{
        transform: scaleX(0);
        opacity: 0.35;
      }}
      to {{
        transform: scaleX(1);
        opacity: 1;
      }}
    }}

    @keyframes topIpValueFade {{
      from {{
        opacity: 0;
        transform: translateX(-6px);
      }}
      to {{
        opacity: 1;
        transform: translateX(0);
      }}
    }}

    .bar-row {{
      display: grid;
      grid-template-columns: minmax(90px, 160px) 1fr minmax(60px, 90px);
      gap: 12px;
      align-items: center;
      margin: 10px 0;
      font-size: clamp(12px, 1vw, 14px);
    }}

    .bar-label {{
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      font-family: monospace;
      color: var(--blue-dark);
      font-weight: 700;
    }}

    .bar-track {{
      background: #e6f2f8;
      height: 12px;
      border-radius: 999px;
      overflow: hidden;
      border: 1px solid rgba(78, 188, 232, 0.18);
    }}

    .bar-fill {{
      background: linear-gradient(90deg, var(--cyan), var(--blue-dark));
      height: 100%;
      border-radius: 999px;
      transform-origin: left center;
      animation: topIpBarGrow 1.1s cubic-bezier(.2, .8, .2, 1) both;
    }}

    .bar-value {{
      text-align: right;
      font-family: monospace;
      color: #23394f;
      opacity: 0;
      animation: topIpValueFade 0.55s ease-out both;
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

    @media (prefers-reduced-motion: reduce) {{
      .bar-fill,
      .bar-value {{
        animation: none !important;
        opacity: 1 !important;
        transform: none !important;
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

    <section class="cards">
      <div class="card">
        <div class="card-title">Unique connections</div>
        <div class="card-value">{fmt_int(unique_connections)}</div>
      </div>

      <div class="card">
        <div class="card-title">Total traffic</div>
        <div class="card-value">{fmt_gb(total_bytes)}</div>
      </div>

      <div class="card">
        <div class="card-title">Egress</div>
        <div class="card-value">{fmt_gb(egress_bytes)}</div>
      </div>

      <div class="card">
        <div class="card-title">Ingress</div>
        <div class="card-value">{fmt_gb(ingress_bytes)}</div>
      </div>
    </section>

    <section class="panel">
      <div class="panel-header">
        <h2>Unique connections trend</h2>
        <span class="panel-tag">Per minute</span>
      </div>
      {chart}
    </section>

    <section class="two-cols">
      <div class="panel">
        <div class="panel-header">
          <h2>Top source IPs</h2>
          <span class="panel-tag">Source</span>
        </div>
        {make_bar_list(top_src)}
      </div>

      <div class="panel">
        <div class="panel-header">
          <h2>Top destination IPs</h2>
          <span class="panel-tag">Destination</span>
        </div>
        {make_bar_list(top_dst)}
      </div>
    </section>

    <footer class="footer">
      <span>Generated: {html.escape(generated_at)}</span>
      <span>Elasticsearch: {html.escape(ES_URL)}</span>
      <span>Index: {html.escape(ES_INDEX)}</span>
      <span>Connection field: {html.escape(CONNECTION_FIELD)}</span>
      <span>Byte fields: {html.escape(bytes_fields_text)}</span>
      <span>IP fields: {html.escape(src_field)}, {html.escape(dst_field)}</span>
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

    connection_docs = count_docs_with_field(CONNECTION_FIELD)
    print(f"Connection field {CONNECTION_FIELD}: {connection_docs} documents")
    print("")

    bytes_field_a, bytes_field_b = choose_bytes_fields()

    src_field = choose_first_available_field(SOURCE_IP_FIELDS, "source IP")
    dst_field = choose_first_available_field(DESTINATION_IP_FIELDS, "destination IP")

    conn_data = es_post(f"{ES_INDEX}/_search", query_connections())
    bytes_data = es_post(f"{ES_INDEX}/_search", query_bytes(bytes_field_a, bytes_field_b))
    trend_data = es_post(f"{ES_INDEX}/_search", query_trend())
    top_src_data = es_post(f"{ES_INDEX}/_search", query_top_terms(src_field, TOP_TERMS_SIZE))
    top_dst_data = es_post(f"{ES_INDEX}/_search", query_top_terms(dst_field, TOP_TERMS_SIZE))

    unique_connections = conn_data.get("aggregations", {}).get("unique_connections", {}).get("value", 0)

    aggs_bytes = bytes_data.get("aggregations", {})
    bytes_a = aggs_bytes.get("bytes_a", {}).get("value", 0)
    bytes_b = aggs_bytes.get("bytes_b", {}).get("value", 0) if bytes_field_b else 0

    total_bytes = bytes_a + bytes_b
    egress_bytes = bytes_a
    ingress_bytes = bytes_b

    buckets = trend_data.get("aggregations", {}).get("connections_per_minute", {}).get("buckets", [])

    trend_points = []
    for bucket in buckets:
        value = bucket.get("unique_connections", {}).get("value", 0)
        timestamp = bucket.get("key_as_string", "")

        label = timestamp
        if "T" in timestamp:
            label = timestamp.split("T", 1)[1][:5]

        trend_points.append({
            "label": label,
            "value": value
        })

    top_src = top_src_data.get("aggregations", {}).get("top", {}).get("buckets", [])
    top_dst = top_dst_data.get("aggregations", {}).get("top", {}).get("buckets", [])

    html_doc = generate_html(
        unique_connections=unique_connections,
        total_bytes=total_bytes,
        egress_bytes=egress_bytes,
        ingress_bytes=ingress_bytes,
        trend_points=trend_points,
        top_src=top_src,
        top_dst=top_dst,
        bytes_field_a=bytes_field_a,
        bytes_field_b=bytes_field_b,
        src_field=src_field,
        dst_field=dst_field
    )

    with open(OUTPUT_HTML, "w", encoding="utf-8") as f:
        f.write(html_doc)

    print("Results:")
    print(f"  Unique connections: {fmt_int(unique_connections)}")
    print(f"  Total traffic:      {fmt_gb(total_bytes)}")
    print(f"  Egress:             {fmt_gb(egress_bytes)}")
    print(f"  Ingress:            {fmt_gb(ingress_bytes)}")
    print("")
    print(f"HTML generated successfully: {OUTPUT_HTML}")


if __name__ == "__main__":
    main()
