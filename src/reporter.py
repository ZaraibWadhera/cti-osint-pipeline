"""
reporter.py
-----------
Generates charts and an HTML Intelligence Brief.
"""
import os, base64, io, matplotlib.pyplot as plt
from pathlib import Path
from typing import Dict, List
import datetime as dt

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
CHARTS = REPORTS / "charts"
CHARTS.mkdir(parents=True, exist_ok=True)

def _save_bar(data: dict, title: str, fname: str):
    # One chart per figure, no explicit colors/styles
    plt.figure()
    items = sorted(data.items(), key=lambda x: x[1], reverse=True)
    labels = [k for k,_ in items]
    values = [v for _,v in items]
    plt.bar(labels, values)
    plt.title(title)
    plt.xticks(rotation=25, ha="right")
    plt.tight_layout()
    out = CHARTS / fname
    plt.savefig(out)
    plt.close()
    return out

def _save_line(data: dict, title: str, fname: str):
    plt.figure()
    items = sorted(data.items(), key=lambda x: x[0])
    xs = [k for k,_ in items]
    ys = [v for _,v in items]
    plt.plot(xs, ys, marker="o")
    plt.title(title)
    plt.xticks(rotation=25, ha="right")
    plt.tight_layout()
    out = CHARTS / fname
    plt.savefig(out)
    plt.close()
    return out

def generate_html(analysis: Dict):
    # Make charts
    type_chart = _save_bar(analysis["summary"]["by_type"], "Threats by Type", "by_type.png")
    trend_chart = _save_line(analysis["summary"]["daily"], "IOC Events by Day", "daily.png")
    # Build a simple HTML report
    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cyber Threat Intelligence Brief</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; }}
  .card {{ border: 1px solid #e5e7eb; border-radius: 14px; padding: 16px; margin-bottom: 16px; }}
  h1 {{ margin: 0 0 4px 0; }}
  h2 {{ margin-top: 0; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th, td {{ border-bottom: 1px solid #f1f5f9; padding: 8px; font-size: 14px; text-align: left; }}
  .muted {{ color: #6b7280; font-size: 13px; }}
  img {{ max-width: 100%; height: auto; border-radius: 10px; }}
  .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }}
  @media (max-width: 800px) {{ .grid {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
  <h1>Cyber Threat Intelligence Brief</h1>
  <div class="muted">Generated automatically</div>

  <div class="card">
    <h2>Executive Summary</h2>
    <p>This report summarizes recent open-source cyber threat activity observed across curated feeds and sample OSINT data. It highlights prevalent TTPs, top indicators, and mitigation guidance.</p>
  </div>

  <div class="grid">
    <div class="card">
      <h3>Threats by Type</h3>
      <img src="charts/{type_chart.name}" alt="Threats by Type">
    </div>
    <div class="card">
      <h3>IOC Events by Day</h3>
      <img src="charts/{trend_chart.name}" alt="IOC Trend">
    </div>
  </div>

  <div class="card">
    <h3>Top Indicators</h3>
    <table>
      <thead><tr><th>Indicator</th><th>Type</th><th>Count</th></tr></thead>
      <tbody>
      {"".join([f"<tr><td>{ioc}</td><td>-</td><td>{cnt}</td></tr>" for ioc,cnt in analysis["summary"]["top_iocs"]])}
      </tbody>
    </table>
  </div>

  <div class="card">
    <h3>Enriched Events (Sample)</h3>
    <table>
      <thead><tr>
        <th>Time</th><th>Source</th><th>Threat</th><th>Indicator</th><th>Type</th><th>Actor</th><th>Malware</th><th>MITRE</th>
      </tr></thead>
      <tbody>
      {"".join([f"<tr><td>{r['timestamp']}</td><td>{r['source']}</td><td>{r['threat_type']}</td><td>{r['indicator']}</td><td>{r['indicator_type']}</td><td>{r['actor']}</td><td>{r['malware']}</td><td>{r['mitre_technique_id']}</td></tr>" for r in analysis["enriched"][:25]])}
      </tbody>
    </table>
  </div>

  <div class="card">
    <h3>Recommended Mitigations</h3>
    <ul>
      <li>Enable phishing-resistant MFA and block lookalike domains with strict DMARC/DKIM/SPF.</li>
      <li>Harden external services; patch high-risk CVEs rapidly; restrict RDP and SMB exposure.</li>
      <li>Monitor for credential dumping tools (e.g., Mimikatz) and unusual LSASS access.</li>
      <li>Detect and block C2 traffic with egress filtering and DNS inspection.</li>
      <li>Establish DLP policies to detect outbound exfiltration attempts.</li>
    </ul>
  </div>

  <div class="muted">© {dt.date.today().isoformat()} — CTI/OSINT Pipeline</div>
</body>
</html>"""
    out = (REPORTS / "intel_brief.html")
    out.write_text(html, encoding="utf-8")
    return out
