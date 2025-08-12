# Cyber Threat Intelligence & OSINT Analysis (Independent)

A complete, portfolio-ready **CTI/OSINT pipeline** that collects (via APIs/RSS), processes, analyzes, and reports on open-source cyber threat intelligence.

> This repository includes **runnable Python code**, a **sample SQLite database**, **charts**, and a **polished HTML Intelligence Brief** so you can showcase real output immediately.

## Features
- **Collection**: (stubs + ready-to-fill) collectors for AlienVault OTX, Shodan, and security RSS feeds
- **Processing**: data cleaning, IOC normalization (IPs, domains, hashes), deduplication
- **Analysis**: simple trend detection, TTP classification w/ MITRE ATT&CK mapping
- **Storage**: SQLite database for structured queries
- **Reporting**: HTML Intelligence Brief with charts (matplotlib), mitigation recommendations

## Quickstart
```bash
# 1) Create venv (optional)
python -m venv .venv && source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 2) Install deps
pip install -r requirements.txt

# 3) Configure (optional: add API keys)
cp config.sample.yaml config.yaml  # edit with your keys

# 4) Run the pipeline (uses sample data by default)
python src/pipeline.py

# 5) Open the generated report
open reports/intel_brief.html  # Windows: start reports\intel_brief.html
```
If you add API keys, uncomment the respective sections in `collector.py` to pull **live** data.

## Project Structure
```
cti-osint-project/
├── data/                 # sample raw + processed data
├── reports/              # charts + report outputs
├── src/
│   ├── collector.py      # data collection from RSS/APIs
│   ├── processor.py      # cleaning and normalization
│   ├── analyzer.py       # trend detection + TTP mapping
│   ├── reporter.py       # HTML report generation
│   ├── pipeline.py       # orchestrates the end-to-end flow
│   └── mitre_mapping.json
├── requirements.txt
├── config.sample.yaml
└── README.md
```

## MITRE ATT&CK
This project includes a minimal mapping (examples) to demonstrate how to attach ATT&CK technique IDs to observed behaviors. Expand `src/mitre_mapping.json` as needed.

## Disclaimer
Only use OSINT sources **legally** and **ethically**. Respect terms of service and privacy laws. The sample data here is synthetic and for demonstration only.

— Generated 2025-08-12


## Badges
![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-green)

## CI
A basic GitHub Actions workflow is included at `.github/workflows/python-checks.yml` for lint/checks.

## Screenshots
Charts are generated to `reports/charts/` on each run. Include them in your README after running once.

## Ethics & Legal
Only collect OSINT that is lawful and permitted by source ToS. Respect privacy and do not attempt to deanonymize individuals.
