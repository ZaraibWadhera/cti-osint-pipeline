# Project Overview

**Goal:** Demonstrate an end-to-end CTI/OSINT workflow suitable for a portfolio.

**Pipeline**
- Collection: sample + optional RSS/APIs (OTX, Shodan)
- Processing: IOC detection, normalization, dedup
- Analysis: simple trend detection, MITRE ATT&CK mapping
- Storage: SQLite + CSV
- Reporting: HTML brief with charts

**How to Extend**
- Add real API calls in `collector.py`
- Expand MITRE mappings in `src/mitre_mapping.json`
- Add dashboards (Streamlit/FastAPI) for browsing events
