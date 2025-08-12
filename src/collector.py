"""
collector.py
-------------
Collection layer for OSINT data. By default, loads local sample CSV.
Uncomment API sections and add keys in config.yaml to collect live data.
"""
import csv, os, json, time, yaml
try:
    import feedparser
except Exception:
    feedparser = None
try:
    import requests
except Exception:
    requests = None
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
CONFIG = ROOT / "config.yaml"

def load_config():
    if CONFIG.exists():
        with open(CONFIG, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    # fallback to sample
    with open(ROOT / "config.sample.yaml", "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def collect_from_rss(feeds):
    rows = []
    for url in feeds:
        d = feedparser.parse(url)
        for entry in d.entries[:25]:
            rows.append({
                "timestamp": getattr(entry, "published", ""),
                "source": url,
                "threat_type": "",   # classify later
                "indicator": getattr(entry, "link", ""),
                "indicator_type": "url",
                "actor": "",
                "malware": "",
                "description": getattr(entry, "title", ""),
            })
    return rows

def collect_from_otx(api_key):
    # Example: pull pulses (stubbed without external calls)
    # If you have an OTX key, you can implement here using requests.get with headers:
    # headers = {"X-OTX-API-KEY": api_key}
    # resp = requests.get("https://otx.alienvault.com/api/v1/pulses/subscribed", headers=headers, timeout=20)
    # Map indicators to our schema.
    return []

def collect_from_shodan(api_key):
    # Example query (stubbed):
    # url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query=has_screenshot:true"
    # resp = requests.get(url, timeout=20).json()
    return []

def load_sample():
    rows = []
    with open(DATA / "raw_osint_sample.csv", "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append(r)
    return rows

def collect():
    cfg = load_config()
    rows = []
    # 1) Sample
    rows.extend(load_sample())
    # 2) RSS (optional)
    if "feeds" in cfg and cfg["feeds"]:
        rows.extend(collect_from_rss(cfg["feeds"]))
    # 3) OTX (optional)
    if cfg.get("otx", {}).get("api_key"):
        rows.extend(collect_from_otx(cfg["otx"]["api_key"]))
    # 4) Shodan (optional)
    if cfg.get("shodan", {}).get("api_key"):
        rows.extend(collect_from_shodan(cfg["shodan"]["api_key"]))
    return rows
