"""
processor.py
-------------
Cleans and normalizes collected data.
"""
import re, hashlib, datetime as dt
from typing import List, Dict

IOC_DOMAIN = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}")
IOC_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IOC_HASH = re.compile(r"\b[a-f0-9]{32,64}\b", re.I)
IOC_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)

def normalize_timestamp(ts: str) -> str:
    if not ts:
        return dt.datetime.utcnow().isoformat() + "Z"
    try:
        return dt.datetime.fromisoformat(ts.replace("Z","")).isoformat() + "Z"
    except Exception:
        return dt.datetime.utcnow().isoformat() + "Z"

def guess_indicator_type(indicator: str) -> str:
    if IOC_IP.search(indicator): return "ip"
    if IOC_DOMAIN.search(indicator): return "domain"
    if IOC_CVE.search(indicator): return "cve"
    if IOC_HASH.search(indicator): return "hash"
    if indicator.startswith("http"): return "url"
    return "other"

def clean(rows: List[Dict]) -> List[Dict]:
    seen = set()
    out = []
    for r in rows:
        indicator = (r.get("indicator") or "").strip()
        if not indicator:
            # try to extract from description
            text = (r.get("description") or "")
            m = IOC_IP.search(text) or IOC_DOMAIN.search(text) or IOC_CVE.search(text) or IOC_HASH.search(text)
            indicator = m.group(0) if m else ""
        ind_type = r.get("indicator_type") or guess_indicator_type(indicator) if indicator else "other"
        key = (indicator, ind_type)
        if key in seen: 
            continue
        seen.add(key)
        out.append({
            "timestamp": normalize_timestamp(r.get("timestamp","")),
            "source": (r.get("source") or "").strip(),
            "threat_type": (r.get("threat_type") or "").strip(),
            "indicator": indicator,
            "indicator_type": ind_type,
            "actor": (r.get("actor") or "").strip(),
            "malware": (r.get("malware") or "").strip(),
            "description": (r.get("description") or "").strip(),
        })
    return out
