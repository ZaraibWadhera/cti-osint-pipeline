"""
analyzer.py
-----------
Performs simple classification and MITRE ATT&CK mapping.
"""
import json, datetime as dt
from collections import Counter, defaultdict
from typing import List, Dict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MITRE = json.loads((ROOT / "src" / "mitre_mapping.json").read_text())

KEYWORDS = {
    "phishing": ["phish", "credential", "mfa fatigue", "fake", "login"],
    "ransomware": ["ransom", "encrypt", "double extortion", "ALPHV", "LockBit"],
    "credential_dumping": ["mimikatz", "lsass", "credential dumping", "hashdump"],
    "command_and_control": ["c2", "command and control", "beacon", "cobalt strike"],
    "exfiltration": ["exfil", "data leak", "outbound"],
    "exploiting_public_facing_app": ["cve", "exploit", "rce", "public-facing"]
}

def classify(row: Dict) -> str:
    t = (row.get("threat_type") or "").lower()
    if t: 
        return t
    text = " ".join([row.get("description",""), row.get("indicator","")]).lower()
    for label, kws in KEYWORDS.items():
        if any(k in text for k in kws):
            return label
    return "unknown"

def attach_mitre(threat_type: str) -> Dict:
    return MITRE.get(threat_type, {"tactic":"Unknown","technique_id":"Unknown"})

def analyze(rows: List[Dict]) -> Dict:
    # classify
    enriched = []
    for r in rows:
        ttype = classify(r)
        mitre = attach_mitre(ttype)
        r2 = dict(r)
        r2["threat_type"] = ttype
        r2["mitre_tactic"] = mitre["tactic"]
        r2["mitre_technique_id"] = mitre["technique_id"]
        enriched.append(r2)
    # counts
    by_type = Counter([r["threat_type"] for r in enriched])
    # daily trend (count per day)
    daily = Counter([r["timestamp"][:10] for r in enriched])
    # top indicators
    by_indicator = Counter([r["indicator"] for r in enriched if r["indicator"]])
    top_iocs = by_indicator.most_common(10)
    return {
        "enriched": enriched,
        "summary": {
            "by_type": dict(by_type),
            "daily": dict(daily),
            "top_iocs": top_iocs
        }
    }
