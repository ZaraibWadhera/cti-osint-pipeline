"""
pipeline.py
-----------
End-to-end runner: collect -> process -> analyze -> store -> report
"""
import csv, sqlite3
from pathlib import Path
from collector import collect
from processor import clean
from analyzer import analyze
from reporter import generate_html

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
REPORTS = ROOT / "reports"
DB = ROOT / "cti_osint.db"

def to_sqlite(rows):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS intel_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source TEXT,
            threat_type TEXT,
            indicator TEXT,
            indicator_type TEXT,
            actor TEXT,
            malware TEXT,
            description TEXT,
            mitre_tactic TEXT,
            mitre_technique_id TEXT
        )
    """)
    # insert
    cur.executemany("""
        INSERT INTO intel_events
        (timestamp, source, threat_type, indicator, indicator_type, actor, malware, description, mitre_tactic, mitre_technique_id)
        VALUES (:timestamp, :source, :threat_type, :indicator, :indicator_type, :actor, :malware, :description, :mitre_tactic, :mitre_technique_id)
    """, rows)
    conn.commit()
    conn.close()

def main():
    # 1) collect
    raw = collect()
    # 2) clean
    cleaned = clean(raw)
    # 3) analyze
    result = analyze(cleaned)
    enriched = result["enriched"]
    # 4) save CSV
    out_csv = DATA / "processed_events.csv"
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        fieldnames = list(enriched[0].keys())
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(enriched)
    # 5) to sqlite
    to_sqlite(enriched)
    # 6) report
    report = generate_html(result)
    print(f"Report written to: {report}")
    print(f"SQLite DB: {DB}")
    print(f"Processed CSV: {out_csv}")

if __name__ == "__main__":
    main()
