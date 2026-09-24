import csv
import os
import sqlite3
import time
import logging
from backend.config import DATA_DIR, BASE_DIR

logger = logging.getLogger("data_indexer")

DB_PATH = BASE_DIR / "data" / "fraud_graph.db"

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def initialize_database(force_rebuild: bool = False):
    """
    Initializes SQLite graph tables and indexes for local development fallback
    and fast graph relationship queries.
    """
    if DB_PATH.exists() and not force_rebuild:
        print(f"Database already exists at {DB_PATH}. Checking tables...")
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM case_pack")
            count = cursor.fetchone()[0]
            if count == 20:
                print(f"Database contains all {count} benchmark cases. Ready.")
                conn.close()
                return
        except Exception:
            pass
        conn.close()

    print(f"Building local graph store at {DB_PATH}...")
    start_time = time.time()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("PRAGMA synchronous = OFF")
    cur.execute("PRAGMA journal_mode = MEMORY")

    # Create tables
    cur.execute("""
    CREATE TABLE IF NOT EXISTS case_pack (
        case_id TEXT PRIMARY KEY,
        opened_at TEXT,
        trigger_type TEXT,
        trigger_text TEXT,
        flagged_txn_id TEXT,
        card_id TEXT,
        customer_id TEXT,
        risk_score REAL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS closed_cases (
        case_id TEXT PRIMARY KEY,
        customer_id TEXT,
        card_id TEXT,
        opened_at TEXT,
        closed_at TEXT,
        outcome TEXT,
        pattern TEXT,
        first_fraud_txn_id TEXT,
        txn_ids TEXT,
        n_txns INTEGER,
        exposure_usd REAL,
        connected_card_ids TEXT,
        actions_taken TEXT,
        report_filed TEXT,
        analyst_notes TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS identity (
        TransactionID TEXT PRIMARY KEY,
        device_profile TEXT,
        DeviceInfo TEXT,
        id_30 TEXT,
        id_31 TEXT,
        id_33 TEXT,
        DeviceType TEXT,
        id_15 TEXT,
        id_23 TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS transactions (
        TransactionID TEXT PRIMARY KEY,
        customer_id TEXT,
        card_id TEXT,
        card1 TEXT,
        card2 TEXT,
        card3 TEXT,
        card4 TEXT,
        card5 TEXT,
        card6 TEXT,
        TransactionAmt REAL,
        ProductCD TEXT,
        addr1 TEXT,
        addr2 TEXT,
        dist1 REAL,
        dist2 REAL,
        P_emaildomain TEXT,
        R_emaildomain TEXT,
        ts TEXT,
        channel TEXT,
        risk_score REAL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS investigation_cases (
        case_id TEXT PRIMARY KEY,
        customer_id TEXT,
        card_id TEXT,
        opened_at TEXT,
        status TEXT,
        verdict TEXT,
        fraud_probability REAL,
        pattern TEXT,
        pattern_description TEXT,
        exposure_usd REAL,
        summary TEXT,
        sar_filed INTEGER,
        flagged_txn_id TEXT
    )
    """)

    # Load Case Pack
    print("Loading case_pack.csv...")
    with open(DATA_DIR / "case_pack.csv", "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cur.execute("""
            INSERT OR REPLACE INTO case_pack VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                row["case_id"],
                row["opened_at"],
                row["trigger_type"],
                row["trigger_text"],
                row["flagged_txn_id"],
                row["card_id"],
                row["customer_id"],
                float(row["risk_score"]) if row["risk_score"] else None
            ))

    # Load Closed Cases
    print("Loading closed_cases_history.csv...")
    with open(DATA_DIR / "closed_cases_history.csv", "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = []
        for row in reader:
            rows.append((
                row["case_id"],
                row["customer_id"],
                row["card_id"],
                row["opened_at"],
                row["closed_at"],
                row["outcome"],
                row["pattern"],
                row["first_fraud_txn_id"],
                row["txn_ids"],
                int(row["n_txns"]) if row["n_txns"] else 0,
                float(row["exposure_usd"]) if row["exposure_usd"] else 0.0,
                row["connected_card_ids"],
                row["actions_taken"],
                row["report_filed"],
                row["analyst_notes"]
            ))
        cur.executemany("INSERT OR REPLACE INTO closed_cases VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)

    # Load Identity
    print("Loading identity.csv...")
    with open(DATA_DIR / "identity.csv", "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = []
        for row in reader:
            dev = f"{row.get('DeviceInfo', '').strip()} | {row.get('id_30', '').strip()} | {row.get('id_31', '').strip()} | {row.get('id_33', '').strip()}"
            rows.append((
                row["TransactionID"],
                dev,
                row.get("DeviceInfo", ""),
                row.get("id_30", ""),
                row.get("id_31", ""),
                row.get("id_33", ""),
                row.get("DeviceType", ""),
                row.get("id_15", ""),
                row.get("id_23", "")
            ))
            if len(rows) >= 10000:
                cur.executemany("INSERT OR REPLACE INTO identity VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
                rows = []
        if rows:
            cur.executemany("INSERT OR REPLACE INTO identity VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)

    # Build known txn_id -> card_id map from closed cases and case pack
    print("Building card ID index...")
    txn_to_card = {}
    with open(DATA_DIR / "case_pack.csv", "r", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            txn_to_card[r["flagged_txn_id"]] = r["card_id"]

    with open(DATA_DIR / "closed_cases_history.csv", "r", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            cid = r["card_id"]
            for tid in r["txn_ids"].split("|"):
                if tid:
                    txn_to_card[tid] = cid

    # Load Transactions
    print("Loading transactions.csv (this populates 590,742 records)...")
    with open(DATA_DIR / "transactions.csv", "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = []
        count = 0
        for row in reader:
            tid = row["TransactionID"]
            cust = row["customer_id"]
            # If card_id is known from cases, use it; otherwise assign deterministic card format
            card_id = txn_to_card.get(tid, f"{cust}-K1")
            
            rows.append((
                tid,
                cust,
                card_id,
                row.get("card1", ""),
                row.get("card2", ""),
                row.get("card3", ""),
                row.get("card4", ""),
                row.get("card5", ""),
                row.get("card6", ""),
                float(row["TransactionAmt"]) if row.get("TransactionAmt") else 0.0,
                row.get("ProductCD", ""),
                row.get("addr1", ""),
                row.get("addr2", ""),
                float(row["dist1"]) if row.get("dist1") else None,
                float(row["dist2"]) if row.get("dist2") else None,
                row.get("P_emaildomain", ""),
                row.get("R_emaildomain", ""),
                row.get("ts", ""),
                row.get("channel", ""),
                float(row["risk_score"]) if row.get("risk_score") else 0.0
            ))
            count += 1
            if len(rows) >= 20000:
                cur.executemany("""
                INSERT OR REPLACE INTO transactions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, rows)
                rows = []
                print(f"  Inserted {count} transactions...")

        if rows:
            cur.executemany("""
            INSERT OR REPLACE INTO transactions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, rows)

    print("Creating indexes...")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_txn_card ON transactions(card_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_txn_cust ON transactions(customer_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_txn_ts ON transactions(ts)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_txn_addr ON transactions(addr1)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ident_profile ON identity(device_profile)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cases_pattern ON closed_cases(pattern)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cases_card ON closed_cases(card_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cases_cust ON closed_cases(customer_id)")

    conn.commit()
    conn.close()
    elapsed = time.time() - start_time
    print(f"Database initialization complete in {elapsed:.1f}s at {DB_PATH}")

if __name__ == "__main__":
    initialize_database()
