import csv
import sqlite3

conn = sqlite3.connect('data/fraud_graph.db')
c = conn.cursor()

with open('data/case_pack.csv', 'r', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        txn_id = row['flagged_txn_id']
        c.execute('SELECT TransactionAmt, channel, addr1, P_emaildomain, ts, risk_score FROM transactions WHERE TransactionID = ?', (txn_id,))
        txn = c.fetchone()
        c.execute('SELECT DeviceType, DeviceInfo, id_30, id_31, id_15 FROM identity WHERE TransactionID = ?', (txn_id,))
        ident = c.fetchone()
        c.execute('SELECT COUNT(*) FROM transactions WHERE card_id = ?', (row['card_id'],))
        card_txns = c.fetchone()[0]
        print(f"{row['case_id']}: Card={row['card_id']} ({card_txns} txns), Txn={txn_id}, Amt=${txn[0] if txn else '?'}, Chan={txn[1] if txn else '?'}, Region={txn[2] if txn else '?'}, Device={ident[1] if ident else 'None'}, id15={ident[4] if ident else 'None'}")
