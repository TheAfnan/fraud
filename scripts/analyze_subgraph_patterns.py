import sqlite3

conn = sqlite3.connect('data/fraud_graph.db')
c = conn.cursor()

# Check device sharing among benchmark cases
print("--- Check shared devices ---")
c.execute("""
    SELECT i.device_profile, i.DeviceInfo, i.id_30, i.id_31, COUNT(DISTINCT t.card_id) as card_count, GROUP_CONCAT(DISTINCT t.card_id)
    FROM identity i
    JOIN transactions t ON i.TransactionID = t.TransactionID
    WHERE i.device_profile IS NOT NULL AND i.device_profile != ''
    GROUP BY i.device_profile
    HAVING card_count > 1
""")
shared_devs = c.fetchall()
for d in shared_devs:
    print(f"Device {d[0]} ({d[1]}, {d[2]}, {d[3]}): used by {d[4]} cards: {d[5]}")

print("\n--- Check historical closed cases on these devices ---")
for d in shared_devs:
    c.execute("""
        SELECT case_id, pattern, outcome, exposure_usd, connected_card_ids 
        FROM closed_cases 
        WHERE analyst_notes LIKE ? OR connected_card_ids LIKE ?
    """, (f"%{d[1]}%", f"%{d[0]}%"))
    cases = c.fetchall()
    if cases:
        print(f"Device {d[1]} in historical cases: {[cs[0] for cs in cases]}")

print("\n--- Check regional distribution for in_person cases (001, 003, 007, 012, 018) ---")
in_person_cards = [
    ('HHG-001', 'C12382-K1', '444.0'),
    ('HHG-003', 'C08623-K2', '330.0'),
    ('HHG-007', 'C09933-K2', '264.0'),
    ('HHG-012', 'C05876-K2', '494.0'),
    ('HHG-018', 'C02354-K2', '126.0')
]
for cid, card, target_reg in in_person_cards:
    c.execute("SELECT addr1, COUNT(*) FROM transactions WHERE card_id = ? GROUP BY addr1 ORDER BY COUNT(*) DESC LIMIT 5", (card,))
    top_regs = c.fetchall()
    print(f"{cid} ({card}, target {target_reg}): top historical regions = {top_regs}")

