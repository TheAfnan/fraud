import sys
import json
import sqlite3
import urllib.request
import logging
from pathlib import Path
from typing import Dict, List, Any

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.config import BASE_DIR, TG_GRAPH
from backend.tigergraph.client import tigergraph_client

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger('tg_benchmark_loader')

DB_PATH = BASE_DIR / 'data' / 'fraud_graph.db'

def post_batch(payload: Dict[str, Any]) -> int:
    url = f'{tigergraph_client.host}/restpp/graph/{TG_GRAPH}'
    headers = tigergraph_client._get_auth_headers()
    headers['Content-Type'] = 'application/json'
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=60.0) as resp:
        res = json.loads(resp.read().decode('utf-8'))
        results = res.get('results', [{}])[0]
        accepted_v = results.get('accepted_vertices', 0)
        accepted_e = results.get('accepted_edges', 0)
        return accepted_v + accepted_e

def load_benchmark_data():
    logger.info('Starting Benchmark Ingestion into TigerGraph Savanna Cloud...')
    if not tigergraph_client.is_live():
        logger.error('TigerGraph is NOT live. Check .env and cluster status.')
        sys.exit(1)

    tigergraph_client.request_token()

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute('SELECT case_id, card_id, customer_id, flagged_txn_id FROM case_pack')
    benchmark_cases = cur.fetchall()
    benchmark_cards = list({row[1] for row in benchmark_cases})
    benchmark_custs = list({row[2] for row in benchmark_cases})

    logger.info(f'Targeting {len(benchmark_cases)} benchmark cases, {len(benchmark_cards)} cards, {len(benchmark_custs)} customers.')

    # 1. Customers & Cards
    payload = {'vertices': {'Customer': {}, 'Card': {}}, 'edges': {'Customer': {}}}
    for cust in benchmark_custs:
        payload['vertices']['Customer'][cust] = {'customer_id': {'value': cust}}

    for card_id in benchmark_cards:
        cur.execute('SELECT customer_id, card1, card2, card3, card4, card5, card6 FROM transactions WHERE card_id = ? LIMIT 1', (card_id,))
        crow = cur.fetchone()
        if crow:
            cust_id, c1, c2, c3, c4, c5, c6 = crow
        else:
            cust_id = card_id.split('-')[0]
            c1 = c2 = c3 = c4 = c5 = c6 = ''

        payload['vertices']['Card'][card_id] = {
            'card_id': {'value': card_id},
            'customer_id': {'value': cust_id},
            'card1': {'value': str(c1 or '')},
            'card2': {'value': str(c2 or '')},
            'card3': {'value': str(c3 or '')},
            'card4': {'value': str(c4 or '')},
            'card5': {'value': str(c5 or '')},
            'card6': {'value': str(c6 or '')}
        }
        if cust_id not in payload['edges']['Customer']:
            payload['edges']['Customer'][cust_id] = {'OWNS': {'Card': {}}}
        payload['edges']['Customer'][cust_id]['OWNS']['Card'][card_id] = {}

    count = post_batch(payload)
    logger.info(f'Uploaded Customers & Cards (Accepted records: {count})')

    # 2. Transactions for benchmark cards
    placeholders = ','.join(['?'] * len(benchmark_cards))
    cur.execute(f'SELECT TransactionID, customer_id, card_id, TransactionAmt, ts, ProductCD, channel, risk_score, addr1, addr2, dist1, dist2, P_emaildomain FROM transactions WHERE card_id IN ({placeholders}) ORDER BY card_id, ts ASC', benchmark_cards)
    txns = cur.fetchall()
    logger.info(f'Retrieved {len(txns)} transactions for benchmark cards.')

    txn_ids = [t[0] for t in txns]
    ident_map = {}
    if txn_ids:
        cur.execute(f'SELECT TransactionID, device_profile, DeviceInfo, id_30, id_31, id_33, DeviceType, id_23 FROM identity WHERE TransactionID IN ({','.join(['?']*len(txn_ids))})', txn_ids)
        for irow in cur.fetchall():
            ident_map[irow[0]] = irow

    chunk_size = 400
    for i in range(0, len(txns), chunk_size):
        chunk = txns[i:i + chunk_size]
        t_payload = {
            'vertices': {'Transaction': {}, 'DeviceProfile': {}, 'EmailDomain': {}, 'BillingRegion': {}},
            'edges': {'Card': {}, 'Transaction': {}}
        }

        for row in chunk:
            tid, cust, cid, amt, ts, prod, chan, risk, a1, a2, d1, d2, p_email = row

            t_payload['vertices']['Transaction'][tid] = {
                'txn_id': {'value': str(tid)},
                'amount': {'value': float(amt or 0.0)},
                'ts': {'value': str(ts)},
                'product_cd': {'value': str(prod or '')},
                'channel': {'value': str(chan or '')},
                'risk_score': {'value': float(risk or 0.0)},
                'addr1': {'value': str(a1 or '')},
                'addr2': {'value': str(a2 or '')},
                'dist1': {'value': float(d1) if d1 is not None else 0.0},
                'dist2': {'value': float(d2) if d2 is not None else 0.0}
            }

            if cid not in t_payload['edges']['Card']:
                t_payload['edges']['Card'][cid] = {'MADE': {'Transaction': {}}}
            t_payload['edges']['Card'][cid]['MADE']['Transaction'][tid] = {}

            if p_email:
                t_payload['vertices']['EmailDomain'][p_email] = {'domain': {'value': str(p_email)}}
                if tid not in t_payload['edges']['Transaction']:
                    t_payload['edges']['Transaction'][tid] = {}
                if 'PURCHASER_EMAIL' not in t_payload['edges']['Transaction'][tid]:
                    t_payload['edges']['Transaction'][tid]['PURCHASER_EMAIL'] = {'EmailDomain': {}}
                t_payload['edges']['Transaction'][tid]['PURCHASER_EMAIL']['EmailDomain'][p_email] = {}

            if a1:
                t_payload['vertices']['BillingRegion'][str(a1)] = {'region_code': {'value': str(a1)}}
                if tid not in t_payload['edges']['Transaction']:
                    t_payload['edges']['Transaction'][tid] = {}
                if 'BILLED_IN' not in t_payload['edges']['Transaction'][tid]:
                    t_payload['edges']['Transaction'][tid]['BILLED_IN'] = {'BillingRegion': {}}
                t_payload['edges']['Transaction'][tid]['BILLED_IN']['BillingRegion'][str(a1)] = {}

            if tid in ident_map:
                _, dprof, dinfo, os_val, browser, screen, dev_type, is_proxy = ident_map[tid]
                if dprof and dprof != '|||':
                    t_payload['vertices']['DeviceProfile'][dprof] = {
                        'profile_id': {'value': str(dprof)},
                        'device_info': {'value': str(dinfo or '')},
                        'os': {'value': str(os_val or '')},
                        'browser': {'value': str(browser or '')},
                        'screen': {'value': str(screen or '')},
                        'device_type': {'value': str(dev_type or '')},
                        'is_proxy': {'value': str(is_proxy or '')}
                    }
                    if tid not in t_payload['edges']['Transaction']:
                        t_payload['edges']['Transaction'][tid] = {}
                    if 'FROM_DEVICE' not in t_payload['edges']['Transaction'][tid]:
                        t_payload['edges']['Transaction'][tid]['FROM_DEVICE'] = {'DeviceProfile': {}}
                    t_payload['edges']['Transaction'][tid]['FROM_DEVICE']['DeviceProfile'][dprof] = {
                        'device_status': {'value': 'active'}
                    }

        c_count = post_batch(t_payload)
        logger.info(f'Uploaded batch {i//chunk_size + 1}/{(len(txns)-1)//chunk_size + 1} (Accepted records: {c_count})')

    # 3. Closed Cases
    cur.execute('SELECT case_id, customer_id, card_id, opened_at, closed_at, outcome, pattern, first_fraud_txn_id, n_txns, exposure_usd, actions_taken, report_filed, analyst_notes FROM closed_cases LIMIT 2000')
    cases = cur.fetchall()
    logger.info(f'Uploading {len(cases)} historical closed cases into TigerGraph...')

    case_chunk = 500
    for i in range(0, len(cases), case_chunk):
        chunk = cases[i:i + case_chunk]
        c_payload = {'vertices': {'ClosedCase': {}}, 'edges': {'ClosedCase': {}}}
        for row in chunk:
            case_id, cust, cid, op, cl, outc, pat, f_txn, n_t, exp, act, rep, notes = row
            c_payload['vertices']['ClosedCase'][case_id] = {
                'case_id': {'value': str(case_id)},
                'customer_id': {'value': str(cust or '')},
                'card_id': {'value': str(cid or '')},
                'opened_at': {'value': str(op or '1970-01-01 00:00:00')},
                'closed_at': {'value': str(cl or '1970-01-01 00:00:00')},
                'outcome': {'value': str(outc or '')},
                'pattern': {'value': str(pat or '')},
                'first_fraud_txn_id': {'value': str(f_txn or '')},
                'n_txns': {'value': int(n_t or 0)},
                'exposure_usd': {'value': float(exp or 0.0)},
                'actions_taken': {'value': str(act or '')},
                'report_filed': {'value': str(rep or 'No')},
                'analyst_notes': {'value': str(notes or '')}
            }

            if cid in benchmark_cards:
                if case_id not in c_payload['edges']['ClosedCase']:
                    c_payload['edges']['ClosedCase'][case_id] = {}
                if 'ON_CARD' not in c_payload['edges']['ClosedCase'][case_id]:
                    c_payload['edges']['ClosedCase'][case_id]['ON_CARD'] = {'Card': {}}
                c_payload['edges']['ClosedCase'][case_id]['ON_CARD']['Card'][cid] = {}

        c_count = post_batch(c_payload)
        logger.info(f'Uploaded ClosedCase batch {i//case_chunk + 1}/{(len(cases)-1)//case_chunk + 1} (Accepted records: {c_count})')

    conn.close()
    logger.info('TigerGraph Savanna benchmark ingestion successfully completed!')

if __name__ == '__main__':
    load_benchmark_data()