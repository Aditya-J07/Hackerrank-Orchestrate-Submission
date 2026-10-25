"""Ghost Data audit agent. Usage: python3 code/main.py [requests.csv] [out.csv]"""
import csv, json, os, sys
sys.path.insert(0, os.path.dirname(__file__))
from ident import rd, D
import engine
def run(reqf, outf):
    rows = []
    for r in rd(os.path.basename(reqf)) if os.path.dirname(reqf) in ('', D) else list(csv.DictReader(open(reqf, encoding='utf-8'))):
        status, steps = engine.audit(r)
        rows.append((r['case_id'], status, json.dumps(steps, ensure_ascii=False, separators=(',', ':'))))
    rows.sort(key=lambda x: (int(x[0].split('_')[-1]) if x[0].split('_')[-1].isdigit() else 0, x[0]))
    with open(outf, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f); w.writerow(['case_id', 'deletion_status', 'steps_json']); w.writerows(rows)
    return rows
if __name__ == '__main__':
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    reqf = sys.argv[1] if len(sys.argv) > 1 else os.path.join(D, 'deletion_requests.csv')
    outf = sys.argv[2] if len(sys.argv) > 2 else os.path.join(root, 'output.csv')
    rows = run(reqf, outf)
    import collections; print(len(rows), 'rows', collections.Counter(r[1] for r in rows))
