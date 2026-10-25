import sys
sys.path.insert(0, 'code')
from ident import rd
import engine, json

req = rd('sample_deletion_requests.csv')
gold = {r['case_id']: r for r in rd('sample_output.csv')}

for r in req:
    st, steps = engine.audit(r)
    g = gold[r['case_id']]
    gs = json.loads(g['steps_json'])
    diffs = []
    for s1, s2 in zip(steps, gs):
        for k in set(s1.keys()) | set(s2.keys()):
            if s1.get(k) != s2.get(k):
                diffs.append((s1['resource_id'], k, s1.get(k), s2.get(k)))
    if diffs:
        print(f"{r['case_id']} ({st}):")
        for d in diffs:
            print(f"  {d[0]} field {d[1]}: mine={repr(d[2])} vs gold={repr(d[3])}")
