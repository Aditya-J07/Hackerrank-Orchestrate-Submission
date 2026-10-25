import sys, json, collections
from ident import rd
import engine
def key(s): return (s['phase'], s['operation'], s['system_id'], s['resource_id'])
def run(reqf='sample_deletion_requests.csv', goldf='sample_output.csv', verbose=0):
    req = rd(reqf); gold = {r['case_id']: r for r in rd(goldf)}
    tot = collections.Counter(); bad = []
    for r in req:
        st, steps = engine.audit(r); g = gold[r['case_id']]; gs = json.loads(g['steps_json'])
        a, b = {key(s) for s in steps}, {key(s) for s in gs}
        tot['cases'] += 1; tot['status_ok'] += st == g['deletion_status']
        tot['set_ok'] += a == b; tot['seq_ok'] += [key(s) for s in steps] == [key(s) for s in gs]
        tot['exact_ok'] += steps_norm(steps) == steps_norm(gs)
        tot['tp'] += len(a & b); tot['fp'] += len(a - b); tot['fn'] += len(b - a)
        if a != b or st != g['deletion_status']: bad.append((r['case_id'], st, g['deletion_status'], sorted(a - b), sorted(b - a)))
    p = tot['tp'] / max(1, tot['tp'] + tot['fp']); rc = tot['tp'] / max(1, tot['tp'] + tot['fn'])
    print({k: tot[k] for k in ('cases','status_ok','set_ok','seq_ok','exact_ok')}, 'step P=%.3f R=%.3f' % (p, rc))
    for b in bad[:verbose]: print(b[0], b[1], b[2], '\n   extra', b[3], '\n   missing', b[4])
def steps_norm(s): return json.dumps([dict(sorted(x.items())) for x in s], sort_keys=True)
if __name__ == '__main__': run(verbose=int(sys.argv[1]) if len(sys.argv) > 1 else 0)
