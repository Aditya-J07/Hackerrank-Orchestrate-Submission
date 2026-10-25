"""Analyze case_26 observations."""
import sys, os
sys.path.insert(0, 'code')
from ident import rd, resolve
import engine, evidence as E

req = next(r for r in rd('sample_deletion_requests.csv') if r['case_id'] == 'case_26')
print('case_26:', req['email'], 'audit_at:', req['audit_at'])
uid, idn = resolve(req['email'], req['audit_at'])
print('uid:', uid, 'idn:', idn)

E._ALL = None
engine._OWN = None
obs = engine.collect(uid, idn, req['audit_at'])

print('\nAll observations:')
for rid, o in obs.items():
    r = o['rec']
    print(f"  {rid}: states={o['states']} file={r.file_id} captured={r.captured_at} observed_at={r.raw.get('observed_at','') if isinstance(r.raw,dict) else ''}")
    if isinstance(r.raw, dict):
        print(f"    raw_keys={list(r.raw.keys())[:8]}")
        if 'profile' in r.raw:
            print(f"    profile={r.raw['profile']}")
        if 'status_code' in r.raw:
            print(f"    status_code={r.raw['status_code']}")
        if 'account_status' in r.raw:
            print(f"    account_status={r.raw['account_status']}")
