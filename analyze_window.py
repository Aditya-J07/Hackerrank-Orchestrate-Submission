"""Analyze window_links cases."""
import sys
sys.path.insert(0, 'code')
from ident import rd, resolve, IDS, AUD
import engine, evidence as E
from datetime import datetime

_P = datetime.strptime

samples = {r['case_id']: r for r in rd('sample_deletion_requests.csv')}

# Cases with window_link problems: 21, 23, 25, 27, 28, 31
problem_cases = ['case_21', 'case_23', 'case_25', 'case_27', 'case_28', 'case_31']
print("Case reported_at windows and uids:")
for cid in problem_cases:
    req = samples[cid]
    uid, idn = resolve(req['email'], req['audit_at'])
    print(f"  {cid}: uid={uid} reported_at={req['reported_at']} audit_at={req['audit_at']}")

print("\nActivity rows (DELETE/ANONYMIZE from deletion_worker on account_service/analytics_platform):")
E._ALL = None
engine._OWN = None

ACTIVITY = rd('system_activity.csv')
from engine import _P as parse_t

for a in ACTIVITY:
    if (a['source_system'] == 'deletion_worker' and 
        a['event_type'] in ('DELETE_RECORD', 'ANONYMIZE_RECORD') and
        a['target_system'] in ('account_service', 'analytics_platform')):
        print(f"  {a['event_time']} {a['event_type']} {a['target_system']} {a['resource_id']}")

print("\nOwners of account/analytics resources:")
own = engine.owners_of_resources()
for rid, owners in own.items():
    if 'account' in rid or 'analytics' in rid:
        print(f"  {rid}: {owners}")
