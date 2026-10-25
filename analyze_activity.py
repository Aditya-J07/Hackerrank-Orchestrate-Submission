"""Analyze activity windows for cases 21, 23, 25, 27, 28, 31."""
import sys
sys.path.insert(0, 'code')
from ident import rd
from datetime import datetime

ACTIVITY = rd('system_activity.csv')
_P = lambda t: datetime.strptime(t, '%Y-%m-%dT%H:%M:%SZ')

cases = [
    ('case_21', 'user_21', '2026-09-05T12:00:00Z'),
    ('case_23', 'user_23', '2026-09-05T12:00:00Z'),
    ('case_25', 'user_25', '2026-09-02T12:00:00Z'),
    ('case_27', 'user_27', '2026-08-30T12:00:00Z'),
    ('case_28', 'user_28', '2026-08-30T12:00:00Z'),
    ('case_31', 'user_541', '2026-09-06T12:00:00Z'),
]

for cid, uid, reported_at in cases:
    rep = _P(reported_at)
    print(f'\n=== {cid} uid={uid} reported_at={reported_at} ===')
    for a in ACTIVITY:
        if (a['source_system'] == 'deletion_worker' and
                a['event_type'] in ('DELETE_RECORD', 'ANONYMIZE_RECORD') and
                a['target_system'] in ('account_service', 'analytics_platform')):
            dt = (rep - _P(a['event_time'])).total_seconds()
            if -900 <= dt <= 4 * 3600:
                det = a['details'][:80]
                print(f"  dt={dt:.0f}s  {a['event_time']}  {a['event_type']}  {a['resource_id']}  details={det}")

# Also show expected sample output for these cases
print('\n\n=== Expected answers from sample_output ===')
import json, csv
for row in csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8')):
    if row['case_id'] in [c[0] for c in cases]:
        steps = json.loads(row['steps_json'])
        acct = [s for s in steps if 'account' in s.get('resource_id', '')]
        ana = [s for s in steps if 'analytics' in s.get('resource_id', '')]
        print(f"  {row['case_id']}: status={row['deletion_status']}")
        for s in acct + ana:
            print(f"    {s['resource_id']} {s['operation']} ev={s['evidence_id']}")
