import csv, os
D = os.path.join(os.path.dirname(__file__), '..', 'dataset')
def rd(n): return list(csv.DictReader(open(os.path.join(D, n), encoding='utf-8')))
IDS = rd('user_identities.csv'); AUD = rd('user_audit_log.csv')
def resolve(email, audit_at):
    """Return user_id + set of all identifiers (current + historical) known at audit_at."""
    e = email.strip().lower()
    uid = None
    for r in IDS:
        if r['email'].lower() == e: uid = r['user_id']
    if not uid:
        for a in AUD:
            if a['field_name'] == 'email' and (a['old_value'].lower() == e or a['new_value'].lower() == e):
                uid = a['user_id']
    if not uid: return None
    cur = next(r for r in IDS if r['user_id'] == uid)
    idents = {'emails': {cur['email'].lower()}, 'phones': {cur['phone']}, 'names': {cur['name']}, 'hashes': {cur['email_hash']}}
    for a in AUD:
        if a['user_id'] != uid or a['event_time'] > audit_at: continue
        f = a['field_name']; k = {'email':'emails','phone':'phones','name':'names','email_hash':'hashes'}.get(f)
        if k:
            for v in (a['old_value'], a['new_value']):
                if v: idents[k].add(v.lower() if k=='emails' else v)
    idents['emails'].add(e)
    return uid, idents
