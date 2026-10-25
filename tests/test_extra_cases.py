"""Three additional hand-made evaluation cases (synthetic requests run through the real engine)."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import engine
from intent import wants_deletion

def test_non_deletion_request_is_not_applicable():
    req = dict(case_id='x1', email='amina.elmasri@gmail.com', requested_at='2026-08-18T09:14:00Z', reported_status='COMPLETE',
               reported_at='2026-08-20T16:42:00Z', audit_at='2026-09-03T11:30:00Z',
               request_text='Please update my phone number. Do not close the account.')
    assert engine.audit(req) == ('NOT_APPLICABLE', [])

def test_multilingual_deletion_intent():
    assert wants_deletion('Je demande la suppression définitive du compte associé à cette adresse e-mail.')
    assert wants_deletion('このメールアドレスに関連するアカウントの完全な削除を依頼します。')

def test_step_order_and_numbering():
    req = dict(case_id='x3', email='leila.haddad@yahoo.com', requested_at='2026-08-27T14:17:00Z', reported_status='COMPLETE',
               reported_at='2026-08-28T09:03:00Z', audit_at='2026-09-08T13:40:00Z', request_text='Please delete my account and data.')
    st, steps = engine.audit(req)
    assert [s['step_no'] for s in steps] == list(range(1, len(steps) + 1))
    phases = [s['phase'] for s in steps]
    assert phases == sorted(phases, key=['FINDING', 'REMEDIATION', 'VERIFICATION'].index)
    if st == 'INCOMPLETE':
        assert all(s['evidence_id'] == '' for s in steps if s['phase'] != 'FINDING')
if __name__ == '__main__':
    for n, f in list(globals().items()):
        if n.startswith('test_'): f(); print('PASS', n)
