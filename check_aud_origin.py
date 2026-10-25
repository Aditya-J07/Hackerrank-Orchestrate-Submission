import csv, json, sys
sys.path.insert(0, 'code')
import evidence as E

recs = E.load_all()
ev_rids = {r.resource_id: r.file_id for r in recs}
with open('dataset/sample_output.csv', encoding='utf-8') as f:
    for row in csv.DictReader(f):
        steps = json.loads(row['steps_json'])
        auds = [s['resource_id'] for s in steps if s['resource_id'].startswith('audit_record_')]
        for a in auds:
            print(f"{row['case_id']}: {a} in_evidence={a in ev_rids} fid={ev_rids.get(a)}")
