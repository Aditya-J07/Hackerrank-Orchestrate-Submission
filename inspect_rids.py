import csv, json

with open("dataset/sample_output.csv", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        steps = json.loads(row["steps_json"])
        rids = [s["resource_id"] for s in steps]
        auds = [r for r in rids if r.startswith("audit_record_")]
        supps = [r for r in rids if r.startswith("support_")]
        accs = [r for r in rids if r.startswith("account_")]
        srchs = [r for r in rids if r.startswith("search_")]
        anals = [r for r in rids if r.startswith("analytics_")]
        print(row["case_id"], "aud:", auds, "acc:", accs, "supp:", supps, "srch:", srchs, "anal:", anals)
