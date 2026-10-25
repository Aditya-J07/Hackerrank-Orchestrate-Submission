# Ghost Data Still Exists: deletion audit agent

Run: `python3 code/main.py` writes `output.csv` at the repo root. Evaluate: `python3 code/evaluate.py`. Tests: `python3 code/tests/test_extra_cases.py`.
Requires Python 3.9+ and only the standard library.

Pipeline: `ident.py` (current + historical identifiers) -> `intent.py` (deletion vs NOT_APPLICABLE) -> `evidence.py` (SQL, JSON, TXT, 6 log dialects) -> `engine.py` (rules from `deletion_rules.csv`, activity-based linking, ordered steps) -> `main.py`.
No hardcoded case IDs or labels. Evidence after `audit_at` is ignored.
Status: partial. PDF/PNG evidence is not yet parsed and some linking is heuristic; see `evaluation/evaluation_report.md`.
