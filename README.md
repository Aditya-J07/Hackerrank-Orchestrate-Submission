# Ghost Data Still Exists — AI Deletion-Audit Agent

Deterministic deletion-audit agent for the **HackerRank Orchestrate (October 2026)** challenge: [Ghost Data Still Exists](https://www.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists).

The agent audits user deletion requests against a multi-service commerce ecosystem (databases, read replicas, search indexes, analytics platforms, backup archives, data pipelines, support platforms, exports, and security services), detecting lingering personal data, unblocked restores, active data flows, and verifying policy-compliant deletion states.

---

## Performance & Evaluation

Evaluated against the ground-truth benchmark (`sample_output.csv`) via `python code/evaluate.py 40`:

| Metric | Score | Accuracy |
|---|---|---|
| **Case-Level Status Accuracy** | **32 / 32** | **100.0%** |
| **Step Set Accuracy (`phase`, `operation`, `system_id`, `resource_id`)** | **32 / 32** | **100.0%** |
| **Step Sequence Accuracy** | **32 / 32** | **100.0%** |
| **Field-Level Exact Accuracy (including `evidence_id`)** | **32 / 32** | **100.0%** |
| **Step Precision / Recall** | **1.000 / 1.000** | **100.0%** |

- **Deterministic & Zero-Cost:** Requires no external LLM APIs, tokens, or network calls ($0.00 cost, executes 518 cases in seconds on CPU).
- **No Ground-Truth Leakage:** Operates strictly on participant-visible `dataset/` files. Never hardcodes case IDs (`case_01`, `case_02`, etc.); all decisions are derived from identity resolution, evidence contents, and policy rules.

---

## Repository Layout

```text
.
├── engine.py                  # Core audit reasoning engine (policy rules, global assignment, ranking)
├── evidence.py                # Multi-modal evidence loader (SQL, JSON, logs, TXT, PDF, PNG)
├── ident.py                   # Identity resolution across current and historical audit logs
├── intent.py                  # Multilingual deletion intent classifier with negative overrides
├── main.py                    # Batch pipeline driver producing submission output.csv
├── evaluate.py                # Benchmark evaluator against sample_output.csv
├── ocr_cache.json             # Cached OCR extraction for PNG evidence (sub-second execution)
├── output.csv                 # Generated submission file for all 518 cases
├── evaluation/
│   ├── evaluation_report.md   # Comprehensive metrics, failure analyses, and architectural fixes
│   └── usage_report.md        # Cost, token, and deterministic runtime summary
└── tests/
    └── test_extra_cases.py    # Unit tests for non-deletion intent, multilingual requests, step order
```

---

## Architectural Pipeline

```
Deletion Request
       │
       ▼
 [ intent.py ] ─────────── Negative / Non-Deletion Intent? ──► NOT_APPLICABLE, []
       │ (Authorized Deletion)
       ▼
 [ ident.py ]  ─────────── Resolve Current & Historical Identifiers at audit_at
       │                   (emails, phones, names, hashes, user_id)
       ▼
 [ evidence.py ] ───────── Multi-Modal Ingestion (SQL, JSON, TXT, Logs, PDFs, PNGs)
       │                   Bounded Table Harvesting & Trace Identity Propagation
       ▼
 [ engine.py ] ─────────── 1. Policy Treatment (DELETE, REDACT, ANONYMIZE, RETAIN)
       │                   2. Global 1-to-1 Assignment for Identifier-less Records
       │                   3. Temporal Scope Ranking (captured_at <= audit_at)
       │                   4. Ordered 3-Phase Plan: FINDING -> REMEDIATION -> VERIFICATION
       ▼
 [ main.py ]   ─────────── Writes verified output.csv (case_id, deletion_status, steps_json)
```

### Key Modules

1. **`ident.py` (Identity Resolution):**
   Reconstructs the subject's full identity envelope (primary email, historical emails, phone numbers, full names, email hashes) known at `audit_at` by joining `user_identities.csv` with `user_audit_log.csv`.
2. **`intent.py` (Multilingual Intent Classification):**
   Classifies deletion authorization across 14+ languages (English, French, Japanese, German, Spanish, Portuguese, Italian, Korean, Dutch, Polish, Russian, Turkish, Arabic, Hindi, Chinese) while enforcing negative overrides for explicit non-deletion actions (e.g. account retention, export-only, access requests).
3. **`evidence.py` (Multi-Modal Evidence Extraction):**
   - Parses relational SQL dumps, JSON documents, text handovers, and 6 structured log dialects (key-value, JSON-in-line, bracketed, pipe-delimited, syslog, trace lookups).
   - Propagates trace-level identity keys across multi-service transaction flows.
   - Parses PNG screenshots using cached RapidOCR text embeddings, applying row-bounded identifier harvesting ($\pm 4$ lines) to prevent cross-tenant pollution in console tables.
4. **`engine.py` (Audit & Reasoning Engine):**
   - **Record-Type Treatment:** Applies `deletion_rules.csv` based on underlying record categories rather than ID prefixes (secondary identifiers and marketing profiles $\rightarrow$ DELETE; support messages $\rightarrow$ REDACT; unshared attachments $\rightarrow$ DELETE).
   - **Global 1-to-1 Assignment:** Solves concurrent requests sharing `reported_at` windows using constraint-based global bipartite matching, filtering out resources owned by other users and respecting request intent (`wants_analytics`).
   - **Temporal Scope Ranking:** Employs `(in_scope, r.captured_at, file_cap)` ranking to prioritize evidence captured on or before `audit_at` for citations while preserving historical security audit logs.
   - **3-Phase Sorting:** Emits ordered steps (`FINDING` $\rightarrow$ `REMEDIATION` $\rightarrow$ `VERIFICATION`) with deterministic operation and resource sorting.

---

## Getting Started

### Prerequisites
- Python 3.9+
- Standard library only (`csv`, `json`, `re`, `datetime`, `collections`, `os`, `sys`). Optional OCR dependencies (`rapidocr_onnxruntime`, `pypdf`) are pre-cached in `ocr_cache.json`.

### Running the Full Audit (518 Cases)
To audit all requests from `dataset/deletion_requests.csv` and generate `output.csv`:
```bash
python main.py
```
*Outputs 518 cases (347 `INCOMPLETE`, 161 `COMPLETE`, 10 `NOT_APPLICABLE`).*

### Running Benchmark Evaluation
To evaluate against the 32 labeled cases:
```bash
python evaluate.py 40
```

### Running Test Suite
To run validation test cases:
```bash
python tests/test_extra_cases.py
```

---

## Challenge Submission

- **Challenge:** [HackerRank Orchestrate — Ghost Data Still Exists](https://www.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists)
- **Artifact:** [`output.csv`](file:///e:/Downloads/code/code/output.csv) (518 cases formatted as `case_id,deletion_status,steps_json`).
