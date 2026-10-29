# P1: Local risk and evidence engine

The engine in `app/risk_evidence.py` correlates request/scanner metadata locally.
It uses deterministic, explainable rules and bounded in-memory buffers. It does
not call an external model, send telemetry outside the process, block requests,
or claim to identify AI agents.

## API

- `GET /api/security/evidence?limit=100`: bounded recent evidence.
- `GET /api/security/incidents?limit=50`: bounded incident summaries with a
  short ordered sequence of supporting events.
- `GET /api/metrics`: includes current evidence-engine capacity and counts.

Limits are controlled by:
- `SECURITYMATRIX_EVIDENCE_EVENTS` (default 2,000; accepted 100–10,000).
- `SECURITYMATRIX_EVIDENCE_INCIDENTS` (default 250; accepted 25–1,000).
- `SECURITYMATRIX_EVIDENCE_WINDOW_SECONDS` (default 300; accepted 30–3,600).

Only a keyed hash derived from the direct peer address and a truncated User-Agent
is used internally for request correlation. The raw address is not stored by this
engine, forwarded headers are not trusted, and the actor hash is removed before
events are exposed or written to the JSONL audit log. Shared NAT and changing
User-Agent values can cause grouping errors; the score is for analyst triage only.

## Scoring and interpretation

Base scores use existing request signals and bounded severity mapping for
scanner findings. Repeated events for the same hashed actor in a fixed time
bucket add at most 20 points. Each incident preserves at most 50 sequence
entries. The engine uses a fixed time bucket, not a sliding window. Incident IDs
are opaque correlation labels, not proof of attribution.

No event score automatically blocks a request, changes permissions, or triggers
a network scan. Analysts should review source evidence and false positives before
taking action. The engine's buffers reset on restart; the JSONL log remains the
separate, size-limited audit record.

## Test

Run the focused tests:

```bash
python -m pytest -q tests/test_risk_evidence.py tests/test_risk_evidence_api.py
```

Review the CI run on the P1 pull request before merging.
