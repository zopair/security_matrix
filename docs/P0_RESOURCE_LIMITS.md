# P0: bounded resource controls

SecurityMatrix deception is **disabled by default**. Set
`SECURITYMATRIX_DECEPTION_ENABLED=true` only in an isolated test environment
after reviewing network access and the reverse-proxy configuration.

## Limits

- Synthetic response body: `SECURITYMATRIX_DECEPTION_MAX_RESPONSE_BYTES`
  (default 2,048 bytes; accepted range 256–8,192).
- Per-client decoy rate: `SECURITYMATRIX_DECEPTION_MAX_HITS` requests per
  `SECURITYMATRIX_DECEPTION_WINDOW_SECONDS` (defaults 8 per 60 seconds).
- In-memory decoy events: 500 entries; rate-limit client keys: at most 2,000.
- Main in-memory event buffer: `SECURITYMATRIX_MAX_EVENTS` (100–10,000).
- JSONL audit log: `SECURITYMATRIX_MAX_LOG_BYTES` (64 KiB–10 MiB; default 1 MiB)
  with one rotated backup at `events.jsonl.1`.
- Request bodies are streamed and capped before JSON parsing: 1 MiB for finding
  ingestion and 16 KiB for local assessment requests.

Rate limiting and buffers are process-local. They reset on restart and are not a
replacement for edge/proxy limits in multi-worker or multi-instance deployments.
The client key hashes the direct peer address; forwarded headers are deliberately
not trusted. Shared NAT may group multiple users under one limit.

## Behavioral safety

The request gateway records suspicious patterns but does not convert arbitrary
unknown paths into successful synthetic responses. Only exact, explicit decoy
routes return synthetic data, and only while the opt-in flag is enabled.
All decoy content is fixed, synthetic, and never reads production secrets or
calls an external service. Oversized bodies are rejected before parsing.

## Verification

Run locally in the repository environment:

```bash
python -m pytest -q tests/test_p0_resource_bounds.py
```

The tests cover disabled-by-default behavior, normal health route availability,
non-interception of suspicious unknown paths, rate limiting, response-size caps,
and request-body limits. Review CI results before merging; this change does not
claim production readiness or a successful test run until CI actually completes.
