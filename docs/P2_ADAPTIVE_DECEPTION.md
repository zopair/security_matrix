# P2: bounded adaptive deception

The opt-in decoy routes select among three fixed synthetic response profiles. The
profile changes with the per-client request sequence; content size, record count,
and output schemas remain finite and capped. This is deliberately bounded
polymorphism, not a promise that a capable attacker cannot recognize synthetic
content.

## Safety controls

- Disabled by default via `SECURITYMATRIX_DECEPTION_ENABLED=false`.
- Exact registered routes only; arbitrary suspicious paths are not redirected
  into decoys.
- Existing per-client rate limits apply; rate-limited events are added to the
  local evidence engine.
- Responses use `Cache-Control: no-store` and include a profile number for
  controlled testing.
- No production credentials, secrets, internal service discovery, unbounded
  strings, recursive output, external network calls, or resource-exhaustion
  behavior is generated.
- Response bodies are checked against `SECURITYMATRIX_DECEPTION_MAX_RESPONSE_BYTES`.

## Test in isolation

Enable deception only in a disposable local/test environment. Do not turn it on
for production traffic until routes, proxy behavior, monitoring, and false
positive handling are reviewed.

```bash
python -m pytest -q tests/test_adaptive_deception.py tests/test_p0_resource_bounds.py
```

Profiles are a defensive telemetry aid, not an access-control boundary. Real
authorization, least privilege, key isolation, and rate limiting at the edge
remain the primary protections.
