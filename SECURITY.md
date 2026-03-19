# Security Policy

## Status

`fastapi-mpp` is **Beta** software.

**Beta - use with caution.**

This library handles payment authorization metadata and must be deployed with strict
operational controls. `v0.2` focuses on urgent hardening, but it is not a complete
security program by itself.

## Threat Model Summary

The middleware is exposed to untrusted HTTP clients and potentially malicious agents.
Primary threats include:

- Receipt forgery or tampering.
- Replay of valid receipts to charge-free call paths.
- Session token theft/reuse (session hijacking).
- Challenge swapping or unbound challenge replay across routes.
- Header-based memory/CPU abuse (oversized or malformed inputs).
- Challenge flooding and resource exhaustion.
- Downgrade attacks through legacy, non-standard header paths.
- Insecure transport leaks when TLS is not strictly enforced.

Assumptions:

- Provider cryptographic verification (`pympp.validate` or custom validator) is trustworthy.
- Application secrets (for session signing) are managed securely.
- Reverse proxy forwards trusted `X-Forwarded-*` headers only.

## Known Vulnerabilities (v0.1.1) and v0.2 Status

1. Receipt validation optional / bypass-prone
- v0.1.1: `receipt_validator` could be absent in production paths.
- v0.2 status: **Mitigated** with fail-closed startup behavior in production mode.
- Residual risk: misconfigured debug mode in production.

2. Receipt replay attacks
- v0.1.1: no receipt consumption registry with expiry.
- v0.2 status: **Mitigated (basic)** with in-memory consumed-receipt TTL tracking.
- Residual risk: in-memory store is process-local; multi-instance replay remains possible.

3. Session hijacking / weak session IDs
- v0.1.1: session IDs were bearer-like and weakly bound.
- v0.2 status: **Mitigated (basic)** with HMAC-signed opaque tokens and claim checks.
- Residual risk: stolen valid token can be used until expiry.

4. Unbound challenges
- v0.1.1: challenge-response linkage was weak.
- v0.2 status: **Mitigated (basic)** by issuing challenge IDs and validating route/amount/currency binding.
- Residual risk: in-memory challenge state is single-process only.

5. Non-conformance to Payment authentication draft behavior
- v0.1.1: legacy header model only.
- v0.2 status: **Partially mitigated** with `WWW-Authenticate: Payment ...`,
  `Authorization: Payment credential="..."`, and `Payment-Receipt` support.
- Residual risk: draft is evolving; full normative conformance is not yet claimed.

6. Header memory DoS
- v0.1.1: weak header-size and malformed-input rejection.
- v0.2 status: **Mitigated (basic)** with `8KB` size limits and strict parsing.

7. Challenge flooding / basic abuse controls
- v0.1.1: no challenge issuance throttling.
- v0.2 status: **Mitigated (basic)** with in-memory per-IP challenge rate limiting.
- Residual risk: weak in distributed deployments and vulnerable to IP spoofing behind bad proxies.

8. Insecure transport acceptance
- v0.1.1: no strict HTTPS enforcement.
- v0.2 status: **Mitigated** in production mode with HTTPS checks.
- Residual risk: depends on correct proxy header trust configuration.

9. Excessive sensitive logging
- v0.1.1: risk of logging full receipt payloads.
- v0.2 status: **Mitigated** by avoiding full receipt logging and logging only minimal identifiers.

## Vulnerability Disclosure

Please report security issues through GitHub:

- Issues: https://github.com/your-org/fastapi-mpp/issues

Recommended report contents:

- Affected version(s)
- Reproduction steps / proof of concept
- Impact assessment
- Suggested remediation (optional)

Security bug reports should avoid posting real payment credentials or secrets.

## Production Hardening Checklist

Before production rollout, verify all items:

- Install with Tempo validation support: `pip install "fastapi-mpp[tempo]"` or provide a custom `receipt_validator`.
- Ensure production mode (`debug_mode=False`) is active.
- Configure `MPP_SESSION_SECRET` with a strong random secret.
- Enforce TLS end-to-end and trusted proxy header handling.
- Use persistent shared stores (Redis) for replay/session/challenge state.
- Set tight session/challenge TTLs and sane per-endpoint budgets.
- Monitor `409`, `429`, and `400 invalid_receipt` patterns.
- Scrub logs for sensitive receipt/payment data.
- Disable legacy headers when all clients support Payment auth headers.
- Add integration tests for replay, signature tampering, and route-scope hijack attempts.

## Remaining Risk and Honesty Statement

`v0.2` addresses critical immediate weaknesses but is not the final security state.
In-memory controls are not sufficient for horizontally scaled production systems,
and protocol conformance remains partial while the payment authentication draft evolves.
