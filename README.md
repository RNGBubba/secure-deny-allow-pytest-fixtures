# Secure Deny/Allow Pytest Fixtures

Reusable assertions for two security controls:

- guest access to a protected resource returns HTTP 401;
- encoded path traversal requests are rejected while a safe file path remains available.

The tests use a tiny in-memory demo adapter. Replace `app.request` with an adapter for the service under test; the assertions intentionally check observable status codes rather than implementation details.

## Run

```text
pytest -q
```

This is defensive QA test code, not an exploit tool. It makes no network requests and does not access files outside the fixture's in-memory map.
