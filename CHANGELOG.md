# auth-template - Changelog
# 3.0.0

- Require IAM 5 and accept authentication protection options.
- Return `null` for expected authentication rejection and blocked attempts;
  narrowly classify SimpleWebAuthn validation errors and propagate outages.
- Reject inactive principals before authentication verification.
- Document the principal-to-application-session boundary and HTTP error handling.
