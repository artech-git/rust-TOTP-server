# Security policy

This service is an authentication component, so security reports are handled
ahead of everything else.

## Reporting a vulnerability

Please do **not** open a public issue for anything that could be exploited.
Use GitHub's private reporting instead: **Security → Report a vulnerability**
on this repository. Include the affected endpoint or module, steps to
reproduce, and the impact you believe it has.

You will get an acknowledgement within a few days. Fixes ship as a patch
release with a note in the release description; credit is given if you want it.

## Supported versions

Only the latest release on `main` receives fixes.

## What is in scope

- Anything that lets a TOTP code, recovery code or session token be reused,
  forged, brute-forced faster than the documented limits, or bypassed.
- Anything that reveals a stored secret, a recovery-code hash, or another
  user's data.
- Rate-limit or lockout bypasses, including through trusted-proxy headers.
- Dependency advisories that reach this binary (CI runs `cargo audit`).

Denial-of-service findings that require more resources than the documented
single-instance deployment is meant to absorb are welcome but lower priority.

## Operational notes for deployers

- Run `totp-server keygen` and set **both** keys for production; the ephemeral
  defaults are for development only.
- Keep `secret_encryption_key` stable. Rotating it makes every stored TOTP
  secret unreadable.
- Enable `server.trust_proxy` only behind a proxy you control, and never
  expose the service directly to the internet with it on.
- Treat `/metrics` as internal.
