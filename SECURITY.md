# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | Yes       |

## Reporting a Vulnerability

Please do **not** open a public GitHub issue for security vulnerabilities.

Report security issues by emailing **security@defensepoint.com**. Include:

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fix (optional)

We will acknowledge receipt within 48 hours and aim to release a fix within 14 days for critical issues.

## Scope

This plugin runs inside Keycloak and sits in the authentication flow. When
reporting, it helps to say which trust boundary is involved:

- The authenticator's decision path: the risk level it receives from the engine
  and the step-up it selects from that level
- Its behaviour when the engine cannot be reached, which is governed by the
  realm's `adaptiveAuthFailureMode`: `mandatory` denies the login, otherwise
  the login proceeds at the realm's configured fallback risk level
- The authentication context it sends to the engine, which carries the client,
  IP address, user agent and other request signals
- The webhook event listener that forwards login events to the engine
- The step-up authenticators themselves, including emailed codes and TOTP
