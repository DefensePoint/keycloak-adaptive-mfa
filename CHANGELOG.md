# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- The Adaptive MFA admin page's settings and scoring calls say what is wrong.
  A realm without an engine endpoint, or without the `adaptive-auth-api` client
  or its secret, gets a 409 saying Adaptive MFA is not set up for the realm and
  what is missing; before, the engine was called without a token, or at a URL
  with no host, and the page showed "AMFA engine returned HTTP 401: Malformed
  token" or "AMFA engine unreachable: null". A token request that fails gets a
  502 with what the token endpoint answered. An unreachable engine is described
  in words: an unknown host is named as one, a timeout says how long was
  waited, and a refused connection keeps its detail

- Switching AMFA off for a realm (the admin page's "Enabled" switch, realm
  attribute `adaptiveToggle=false`) now takes effect at login: the engine is
  sent neither the auth context nor the risk request, and the login continues
  as low risk (risk level 1, decision source `amfa_off`). That is the level a
  low-risk answer from the engine gives, so a step-up set at level 2 or above
  does not fire, while a flow branch for level 1 (`EQUAL` or `LESS_OR_EQUAL`)
  runs for every login. A realm without the attribute keeps AMFA as before.
  While AMFA is off the engine records no logins either (the login webhook was
  already off), so after switching back on its history-based signals, such as
  inactive account, do not count the logins made in between

## [1.0.1] - 2026-09-22

### Added

- Adaptive authentication authenticator that calls the AMFA engine for risk evaluation
- Step-up MFA based on risk level (OTP, email code, or deny)
- Configurable fallback risk level per realm
- Configurable failure mode (mandatory or advisory) when the engine is unreachable
- Conditional authenticator with configurable comparison operators
- Webhook event listener that forwards login events to the engine
- Email OTP authenticator (6-digit code, 300-second TTL)
- User-agent parsing for device and browser detection
- Unit tests with JUnit 5 and Mockito
- SECURITY.md, CODE_OF_CONDUCT.md, and CONTRIBUTING.md

[1.0.1]: https://github.com/DefensePoint/keycloak-adaptive-mfa/releases/tag/v1.0.1
