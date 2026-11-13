# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Switching AMFA off for a realm (the admin page's "Enabled" switch, realm
  attribute `adaptiveToggle=false`) now takes effect at login: the engine is
  sent neither the auth context nor the risk request, and the login continues
  as low risk (risk level 1, decision source `amfa_off`). That is the level a
  low-risk answer from the engine gives, so a step-up set at level 2 or above
  does not fire, while a flow branch for level 1 (`EQUAL` or `LESS_OR_EQUAL`)
  runs for every login. While AMFA is off the engine records no logins
  either (the login webhook was already off), so after switching back on its
  history-based signals, such as inactive account, do not count the logins
  made in between

### Changed

- A realm without the `adaptiveToggle` attribute is on only when it has an
  engine endpoint (`adaptiveAuthEndpoint`), as a realm set up through the
  admin REST API has; a realm never set up for AMFA, master included, is now
  off, and its logins no longer ask the engine. The exception is a realm
  without a switch in `mandatory` failure mode: it stays on, so a missing
  endpoint still denies its logins instead of letting them through as low
  risk. A set switch decides as before, and only `true` is on. The risk request, the auth context and the
  login webhook all follow this rule, so a realm with an endpoint but no
  switch now also sends the login webhook. Upgrade the admin UI with it: the
  admin UI release that reads the switch the same way shows these realms as
  they are treated at login

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
