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
- The login webhook follows the same switch as the login steps: only an
  explicit `adaptiveToggle=false` switches AMFA off, and a realm without the
  attribute is on. It goes to every realm that is not switched off and has an
  engine endpoint (`adaptiveAuthEndpoint`). Before, it went only to a realm
  with `adaptiveToggle=true`, so a realm set up through the admin REST API,
  which has an endpoint but no switch, was risk-checked at login while the
  engine never heard of its logins, and a hand-set value such as `yes` sent
  logins to the engine without the webhook
- A realm with the AMFA step in its login flow but no engine endpoint, for
  example after an admin REST update that replaced the realm's attributes
  without the AMFA ones, no longer sends the risk request to an invalid URL.
  The risk step logs `ADAPTIVE_AUTH_ENGINE_UNREACHABLE` naming the missing
  endpoint and applies the failure mode, so the login gets the fallback risk
  level, or is denied in `mandatory` mode; the auth context step sends nothing.
  Upgrade the admin UI with it: its matching release shows such a realm as on
  and asks for the endpoint

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
