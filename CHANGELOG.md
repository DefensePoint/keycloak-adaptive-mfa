# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- The events of a login AMFA scored carry an `amfa_event_id` detail: the ID of
  the engine's decision, which the login webhook also reports the LOGIN under.
  A monitoring tool that reads both Keycloak's events and the engine's records
  can then join a LOGIN to the engine's record of it and show the login once
  instead of twice. An SSO login's LOGIN event carries it when the
  `amfa-login-event-details` required action is registered, as for the other
  AMFA details

### Changed

- A login webhook for an event with no user at all, such as a login with an
  unknown username, goes out on a lane picked by the event's own ID instead of
  the realm's one lane. A burst of them, as in a password-guessing run, spreads
  over the lanes instead of queueing behind one another and filling that lane,
  after which further ones were dropped. Events with a user still keep that
  user's order

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

- The AMFA TOTP step refuses a code, even the right one, while the realm's
  brute-force protection has the account locked out. Before, wrong codes on
  this step locked the account, but the right code still logged it in and
  cleared the lockout, so the lockout did not stop a code-guessing run. As on
  Keycloak's own OTP form, a locked-out account is told "Invalid authenticator
  code", which does not reveal the lockout, and the refusal is not counted as
  another failed login. The email code step already had this check

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
- The risk-level condition ("Conditional - User Risk Level") counts a login
  AMFA did not score as the highest risk, for example when the flow has no
  risk step before it. Such a login no longer matches "equal" or "less or
  equal", so a sub-flow meant for low-risk logins no longer runs for it, and
  it now matches "greater or equal", so a step-up runs instead of the login
  going on with the password alone. A warning that the condition got an
  unscored login is logged once per realm and condition. A condition
  without a config, or with a level that is not a number, no longer fails
  the login: it compares against no level, so "greater or equal" matches
  and the step-up runs, and the comparison or level that cannot be used is
  logged once

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
