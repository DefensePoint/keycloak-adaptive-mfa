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

- The email code step no longer gives a lockout away. Once brute-force
  protection locked the account out, the code page said "Invalid username or
  password.", which no wrong code shows, so a code guesser could tell the
  account had been locked. A wrong code also showed the raw key
  `invalidOTPMessage`, which no theme defines. Both now show Keycloak's
  "Invalid authenticator code.", as Keycloak's own OTP form and the TOTP step
  do. A permanent lockout still ends on Keycloak's "Account is disabled" page

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

- The email code step no longer sends a new code every time it is shown. A
  page reload showed the step again and sent a new email each time, without
  limit, so a reload loop could flood the user's inbox and hand out fresh codes
  to guess at. A reload now shows the code already sent. A new code is sent
  only on Resend, when the code has expired or after three wrong guesses, and
  one login gets at most three codes; the step's new "Codes per login" setting
  changes that. Resend at the limit keeps the code already sent. Once no
  valid code is left, the step shows that too many codes were requested, and
  the user starts the login again; this is recorded once per login, as a
  `LOGIN_ERROR` event (`reached_resend_otp_limit`). A code whose email could
  not be sent does not count. The limit is per login: a new login allows as
  many codes again, so a flood of emails is slowed, not capped.

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
