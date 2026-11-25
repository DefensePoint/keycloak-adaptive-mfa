# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- The service account token is reused until shortly before it expires,
  instead of being fetched from Keycloak for every engine call. Every login
  asked Keycloak's token endpoint for a fresh token twice, over HTTP (in the
  auth-context and decision steps), and every admin page call once more, so a
  busy Keycloak got that token work on top of the logins: under load the token
  requests timed out and the engine was called without a token. A token is now
  kept per realm, client, token endpoint address and client secret, used until
  30 seconds before its expiry, and replaced by one request while the others
  keep using it; a rotated secret gets a new token, and one the engine rejects
  (HTTP 401 or 403, as after a signing key rotation) is dropped. Each Keycloak
  node keeps its own tokens.
- A login the engine rate-limits steps up instead of taking the realm's
  fallback level. The engine answers a user's `/decision` requests over its
  rate limit with 429, and the plugin handled that like an outage: the login
  got the realm's fallback risk level, so with a fallback of 1 anyone with the
  user's password could pass MFA by logging in until the engine rate-limited
  that user. A 429 now gives the higher of 3 and the fallback level, in
  advisory and mandatory failure mode alike (refusing would let anyone who can
  spend a user's budget lock them out), with the login event's
  `decision_source` set to `rate_limited` and a warning in the log without
  `ADAPTIVE_AUTH_ENGINE_UNREACHABLE`, since the engine is up. Other error
  answers, timeouts and refused connections are handled as before.
- An error answer from the engine to a decision request is logged once. The
  engine call logged an unmarked error of its own, showing only the response
  object, before the error starting with `ADAPTIVE_AUTH_ENGINE_UNREACHABLE`,
  so each such failure gave two error lines and only one matched an alert on
  the marker. The marked line now carries the HTTP status and the engine's
  answer.

## [1.1.0] - 2026-11-19

Upgrading from 1.0.1:

- Register the `AMFA details on login events` required action
  (`amfa-login-event-details`) in each realm that uses AMFA: Authentication →
  Required actions → Register. Keycloak does not register it by itself.
  Without it, the LOGIN event of an SSO login, or of a login that ends with a
  required action such as TOTP setup, has no AMFA details, `amfa_event_id`
  included, and a login that ends with a required action reaches the engine
  without its device details
- Upgrade the admin UI to its 1.1.0 release at the same time; it reads the
  AMFA switch the same way and sets up a realm without an engine endpoint
- Keycloak 26.6 only, as before: the Email OTP step fails on other Keycloak
  lines (see Compatibility in the README). The JAR still needs
  `io.vavr:vavr` 1.0.1 next to it
- Behaviour that changes for existing realms: the AMFA switch
  (`adaptiveToggle`) now applies at login, and only an explicit `false`
  switches AMFA off, so a realm set to `false` logs in as low risk without
  asking the engine, and a realm without the attribute that has an engine
  endpoint now gets the login webhook too; a wrong code on the email or TOTP
  step is now a `LOGIN_ERROR` event that the engine counts among the user's
  failed logins; the email step sends at most three codes per login, which
  its "Codes per login" setting changes

### Added

- The events of a login AMFA scored carry an `amfa_event_id` detail: the ID of
  the engine's decision, which the login webhook also reports the LOGIN under.
  A monitoring tool that reads both Keycloak's events and the engine's records
  can then join a LOGIN to the engine's record of it and show the login once
  instead of twice. An SSO login's LOGIN event carries it when the
  `amfa-login-event-details` required action is registered, as for the other
  AMFA details

- A required action, `AMFA details on login events`
  (`amfa-login-event-details`), adds the login's AMFA details, such as
  `risk_level`, `user_agent`, `screen_resolution` and `amfa_event_id`, to a
  LOGIN event that Keycloak sends as a new event: the LOGIN of a login that
  ends with a required action, such as TOTP setup or a password change, and
  the LOGIN of an SSO login. Before, those LOGIN events had no AMFA details,
  and for a login that ended with a required action the login webhook sent
  the engine an empty user agent, screen resolution and language. The action
  only acts on a login AMFA scored, never shows the user a page, cannot be
  requested by a client and logs an error instead of failing the login.
  Keycloak does not register it by itself; see "Upgrading from 1.0.1"

### Changed

- A wrong code on the AMFA email or TOTP step is recorded as a `LOGIN_ERROR`
  event, as Keycloak's own OTP form records one: `invalid_user_otp` on the
  email step and `invalid_user_credentials` on the TOTP step, where an empty
  code counts the same way. Before, a wrong code counted towards brute-force
  protection but left no event, so a monitoring tool saw no code guessing on
  these steps. These events, and the email step's limit and the lockout
  refusals of both steps, carry the login's AMFA details, such as `risk_level`
  and `amfa_event_id`. The login webhook sends them to the engine like any
  other `LOGIN_ERROR`; the LOGIN after the right code stays linked to its
  decision. The engine counts them among the user's failed logins of the last
  24 hours, as it already did for wrong codes on Keycloak's own OTP form: after
  two, a login the engine finds very unfamiliar, or one after two high-risk
  logins, is raised from Risk 3 to Risk 4

- The login webhook is sent in the background instead of on the login
  thread. Before, each login waited for the engine to answer its webhook, up
  to the 5 second timeout when the engine was slow or unreachable, on top of
  the risk request. The webhook is still signed during the login, then waits
  in a queue per user and goes out on one of 32 sending threads. One user's
  webhooks go out one at a time, in the order Keycloak emitted them, and a
  user with many waiting, as in a password-guessing run on one account,
  holds at most one thread and takes turns with the others. A user can have
  250 webhooks waiting and all users together 8000. A webhook that finds its
  queue full, or that waited past its 30 second token, is dropped with a
  warning in the log instead of holding up a login. A webhook for an event
  with no user at all, such as a login with an unknown username, has a queue
  of its own, so a burst of them is sent in parallel. When Keycloak shuts
  down, the waiting webhooks get 5 seconds to go out

- The login webhook reports a LOGIN that followed the AMFA risk step under
  the ID of the engine's decision for that login, the ID the risk request
  already carried, instead of under Keycloak's event ID. An engine that links
  a login's outcome to its decision by ID can then do so however long the
  user took between the risk step and the end of the login, for example to
  enter a TOTP code. Every other event keeps Keycloak's event ID, including a
  `LOGIN_ERROR` earlier in the same login, and so does a LOGIN without the
  AMFA step, such as a silent re-login on an existing session

### Fixed

- A realm whose `fallbackRisk` is missing, not a number or outside 1-4 gets
  one warning in the log for that value, not one on every login. Another
  unusable value, or the same one after it was fixed in between, is warned
  about again. The login still uses Risk 3 as the fallback, as before

- The email code page shows the address masked, as `jon*****@example.com`,
  not in full. The page comes after the password and before the second
  factor, so someone with only the password learned the account's address
  from it. The domain stays, so the user still knows which mailbox to check

- The debug line logged before each call to the risk engine no longer lets a
  value split it. It logged the User-Agent, IP address, client, realm, group,
  the engine's own auth-context hash and the engine URL as they were, so a
  carriage return or line feed in any of them started a new, forged log line.
  They are now sanitized the same way as the authenticator's own debug line

- The TOTP step checks the code against the authenticator device the user
  picked on the code page, as Keycloak's own OTP form does. It always used the
  default device, so a user with two devices could only log in with the
  default one's code. Without a choice it is still the default device. The
  choice is kept selected after a wrong code and recorded on the event as
  `selected_credential_id`. A picked ID that is not one of the user's devices
  is refused like a wrong code

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

- An SSO login, through an identity provider whose post login flow runs the
  AMFA steps, reaches the engine with its context. Keycloak sends the LOGIN
  event of such a login without the details the AMFA steps added, so the
  login webhook sent the engine an empty user agent, language, screen
  resolution and auth context hash, and the engine kept SSO users' history
  without them. The AMFA steps now also keep these four values on the user
  session, and the webhook uses them for an SSO LOGIN that lacks them. A
  silent re-login on an existing session, and account changes inside it,
  still send them empty, so a stolen session cookie cannot report the
  victim's device as its own

- A login that the flow refuses after the AMFA risk step, such as at a deny
  step for a high risk level, is reported to the engine as a failed login of
  its user. Keycloak emits such a refusal without a user ID, as a
  `LOGIN_ERROR`, or through an identity provider as an
  `IDENTITY_PROVIDER_POST_LOGIN_ERROR`, which the webhook did not forward at
  all, so the engine could not tell whose login was refused. The events of a
  login AMFA scored now carry an `amfa_user_id` detail, the ID of the user
  AMFA scored, and the webhook uses it for a failed login without a user ID
  when it names a user of the realm. An `IDENTITY_PROVIDER_POST_LOGIN_ERROR`
  is sent to the engine as a `LOGIN_ERROR`, and only once, although Keycloak
  emits it twice

- A login request without a `User-Agent` header no longer fails. The risk
  step threw an error on it, so the login ended on an error page, and the
  auth context step logged the engine as unreachable and sent no context.
  Both now send the engine an empty user agent, and the login goes on

- The Adaptive MFA admin REST endpoints (`amfa-api`) answer with
  `Cache-Control: no-cache`, as Keycloak's own admin endpoints do, errors
  included. They sent no caching headers, so a browser or proxy could keep
  and reuse an answer that holds realm settings or admin data

- The service account token request, made before each call to the engine at
  login and on the admin page, waits at most 5 seconds to connect, to get a
  pooled connection and to read the answer, as the engine calls at login do.
  It used Keycloak's default HTTP client, which sets no connect timeout, so
  when the address the token endpoint is reached at dropped packets, every
  login waited on the operating system's connect timeout, a minute or more,
  before applying the failure mode. A failed token request still ends in the
  realm's fallback risk level, or a denial in `mandatory` mode, as before

- The Adaptive MFA admin page's settings and scoring calls wait at most 10
  seconds on the engine to connect, to get a pooled connection and to read
  the answer. They used Keycloak's default HTTP client, with no connect
  timeout and a 5 second read timeout, so an engine address that dropped
  packets held the page for over a minute, while a save the engine took more
  than 5 seconds to answer was reported as failed. A timeout now ends in the
  same "AMFA engine unreachable" error as a refused connection

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

[1.1.0]: https://github.com/DefensePoint/keycloak-adaptive-mfa/releases/tag/v1.1.0
[1.0.1]: https://github.com/DefensePoint/keycloak-adaptive-mfa/releases/tag/v1.0.1
