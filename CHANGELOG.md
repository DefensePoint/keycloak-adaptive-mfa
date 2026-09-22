# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-09-18

### Added

- Adaptive authentication authenticator that calls the AMFA engine for risk evaluation
- Step-up MFA based on risk level (OTP, email code, or deny)
- Configurable fallback risk level per realm
- Configurable failure mode (mandatory or advisory) when the engine is unreachable
- Conditional authenticator with configurable comparison operators (equal, less-or-equal, greater-or-equal)
- Webhook event listener that forwards login events to the engine
- Email OTP authenticator with configurable code length and TTL
- User-agent parsing for device and browser detection

[1.0.0]: https://github.com/DefensePoint/keycloak-adaptive-mfa/releases/tag/v1.0.0
