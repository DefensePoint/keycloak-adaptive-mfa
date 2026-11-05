# Keycloak Adaptive MFA Extension

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Keycloak SPI plugin for the [Adaptive MFA Engine](https://github.com/DefensePoint/keycloak-adaptive-mfa-engine). Integrates adaptive risk-based authentication flows into Keycloak 26.x by calling the engine on every login and enforcing step-up MFA based on the returned risk level.

This is one of three repositories that make up the full AMFA system:

| Repository | Language | Role |
|---|---|---|
| [keycloak-adaptive-mfa-engine](https://github.com/DefensePoint/keycloak-adaptive-mfa-engine) | Python | Risk evaluation engine + Docker Compose stack |
| [**keycloak-adaptive-mfa**](https://github.com/DefensePoint/keycloak-adaptive-mfa) (this repo) | Java | Keycloak SPI plugin — authenticator that calls the engine |
| [keycloak-adaptive-mfa-admin-ui](https://github.com/DefensePoint/keycloak-adaptive-mfa-admin-ui) | TypeScript | Keycloak Admin UI extension — AMFA configuration pages |

## Features

- **Adaptive Auth Authenticator** — calls the AMFA engine, enforces step-up MFA based on ACR decision
- **Auth Context Authenticator** — captures device fingerprint, geo, and UA data at login time
- **MFA Factors** — Email OTP, TOTP
- **REST API** — `/{realm}/amfa-api/` endpoints for risk policy configuration

## Compatibility

| Version | Keycloak |
|---------|----------|
| 1.x     | 26.6     |

**Keycloak versions other than 26.6:** the Email OTP step does not work there yet. `MfaEmailAuthenticator` calls `BruteForceProtector.successfulLogin` and `failedLogin`, whose signatures differ between Keycloak lines: 26.0 to 26.5 take four arguments, 26.6 adds a `String` category, and 26.7 and newer take a `Set<String>` instead. On any line but 26.6, submitting an email code fails with `NoSuchMethodError` (HTTP 500), for local and identity-provider logins alike. Moving the plugin to another Keycloak line requires updating those two calls, and a jar built that way no longer runs on 26.6.

## Prerequisites

- **JDK 17+**
- **Maven 3.8+**

On macOS with Homebrew:

```bash
brew install openjdk@17 maven
echo 'export JAVA_HOME="/opt/homebrew/opt/openjdk@17"' >> ~/.bash_profile
echo 'export PATH="$JAVA_HOME/bin:$PATH"' >> ~/.bash_profile
source ~/.bash_profile
```

## Installation

### Using the pre-built JAR

The `keycloak-adaptive-mfa-engine` Docker stack ships a pre-built JAR — no manual installation needed if
you are running the full stack. See the [keycloak-adaptive-mfa-engine](https://github.com/DefensePoint/keycloak-adaptive-mfa-engine) repo.

For a standalone Keycloak deployment:

1. Download the JAR from [Releases](https://github.com/DefensePoint/keycloak-adaptive-mfa/releases).
2. Place it in Keycloak's `providers/` directory.
3. Restart Keycloak.

### Per-Realm Configuration

The plugin needs no environment variables. Each realm that uses AMFA is
configured through Keycloak itself:

| Setting | Where | Purpose |
|---|---|---|
| AMFA Engine Endpoint | Realm settings → Security defenses → Adaptive MFA | Base URL of the AMFA engine (e.g. `http://adaptive_auth`) |
| `adaptive-auth-api` client | Clients (confidential, service accounts enabled) | Service account the plugin uses to call the engine |
| `aud=amfa` audience mapper | On the `adaptive-auth-api` client | Required — the engine enforces the token audience |
| `frontendUrl` realm attribute | Realm attributes (split-horizon Docker only) | Pins the token issuer to a URL the engine can trust and reach |
| `AMFA details on login events` required action | Authentication → Required actions → Register | Recommended. Puts the AMFA details on the LOGIN event of a login that ends with a required action, such as TOTP setup or a password change |

Without the `AMFA details on login events` required action, a login that ends
with a required action reaches the engine without its user agent, screen
resolution and locale, so the engine records an unknown device for it, and the
stored LOGIN event has no risk level. With it, the stored LOGIN event of an SSO
login carries the AMFA details too. Keycloak does not register custom required
actions by itself, so register it in each realm that uses AMFA. It never shows
the user a page. Do not make it a default action: like any pending required
action, it would stop a user from logging in with a direct grant until they log
in once in a browser. Unregister it before downgrading to a plugin version
without it, or Keycloak logs a warning on every login.

See the engine repository's `docs/keycloak-setup.md` for step-by-step instructions.
Email OTP is sent through the realm's standard SMTP settings (Realm Settings → Email) —
no additional configuration is required.

## Building from Source

```bash
mvn clean package -DskipTests
# Output: target/keycloak-adaptive-mfa-<version>.jar
```

To deploy your build into the running `keycloak-adaptive-mfa-engine` Docker stack:

```bash
cp target/keycloak-adaptive-mfa-*.jar ../keycloak-adaptive-mfa-engine/config/keycloak/keycloak-adaptive-mfa.jar
docker compose -f ../keycloak-adaptive-mfa-engine/config/keycloak/docker-compose.yml restart keycloak
```

To run tests:

```bash
mvn test
```

## Local Development

### Debug logging

To trace the extension's behaviour locally, raise its log level to DEBUG while keeping
Keycloak itself at INFO. Either mount the sample config at
[`conf/keycloak.conf`](conf/keycloak.conf) into `/opt/keycloak/conf/`, or set the env
var in `keycloak-adaptive-mfa-engine/config/keycloak/docker-compose.yml`:

```bash
KC_LOG_LEVEL="info,org.keycloak.amfa:debug"
```

This is already set in the shipped compose file. Do not enable DEBUG in production — the
output is verbose.

### Running the full stack

This repo only builds the SPI JAR. To run a complete local environment with Keycloak,
the AMFA engine, PostgreSQL, Redis, and Mailpit, use the Docker Compose stack in the
`keycloak-adaptive-mfa-engine` repo.

## Related Projects

- [keycloak-adaptive-mfa-engine](https://github.com/DefensePoint/keycloak-adaptive-mfa-engine) — Python risk engine
- [keycloak-adaptive-mfa-admin-ui](https://github.com/DefensePoint/keycloak-adaptive-mfa-admin-ui) — Keycloak Admin UI extension

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0 — see [LICENSE](LICENSE).
