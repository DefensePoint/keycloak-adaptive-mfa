# Contributing to Keycloak Adaptive MFA

Thank you for your interest in contributing!

## Getting Started

1. Fork the repository and create a branch from `main`.
2. Follow the setup instructions in the README to build the project locally.
3. Make your changes, add tests where applicable, and ensure all existing tests pass.
4. Open a pull request with a clear description of the change.

## Development Setup

```bash
# Build the SPI JAR
mvn clean package -DskipTests

# Deploy into the keycloak-adaptive-mfa-engine Docker stack
cp target/keycloak-adaptive-mfa-*.jar ../keycloak-adaptive-mfa-engine/config/keycloak/keycloak-adaptive-mfa.jar
docker compose -f ../keycloak-adaptive-mfa-engine/config/keycloak/docker-compose.yml restart keycloak
```

## Running Tests

```bash
mvn test
```

## Code Style

- Java 17+, Maven build
- Keycloak SPI interfaces; all Keycloak dependencies are `provided` scope
- New authenticators go in `src/main/java/org/keycloak/amfa/authenticator/`
- All new code should have corresponding unit tests in `src/test/`

## Pull Request Guidelines

- Keep pull requests focused on a single concern
- Include a test for any bug fix or new feature
- Update relevant documentation if behavior changes

## Developer Certificate of Origin (DCO)

This project requires a DCO sign-off on every commit. By signing off, you
certify that you wrote the change or otherwise have the right to submit it
under the project's open-source license.

Add a `Signed-off-by` line to each commit message:

```
Signed-off-by: Your Name <your.email@example.com>
```

Git can do this automatically with `git commit -s`.

By signing off you agree to the
[Developer Certificate of Origin](https://developercertificate.org/).

## Reporting Issues

Open a GitHub issue with a clear description, steps to reproduce, and the
version you are running.
