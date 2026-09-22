/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.events;

import lombok.extern.slf4j.Slf4j;
import org.keycloak.amfa.authenticator.adaptiveauth.AdaptiveAuthUtils;
import org.keycloak.amfa.util.EventBuilderHelper;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.urls.UrlType;
import org.keycloak.services.Urls;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Emits login events to the AMFA engine's {@code /login_event/webhook} so the
 * engine can record authentication history — the data every behavioural /
 * ML risk signal learns from.
 *
 * <p>The event is delivered as a realm-signed RS256 JWT in the
 * {@code SignedPayload} header, which is exactly what the engine's webhook
 * verifier expects (signature via the realm JWKS, issuer + replay checks). The
 * listener is inert on realms that have not enabled AMFA, and never blocks or
 * fails a login: webhook delivery is best-effort and all errors are swallowed.
 */
@Slf4j
public class AmfaWebhookEventListenerProvider implements EventListenerProvider {

    private static final String WEBHOOK_PATH = "/login_event/webhook";
    private static final long TOKEN_LIFETIME_SECONDS = 30L;

    /**
     * Default audience for webhook event tokens, distinct from any other
     * AMFA token (e.g. the {@code amfa} audience on the /decision
     * service-account token). This token is hand-built here rather than
     * issued through a client's configured scopes, so this value is fully
     * under this listener's control — an ordinary end-user or
     * service-account token minted for some other purpose does not carry
     * it, even if it is otherwise signed by a trusted realm.
     *
     * <p>Overridable via the {@code AMFA_WEBHOOK_AUDIENCE} environment
     * variable, which must match the engine's own {@code AMFA_WEBHOOK_AUDIENCE}
     * (see the AMFA engine's environment.py) — the two sides are independently
     * deployed, so this is deliberately a shared deployment setting rather
     * than a value hardcoded into either codebase.
     */
    private static final String DEFAULT_WEBHOOK_AUDIENCE = "amfa-webhook-event";

    private static String resolveWebhookAudience() {
        String configured = System.getenv("AMFA_WEBHOOK_AUDIENCE");
        return (configured == null || configured.isBlank())
                ? DEFAULT_WEBHOOK_AUDIENCE
                : configured;
    }

    private static final String WEBHOOK_AUDIENCE = resolveWebhookAudience();

    // Events forwarded to the engine: terminal login outcomes (which carry the
    // authentication context and history), plus sensitive account-lifecycle
    // actions (E4). The latter have no login auth-context; the engine tolerates
    // the absent fields and uses them to flag a login that follows a recent
    // password/credential/email change (account-takeover pattern).
    /**
     * How long to wait when delivering an event, before giving up on it.
     *
     * <p>The catch below already keeps a failed delivery from changing the login
     * outcome, but without a timeout it could not keep a *slow* one from delaying it:
     * this call is synchronous on the login thread. Measured against an engine that
     * drops packets, the final step of a login sat here for 75 seconds after the
     * decision call had already fallen back, so the login was held long after the risk
     * question had been answered. Same 5s budget as the two engine calls.
     */
    private static final int WEBHOOK_TIMEOUT_MILLIS = 5000;

    private static final Set<EventType> FORWARDED_EVENTS = EnumSet.of(
            EventType.LOGIN,
            EventType.LOGIN_ERROR,
            EventType.UPDATE_PASSWORD,
            EventType.RESET_PASSWORD,
            EventType.UPDATE_CREDENTIAL,
            EventType.REMOVE_CREDENTIAL,
            EventType.UPDATE_EMAIL,
            // Linking/unlinking an external identity provider is an
            // account-access change and a classic account-takeover vector.
            EventType.FEDERATED_IDENTITY_LINK,
            EventType.IDENTITY_PROVIDER_LINK_ACCOUNT,
            EventType.REMOVE_FEDERATED_IDENTITY);

    private final KeycloakSession session;

    public AmfaWebhookEventListenerProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void onEvent(Event event) {
        if (!FORWARDED_EVENTS.contains(event.getType())) {
            return;
        }
        try {
            RealmModel realm = session.realms().getRealm(event.getRealmId());
            if (realm == null || !amfaEnabled(realm)) {
                return;
            }
            String endpoint = realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_ENDPOINT);
            if (endpoint == null || endpoint.isBlank()) {
                return;
            }

            String signedPayload = buildSignedPayload(realm, event);
            if (signedPayload == null) {
                return;
            }

            String url = endpoint.replaceAll("/+$", "") + WEBHOOK_PATH;
            SimpleHttp.Response response = SimpleHttp.doPost(url, session)
                    .header("SignedPayload", signedPayload)
                    .connectTimeoutMillis(WEBHOOK_TIMEOUT_MILLIS)
                    .connectionRequestTimeoutMillis(WEBHOOK_TIMEOUT_MILLIS)
                    .socketTimeOutMillis(WEBHOOK_TIMEOUT_MILLIS)
                    .json(new HashMap<>())
                    .asResponse();
            if (response.getStatus() >= 300) {
                log.warn("AMFA webhook returned HTTP {} for event {} (realm {})",
                        response.getStatus(), event.getType(), realm.getName());
            }
        } catch (Exception e) {
            // Never let webhook delivery affect the login outcome.
            log.warn("AMFA webhook delivery failed for event {}: {}",
                    event.getType(), e.getMessage());
        }
    }

    @Override
    public void onEvent(AdminEvent adminEvent, boolean includeRepresentation) {
        // AMFA only cares about end-user authentication events.
    }

    @Override
    public void close() {
    }

    private boolean amfaEnabled(RealmModel realm) {
        return Boolean.parseBoolean(realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_TOGGLE));
    }

    /**
     * Build the realm-signed JWT whose claims are the webhook payload the engine
     * consumes ({@code WebhookPayload}: type/id/timestamp/version + data +
     * authContextModel), plus the registered iss/iat/exp/jti claims the verifier
     * checks. Returns null if the realm has no active RS256 signing key.
     */
    private String buildSignedPayload(RealmModel realm, Event event) {
        KeyWrapper key = session.keys().getActiveKey(realm, KeyUse.SIG, Algorithm.RS256);
        if (key == null) {
            log.warn("No active RS256 signing key for realm {}; skipping AMFA webhook", realm.getName());
            return null;
        }

        Map<String, String> details = event.getDetails() != null ? event.getDetails() : Map.of();

        String userId = event.getUserId();
        String username = details.get("username");
        String email = null;
        if (userId != null) {
            UserModel user = session.users().getUserById(realm, userId);
            if (user != null) {
                email = user.getEmail();
                if (username == null) {
                    username = user.getUsername();
                }
            }
        }

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("user_id", userId);
        data.put("user_email", email);
        data.put("username", username);
        data.put("event_timestamp", event.getTime());
        data.put("error", event.getError());
        // A LOGIN_ERROR fails at the password step, before the Auth Context
        // authenticator computes a hash, so this detail is absent. The engine's
        // AuthEventDetails requires auth_context_hash as a non-null string, so
        // sending null made it reject every failed-login event (400) -- which
        // meant failed logins were never recorded and the failure-count hazard
        // escalation could never fire. Coalesce to "" so failures are recorded.
        data.put("auth_context_hash", nz(details.get(EventBuilderHelper.AUTH_CONTEXT_HASH_DETAIL)));

        // The engine's AuthContextSchema requires these as non-null strings.
        // A login can legitimately lack a locale (no Accept-Language), screen
        // resolution, or user agent; sending JSON null would make the engine
        // reject the whole event (400), silently stopping history accumulation.
        // Coalesce to "" so history is always recorded, matching how the
        // authenticators feed the /decision endpoint.
        Map<String, Object> authContext = new LinkedHashMap<>();
        authContext.put("client", nz(event.getClientId()));
        authContext.put("ip_address", nz(event.getIpAddress()));
        authContext.put("user_agent", nz(details.get(EventBuilderHelper.USER_AGENT_DETAIL)));
        authContext.put("system_language", nz(details.get(EventBuilderHelper.LOCALE_DETAIL)));
        authContext.put("screen_resolution", nz(details.get(EventBuilderHelper.SCREEN_RESOLUTION_DETAIL)));
        authContext.put("cookie", null);

        long now = Time.currentTime();
        String issuer = Urls.realmIssuer(session.getContext().getUri(UrlType.FRONTEND).getBaseUri(), realm.getName());

        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", issuer);
        claims.put("iat", now);
        claims.put("exp", now + TOKEN_LIFETIME_SECONDS);
        claims.put("jti", UUID.randomUUID().toString());
        claims.put("aud", WEBHOOK_AUDIENCE);
        // The real Keycloak user this event is about, set server-side from the
        // Event object itself (never client-suppliable). The engine verifies
        // this equals data.user_id before trusting the event, so a signed
        // token cannot be reshaped to claim an event about a different user
        // than the one it was actually issued for.
        claims.put("sub", userId);
        claims.put("type", event.getType().toString());
        claims.put("id", event.getId() != null ? event.getId() : UUID.randomUUID().toString());
        claims.put("timestamp", event.getTime());
        claims.put("version", "1");
        claims.put("data", data);
        claims.put("authContextModel", authContext);

        SignatureSignerContext signer = session.getProvider(SignatureProvider.class, Algorithm.RS256).signer(key);
        return new JWSBuilder().type("JWT").kid(key.getKid()).jsonContent(claims).sign(signer);
    }

    /** Null-safe: return "" for a null value so required engine fields never serialize as JSON null. */
    private static String nz(String value) {
        return value == null ? "" : value;
    }
}
