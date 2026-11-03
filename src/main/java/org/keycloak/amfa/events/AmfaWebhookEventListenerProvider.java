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
import org.keycloak.events.Details;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.urls.UrlType;
import org.keycloak.services.Urls;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;

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
            EventType.REMOVE_FEDERATED_IDENTITY,
            // A login through an identity provider that fails in the
            // provider's post login flow, e.g. refused by AMFA's deny tier.
            // Sent to the engine as LOGIN_ERROR (see engineEventType).
            EventType.IDENTITY_PROVIDER_POST_LOGIN_ERROR);

    static boolean isForwarded(EventType type) {
        return FORWARDED_EVENTS.contains(type);
    }

    /** How long a brokered denial is remembered, comfortably longer than one request. */
    private static final long POST_LOGIN_ERROR_DEDUP_SECONDS = 60L;

    /**
     * Keycloak emits one denial of a brokered login twice, identical but for
     * the event ID, and delivers each copy in its own session to its own
     * listener instance. Forwarding both made the engine count two failed
     * logins for one refused attempt, so the first copy claims the login
     * session (code_id) in Keycloak's single-use store, which is shared across
     * sessions and cluster nodes and expires on its own. Other events are
     * never deduplicated.
     */
    boolean firstOfItsKind(Event event) {
        if (event.getType() != EventType.IDENTITY_PROVIDER_POST_LOGIN_ERROR) {
            return true;
        }
        Map<String, String> details = event.getDetails() != null ? event.getDetails() : Map.of();
        String codeId = details.get(Details.CODE_ID);
        return codeId == null
                || session.singleUseObjects().putIfAbsent("amfa.post-login-error." + codeId, POST_LOGIN_ERROR_DEDUP_SECONDS);
    }

    private final KeycloakSession session;

    public AmfaWebhookEventListenerProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void onEvent(Event event) {
        if (!isForwarded(event.getType()) || !firstOfItsKind(event)) {
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
    String buildSignedPayload(RealmModel realm, Event event) {
        KeyWrapper key = session.keys().getActiveKey(realm, KeyUse.SIG, Algorithm.RS256);
        if (key == null) {
            log.warn("No active RS256 signing key for realm {}; skipping AMFA webhook", realm.getName());
            return null;
        }

        Map<String, String> details = event.getDetails() != null ? event.getDetails() : Map.of();
        Supplier<UserSessionModel> loginSession = brokeredLoginSession(realm, event, details);

        String userId = event.getUserId();
        if (userId == null && isLoginFailure(event.getType())) {
            userId = scoredUserOf(realm, details);
        }
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
        data.put("auth_context_hash", contextValue(details, loginSession, EventBuilderHelper.AUTH_CONTEXT_HASH_DETAIL));

        // The engine's AuthContextSchema requires these as non-null strings.
        // A login can legitimately lack a locale (no Accept-Language), screen
        // resolution, or user agent; sending JSON null would make the engine
        // reject the whole event (400), silently stopping history accumulation.
        // Coalesce to "" so history is always recorded, matching how the
        // authenticators feed the /decision endpoint.
        Map<String, Object> authContext = new LinkedHashMap<>();
        authContext.put("client", nz(event.getClientId()));
        authContext.put("ip_address", nz(event.getIpAddress()));
        authContext.put("user_agent", contextValue(details, loginSession, EventBuilderHelper.USER_AGENT_DETAIL));
        authContext.put("system_language", contextValue(details, loginSession, EventBuilderHelper.LOCALE_DETAIL));
        authContext.put("screen_resolution", contextValue(details, loginSession, EventBuilderHelper.SCREEN_RESOLUTION_DETAIL));
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
        claims.put("type", engineEventType(event.getType()));
        claims.put("id", event.getId() != null ? event.getId() : UUID.randomUUID().toString());
        claims.put("timestamp", event.getTime());
        claims.put("version", "1");
        claims.put("data", data);
        claims.put("authContextModel", authContext);

        SignatureSignerContext signer = session.getProvider(SignatureProvider.class, Algorithm.RS256).signer(key);
        return new JWSBuilder().type("JWT").kid(key.getKid()).jsonContent(claims).sign(signer);
    }

    private static boolean isLoginFailure(EventType type) {
        return type == EventType.LOGIN_ERROR || type == EventType.IDENTITY_PROVIDER_POST_LOGIN_ERROR;
    }

    /**
     * The event type the engine is sent. A login refused in an identity
     * provider's post login flow is the brokered form of LOGIN_ERROR, and is
     * sent as one, the type the engine counts as a failed login and closes the
     * user's open decision with.
     */
    private static String engineEventType(EventType type) {
        return type == EventType.IDENTITY_PROVIDER_POST_LOGIN_ERROR
                ? EventType.LOGIN_ERROR.toString() : type.toString();
    }

    /**
     * The user a failed login belonged to, when Keycloak left it off the event.
     *
     * <p>A login refused after AMFA's step ran (AMFA's deny tier) is emitted
     * without a user ID, as LOGIN_ERROR or, through an identity provider,
     * IDENTITY_PROVIDER_POST_LOGIN_ERROR, so the engine could not tell whose
     * attempt was refused. The event keeps the flow's details, and AMFA's step
     * added the ID of the user it scored. It is set server-side from the
     * authenticated user, and used only if it still names a user of the realm.
     */
    private String scoredUserOf(RealmModel realm, Map<String, String> details) {
        String id = details.get(EventBuilderHelper.USER_ID_DETAIL);
        if (id == null || id.isBlank()) {
            return null;
        }
        return session.users().getUserById(realm, id) != null ? id : null;
    }

    /**
     * The user session whose AMFA notes may fill in a brokered login's context,
     * read at most once and only when a field needs it.
     *
     * <p>A brokered (SSO) login's LOGIN event is emitted by Keycloak's broker
     * code with a fresh EventBuilder, so it carries only the broker's own
     * details, none of AMFA's. When the AMFA authenticators ran in the identity
     * provider's post login flow, in that same request, they also stored their
     * values as user-session notes. Only that event may use them: a silent
     * re-login (a session cookie let through without AMFA's steps) or an
     * account change inside the session did not produce those values, and
     * inheriting them would report the login's device as its own, which with
     * a stolen cookie means the victim's browser next to the attacker's IP.
     */
    private Supplier<UserSessionModel> brokeredLoginSession(RealmModel realm, Event event, Map<String, String> details) {
        if (event.getType() != EventType.LOGIN || !details.containsKey(Details.IDENTITY_PROVIDER)
                || event.getSessionId() == null) {
            return () -> null;
        }
        UserSessionModel[] found = new UserSessionModel[1];
        boolean[] read = new boolean[1];
        return () -> {
            if (!read[0]) {
                found[0] = session.sessions().getUserSession(realm, event.getSessionId());
                read[0] = true;
            }
            return found[0];
        };
    }

    /**
     * The event detail when present, else the matching AMFA user-session note
     * (how a brokered login's context survives), else "".
     */
    private static String contextValue(Map<String, String> details, Supplier<UserSessionModel> loginSession, String detailKey) {
        String value = details.get(detailKey);
        if (value == null || value.isBlank()) {
            UserSessionModel userSession = loginSession.get();
            if (userSession != null) {
                value = userSession.getNote(EventBuilderHelper.userSessionNoteKey(detailKey));
            }
        }
        return nz(value);
    }

    /** Null-safe: return "" for a null value so required engine fields never serialize as JSON null. */
    private static String nz(String value) {
        return value == null ? "" : value;
    }
}
