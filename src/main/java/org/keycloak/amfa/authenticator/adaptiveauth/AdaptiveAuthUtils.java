/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.authenticator.adaptiveauth;

import org.keycloak.amfa.authenticator.adaptiveauth.model.AdaptiveAuthResponse;
import org.keycloak.amfa.service.serviceaccount.ServiceAccountService;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Slf4j
public class AdaptiveAuthUtils {
    public static final String ADAPTIVE_AUTH_CONDITIONAL_AUTHENTICATOR_RISK_LEVEL_CONFIG = "conditionalAuthRiskLevelConfig";
    public static final String ADAPTIVE_AUTH_CONDITIONAL_AUTHENTICATOR_OPERATOR_CONFIG = "conditionalAuthRiskLevelOperator";
    public static final String ADAPTIVE_AUTH_ENDPOINT = "adaptiveAuthEndpoint";
    public static final String ADAPTIVE_AUTH_TOGGLE = "adaptiveToggle";
    public static final int HIGH_RISK_LEVEL = 3;
    private static final String ADAPTIVE_AUTH_API_CLIENT_ID = "adaptive-auth-api";
    public static final String ADAPTIVE_AUTH_API_FALLBACK_RISK_LEVEL="fallbackRisk";
    public static final String ADAPTIVE_AUTH_API_NOTIFY_ON_RISKY_LOGIN="notifyUsersRiskyLogin";

    /**
     * Whether an unreachable engine is an ADVISORY condition (proceed at the
     * realm's {@link #ADAPTIVE_AUTH_API_FALLBACK_RISK_LEVEL fallbackRisk}, the
     * long-standing default) or a MANDATORY one (deny the login outright).
     *
     * <p>Without an explicit, realm-scoped setting for this, every failure to reach
     * the engine -- connection refused, timeout, non-2xx response, or a
     * TLS/certificate error -- would silently proceed at a fixed, sometimes-
     * permissive fallback level, with nothing to distinguish that from a genuine
     * decision anywhere downstream. Making the choice explicit lets an operator
     * who needs the engine to be a real security control (not just a risk signal)
     * choose to fail closed instead.
     */
    public static final String ADAPTIVE_AUTH_FAILURE_MODE = "adaptiveAuthFailureMode";
    public static final String FAILURE_MODE_ADVISORY = "advisory";
    public static final String FAILURE_MODE_MANDATORY = "mandatory";

    /** The range the engine can return; anything outside it is a configuration error. */
    public static final int MIN_RISK_LEVEL = 1;
    public static final int MAX_RISK_LEVEL = 4;

    /**
     * Per realm, the unusable {@code fallbackRisk} value last warned about. The
     * value is read on every login, so without this a misconfigured realm logged
     * the same warning on every login. A realm is warned about again when its
     * value changes to another unusable one, or is fixed and later broken again.
     * Bounded by the number of realms.
     */
    private static final ConcurrentMap<String, String> WARNED_FALLBACK_RISK = new ConcurrentHashMap<>();
    private static final String UNSET = "\0unset";

    /**
     * The risk level to apply when the engine cannot be consulted.
     *
     * <p>Read from the realm's {@code fallbackRisk} attribute. Every failure to read a
     * usable value falls back to {@link #HIGH_RISK_LEVEL} rather than propagating,
     * because this value exists precisely for the case where something has already gone
     * wrong, and it is the wrong moment to add a second failure.
     *
     * <p>Parsing the attribute inline in the caller, rather than through this helper,
     * would throw NumberFormatException from inside the authenticator for any realm
     * missing the attribute, failing every login in that realm with an opaque error
     * naming nothing. A realm can end up in that state easily: the admin REST API
     * replaces the whole attribute map on update, so one PUT that omits the AMFA
     * attributes removes them.
     *
     * <p>Erring high is deliberate. An unconfigured realm asks for a step-up rather than
     * either refusing every login or waving everyone through, and it matches the
     * engine's own FALLBACK_RISK_LEVEL default.
     */
    public static int getFallbackRiskLevel(RealmModel realm) {
        String configured = realm == null
                ? null
                : realm.getAttribute(ADAPTIVE_AUTH_API_FALLBACK_RISK_LEVEL);

        if (configured == null || configured.trim().isEmpty()) {
            if (firstWarningFor(realm, configured == null ? UNSET : configured)) {
                log.warn("Realm attribute '" + ADAPTIVE_AUTH_API_FALLBACK_RISK_LEVEL
                        + "' is not set" + realmSuffix(realm) + "; using Risk "
                        + HIGH_RISK_LEVEL + " when the engine cannot be reached. Set it to a "
                        + "value between " + MIN_RISK_LEVEL + " and " + MAX_RISK_LEVEL + ".");
            }
            return HIGH_RISK_LEVEL;
        }

        int level;
        try {
            level = Integer.parseInt(configured.trim());
        } catch (NumberFormatException e) {
            if (firstWarningFor(realm, configured)) {
                log.warn("Realm attribute '" + ADAPTIVE_AUTH_API_FALLBACK_RISK_LEVEL + "' is '"
                        + configured + "'" + realmSuffix(realm) + ", which is not a number; "
                        + "using Risk " + HIGH_RISK_LEVEL + ".");
            }
            return HIGH_RISK_LEVEL;
        }

        if (level < MIN_RISK_LEVEL || level > MAX_RISK_LEVEL) {
            if (firstWarningFor(realm, configured)) {
                log.warn("Realm attribute '" + ADAPTIVE_AUTH_API_FALLBACK_RISK_LEVEL + "' is "
                        + level + realmSuffix(realm) + ", outside the valid range "
                        + MIN_RISK_LEVEL + "-" + MAX_RISK_LEVEL + "; using Risk "
                        + HIGH_RISK_LEVEL + ".");
            }
            return HIGH_RISK_LEVEL;
        }

        WARNED_FALLBACK_RISK.remove(realmKey(realm));
        return level;
    }

    /** Whether this unusable value is new for the realm, recording it if so. */
    private static boolean firstWarningFor(RealmModel realm, String value) {
        return !Objects.equals(WARNED_FALLBACK_RISK.put(realmKey(realm), value), value);
    }

    private static String realmKey(RealmModel realm) {
        return realm == null ? "" : String.valueOf(realm.getId());
    }

    /**
     * Whether the realm's AMFA switch (the admin page's "Enabled") is off.
     *
     * <p>Only an explicit {@code false} counts. The login steps run only in a realm
     * whose flow contains them, so a realm without the attribute is one that put
     * AMFA in its login on purpose. It may have lost the attribute: a realm update
     * through the admin REST API replaces the whole attribute map, so one PUT that
     * omits the AMFA attributes removes the switch, the endpoint and the failure
     * mode together. Treating that as off would let its logins through as low
     * risk; treated as on, a realm without an endpoint gets the fallback level (see
     * {@link #getFallbackRiskLevel}), or is denied in mandatory failure mode. The
     * login webhook and the admin page read the switch the same way.
     */
    public static boolean isSwitchedOff(RealmModel realm) {
        String toggle = realm == null ? null : realm.getAttribute(ADAPTIVE_AUTH_TOGGLE);
        return toggle != null && "false".equalsIgnoreCase(toggle.trim());
    }

    /** The realm's engine endpoint, or null when it has none. */
    public static String engineEndpoint(RealmModel realm) {
        String endpoint = realm == null ? null : realm.getAttribute(ADAPTIVE_AUTH_ENDPOINT);
        return endpoint == null || endpoint.isBlank() ? null : endpoint.trim();
    }

    /**
     * The request's User-Agent header in the form sent to the engine, or an empty
     * string when the request has none. A client may leave the header out, and the
     * engine requires the field, so a missing header must not become null.
     */
    public static String userAgent(HttpRequest request) {
        List<String> values = request.getHttpHeaders().getRequestHeaders().get("User-Agent");
        return values == null ? "" : values.toString();
    }

    private static String realmSuffix(RealmModel realm) {
        return realm == null ? "" : " in realm " + realm.getName();
    }

    /**
     * Whether the realm has opted into MANDATORY mode: any value other than the
     * literal string {@link #FAILURE_MODE_MANDATORY} (case-insensitive) -- unset,
     * blank, {@link #FAILURE_MODE_ADVISORY}, or a typo -- is treated as advisory,
     * the existing default behavior, so this can never be silently stricter than
     * an operator intended. A realm that means to fail closed must say so
     * unambiguously.
     */
    public static boolean isFailureModeMandatory(RealmModel realm) {
        String configured = realm == null
                ? null
                : realm.getAttribute(ADAPTIVE_AUTH_FAILURE_MODE);
        return configured != null && FAILURE_MODE_MANDATORY.equalsIgnoreCase(configured.trim());
    }

    public enum OS {
        MAC_OS("Mac OS"),
        IOS("iOS"),
        WIN32("Windows"),
        WIN64("Windows"),
        LINUX("Linux"),
        DROID("Droid"),
        SYMBIAN("Symbian"),
        BLACKBERRY("Blackberry"),
        J2ME("Java ME"),
        SUN_OS("Sun OS"),
        BOT("Bot"),
        UNKNOWN("Unknown");

        private final String name;

        OS(String name) {
            this.name = name;
        }

        public String getName() {
            return name;
        }
    }

    public enum Browser {
        IE_6("Internet Explorer"),
        IE_7("Internet Explorer"),
        IE_8("Internet Explorer"),
        IE_9("Internet Explorer"),
        IE_10("Internet Explorer"),
        IE_11("Internet Explorer"),
        EDGE("Edge"),
        CHROME("Chrome"),
        SAFARI("Safari"),
        FIREFOX_3("Firefox"),
        FIREFOX("Firefox"),
        OPERA("Opera"),
        UCWEB("UC Browser"),
        BOT("Bot"),
        UNKNOWN("Unknown");

        private final String name;

        Browser(String name) {
            this.name = name;
        }

        public String getName() {
            return this.name;
        }
    }

    public AdaptiveAuthDecision getUserAdaptiveAuthDecision(KeycloakSession session, AuthenticationSessionModel authSession, int defaultRiskLevel, String userId, String clientId, String ipAddress, String userAgent, String locales, String screenResolution, String realmName, String groupId, String eventId,String authContexthash) {
        // Deliberately two SEPARATE try/catch blocks, neither nested inside the
        // other: handleEngineFailure() can itself throw EngineUnavailableException
        // (mandatory mode), and that must propagate straight out of this method,
        // not get re-caught by an enclosing catch (Exception e) here and reported
        // under the wrong message with a doubled log line.
        RealmModel realm = authSession.getRealm();
        String url = engineEndpoint(realm);
        if (url == null) {
            // Nothing to ask: no token, and no request to "null/decision".
            return handleEngineFailure(realm, defaultRiskLevel,
                    "The realm has the AMFA step in its login flow but no engine endpoint ("
                            + ADAPTIVE_AUTH_ENDPOINT + "); set it on the realm's Adaptive MFA page, "
                            + "or switch AMFA off there", null);
        }
        AdaptiveAuthService adaptiveAuthService = new AdaptiveAuthService(session);

        String token;
        try {
            token = ServiceAccountService.getServiceAccountToken(realm, session, ADAPTIVE_AUTH_API_CLIENT_ID);

            if (token == null)
                throw new Exception("Token is NULL");
        } catch (Exception e) {
            return handleEngineFailure(realm, defaultRiskLevel,
                    "Failed to get AccessToken: " + e.getMessage(), e);
        }

        try {
            AdaptiveAuthResponse adaptiveAuthResponse = adaptiveAuthService.getAdaptiveAuthDecision(token, url + "/decision", userId, clientId, ipAddress, userAgent, locales, screenResolution, realmName, groupId, eventId,authContexthash);
            log.debug("{}", adaptiveAuthResponse);
            return new AdaptiveAuthDecision(adaptiveAuthResponse.getRiskLevel(), false);
        } catch (EngineRateLimitedException e) {
            // Not an outage: the engine is up and refused this user's request.
            // The fallback level would make the login easier to pass -- at 1,
            // a login after enough quick ones would get past MFA -- and
            // refusing would let anyone who can spend a user's budget lock
            // them out. So it steps up, in either failure mode.
            int riskLevel = Math.max(defaultRiskLevel, HIGH_RISK_LEVEL);
            log.warn("AMFA rate-limited the decision for a login in realm {}; it steps up at risk level {}: {}",
                    realm.getName(), riskLevel, e.getMessage());
            return AdaptiveAuthDecision.rateLimited(riskLevel);
        } catch (Exception e) {
            return handleEngineFailure(realm, defaultRiskLevel, "Failed to get a decision", e);
        }
    }

    /**
     * Every failure to reach the engine funnels through here -- connection refused,
     * timeout, non-2xx response, or a TLS/certificate error, since none of those
     * are distinguished by the callers above -- and this is the one place that
     * decides what happens next, instead of that decision being made implicitly
     * by always returning the fallback.
     *
     * <p>"ADAPTIVE_AUTH_ENGINE_UNREACHABLE" is a stable, greppable marker so a log
     * shipper/alert rule can catch this independent of the surrounding message
     * text, which may change.
     */
    private AdaptiveAuthDecision handleEngineFailure(RealmModel realm, int defaultRiskLevel, String message, Exception e) {
        log.error("ADAPTIVE_AUTH_ENGINE_UNREACHABLE Method: getUserAdaptiveAuthDecision -> " + message, e);
        if (isFailureModeMandatory(realm)) {
            throw new EngineUnavailableException(message, e);
        }
        return new AdaptiveAuthDecision(defaultRiskLevel, true);
    }
}