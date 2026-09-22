/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.authenticator.adaptiveauth;

import org.keycloak.amfa.authenticator.adaptiveauth.model.AdaptiveAuthResponse;
import org.keycloak.amfa.service.serviceaccount.ServiceAccountService;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sessions.AuthenticationSessionModel;

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
            log.warn("Realm attribute '" + ADAPTIVE_AUTH_API_FALLBACK_RISK_LEVEL
                    + "' is not set" + realmSuffix(realm) + "; using Risk "
                    + HIGH_RISK_LEVEL + " when the engine cannot be reached. Set it to a "
                    + "value between " + MIN_RISK_LEVEL + " and " + MAX_RISK_LEVEL + ".");
            return HIGH_RISK_LEVEL;
        }

        int level;
        try {
            level = Integer.parseInt(configured.trim());
        } catch (NumberFormatException e) {
            log.warn("Realm attribute '" + ADAPTIVE_AUTH_API_FALLBACK_RISK_LEVEL + "' is '"
                    + configured + "'" + realmSuffix(realm) + ", which is not a number; "
                    + "using Risk " + HIGH_RISK_LEVEL + ".");
            return HIGH_RISK_LEVEL;
        }

        if (level < MIN_RISK_LEVEL || level > MAX_RISK_LEVEL) {
            log.warn("Realm attribute '" + ADAPTIVE_AUTH_API_FALLBACK_RISK_LEVEL + "' is "
                    + level + realmSuffix(realm) + ", outside the valid range "
                    + MIN_RISK_LEVEL + "-" + MAX_RISK_LEVEL + "; using Risk "
                    + HIGH_RISK_LEVEL + ".");
            return HIGH_RISK_LEVEL;
        }

        return level;
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
        String url = realm.getAttribute(ADAPTIVE_AUTH_ENDPOINT);
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