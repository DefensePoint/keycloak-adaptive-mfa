/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.authenticator.adaptiveauth;

/**
 * The result of {@link AdaptiveAuthUtils#getUserAdaptiveAuthDecision}.
 *
 * <p>Carries not just the risk level but WHERE it came from: a genuine answer
 * from the engine, or the realm's configured fallback because the engine could
 * not be consulted. Previously a bare {@code int} made these two cases
 * indistinguishable everywhere downstream, including in the Keycloak login
 * event, so a silently degraded deployment looked identical to a healthy one.
 *
 * <p>The source is the login event's decision_source detail.
 */
public class AdaptiveAuthDecision {
    /** The engine decided. */
    public static final String SOURCE_ENGINE = "engine";
    /** The engine could not be consulted; the realm's fallback level applies. */
    public static final String SOURCE_FALLBACK = "fallback";
    /**
     * The engine answered 429: it is up but refused this user's request. Not an
     * outage, and not a reason to make the login easier: the login steps up.
     */
    public static final String SOURCE_RATE_LIMITED = "rate_limited";

    private final int riskLevel;
    private final String source;

    public AdaptiveAuthDecision(int riskLevel, boolean fromFallback) {
        this(riskLevel, fromFallback ? SOURCE_FALLBACK : SOURCE_ENGINE);
    }

    private AdaptiveAuthDecision(int riskLevel, String source) {
        this.riskLevel = riskLevel;
        this.source = source;
    }

    /** A login the engine rate-limited, at {@code riskLevel}. */
    public static AdaptiveAuthDecision rateLimited(int riskLevel) {
        return new AdaptiveAuthDecision(riskLevel, SOURCE_RATE_LIMITED);
    }

    public int getRiskLevel() {
        return riskLevel;
    }

    public boolean isFromFallback() {
        return SOURCE_FALLBACK.equals(source);
    }

    public String getSource() {
        return source;
    }
}
