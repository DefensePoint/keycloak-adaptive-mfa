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
 */
public class AdaptiveAuthDecision {
    private final int riskLevel;
    private final boolean fromFallback;

    public AdaptiveAuthDecision(int riskLevel, boolean fromFallback) {
        this.riskLevel = riskLevel;
        this.fromFallback = fromFallback;
    }

    public int getRiskLevel() {
        return riskLevel;
    }

    public boolean isFromFallback() {
        return fromFallback;
    }
}
