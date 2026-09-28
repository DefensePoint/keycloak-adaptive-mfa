/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.authenticator.adaptiveauth;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AdaptiveAuthDecisionTest {

    @Test
    void constructorAndGetters() {
        AdaptiveAuthDecision decision = new AdaptiveAuthDecision(2, false);
        assertEquals(2, decision.getRiskLevel());
        assertFalse(decision.isFromFallback());
    }

    @Test
    void isFromFallback_trueWhenFallback() {
        AdaptiveAuthDecision decision = new AdaptiveAuthDecision(3, true);
        assertTrue(decision.isFromFallback());
        assertEquals(3, decision.getRiskLevel());
    }

    @Test
    void isFromFallback_falseWhenEngine() {
        AdaptiveAuthDecision decision = new AdaptiveAuthDecision(1, false);
        assertFalse(decision.isFromFallback());
    }
}
