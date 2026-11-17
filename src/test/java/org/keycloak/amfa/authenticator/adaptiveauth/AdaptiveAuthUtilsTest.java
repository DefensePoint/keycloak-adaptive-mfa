/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.authenticator.adaptiveauth;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import jakarta.ws.rs.core.MultivaluedHashMap;
import org.keycloak.http.HttpRequest;
import org.keycloak.amfa.service.serviceaccount.ServiceAccountService;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AdaptiveAuthUtilsTest {

    @Mock
    private RealmModel realm;

    // --- getFallbackRiskLevel ---

    @Test
    void getFallbackRiskLevel_returnsConfiguredValue() {
        when(realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_API_FALLBACK_RISK_LEVEL)).thenReturn("2");
        assertEquals(2, AdaptiveAuthUtils.getFallbackRiskLevel(realm));
    }

    @Test
    void getFallbackRiskLevel_returnsConfiguredValueAtMinBound() {
        when(realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_API_FALLBACK_RISK_LEVEL)).thenReturn("1");
        assertEquals(1, AdaptiveAuthUtils.getFallbackRiskLevel(realm));
    }

    @Test
    void getFallbackRiskLevel_returnsConfiguredValueAtMaxBound() {
        when(realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_API_FALLBACK_RISK_LEVEL)).thenReturn("4");
        assertEquals(4, AdaptiveAuthUtils.getFallbackRiskLevel(realm));
    }

    @Test
    void getFallbackRiskLevel_returnsHighRiskWhenAttributeIsNull() {
        when(realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_API_FALLBACK_RISK_LEVEL)).thenReturn(null);
        assertEquals(AdaptiveAuthUtils.HIGH_RISK_LEVEL, AdaptiveAuthUtils.getFallbackRiskLevel(realm));
    }

    @Test
    void getFallbackRiskLevel_returnsHighRiskWhenAttributeIsBlank() {
        when(realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_API_FALLBACK_RISK_LEVEL)).thenReturn("  ");
        assertEquals(AdaptiveAuthUtils.HIGH_RISK_LEVEL, AdaptiveAuthUtils.getFallbackRiskLevel(realm));
    }

    @Test
    void getFallbackRiskLevel_returnsHighRiskWhenNonNumeric() {
        when(realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_API_FALLBACK_RISK_LEVEL)).thenReturn("abc");
        assertEquals(AdaptiveAuthUtils.HIGH_RISK_LEVEL, AdaptiveAuthUtils.getFallbackRiskLevel(realm));
    }

    @Test
    void getFallbackRiskLevel_returnsHighRiskWhenOutOfRangeZero() {
        when(realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_API_FALLBACK_RISK_LEVEL)).thenReturn("0");
        assertEquals(AdaptiveAuthUtils.HIGH_RISK_LEVEL, AdaptiveAuthUtils.getFallbackRiskLevel(realm));
    }

    @Test
    void getFallbackRiskLevel_returnsHighRiskWhenOutOfRangeFive() {
        when(realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_API_FALLBACK_RISK_LEVEL)).thenReturn("5");
        assertEquals(AdaptiveAuthUtils.HIGH_RISK_LEVEL, AdaptiveAuthUtils.getFallbackRiskLevel(realm));
    }

    @Test
    void getFallbackRiskLevel_returnsHighRiskWhenNegative() {
        when(realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_API_FALLBACK_RISK_LEVEL)).thenReturn("-1");
        assertEquals(AdaptiveAuthUtils.HIGH_RISK_LEVEL, AdaptiveAuthUtils.getFallbackRiskLevel(realm));
    }

    @Test
    void getFallbackRiskLevel_returnsHighRiskWhenRealmIsNull() {
        assertEquals(AdaptiveAuthUtils.HIGH_RISK_LEVEL, AdaptiveAuthUtils.getFallbackRiskLevel(null));
    }

    // --- isFailureModeMandatory ---

    @Test
    void isFailureModeMandatory_returnsTrueForMandatory() {
        when(realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_FAILURE_MODE)).thenReturn("mandatory");
        assertTrue(AdaptiveAuthUtils.isFailureModeMandatory(realm));
    }

    @Test
    void isFailureModeMandatory_returnsTrueCaseInsensitive() {
        when(realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_FAILURE_MODE)).thenReturn("MANDATORY");
        assertTrue(AdaptiveAuthUtils.isFailureModeMandatory(realm));
    }

    @Test
    void isFailureModeMandatory_returnsFalseForAdvisory() {
        when(realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_FAILURE_MODE)).thenReturn("advisory");
        assertFalse(AdaptiveAuthUtils.isFailureModeMandatory(realm));
    }

    @Test
    void isFailureModeMandatory_returnsFalseForNull() {
        when(realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_FAILURE_MODE)).thenReturn(null);
        assertFalse(AdaptiveAuthUtils.isFailureModeMandatory(realm));
    }

    @Test
    void isFailureModeMandatory_returnsFalseForBlank() {
        when(realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_FAILURE_MODE)).thenReturn("");
        assertFalse(AdaptiveAuthUtils.isFailureModeMandatory(realm));
    }

    @Test
    void isFailureModeMandatory_returnsFalseForTypo() {
        when(realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_FAILURE_MODE)).thenReturn("mandatoryy");
        assertFalse(AdaptiveAuthUtils.isFailureModeMandatory(realm));
    }

    @Test
    void isFailureModeMandatory_returnsFalseWhenRealmIsNull() {
        assertFalse(AdaptiveAuthUtils.isFailureModeMandatory(null));
    }

    // --- isSwitchedOff ---
    //
    // Only an explicit "false" switches AMFA off. A realm without the attribute
    // is on: the login steps run only in a realm whose flow contains them, and
    // one admin REST update that omits the AMFA attributes removes the switch,
    // which must not let that realm's logins through as low risk.

    private void toggle(String value) {
        lenient().when(realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_TOGGLE)).thenReturn(value);
    }

    @Test
    void isSwitchedOff_trueForFalse() {
        toggle("false");
        assertTrue(AdaptiveAuthUtils.isSwitchedOff(realm));
    }

    @Test
    void isSwitchedOff_trueForFalseInAnyCaseAndSpacing() {
        toggle(" FALSE ");
        assertTrue(AdaptiveAuthUtils.isSwitchedOff(realm));
    }

    @Test
    void isSwitchedOff_falseWithoutASwitch() {
        toggle(null);
        assertFalse(AdaptiveAuthUtils.isSwitchedOff(realm));
    }

    @Test
    void isSwitchedOff_falseForABlankSwitch() {
        toggle("  ");
        assertFalse(AdaptiveAuthUtils.isSwitchedOff(realm));
    }

    @Test
    void isSwitchedOff_falseForTrue() {
        toggle("true");
        assertFalse(AdaptiveAuthUtils.isSwitchedOff(realm));
    }

    @Test
    void isSwitchedOff_falseForAnyOtherValue() {
        for (String value : new String[]{"yes", "1", "on", "enabled"}) {
            toggle(value);
            assertFalse(AdaptiveAuthUtils.isSwitchedOff(realm), value);
        }
    }

    @Test
    void isSwitchedOff_falseWhenRealmIsNull() {
        assertFalse(AdaptiveAuthUtils.isSwitchedOff(null));
    }

    // --- getUserAdaptiveAuthDecision without an endpoint ---
    //
    // A realm with the AMFA step in its flow and no engine endpoint, as one whose
    // AMFA attributes an admin REST update removed: the engine cannot be asked, so
    // the failure mode decides, without requesting a token or calling "null/decision".

    @Test
    void decision_withoutAnEndpoint_isTheFallbackLevelInAdvisoryMode() {
        when(realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_ENDPOINT)).thenReturn(null);
        lenient().when(realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_FAILURE_MODE)).thenReturn("advisory");
        AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
        when(authSession.getRealm()).thenReturn(realm);

        try (MockedStatic<ServiceAccountService> tokens = mockStatic(ServiceAccountService.class)) {
            AdaptiveAuthDecision decision = new AdaptiveAuthUtils().getUserAdaptiveAuthDecision(
                    mock(KeycloakSession.class), authSession, 3, "user-1", "web", "203.0.113.9",
                    "", "", "", "demo", "default", "event-1", "");
            assertEquals(3, decision.getRiskLevel());
            assertTrue(decision.isFromFallback());
            tokens.verifyNoInteractions();
        }
    }

    @Test
    void decision_withoutAnEndpoint_isDeniedInMandatoryMode() {
        when(realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_ENDPOINT)).thenReturn("  ");
        when(realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_FAILURE_MODE)).thenReturn("mandatory");
        AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
        when(authSession.getRealm()).thenReturn(realm);

        try (MockedStatic<ServiceAccountService> tokens = mockStatic(ServiceAccountService.class)) {
            assertThrows(EngineUnavailableException.class, () -> new AdaptiveAuthUtils().getUserAdaptiveAuthDecision(
                    mock(KeycloakSession.class), authSession, 3, "user-1", "web", "203.0.113.9",
                    "", "", "", "demo", "default", "event-1", ""));
            tokens.verifyNoInteractions();
        }
    }

    // --- userAgent ---

    private static HttpRequest requestWithHeaders(MultivaluedHashMap<String, String> headers) {
        HttpRequest request = mock(HttpRequest.class, Answers.RETURNS_DEEP_STUBS);
        when(request.getHttpHeaders().getRequestHeaders()).thenReturn(headers);
        return request;
    }

    @Test
    void userAgent_missingHeaderIsEmpty() {
        assertEquals("", AdaptiveAuthUtils.userAgent(requestWithHeaders(new MultivaluedHashMap<>())));
    }

    @Test
    void userAgent_presentHeaderKeepsItsForm() {
        MultivaluedHashMap<String, String> headers = new MultivaluedHashMap<>();
        headers.add("User-Agent", "Mozilla/5.0 (Macintosh)");
        assertEquals(headers.get("User-Agent").toString(), AdaptiveAuthUtils.userAgent(requestWithHeaders(headers)));
    }
}
