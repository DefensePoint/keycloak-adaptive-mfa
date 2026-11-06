/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.authenticator.adaptiveauth;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import jakarta.ws.rs.core.MultivaluedHashMap;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.RealmModel;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
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

    @Test
    void isSwitchedOff_returnsTrueForFalse() {
        when(realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_TOGGLE)).thenReturn("false");
        assertTrue(AdaptiveAuthUtils.isSwitchedOff(realm));
    }

    @Test
    void isSwitchedOff_returnsTrueCaseInsensitive() {
        when(realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_TOGGLE)).thenReturn(" FALSE ");
        assertTrue(AdaptiveAuthUtils.isSwitchedOff(realm));
    }

    @Test
    void isSwitchedOff_returnsFalseForTrue() {
        when(realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_TOGGLE)).thenReturn("true");
        assertFalse(AdaptiveAuthUtils.isSwitchedOff(realm));
    }

    @Test
    void isSwitchedOff_returnsFalseWhenNotSet() {
        when(realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_TOGGLE)).thenReturn(null);
        assertFalse(AdaptiveAuthUtils.isSwitchedOff(realm));
    }

    @Test
    void isSwitchedOff_returnsFalseForTypo() {
        when(realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_TOGGLE)).thenReturn("off");
        assertFalse(AdaptiveAuthUtils.isSwitchedOff(realm));
    }

    @Test
    void isSwitchedOff_returnsFalseWhenRealmIsNull() {
        assertFalse(AdaptiveAuthUtils.isSwitchedOff(null));
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
