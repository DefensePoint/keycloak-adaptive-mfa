/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.authenticator.adaptiveauth;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ConditionalUserConfiguredAdaptiveAuthAuthenticatorTest {

    @Mock private AuthenticationFlowContext flowContext;
    @Mock private KeycloakSession session;
    @Mock private KeycloakContext keycloakContext;
    @Mock private AuthenticationSessionModel authSession;
    @Mock private AuthenticatorConfigModel configModel;

    private void setupMocks(String riskLevelNote, String configuredRiskLevel, String operator) {
        when(flowContext.getSession()).thenReturn(session);
        when(session.getContext()).thenReturn(keycloakContext);
        when(keycloakContext.getAuthenticationSession()).thenReturn(authSession);
        when(authSession.getAuthNote(AdaptiveAuthAuthenticator.AUTH_NOTE)).thenReturn(riskLevelNote);

        when(flowContext.getAuthenticatorConfig()).thenReturn(configModel);

        Map<String, String> config = new HashMap<>();
        if (configuredRiskLevel != null) {
            config.put(AdaptiveAuthUtils.ADAPTIVE_AUTH_CONDITIONAL_AUTHENTICATOR_RISK_LEVEL_CONFIG, configuredRiskLevel);
        }
        if (operator != null) {
            config.put(AdaptiveAuthUtils.ADAPTIVE_AUTH_CONDITIONAL_AUTHENTICATOR_OPERATOR_CONFIG, operator);
        }
        when(configModel.getConfig()).thenReturn(config);
    }

    // --- EQUAL operator ---

    @Test
    void matchCondition_equalOperator_matching() {
        setupMocks("3", "3", "EQUAL");
        assertTrue(ConditionalUserConfiguredAdaptiveAuthAuthenticator.SINGLETON.matchCondition(flowContext));
    }

    @Test
    void matchCondition_equalOperator_nonMatching() {
        setupMocks("2", "3", "EQUAL");
        assertFalse(ConditionalUserConfiguredAdaptiveAuthAuthenticator.SINGLETON.matchCondition(flowContext));
    }

    // --- LESS_OR_EQUAL operator ---

    @Test
    void matchCondition_lessOrEqual_whenLess() {
        setupMocks("1", "3", "LESS_OR_EQUAL");
        assertTrue(ConditionalUserConfiguredAdaptiveAuthAuthenticator.SINGLETON.matchCondition(flowContext));
    }

    @Test
    void matchCondition_lessOrEqual_whenEqual() {
        setupMocks("3", "3", "LESS_OR_EQUAL");
        assertTrue(ConditionalUserConfiguredAdaptiveAuthAuthenticator.SINGLETON.matchCondition(flowContext));
    }

    @Test
    void matchCondition_lessOrEqual_whenGreater() {
        setupMocks("4", "3", "LESS_OR_EQUAL");
        assertFalse(ConditionalUserConfiguredAdaptiveAuthAuthenticator.SINGLETON.matchCondition(flowContext));
    }

    // --- GREATER_OR_EQUAL operator (default) ---

    @Test
    void matchCondition_greaterOrEqual_whenGreater() {
        setupMocks("4", "3", "GREATER_OR_EQUAL");
        assertTrue(ConditionalUserConfiguredAdaptiveAuthAuthenticator.SINGLETON.matchCondition(flowContext));
    }

    @Test
    void matchCondition_greaterOrEqual_whenEqual() {
        setupMocks("3", "3", "GREATER_OR_EQUAL");
        assertTrue(ConditionalUserConfiguredAdaptiveAuthAuthenticator.SINGLETON.matchCondition(flowContext));
    }

    @Test
    void matchCondition_greaterOrEqual_whenLess() {
        setupMocks("2", "3", "GREATER_OR_EQUAL");
        assertFalse(ConditionalUserConfiguredAdaptiveAuthAuthenticator.SINGLETON.matchCondition(flowContext));
    }
}
