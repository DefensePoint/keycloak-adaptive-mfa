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

    // --- A login AMFA did not score (no risk note) ---

    @Test
    void matchCondition_unscored_neverMatchesLessOrEqual() {
        // A sub-flow meant for low-risk logins must not run for one AMFA never scored.
        setupMocks(null, "1", "LESS_OR_EQUAL");
        assertFalse(ConditionalUserConfiguredAdaptiveAuthAuthenticator.SINGLETON.matchCondition(flowContext));
    }

    @Test
    void matchCondition_unscored_neverMatchesEqual() {
        // Without a level, the condition compares against -1, which an unscored login also has.
        setupMocks(null, null, "EQUAL");
        assertFalse(ConditionalUserConfiguredAdaptiveAuthAuthenticator.SINGLETON.matchCondition(flowContext));
    }

    @Test
    void matchCondition_unscored_matchesGreaterOrEqualAsTheHighestRisk() {
        // A step-up for risky logins must run for a login AMFA never scored, rather
        // than let it in on the password alone.
        setupMocks(null, "2", "GREATER_OR_EQUAL");
        assertTrue(ConditionalUserConfiguredAdaptiveAuthAuthenticator.SINGLETON.matchCondition(flowContext));
    }

    @Test
    void matchCondition_unscored_matchesTheHighestLevel() {
        setupMocks(null, "4", "GREATER_OR_EQUAL");
        assertTrue(ConditionalUserConfiguredAdaptiveAuthAuthenticator.SINGLETON.matchCondition(flowContext));
    }

    @Test
    void matchCondition_unscored_unknownOperatorAlsoMatchesAsTheHighestRisk() {
        setupMocks(null, "2", "MORE_THAN");
        assertTrue(ConditionalUserConfiguredAdaptiveAuthAuthenticator.SINGLETON.matchCondition(flowContext));
    }

    @Test
    void matchCondition_unscored_greaterOrEqualWithoutALevelStillMatches() {
        setupMocks(null, null, "GREATER_OR_EQUAL");
        assertTrue(ConditionalUserConfiguredAdaptiveAuthAuthenticator.SINGLETON.matchCondition(flowContext));
    }

    // --- Comparison and level the condition cannot use ---

    @Test
    void matchCondition_unknownOperator_comparesAsGreaterOrEqual() {
        setupMocks("3", "2", "MORE_THAN");
        assertTrue(ConditionalUserConfiguredAdaptiveAuthAuthenticator.SINGLETON.matchCondition(flowContext));
    }

    @Test
    void matchCondition_withoutConfig_doesNotFailTheLogin() {
        // A condition step added but never configured compares as GREATER_OR_EQUAL against
        // no level, so it matches and the step-up runs, as a config without the level does.
        when(flowContext.getSession()).thenReturn(session);
        when(session.getContext()).thenReturn(keycloakContext);
        when(keycloakContext.getAuthenticationSession()).thenReturn(authSession);
        when(authSession.getAuthNote(AdaptiveAuthAuthenticator.AUTH_NOTE)).thenReturn("1");
        when(flowContext.getAuthenticatorConfig()).thenReturn(null);
        assertTrue(ConditionalUserConfiguredAdaptiveAuthAuthenticator.SINGLETON.matchCondition(flowContext));
    }

    @Test
    void matchCondition_levelThatIsNotANumber_countsAsNoLevel() {
        setupMocks("1", "high", "LESS_OR_EQUAL");
        assertFalse(ConditionalUserConfiguredAdaptiveAuthAuthenticator.SINGLETON.matchCondition(flowContext));
    }

    @Test
    void matchCondition_levelThatIsNotANumber_stillStepsUp() {
        setupMocks("1", "high", "GREATER_OR_EQUAL");
        assertTrue(ConditionalUserConfiguredAdaptiveAuthAuthenticator.SINGLETON.matchCondition(flowContext));
    }
}
