/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.authenticator.adaptiveauth;

import lombok.extern.slf4j.Slf4j;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

@Slf4j
public class ConditionalUserConfiguredAdaptiveAuthAuthenticator implements ConditionalAuthenticator {
    public static final ConditionalUserConfiguredAdaptiveAuthAuthenticator SINGLETON = new ConditionalUserConfiguredAdaptiveAuthAuthenticator();

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        int userRiskLevel = this.getUserAdaptiveAuthRiskLevel(context.getSession());
        int authenticatorRiskLevel = this.getAuthenticatorRiskLevel(context.getAuthenticatorConfig());
        String operator = context.getAuthenticatorConfig() == null ? "GREATER_OR_EQUAL"
                : context.getAuthenticatorConfig().getConfig()
                    .getOrDefault(AdaptiveAuthUtils.ADAPTIVE_AUTH_CONDITIONAL_AUTHENTICATOR_OPERATOR_CONFIG, "GREATER_OR_EQUAL");

        switch (operator) {
            case "EQUAL":
                return userRiskLevel == authenticatorRiskLevel;
            case "LESS_OR_EQUAL":
                return userRiskLevel <= authenticatorRiskLevel;
            case "GREATER_OR_EQUAL":
            default:
                return userRiskLevel >= authenticatorRiskLevel;
        }
    }

    protected int getUserAdaptiveAuthRiskLevel(KeycloakSession session) {
        return session.getContext().getAuthenticationSession().getAuthNote(AdaptiveAuthAuthenticator.AUTH_NOTE) == null ? -1 : Integer.parseInt(session.getContext().getAuthenticationSession().getAuthNote(AdaptiveAuthAuthenticator.AUTH_NOTE));
    }

    protected int getAuthenticatorRiskLevel(AuthenticatorConfigModel config) {
        return Integer.parseInt(config.getConfig().getOrDefault(AdaptiveAuthUtils.ADAPTIVE_AUTH_CONDITIONAL_AUTHENTICATOR_RISK_LEVEL_CONFIG, "-1"));
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // Not used
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // Not used
    }

    @Override
    public void close() {
        // Does nothing
    }
}
