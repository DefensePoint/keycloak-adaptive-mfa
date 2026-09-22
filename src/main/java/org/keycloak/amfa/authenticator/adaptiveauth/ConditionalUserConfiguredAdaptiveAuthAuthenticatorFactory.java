/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.authenticator.adaptiveauth;

import org.keycloak.Config;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public class ConditionalUserConfiguredAdaptiveAuthAuthenticatorFactory implements ConditionalAuthenticatorFactory {
    public static final String PROVIDER_ID = "conditional-adaptive-auth";

    @Override
    public void init(Config.Scope config) {
        // no-op
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // no-op
    }

    @Override
    public void close() {
        // no-op
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Conditional - User Risk Level";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED, AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Executes the current flow only if authenticators are configured and match adaptive auth risk level";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty operator = new ProviderConfigProperty(
                AdaptiveAuthUtils.ADAPTIVE_AUTH_CONDITIONAL_AUTHENTICATOR_OPERATOR_CONFIG,
                "Comparison",
                "How the user's risk level is compared to the configured level: "
                        + "GREATER_OR_EQUAL (>=), EQUAL (==), or LESS_OR_EQUAL (<=).",
                ProviderConfigProperty.LIST_TYPE,
                "GREATER_OR_EQUAL");
        operator.setOptions(List.of("GREATER_OR_EQUAL", "EQUAL", "LESS_OR_EQUAL"));
        return List.of(
                new ProviderConfigProperty(AdaptiveAuthUtils.ADAPTIVE_AUTH_CONDITIONAL_AUTHENTICATOR_RISK_LEVEL_CONFIG, "Risk Level", "Adaptive Auth Risk Level [1, 2, 3...]", ProviderConfigProperty.STRING_TYPE, "1"),
                operator
        );
    }

    @Override
    public ConditionalAuthenticator getSingleton() {
        return ConditionalUserConfiguredAdaptiveAuthAuthenticator.SINGLETON;
    }
}
