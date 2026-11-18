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

import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class ConditionalUserConfiguredAdaptiveAuthAuthenticator implements ConditionalAuthenticator {
    public static final ConditionalUserConfiguredAdaptiveAuthAuthenticator SINGLETON = new ConditionalUserConfiguredAdaptiveAuthAuthenticator();

    private static final String GREATER_OR_EQUAL = "GREATER_OR_EQUAL";
    private static final List<String> COMPARISONS = List.of(GREATER_OR_EQUAL, "EQUAL", "LESS_OR_EQUAL");
    // Realm, condition and value triples already warned about, so a condition with
    // an unknown comparison or level logs once per value instead of on every login.
    private static final Set<String> WARNED = ConcurrentHashMap.newKeySet();

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        int userRiskLevel = this.getUserAdaptiveAuthRiskLevel(context.getSession());
        boolean scored = userRiskLevel >= 0;
        int authenticatorRiskLevel = this.getAuthenticatorRiskLevel(context);
        String operator = comparison(context);

        // A login AMFA did not score counts as the highest risk: it never matches "equal"
        // or "less or equal", so a sub-flow meant for low-risk logins does not run for
        // it, and it always matches "greater or equal", so a step-up does, instead of
        // the login going on with the password alone. Only a flow without the risk
        // step before the condition gets here: switched-off AMFA and the fallback
        // level both score the login.
        if (!scored) {
            warnUnscoredOnce(context);
        }
        switch (operator) {
            case "EQUAL":
                return scored && userRiskLevel == authenticatorRiskLevel;
            case "LESS_OR_EQUAL":
                return scored && userRiskLevel <= authenticatorRiskLevel;
            default:
                return !scored || userRiskLevel >= authenticatorRiskLevel;
        }
    }

    private static void warnUnscoredOnce(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        String alias = config == null ? null : config.getAlias();
        String realmName = context.getRealm() == null ? null : context.getRealm().getName();
        if (WARNED.add("Unscored\u0000" + realmName + "\u0000" + alias)) {
            log.warn("AMFA risk condition {} in realm {} got a login AMFA did not score, so it is "
                    + "matched as the highest risk; put the AMFA risk step before the condition",
                    alias, realmName);
        }
    }

    /**
     * The condition's comparison. A condition without one, or without a config at
     * all, compares as GREATER_OR_EQUAL, as before. So does a value that is not one
     * of the three, which only the REST API or a realm import can set; that is
     * logged once per realm, condition and value.
     */
    private String comparison(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        String key = AdaptiveAuthUtils.ADAPTIVE_AUTH_CONDITIONAL_AUTHENTICATOR_OPERATOR_CONFIG;
        if (config == null || config.getConfig() == null || !config.getConfig().containsKey(key)) {
            return GREATER_OR_EQUAL;
        }
        String configured = config.getConfig().get(key);
        if (configured != null && COMPARISONS.contains(configured)) {
            return configured;
        }
        warnOnce(context, "Comparison", configured, "comparing as " + GREATER_OR_EQUAL);
        return GREATER_OR_EQUAL;
    }

    private static void warnOnce(AuthenticationFlowContext context, String what, String value, String outcome) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        String alias = config == null ? null : config.getAlias();
        String realmName = context.getRealm() == null ? null : context.getRealm().getName();
        if (WARNED.add(what + "\u0000" + realmName + "\u0000" + alias + "\u0000" + value)) {
            log.warn("{} '{}' of AMFA risk condition {} in realm {} cannot be used; {}",
                    what, value, alias, realmName, outcome);
        }
    }

    protected int getUserAdaptiveAuthRiskLevel(KeycloakSession session) {
        return session.getContext().getAuthenticationSession().getAuthNote(AdaptiveAuthAuthenticator.AUTH_NOTE) == null ? -1 : Integer.parseInt(session.getContext().getAuthenticationSession().getAuthNote(AdaptiveAuthAuthenticator.AUTH_NOTE));
    }

    /**
     * The condition's risk level, or -1 when it has none: no config, no level, or a
     * level that is not a number. Then GREATER_OR_EQUAL always matches, so the
     * step-up runs, and the other comparisons never match a scored login.
     */
    protected int getAuthenticatorRiskLevel(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        if (config == null || config.getConfig() == null) {
            return -1;
        }
        String configured = config.getConfig().get(AdaptiveAuthUtils.ADAPTIVE_AUTH_CONDITIONAL_AUTHENTICATOR_RISK_LEVEL_CONFIG);
        if (configured == null) {
            return -1;
        }
        try {
            return Integer.parseInt(configured.trim());
        } catch (NumberFormatException e) {
            warnOnce(context, "Risk level", configured, "comparing against no level");
            return -1;
        }
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
