/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.requiredactions;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.amfa.util.EventBuilderHelper;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.sessions.AuthenticationSessionModel;

import static org.keycloak.amfa.authenticator.adaptiveauth.AdaptiveAuthAuthenticator.EVENT_ID_NOTE;

/**
 * Adds the AMFA details to the LOGIN event of a login that ends with a
 * required action, such as TOTP setup or a password change.
 *
 * <p>The authenticators add the details to the event of the flow they run in.
 * When the login then stops at a required action, the LOGIN that follows is
 * sent from the request that completes the action, with a new event, so the
 * details are missing from it: the webhook sends the engine an empty user
 * agent, screen resolution and locale for that login, and the stored Keycloak
 * event has no risk level. Keycloak passes that LOGIN event to
 * evaluateTriggers just before it sends it. The same holds for the LOGIN of
 * an SSO login, which Keycloak's broker code sends with a new event too, so
 * the stored event gets the details there as well.
 *
 * <p>It only acts when AMFA scored the login, never shows the user a page and
 * cannot be requested by a client. Keycloak does not register custom required
 * actions by itself, so it only runs in realms where an admin registered it.
 */
public class AmfaLoginEventDetails implements RequiredActionProvider, RequiredActionFactory {
    private static final Logger logger = Logger.getLogger(AmfaLoginEventDetails.class);

    public static final String PROVIDER_ID = "amfa-login-event-details";

    @Override
    public InitiatedActionSupport initiatedActionSupport() {
        return InitiatedActionSupport.NOT_SUPPORTED;
    }

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
        try {
            AuthenticationSessionModel authSession = context.getAuthenticationSession();
            // Only a login AMFA scored: a silent re-login on a session cookie
            // would otherwise report another login's device as its own.
            if (authSession != null && authSession.getAuthNote(EVENT_ID_NOTE) != null) {
                EventBuilderHelper.addExtraDetailsToEvent(context.getEvent(), authSession);
            }
        } catch (RuntimeException e) {
            // Never let the details break a login.
            logger.warn("Could not add the AMFA details to the login event", e);
        }
    }

    // Only reached when an admin assigns the action to a user; there is nothing to ask.
    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        context.success();
    }

    @Override
    public void processAction(RequiredActionContext context) {
        context.success();
    }

    @Override
    public String getDisplayText() {
        return "AMFA details on login events";
    }

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
