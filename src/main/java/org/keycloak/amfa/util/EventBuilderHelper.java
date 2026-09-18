/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.util;

import org.keycloak.amfa.authenticator.authcontext.AuthContextAuthenticator;
import org.keycloak.events.EventBuilder;
import org.keycloak.sessions.AuthenticationSessionModel;

import static org.keycloak.amfa.authenticator.adaptiveauth.AdaptiveAuthAuthenticator.*;

public class EventBuilderHelper {

    // Event-detail keys. These carry the per-login authentication context from
    // the AMFA authenticators onto the LOGIN/LOGIN_ERROR event, so the webhook
    // event listener (which only sees the Event, not the auth session) can
    // reconstruct the payload the engine expects.
    public static final String USER_AGENT_DETAIL = USER_AGENT;
    public static final String SCREEN_RESOLUTION_DETAIL = SCREEN_RESOLUTION;
    public static final String LOCALE_DETAIL = LOCAL;
    public static final String AUTH_CONTEXT_HASH_DETAIL = "auth_context_hash";
    /**
     * "engine" or "fallback" -- whether risk_level on this event is a genuine
     * decision from the engine or the realm's configured fallback because the
     * engine could not be consulted. Without this, a silently degraded
     * deployment (engine down, every login proceeding at a fixed fallback
     * level) is indistinguishable from a healthy one in the Keycloak event log,
     * so an operator has no signal to alert on.
     */
    public static final String DECISION_SOURCE_DETAIL = "decision_source";

    public static void addExtraDetailsToEvent(EventBuilder eventBuilder, AuthenticationSessionModel authenticationSession) {
        eventBuilder.detail(RISK_LEVEL, authenticationSession.getAuthNote(AUTH_NOTE));
        eventBuilder.detail(USER_AGENT_DETAIL, authenticationSession.getAuthNote(USER_AGENT));
        eventBuilder.detail(SCREEN_RESOLUTION_DETAIL, authenticationSession.getAuthNote(SCREEN_RESOLUTION));
        eventBuilder.detail(LOCALE_DETAIL, authenticationSession.getAuthNote(LOCAL));
        eventBuilder.detail(AUTH_CONTEXT_HASH_DETAIL, authenticationSession.getAuthNote(AuthContextAuthenticator.AUTH_CONTEXT_HASH));
        eventBuilder.detail(DECISION_SOURCE_DETAIL, authenticationSession.getAuthNote(DECISION_SOURCE_NOTE));
    }
}
