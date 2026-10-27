/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.util;

import org.keycloak.amfa.authenticator.authcontext.AuthContextAuthenticator;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.UserModel;
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
    /**
     * The ID of the user AMFA scored. Keycloak leaves the user off a login
     * its flow refuses after AMFA ran (AMFA's deny tier), as LOGIN_ERROR or,
     * through an identity provider, IDENTITY_PROVIDER_POST_LOGIN_ERROR, but
     * keeps the flow's details; this one tells the webhook whose login it was.
     */
    public static final String USER_ID_DETAIL = "amfa_user_id";

    /**
     * Prefix for the user-session notes that mirror the event details above.
     * A brokered (SSO) login's final LOGIN event is emitted by Keycloak's
     * broker code with a fresh EventBuilder, so the details never reach it;
     * the user-session copy is where the webhook listener finds them instead.
     * Prefixed so AMFA's notes cannot collide with Keycloak's own.
     */
    public static final String USER_SESSION_NOTE_PREFIX = "amfa.";

    /** The user-session note key mirroring the given event-detail key. */
    public static String userSessionNoteKey(String detailKey) {
        return USER_SESSION_NOTE_PREFIX + detailKey;
    }

    public static void addExtraDetailsToEvent(EventBuilder eventBuilder, AuthenticationSessionModel authenticationSession) {
        eventBuilder.detail(RISK_LEVEL, authenticationSession.getAuthNote(AUTH_NOTE));
        detailAndUserSessionNote(eventBuilder, authenticationSession, USER_AGENT_DETAIL, USER_AGENT);
        detailAndUserSessionNote(eventBuilder, authenticationSession, SCREEN_RESOLUTION_DETAIL, SCREEN_RESOLUTION);
        detailAndUserSessionNote(eventBuilder, authenticationSession, LOCALE_DETAIL, LOCAL);
        detailAndUserSessionNote(eventBuilder, authenticationSession, AUTH_CONTEXT_HASH_DETAIL, AuthContextAuthenticator.AUTH_CONTEXT_HASH);
        eventBuilder.detail(DECISION_SOURCE_DETAIL, authenticationSession.getAuthNote(DECISION_SOURCE_NOTE));
        UserModel user = authenticationSession.getAuthenticatedUser();
        if (user != null) {
            eventBuilder.detail(USER_ID_DETAIL, user.getId());
        }
    }

    /** For the four values the webhook payload carries: an event detail and its user-session note. */
    private static void detailAndUserSessionNote(EventBuilder eventBuilder,
            AuthenticationSessionModel authenticationSession, String detailKey, String authNoteKey) {
        String value = authenticationSession.getAuthNote(authNoteKey);
        eventBuilder.detail(detailKey, value);
        if (value != null) {
            authenticationSession.setUserSessionNote(userSessionNoteKey(detailKey), value);
        }
    }
}
