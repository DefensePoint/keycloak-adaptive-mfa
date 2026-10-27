/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.amfa.authenticator.adaptiveauth.AdaptiveAuthAuthenticator;
import org.keycloak.amfa.authenticator.authcontext.AuthContextAuthenticator;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.UserModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.keycloak.sessions.AuthenticationSessionModel;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A brokered (SSO) login's final LOGIN event is emitted by Keycloak's broker
 * code with a fresh EventBuilder, so details added here never reach it. The
 * values must therefore also be stored as user-session notes, which Keycloak
 * copies onto the user session the broker login creates, where the webhook
 * event listener can still find them.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class EventBuilderHelperTest {

    @Mock
    EventBuilder eventBuilder;

    @Mock
    AuthenticationSessionModel authSession;

    @Test
    void storesEachDetailAsAUserSessionNoteForBrokeredLogins() {
        when(eventBuilder.detail(anyString(), anyString())).thenReturn(eventBuilder);
        when(authSession.getAuthNote(AdaptiveAuthAuthenticator.AUTH_NOTE)).thenReturn("2");
        when(authSession.getAuthNote(AdaptiveAuthAuthenticator.USER_AGENT)).thenReturn("Mozilla/5.0 (Macintosh)");
        when(authSession.getAuthNote(AdaptiveAuthAuthenticator.SCREEN_RESOLUTION)).thenReturn("1920x1080");
        when(authSession.getAuthNote(AdaptiveAuthAuthenticator.LOCAL)).thenReturn("en-US");
        when(authSession.getAuthNote(AuthContextAuthenticator.AUTH_CONTEXT_HASH)).thenReturn("abc123");
        when(authSession.getAuthNote(AdaptiveAuthAuthenticator.DECISION_SOURCE_NOTE)).thenReturn("engine");

        EventBuilderHelper.addExtraDetailsToEvent(eventBuilder, authSession);

        // Only the four values the webhook reads back are stored; the risk
        // level and decision source are not part of the webhook payload.
        verify(authSession, never()).setUserSessionNote(
                eq(EventBuilderHelper.userSessionNoteKey(AdaptiveAuthAuthenticator.RISK_LEVEL)), nullable(String.class));
        verify(authSession, never()).setUserSessionNote(
                eq(EventBuilderHelper.userSessionNoteKey(EventBuilderHelper.DECISION_SOURCE_DETAIL)), nullable(String.class));
        verify(authSession).setUserSessionNote(
                EventBuilderHelper.userSessionNoteKey(EventBuilderHelper.USER_AGENT_DETAIL), "Mozilla/5.0 (Macintosh)");
        verify(authSession).setUserSessionNote(
                EventBuilderHelper.userSessionNoteKey(EventBuilderHelper.SCREEN_RESOLUTION_DETAIL), "1920x1080");
        verify(authSession).setUserSessionNote(
                EventBuilderHelper.userSessionNoteKey(EventBuilderHelper.LOCALE_DETAIL), "en-US");
        verify(authSession).setUserSessionNote(
                EventBuilderHelper.userSessionNoteKey(EventBuilderHelper.AUTH_CONTEXT_HASH_DETAIL), "abc123");
    }

    // Keycloak leaves the user off a login denied by AMFA's deny tier; the
    // detail AMFA adds is how the webhook still knows whose login it was.
    @Test
    void namesTheScoredUserOnTheEvent() {
        when(eventBuilder.detail(anyString(), nullable(String.class))).thenReturn(eventBuilder);
        UserModel user = org.mockito.Mockito.mock(UserModel.class);
        when(user.getId()).thenReturn("u-1");
        when(authSession.getAuthenticatedUser()).thenReturn(user);

        EventBuilderHelper.addExtraDetailsToEvent(eventBuilder, authSession);

        verify(eventBuilder).detail(EventBuilderHelper.USER_ID_DETAIL, "u-1");
    }

    @Test
    void noAuthenticatedUserAddsNoUserDetail() {
        when(eventBuilder.detail(anyString(), nullable(String.class))).thenReturn(eventBuilder);
        when(authSession.getAuthenticatedUser()).thenReturn(null);

        EventBuilderHelper.addExtraDetailsToEvent(eventBuilder, authSession);

        verify(eventBuilder, never()).detail(org.mockito.ArgumentMatchers.eq(EventBuilderHelper.USER_ID_DETAIL), nullable(String.class));
    }

    @Test
    void aMissingAuthNoteIsNotStoredAsANote() {
        when(eventBuilder.detail(anyString(), nullable(String.class))).thenReturn(eventBuilder);
        when(authSession.getAuthNote(anyString())).thenReturn(null);

        EventBuilderHelper.addExtraDetailsToEvent(eventBuilder, authSession);

        verify(authSession, never()).setUserSessionNote(anyString(), nullable(String.class));
    }
}
