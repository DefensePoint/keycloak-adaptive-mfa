/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.requiredactions;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.amfa.authenticator.adaptiveauth.AdaptiveAuthAuthenticator;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.events.EventBuilder;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * A LOGIN sent after a required action, such as TOTP setup or a password
 * change, is built from a new event, so the details the authenticators added
 * earlier in the login are not on it. Keycloak hands that LOGIN event to
 * evaluateTriggers just before sending it, which is where this action adds them.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AmfaLoginEventDetailsTest {

    @Mock
    RequiredActionContext context;

    @Mock
    EventBuilder event;

    @Mock
    AuthenticationSessionModel authSession;

    private final AmfaLoginEventDetails action = new AmfaLoginEventDetails();

    @Test
    void addsTheDetailsToTheLoginEventOfALoginAmfaScored() {
        when(context.getEvent()).thenReturn(event);
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(event.detail(anyString(), nullable(String.class))).thenReturn(event);
        when(authSession.getAuthNote(AdaptiveAuthAuthenticator.EVENT_ID_NOTE)).thenReturn("decision-1");
        when(authSession.getAuthNote(AdaptiveAuthAuthenticator.AUTH_NOTE)).thenReturn("2");
        when(authSession.getAuthNote(AdaptiveAuthAuthenticator.USER_AGENT)).thenReturn("Mozilla/5.0 (Macintosh)");

        action.evaluateTriggers(context);

        verify(event).detail(AdaptiveAuthAuthenticator.RISK_LEVEL, "2");
        verify(event).detail(AdaptiveAuthAuthenticator.USER_AGENT, "Mozilla/5.0 (Macintosh)");
    }

    // A login AMFA did not score, such as a silent re-login on a session
    // cookie, must not get details: they would describe another login's device.
    @Test
    void leavesTheEventAloneWhenAmfaDidNotScoreTheLogin() {
        when(context.getEvent()).thenReturn(event);
        when(context.getAuthenticationSession()).thenReturn(authSession);

        action.evaluateTriggers(context);

        verifyNoInteractions(event);
    }

    @Test
    void leavesTheEventAloneWithoutAnAuthenticationSession() {
        when(context.getEvent()).thenReturn(event);

        action.evaluateTriggers(context);

        verifyNoInteractions(event);
    }

    @Test
    void aFailureNeverBreaksTheLogin() {
        when(context.getEvent()).thenReturn(event);
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(authSession.getAuthNote(AdaptiveAuthAuthenticator.EVENT_ID_NOTE)).thenReturn("decision-1");
        when(event.detail(anyString(), nullable(String.class))).thenThrow(new IllegalStateException("boom"));

        assertDoesNotThrow(() -> action.evaluateTriggers(context));
    }

    // Only reached when an admin assigns the action to a user.
    @Test
    void anAssignedActionCompletesWithoutShowingAPage() {
        action.requiredActionChallenge(context);

        verify(context).success();
    }

    @Test
    void cannotBeRequestedByAClient() {
        assertEquals(InitiatedActionSupport.NOT_SUPPORTED, action.initiatedActionSupport());
    }

    // Keycloak's own jars on the test classpath carry a file of the same name,
    // so every copy is read.
    @Test
    void isRegisteredAsARequiredActionFactory() throws IOException {
        boolean listed = false;
        Enumeration<URL> files = getClass().getClassLoader().getResources(
                "META-INF/services/org.keycloak.authentication.RequiredActionFactory");
        while (files.hasMoreElements()) {
            try (InputStream in = files.nextElement().openStream()) {
                String services = new String(in.readAllBytes(), StandardCharsets.UTF_8);
                listed |= services.lines().map(String::trim).anyMatch(AmfaLoginEventDetails.class.getName()::equals);
            }
        }
        assertTrue(listed, "not listed in any RequiredActionFactory service file");
    }
}
