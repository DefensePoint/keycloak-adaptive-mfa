/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.authenticator.adaptiveauth;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.*;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AdaptiveAuthAuthenticatorTest {

    @Mock private KeycloakSession session;
    @Mock private KeycloakContext context;
    @Mock private AuthenticationSessionModel authSession;
    @Mock private RealmModel realm;
    @Mock private ClientModel client;

    // --- parseUserAgent ---

    private String[] parseUserAgent(String ua) throws Exception {
        Method method = AdaptiveAuthAuthenticator.class.getDeclaredMethod("parseUserAgent", String.class);
        method.setAccessible(true);
        try {
            return (String[]) method.invoke(null, ua);
        } catch (InvocationTargetException e) {
            throw (Exception) e.getCause();
        }
    }

    @Test
    void parseUserAgent_chromeOnWindows() throws Exception {
        String[] result = parseUserAgent(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        assertEquals("Windows", result[0]);
        assertEquals("Chrome", result[1]);
    }

    @Test
    void parseUserAgent_safariOnMacOS() throws Exception {
        String[] result = parseUserAgent(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15");
        assertEquals("Mac OS", result[0]);
        assertEquals("Safari", result[1]);
    }

    @Test
    void parseUserAgent_firefoxOnLinux() throws Exception {
        String[] result = parseUserAgent(
                "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0");
        assertEquals("Linux", result[0]);
        assertEquals("Firefox", result[1]);
    }

    @Test
    void parseUserAgent_edge() throws Exception {
        String[] result = parseUserAgent(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0");
        assertEquals("Windows", result[0]);
        assertEquals("Edge", result[1]);
    }

    @Test
    void parseUserAgent_opera() throws Exception {
        String[] result = parseUserAgent(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0");
        assertEquals("Windows", result[0]);
        assertEquals("Opera", result[1]);
    }

    @Test
    void parseUserAgent_ios() throws Exception {
        String[] result = parseUserAgent(
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1");
        assertEquals("iOS", result[0]);
        assertEquals("Safari", result[1]);
    }

    @Test
    void parseUserAgent_android() throws Exception {
        String[] result = parseUserAgent(
                "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36");
        assertEquals("Droid", result[0]);
        assertEquals("Chrome", result[1]);
    }

    @Test
    void parseUserAgent_bot() throws Exception {
        String[] result = parseUserAgent("Googlebot/2.1 (+http://www.google.com/bot.html)");
        assertEquals("Bot", result[0]);
        assertEquals("Bot", result[1]);
    }

    @Test
    void parseUserAgent_null() throws Exception {
        String[] result = parseUserAgent(null);
        assertEquals("Unknown", result[0]);
        assertEquals("Unknown", result[1]);
    }

    @Test
    void parseUserAgent_unknown() throws Exception {
        String[] result = parseUserAgent("SomeRandomAgent/1.0");
        assertEquals("Unknown", result[0]);
        assertEquals("Unknown", result[1]);
    }

    // --- getRealm ---

    @Test
    void getRealm_returnsNullWhenContextIsNull() {
        when(session.getContext()).thenReturn(null);
        assertNull(AdaptiveAuthAuthenticator.getRealm(session));
    }

    @Test
    void getRealm_returnsRealmFromContext() {
        when(session.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(realm);
        assertEquals(realm, AdaptiveAuthAuthenticator.getRealm(session));
    }

    @Test
    void getRealm_returnsRealmFromAuthSession() {
        when(session.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(null);
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(authSession.getRealm()).thenReturn(realm);
        assertEquals(realm, AdaptiveAuthAuthenticator.getRealm(session));
    }

    @Test
    void getRealm_returnsRealmFromClient() {
        when(session.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(null);
        when(context.getAuthenticationSession()).thenReturn(null);
        when(context.getClient()).thenReturn(client);
        when(client.getRealm()).thenReturn(realm);
        assertEquals(realm, AdaptiveAuthAuthenticator.getRealm(session));
    }

    @Test
    void getRealm_returnsNullWhenNothingAvailable() {
        when(session.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(null);
        when(context.getAuthenticationSession()).thenReturn(null);
        when(context.getClient()).thenReturn(null);
        assertNull(AdaptiveAuthAuthenticator.getRealm(session));
    }
}
