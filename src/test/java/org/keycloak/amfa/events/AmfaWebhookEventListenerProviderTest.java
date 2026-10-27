/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.events;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.amfa.util.EventBuilderHelper;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.AsymmetricSignatureSignerContext;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.KeyManager;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.UserSessionProvider;
import org.keycloak.urls.UrlType;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A brokered (SSO) login's LOGIN event carries only the broker's own details,
 * so the webhook used to send the engine an authContextModel with empty
 * user_agent / system_language / screen_resolution and an empty
 * auth_context_hash. When the AMFA steps ran in the identity provider's post
 * login flow, the values exist as user-session notes, and the payload must fall
 * back to them.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AmfaWebhookEventListenerProviderTest {

    @Mock
    KeycloakSession session;
    @Mock
    RealmModel realm;
    @Mock
    KeyManager keys;
    @Mock
    SignatureProvider signatureProvider;
    @Mock
    KeycloakContext context;
    @Mock
    KeycloakUriInfo uriInfo;
    @Mock
    UserProvider users;
    @Mock
    UserSessionProvider sessions;
    @Mock
    UserSessionModel userSession;

    AmfaWebhookEventListenerProvider provider;

    @BeforeEach
    void setUp() throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        KeyWrapper key = new KeyWrapper();
        key.setKid("test-kid");
        key.setAlgorithm(Algorithm.RS256);
        key.setUse(KeyUse.SIG);
        key.setPrivateKey(pair.getPrivate());
        key.setPublicKey(pair.getPublic());

        when(session.keys()).thenReturn(keys);
        when(keys.getActiveKey(realm, KeyUse.SIG, Algorithm.RS256)).thenReturn(key);
        when(session.getProvider(SignatureProvider.class, Algorithm.RS256)).thenReturn(signatureProvider);
        when(signatureProvider.signer(key)).thenReturn(new AsymmetricSignatureSignerContext(key));
        when(session.getContext()).thenReturn(context);
        when(context.getUri(UrlType.FRONTEND)).thenReturn(uriInfo);
        when(uriInfo.getBaseUri()).thenReturn(URI.create("http://kc.test"));
        when(session.users()).thenReturn(users);
        when(users.getUserById(any(), any())).thenReturn(null);
        when(session.sessions()).thenReturn(sessions);
        when(realm.getName()).thenReturn("test-amfa");

        provider = new AmfaWebhookEventListenerProvider(session);
    }

    private Event loginEvent(Map<String, String> details, String sessionId) {
        Event event = new Event();
        event.setType(EventType.LOGIN);
        event.setRealmId("realm-id");
        event.setUserId("user-1");
        event.setSessionId(sessionId);
        event.setClientId("web");
        event.setIpAddress("203.0.113.9");
        event.setTime(1760000000000L);
        event.setDetails(details);
        return event;
    }

    private JsonObject payloadOf(String jws) {
        assertNotNull(jws, "expected a signed payload");
        String body = new String(Base64.getUrlDecoder().decode(jws.split("\\.")[1]), StandardCharsets.UTF_8);
        return JsonParser.parseString(body).getAsJsonObject();
    }

    @Test
    void brokeredLoginWithoutDetailsFallsBackToUserSessionNotes() {
        when(sessions.getUserSession(realm, "us-1")).thenReturn(userSession);
        when(userSession.getNote(EventBuilderHelper.userSessionNoteKey(EventBuilderHelper.USER_AGENT_DETAIL)))
                .thenReturn("Mozilla/5.0 (Macintosh)");
        when(userSession.getNote(EventBuilderHelper.userSessionNoteKey(EventBuilderHelper.LOCALE_DETAIL)))
                .thenReturn("en-US");
        when(userSession.getNote(EventBuilderHelper.userSessionNoteKey(EventBuilderHelper.SCREEN_RESOLUTION_DETAIL)))
                .thenReturn("1920x1080");
        when(userSession.getNote(EventBuilderHelper.userSessionNoteKey(EventBuilderHelper.AUTH_CONTEXT_HASH_DETAIL)))
                .thenReturn("abc123");

        // The broker's LOGIN event: identity_provider detail only, none of AMFA's.
        JsonObject payload = payloadOf(provider.buildSignedPayload(
                realm, loginEvent(Map.of("identity_provider", "corp"), "us-1")));

        JsonObject ctx = payload.getAsJsonObject("authContextModel");
        assertEquals("Mozilla/5.0 (Macintosh)", ctx.get("user_agent").getAsString());
        assertEquals("en-US", ctx.get("system_language").getAsString());
        assertEquals("1920x1080", ctx.get("screen_resolution").getAsString());
        assertEquals("abc123", payload.getAsJsonObject("data").get("auth_context_hash").getAsString());
    }

    @Test
    void eventDetailsOutrankUserSessionNotesWithoutReadingTheSession() {
        when(sessions.getUserSession(eq(realm), any())).thenReturn(userSession);
        when(userSession.getNote(any())).thenReturn("from-note");

        JsonObject payload = payloadOf(provider.buildSignedPayload(realm, loginEvent(Map.of(
                "identity_provider", "corp",
                EventBuilderHelper.USER_AGENT_DETAIL, "UA-from-detail",
                EventBuilderHelper.LOCALE_DETAIL, "da-DK",
                EventBuilderHelper.SCREEN_RESOLUTION_DETAIL, "1440x900",
                EventBuilderHelper.AUTH_CONTEXT_HASH_DETAIL, "hash-from-detail"), "us-1")));

        JsonObject ctx = payload.getAsJsonObject("authContextModel");
        assertEquals("UA-from-detail", ctx.get("user_agent").getAsString());
        assertEquals("da-DK", ctx.get("system_language").getAsString());
        assertEquals("1440x900", ctx.get("screen_resolution").getAsString());
        assertEquals("hash-from-detail", payload.getAsJsonObject("data").get("auth_context_hash").getAsString());
        verify(sessions, never()).getUserSession(any(), any());
    }

    // A silent re-login lets a session cookie through without AMFA's steps.
    // Its LOGIN must not inherit the device data of the login that created the
    // session: with a stolen cookie, that would report the victim's browser
    // alongside the attacker's IP.
    @Test
    void silentReloginDoesNotInheritTheSessionsDeviceData() {
        when(sessions.getUserSession(eq(realm), any())).thenReturn(userSession);
        when(userSession.getNote(any())).thenReturn("from-note");

        JsonObject payload = payloadOf(provider.buildSignedPayload(
                realm, loginEvent(Map.of("auth_method", "openid-connect"), "us-1")));

        JsonObject ctx = payload.getAsJsonObject("authContextModel");
        assertEquals("", ctx.get("user_agent").getAsString());
        assertEquals("", ctx.get("system_language").getAsString());
        assertEquals("", ctx.get("screen_resolution").getAsString());
        assertEquals("", payload.getAsJsonObject("data").get("auth_context_hash").getAsString());
        verify(sessions, never()).getUserSession(any(), any());
    }

    // Account changes such as a password update happen inside a session but
    // are not the login that set its notes, so they keep their own (empty) data.
    @Test
    void nonLoginEventDoesNotInheritTheSessionsDeviceData() {
        when(sessions.getUserSession(eq(realm), any())).thenReturn(userSession);
        when(userSession.getNote(any())).thenReturn("from-note");

        Event event = loginEvent(Map.of("identity_provider", "corp"), "us-1");
        event.setType(EventType.UPDATE_PASSWORD);
        JsonObject ctx = payloadOf(provider.buildSignedPayload(realm, event)).getAsJsonObject("authContextModel");

        assertEquals("", ctx.get("user_agent").getAsString());
        assertEquals("", ctx.get("screen_resolution").getAsString());
        verify(sessions, never()).getUserSession(any(), any());
    }

    @Test
    void noDetailsAndNoSessionStillSendsEmptyStrings() {
        JsonObject payload = payloadOf(provider.buildSignedPayload(realm, loginEvent(Map.of(), null)));

        JsonObject ctx = payload.getAsJsonObject("authContextModel");
        assertEquals("", ctx.get("user_agent").getAsString());
        assertEquals("", ctx.get("system_language").getAsString());
        assertEquals("", ctx.get("screen_resolution").getAsString());
        assertEquals("", payload.getAsJsonObject("data").get("auth_context_hash").getAsString());
    }
}
