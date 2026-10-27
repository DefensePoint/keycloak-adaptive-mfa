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
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Keycloak emits a login denied by AMFA's deny tier without a user ID: as
 * LOGIN_ERROR for a local login and as IDENTITY_PROVIDER_POST_LOGIN_ERROR, an
 * event the webhook did not forward, for a login through an identity
 * provider. The engine then never learned which user was refused, and the
 * user's decision stayed open. Both events carry the details AMFA's own step
 * added, which now include the user it scored.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AmfaWebhookFailureAttributionTest {

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
    org.keycloak.models.SingleUseObjectProvider singleUse;

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
        when(session.sessions()).thenReturn(sessions);
        when(realm.getName()).thenReturn("test-amfa");
        java.util.Set<String> used = new java.util.HashSet<>();
        when(session.singleUseObjects()).thenReturn(singleUse);
        when(singleUse.putIfAbsent(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyLong()))
                .thenAnswer(inv -> used.add(inv.getArgument(0)));

        provider = new AmfaWebhookEventListenerProvider(session);
    }

    private void user(String id, String username) {
        UserModel user = mock(UserModel.class);
        when(user.getId()).thenReturn(id);
        when(user.getUsername()).thenReturn(username);
        when(user.getEmail()).thenReturn(username + "@example.com");
        when(users.getUserById(realm, id)).thenReturn(user);
    }

    private Event event(EventType type, String userId, Map<String, String> details) {
        Event event = new Event();
        event.setType(type);
        event.setRealmId("realm-id");
        event.setUserId(userId);
        event.setClientId("test-login");
        event.setIpAddress("203.0.113.9");
        event.setTime(1760000000000L);
        event.setError("access_denied");
        event.setDetails(details);
        return event;
    }

    private JsonObject payloadOf(String jws) {
        assertNotNull(jws, "expected a signed payload");
        String body = new String(Base64.getUrlDecoder().decode(jws.split("\\.")[1]), StandardCharsets.UTF_8);
        return JsonParser.parseString(body).getAsJsonObject();
    }

    /** The claim's string value, or null when absent: the token omits null values. */
    private static String text(JsonObject obj, String key) {
        return obj.has(key) && !obj.get(key).isJsonNull() ? obj.get(key).getAsString() : null;
    }

    @Test
    void forwardsTheBrokeredLoginDenial() {
        assertTrue(AmfaWebhookEventListenerProvider.isForwarded(EventType.IDENTITY_PROVIDER_POST_LOGIN_ERROR));
    }

    // Keycloak delivers each copy in its own session, to its own listener
    // instance, so only a store shared across sessions can tell them apart.
    @Test
    void aBrokeredDenialIsForwardedOncePerLoginSession() {
        Event first = event(EventType.IDENTITY_PROVIDER_POST_LOGIN_ERROR, null, Map.of("code_id", "c-1"));
        Event duplicate = event(EventType.IDENTITY_PROVIDER_POST_LOGIN_ERROR, null, Map.of("code_id", "c-1"));
        Event otherLogin = event(EventType.IDENTITY_PROVIDER_POST_LOGIN_ERROR, null, Map.of("code_id", "c-2"));
        AmfaWebhookEventListenerProvider secondInstance = new AmfaWebhookEventListenerProvider(session);

        assertTrue(provider.firstOfItsKind(first));
        org.junit.jupiter.api.Assertions.assertFalse(secondInstance.firstOfItsKind(duplicate));
        assertTrue(secondInstance.firstOfItsKind(otherLogin));
    }

    @Test
    void otherEventsAreNeverTreatedAsDuplicates() {
        Event login = event(EventType.LOGIN_ERROR, null, Map.of("code_id", "c-1"));

        assertTrue(provider.firstOfItsKind(login));
        assertTrue(provider.firstOfItsKind(login));
    }

    @Test
    void brokeredDenialReachesTheEngineAsALoginErrorOfItsUser() {
        user("u-sso", "sso-user");

        JsonObject payload = payloadOf(provider.buildSignedPayload(realm, event(
                EventType.IDENTITY_PROVIDER_POST_LOGIN_ERROR, null,
                Map.of(EventBuilderHelper.USER_ID_DETAIL, "u-sso", "identity_provider", "corp", "risk_level", "4"))));

        assertEquals("LOGIN_ERROR", text(payload, "type"));
        assertEquals("u-sso", text(payload, "sub"));
        JsonObject data = payload.getAsJsonObject("data");
        assertEquals("u-sso", text(data, "user_id"));
        assertEquals("sso-user", text(data, "username"));
        assertEquals("access_denied", text(data, "error"));
    }

    @Test
    void localDenialWithoutAUserIdIsAttributedToTheScoredUser() {
        user("u-local", "local-user");

        JsonObject payload = payloadOf(provider.buildSignedPayload(realm, event(
                EventType.LOGIN_ERROR, null, Map.of(EventBuilderHelper.USER_ID_DETAIL, "u-local", "username", "local-user"))));

        assertEquals("LOGIN_ERROR", text(payload, "type"));
        assertEquals("u-local", text(payload, "sub"));
        assertEquals("u-local", text(payload.getAsJsonObject("data"), "user_id"));
    }

    @Test
    void theEventsOwnUserIdWins() {
        user("u-known", "known");
        user("u-other", "other");

        JsonObject payload = payloadOf(provider.buildSignedPayload(realm, event(
                EventType.LOGIN_ERROR, "u-known", Map.of(EventBuilderHelper.USER_ID_DETAIL, "u-other"))));

        assertEquals("u-known", text(payload.getAsJsonObject("data"), "user_id"));
    }

    @Test
    void aDetailNamingNoUserOfTheRealmLeavesTheUserUnknown() {
        JsonObject payload = payloadOf(provider.buildSignedPayload(realm, event(
                EventType.IDENTITY_PROVIDER_POST_LOGIN_ERROR, null, Map.of(EventBuilderHelper.USER_ID_DETAIL, "u-gone"))));

        assertNull(text(payload.getAsJsonObject("data"), "user_id"));
        assertNull(text(payload, "sub"));
    }

    @Test
    void aFailureWithoutTheDetailLeavesTheUserUnknown() {
        JsonObject payload = payloadOf(provider.buildSignedPayload(realm, event(
                EventType.LOGIN_ERROR, null, Map.of("username", "nobody"))));

        assertNull(text(payload.getAsJsonObject("data"), "user_id"));
    }

    @Test
    void onlyFailuresAreAttributedFromTheDetail() {
        user("u-x", "x");

        JsonObject payload = payloadOf(provider.buildSignedPayload(realm, event(
                EventType.UPDATE_PASSWORD, null, Map.of(EventBuilderHelper.USER_ID_DETAIL, "u-x"))));

        assertNull(text(payload.getAsJsonObject("data"), "user_id"));
    }
}
