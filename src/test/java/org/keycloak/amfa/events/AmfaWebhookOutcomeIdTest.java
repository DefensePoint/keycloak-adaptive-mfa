/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.events;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.amfa.authenticator.adaptiveauth.AdaptiveAuthAuthenticator;
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
import org.keycloak.models.UserSessionProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
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
import static org.mockito.Mockito.when;

/**
 * The engine links a login's outcome to the decision that scored it by the
 * webhook id, so a LOGIN after AMFA's step must be sent under that decision's
 * id. Every other event keeps its own id: the engine rejects a second event
 * with the same id, so a wrong code sent under the decision id would cost the
 * LOGIN that follows the right one.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AmfaWebhookOutcomeIdTest {

    private static final String DECISION_ID = "5b0c7a52-1e1f-4a8e-9a43-0f6c2d9e7b11";
    private static final String KEYCLOAK_ID = "kc-event-1";

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
    AuthenticationSessionModel authSession;

    @Mock
    AmfaWebhookSender sender;


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

        // The login AMFA scored: its authentication session holds the decision id.
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(authSession.getAuthNote(AdaptiveAuthAuthenticator.EVENT_ID_NOTE)).thenReturn(DECISION_ID);

        provider = new AmfaWebhookEventListenerProvider(session, sender);
    }

    private Event event(EventType type, Map<String, String> details) {
        Event event = new Event();
        event.setId(KEYCLOAK_ID);
        event.setType(type);
        event.setRealmId("realm-id");
        event.setUserId("user-1");
        event.setSessionId("us-1");
        event.setClientId("web");
        event.setIpAddress("203.0.113.9");
        event.setTime(1760000000000L);
        event.setDetails(details);
        return event;
    }

    private String idSentFor(Event event) {
        String jws = provider.buildSignedPayload(realm, event);
        assertNotNull(jws, "expected a signed payload");
        String body = new String(Base64.getUrlDecoder().decode(jws.split("\\.")[1]), StandardCharsets.UTF_8);
        JsonObject payload = JsonParser.parseString(body).getAsJsonObject();
        return payload.get("id").getAsString();
    }

    @Test
    void loginIsSentUnderItsDecisionId() {
        assertEquals(DECISION_ID, idSentFor(event(EventType.LOGIN, Map.of())));
    }

    @Test
    void brokeredLoginIsSentUnderItsDecisionId() {
        assertEquals(DECISION_ID, idSentFor(event(EventType.LOGIN, Map.of("identity_provider", "corp"))));
    }

    // A wrong code entered before the right one (Keycloak's own OTP form
    // reports it as LOGIN_ERROR): under the decision id, the engine would
    // reject the LOGIN that follows as a duplicate.
    @Test
    void loginErrorKeepsItsOwnId() {
        assertEquals(KEYCLOAK_ID, idSentFor(event(EventType.LOGIN_ERROR, Map.of())));
    }

    @Test
    void brokeredDenialKeepsItsOwnId() {
        assertEquals(KEYCLOAK_ID, idSentFor(event(EventType.IDENTITY_PROVIDER_POST_LOGIN_ERROR, Map.of())));
    }

    @Test
    void accountChangeKeepsItsOwnId() {
        assertEquals(KEYCLOAK_ID, idSentFor(event(EventType.UPDATE_CREDENTIAL, Map.of())));
    }

    // A silent re-login on an existing session runs no AMFA step.
    @Test
    void loginWithoutAnAuthenticationSessionKeepsItsOwnId() {
        when(context.getAuthenticationSession()).thenReturn(null);
        assertEquals(KEYCLOAK_ID, idSentFor(event(EventType.LOGIN, Map.of())));
    }

    @Test
    void loginThatAmfaDidNotScoreKeepsItsOwnId() {
        when(authSession.getAuthNote(AdaptiveAuthAuthenticator.EVENT_ID_NOTE)).thenReturn(null);
        assertEquals(KEYCLOAK_ID, idSentFor(event(EventType.LOGIN, Map.of())));
    }

    @Test
    void blankDecisionIdIsIgnored() {
        when(authSession.getAuthNote(AdaptiveAuthAuthenticator.EVENT_ID_NOTE)).thenReturn(" ");
        assertEquals(KEYCLOAK_ID, idSentFor(event(EventType.LOGIN, Map.of())));
    }
}
