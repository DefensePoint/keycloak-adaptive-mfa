/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.events;

import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpVersion;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicHttpResponse;
import org.apache.http.util.EntityUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.amfa.authenticator.adaptiveauth.AdaptiveAuthUtils;
import org.keycloak.amfa.util.EventBuilderHelper;
import org.keycloak.common.util.Time;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.AsymmetricSignatureSignerContext;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.KeyManager;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.UserProvider;
import org.keycloak.urls.UrlType;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.io.IOException;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * The login thread only signs the event and hands it to the sender; the HTTP
 * call to the engine happens when the sender runs it, with the same request as
 * before.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AmfaWebhookBackgroundSendTest {

    @Mock
    KeycloakSession session;
    @Mock
    RealmProvider realms;
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
    HttpClientProvider httpClientProvider;
    @Mock
    CloseableHttpClient httpClient;
    @Mock
    AmfaWebhookSender sender;

    AmfaWebhookEventListenerProvider provider;

    /** What the engine answers; the client closes it after reading. */
    private static class Answer extends BasicHttpResponse implements CloseableHttpResponse {
        Answer(int status) {
            super(HttpVersion.HTTP_1_1, status, "status");
        }

        @Override
        public void close() {
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        KeyWrapper key = new KeyWrapper();
        key.setKid("test-kid");
        key.setAlgorithm(Algorithm.RS256);
        key.setUse(KeyUse.SIG);
        key.setPrivateKey(pair.getPrivate());
        key.setPublicKey(pair.getPublic());

        when(session.realms()).thenReturn(realms);
        when(realms.getRealm("realm-id")).thenReturn(realm);
        when(realm.getName()).thenReturn("test-amfa");
        when(realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_TOGGLE)).thenReturn("true");
        when(realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_ENDPOINT)).thenReturn("http://engine.test/");
        when(session.keys()).thenReturn(keys);
        when(keys.getActiveKey(realm, KeyUse.SIG, Algorithm.RS256)).thenReturn(key);
        when(session.getProvider(SignatureProvider.class, Algorithm.RS256)).thenReturn(signatureProvider);
        when(signatureProvider.signer(key)).thenReturn(new AsymmetricSignatureSignerContext(key));
        when(session.getContext()).thenReturn(context);
        when(context.getUri(UrlType.FRONTEND)).thenReturn(uriInfo);
        when(uriInfo.getBaseUri()).thenReturn(URI.create("http://kc.test"));
        when(session.users()).thenReturn(users);
        when(session.getProvider(HttpClientProvider.class)).thenReturn(httpClientProvider);
        when(httpClientProvider.getHttpClient()).thenReturn(httpClient);
        when(httpClientProvider.getMaxConsumedResponseSize()).thenReturn(HttpClientProvider.DEFAULT_MAX_CONSUMED_RESPONSE_SIZE);
        Answer ok = new Answer(200);
        ok.setEntity(new StringEntity("{}"));
        when(httpClient.execute(any(HttpUriRequest.class))).thenReturn(ok);
        when(sender.submit(any(), any())).thenReturn(true);

        provider = new AmfaWebhookEventListenerProvider(session, sender);
    }

    private Event event(EventType type, String userId, Map<String, String> details) {
        Event event = new Event();
        event.setType(type);
        event.setRealmId("realm-id");
        event.setUserId(userId);
        event.setClientId("web");
        event.setIpAddress("203.0.113.9");
        event.setTime(1760000000000L);
        event.setDetails(details);
        return event;
    }

    private Runnable queuedFor(String key) {
        ArgumentCaptor<Runnable> webhook = ArgumentCaptor.forClass(Runnable.class);
        verify(sender).submit(eq(key), webhook.capture());
        return webhook.getValue();
    }

    @Test
    void theLoginThreadQueuesTheWebhookWithoutCallingTheEngine() throws Exception {
        provider.onEvent(event(EventType.LOGIN, "user-1", Map.of()));

        Runnable webhook = queuedFor("user-1");
        verify(httpClient, never()).execute(any(HttpUriRequest.class));

        webhook.run();

        ArgumentCaptor<HttpUriRequest> sent = ArgumentCaptor.forClass(HttpUriRequest.class);
        verify(httpClient).execute(sent.capture());
        HttpRequestBase request = (HttpRequestBase) sent.getValue();
        assertEquals("POST", request.getMethod());
        assertEquals("http://engine.test/login_event/webhook", request.getURI().toString());
        assertNotNull(request.getFirstHeader("SignedPayload"));
        assertEquals("{}", EntityUtils.toString(((HttpEntityEnclosingRequest) request).getEntity()));
        assertEquals(5000, request.getConfig().getSocketTimeout());
        assertEquals(5000, request.getConfig().getConnectTimeout());
        assertEquals(5000, request.getConfig().getConnectionRequestTimeout());
    }

    @Test
    void aRefusedLoginWithoutAUserGoesOnTheScoredUsersLane() {
        provider.onEvent(event(EventType.LOGIN_ERROR, null, Map.of(EventBuilderHelper.USER_ID_DETAIL, "user-2")));

        queuedFor("user-2");
    }

    @Test
    void refusedLoginsWithoutAnyUserEachGoByTheirOwnId() {
        Event first = event(EventType.LOGIN_ERROR, null, Map.of());
        first.setId("event-1");
        Event second = event(EventType.LOGIN_ERROR, null, Map.of());
        second.setId("event-2");

        provider.onEvent(first);
        provider.onEvent(second);

        verify(sender).submit(eq("event-1"), any());
        verify(sender).submit(eq("event-2"), any());
    }

    @Test
    void aFullQueueDropsTheWebhookWithoutFailingTheLogin() throws Exception {
        when(sender.submit(any(), any())).thenReturn(false);

        assertDoesNotThrow(() -> provider.onEvent(event(EventType.LOGIN, "user-1", Map.of())));
        verify(httpClient, never()).execute(any(HttpUriRequest.class));
    }

    @Test
    void anEngineErrorInTheBackgroundIsSwallowed() throws Exception {
        when(httpClient.execute(any(HttpUriRequest.class))).thenThrow(new IOException("connection refused"));
        provider.onEvent(event(EventType.LOGIN, "user-1", Map.of()));

        assertDoesNotThrow(queuedFor("user-1")::run);
    }

    @Test
    void aWebhookThatWaitedPastItsTokensExpiryIsNotSent() {
        SimpleHttp http = mock(SimpleHttp.class);

        AmfaWebhookEventListenerProvider.deliver(http, "http://engine.test/login_event/webhook", "token",
                Time.currentTime() - 1, EventType.LOGIN, "test-amfa");

        verifyNoInteractions(http);
    }

    @Test
    void anEventAmfaDoesNotForwardIsNotQueued() {
        provider.onEvent(event(EventType.CODE_TO_TOKEN, "user-1", Map.of()));

        verifyNoInteractions(sender);
    }
}
