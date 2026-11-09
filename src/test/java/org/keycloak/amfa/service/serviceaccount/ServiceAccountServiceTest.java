/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.service.serviceaccount;

import org.apache.http.HttpVersion;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHttpResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.mockito.ArgumentCaptor;

import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The service account token is fetched before every engine call, so a token
 * endpoint that does not answer must not hold the login longer than the engine
 * itself may.
 */
class ServiceAccountServiceTest {

    private KeycloakSession session;
    private RealmModel realm;
    private HttpClientProvider provider;

    @BeforeEach
    void setUp() {
        session = mock(KeycloakSession.class);
        realm = mock(RealmModel.class);
        provider = mock(HttpClientProvider.class);
        ClientModel client = mock(ClientModel.class);
        when(client.getSecret()).thenReturn("secret");
        when(realm.getClientByClientId("adaptive-auth-api")).thenReturn(client);
        when(realm.getName()).thenReturn("demo");
        when(provider.getMaxConsumedResponseSize()).thenReturn(HttpClientProvider.DEFAULT_MAX_CONSUMED_RESPONSE_SIZE);
        when(session.getProvider(HttpClientProvider.class)).thenReturn(provider);
    }

    private void keycloakAt(String baseUri) {
        KeycloakUriInfo uri = mock(KeycloakUriInfo.class);
        when(uri.getBaseUri()).thenReturn(URI.create(baseUri));
        KeycloakContext context = mock(KeycloakContext.class);
        when(context.getUri()).thenReturn(uri);
        when(session.getContext()).thenReturn(context);
    }

    /** What the token endpoint answers; the client closes it after reading. */
    private static class Token extends BasicHttpResponse implements CloseableHttpResponse {
        Token() {
            super(HttpVersion.HTTP_1_1, 200, "OK");
        }

        @Override
        public void close() {
        }
    }

    @Test
    void theTokenRequestIsBoundedByTheTimeout() throws Exception {
        CloseableHttpClient client = mock(CloseableHttpClient.class);
        Token token = new Token();
        token.setEntity(new StringEntity("{\"access_token\":\"t1\"}"));
        when(client.execute(any(HttpUriRequest.class))).thenReturn(token);
        when(provider.getHttpClient()).thenReturn(client);
        keycloakAt("http://iam.test");

        assertEquals("t1", ServiceAccountService.getServiceAccountToken(realm, session, "adaptive-auth-api"));

        ArgumentCaptor<HttpUriRequest> request = ArgumentCaptor.forClass(HttpUriRequest.class);
        verify(client).execute(request.capture());
        assertEquals("http://iam.test/realms/demo/protocol/openid-connect/token", request.getValue().getURI().toString());
        RequestConfig config = ((HttpRequestBase) request.getValue()).getConfig();
        assertEquals(ServiceAccountService.TOKEN_TIMEOUT_MILLIS, config.getConnectTimeout());
        assertEquals(ServiceAccountService.TOKEN_TIMEOUT_MILLIS, config.getConnectionRequestTimeout());
        assertEquals(ServiceAccountService.TOKEN_TIMEOUT_MILLIS, config.getSocketTimeout());
    }

    @Test
    void aTokenEndpointThatNeverAnswersGivesNoTokenAfterTheTimeout() throws Exception {
        try (ServerSocket silent = new ServerSocket(0);
             CloseableHttpClient client = HttpClients.createDefault()) {
            Thread accept = new Thread(() -> {
                try (Socket ignored = silent.accept()) {
                    Thread.sleep(60_000);
                } catch (Exception ignored) {
                }
            });
            accept.setDaemon(true);
            accept.start();
            when(provider.getHttpClient()).thenReturn(client);
            keycloakAt("http://127.0.0.1:" + silent.getLocalPort() + "/");

            long start = System.nanoTime();
            String token = ServiceAccountService.getServiceAccountToken(realm, session, "adaptive-auth-api");
            long waitedMillis = (System.nanoTime() - start) / 1_000_000;

            assertNull(token);
            assertTrue(waitedMillis >= ServiceAccountService.TOKEN_TIMEOUT_MILLIS - 500, "waited " + waitedMillis + " ms");
            assertTrue(waitedMillis < ServiceAccountService.TOKEN_TIMEOUT_MILLIS + 3000, "waited " + waitedMillis + " ms");
            accept.interrupt();
        }
    }
}
