/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.util;

import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpVersion;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicHttpResponse;
import org.apache.http.util.EntityUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.amfa.authenticator.authcontext.model.AuthContextModel;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.KeycloakSession;
import org.mockito.ArgumentCaptor;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The engine receives request bodies as the deprecated SimpleHttp sent them,
 * null fields left out, and the engine calls keep their timeouts.
 */
class AmfaHttpTest {

    private KeycloakSession session;
    private CloseableHttpClient client;

    @BeforeEach
    void setUp() throws Exception {
        client = mock(CloseableHttpClient.class);
        Ok ok = new Ok();
        ok.setEntity(new StringEntity("{}"));
        when(client.execute(any(HttpUriRequest.class))).thenReturn(ok);
        HttpClientProvider provider = mock(HttpClientProvider.class);
        when(provider.getHttpClient()).thenReturn(client);
        when(provider.getMaxConsumedResponseSize()).thenReturn(HttpClientProvider.DEFAULT_MAX_CONSUMED_RESPONSE_SIZE);
        session = mock(KeycloakSession.class);
        when(session.getProvider(HttpClientProvider.class)).thenReturn(provider);
    }

    /** What the engine answers; the client closes it after reading. */
    private static class Ok extends BasicHttpResponse implements CloseableHttpResponse {
        Ok() {
            super(HttpVersion.HTTP_1_1, 200, "OK");
        }

        @Override
        public void close() {
        }
    }

    private HttpRequestBase sent() throws Exception {
        ArgumentCaptor<HttpUriRequest> request = ArgumentCaptor.forClass(HttpUriRequest.class);
        verify(client).execute(request.capture());
        return (HttpRequestBase) request.getValue();
    }

    private String sentBody() throws Exception {
        return EntityUtils.toString(((HttpEntityEnclosingRequest) sent()).getEntity());
    }

    @Test
    void aDecisionRequestLeavesOutItsNullFields() throws Exception {
        Map<String, String> body = new LinkedHashMap<>();
        body.put("user_id", "u1");
        body.put("screen_resolution", null);

        AmfaHttp.create(session, 5000).doPost("http://engine.test/decision").json(body).asResponse().getStatus();

        assertEquals("{\"user_id\":\"u1\"}", sentBody());
    }

    @Test
    void anAuthContextLeavesOutItsNullFields() throws Exception {
        AuthContextModel body = new AuthContextModel("web", "203.0.113.9", "", "en-US", null);

        AmfaHttp.create(session, 5000).doPost("http://engine.test/auth_context").json(body).asResponse().getStatus();

        assertEquals("{\"client\":\"web\",\"ip_address\":\"203.0.113.9\",\"user_agent\":\"\","
                + "\"system_language\":\"en-US\"}", sentBody());
    }

    @Test
    void anEngineCallIsBoundedByTheTimeout() throws Exception {
        AmfaHttp.create(session, 5000).doGet("http://engine.test/settings").asResponse().getStatus();

        RequestConfig config = sent().getConfig();
        assertEquals(5000, config.getConnectTimeout());
        assertEquals(5000, config.getConnectionRequestTimeout());
        assertEquals(5000, config.getSocketTimeout());
    }
}
