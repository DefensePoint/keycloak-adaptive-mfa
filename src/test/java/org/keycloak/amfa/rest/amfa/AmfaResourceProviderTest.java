/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.rest.amfa;

import io.vavr.control.Either;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.RuntimeDelegate;
import org.apache.http.HttpVersion;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicHttpResponse;
import org.jboss.resteasy.reactive.NoCache;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.amfa.authenticator.adaptiveauth.AdaptiveAuthUtils;
import org.keycloak.amfa.rest.model.AdaptiveAuthConfig;
import org.keycloak.amfa.rest.model.ErrorResponse;
import org.keycloak.amfa.rest.model.ScoringConfigDTO;
import org.keycloak.amfa.service.AmfaApiService;
import org.keycloak.amfa.service.Guards;
import org.keycloak.amfa.service.serviceaccount.ServiceAccountService;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.AccessToken;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.mockito.MockedStatic;

import java.lang.reflect.Method;
import java.net.SocketTimeoutException;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AmfaResourceProviderTest {

    private MockedStatic<Guards> guards;
    private MockedStatic<ServiceAccountService> serviceAccounts;
    private CloseableHttpClient httpClient;
    private AmfaResourceProvider resource;

    /** What the engine answers; the client closes it after reading. */
    private static class Answer extends BasicHttpResponse implements CloseableHttpResponse {
        Answer() {
            super(HttpVersion.HTTP_1_1, 200, "OK");
        }

        @Override
        public void close() {
        }
    }

    /**
     * Builds the endpoints' responses without a JAX-RS runtime, which Keycloak
     * provides at run time: only their status and entity are kept.
     */
    private static RuntimeDelegate recordingResponses() {
        RuntimeDelegate delegate = mock(RuntimeDelegate.class);
        when(delegate.createResponseBuilder()).thenAnswer(created -> {
            int[] status = {200};
            Object[] entity = {null};
            return mock(Response.ResponseBuilder.class, Mockito.withSettings().defaultAnswer(call -> {
                switch (call.getMethod().getName()) {
                    case "status" -> status[0] = call.getArgument(0) instanceof Response.StatusType type
                            ? type.getStatusCode() : (int) call.getArgument(0);
                    case "entity" -> entity[0] = call.getArgument(0);
                    case "build" -> {
                        return mock(Response.class, Mockito.withSettings().defaultAnswer(read -> switch (read.getMethod().getName()) {
                            case "getStatus" -> status[0];
                            case "getEntity" -> entity[0];
                            default -> null;
                        }));
                    }
                    default -> { }
                }
                return call.getMock();
            }));
        });
        return delegate;
    }

    @BeforeEach
    void setUp() throws Exception {
        RuntimeDelegate.setInstance(recordingResponses());
        guards = mockStatic(Guards.class);
        guards.when(() -> Guards.authenticateRealmAdminRequest(any(), any()))
                .thenReturn(Either.right(new AccessToken()));
        serviceAccounts = mockStatic(ServiceAccountService.class);
        serviceAccounts.when(() -> ServiceAccountService.getServiceAccountToken(any(), any(), anyString()))
                .thenReturn("token");

        httpClient = mock(CloseableHttpClient.class);
        HttpClientProvider provider = mock(HttpClientProvider.class);
        when(provider.getHttpClient()).thenReturn(httpClient);
        when(provider.getMaxConsumedResponseSize()).thenReturn(HttpClientProvider.DEFAULT_MAX_CONSUMED_RESPONSE_SIZE);
        RealmModel realm = mock(RealmModel.class);
        KeycloakContext context = mock(KeycloakContext.class);
        when(context.getRealm()).thenReturn(realm);
        KeycloakSession session = mock(KeycloakSession.class);
        when(session.getContext()).thenReturn(context);
        when(session.getProvider(HttpClientProvider.class)).thenReturn(provider);
        when(realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_ENDPOINT)).thenReturn("http://engine.test");
        when(realm.getName()).thenReturn("test-amfa");

        resource = new AmfaResourceProvider(session, mock(AmfaApiService.class));
    }

    @AfterEach
    void tearDown() {
        serviceAccounts.close();
        guards.close();
        RuntimeDelegate.setInstance(null);
    }

    private void callEveryEngineProxy() throws Exception {
        resource.fetchAdaptiveMFAParameters("Bearer admin");
        resource.updateAdaptiveMFAParameters("Bearer admin", new AdaptiveAuthConfig(List.of(), null));
        resource.fetchScoringConfig("Bearer admin");
        resource.updateScoringConfig("Bearer admin", new ScoringConfigDTO("weighted", null, List.of(0.3, 0.6, 0.9)));
    }

    /**
     * The endpoints return realm settings and admin data, so a browser or proxy
     * must not cache them: a stale answer would show the admin page old values.
     */
    @Test
    void everyEndpointIsMarkedNoCache() {
        List<Method> endpoints = Arrays.stream(AmfaResourceProvider.class.getDeclaredMethods())
                .filter(m -> m.isAnnotationPresent(Path.class))
                .toList();
        assertFalse(endpoints.isEmpty());

        List<String> cacheable = endpoints.stream()
                .filter(m -> !m.isAnnotationPresent(NoCache.class))
                .map(Method::getName)
                .toList();
        assertEquals(List.of(), cacheable);
    }

    @Test
    void everyEngineCallWaitsAtMostTenSeconds() throws Exception {
        when(httpClient.execute(any(HttpUriRequest.class))).thenAnswer(i -> {
            Answer ok = new Answer();
            ok.setEntity(new StringEntity("{}"));
            return ok;
        });

        callEveryEngineProxy();

        ArgumentCaptor<HttpUriRequest> sent = ArgumentCaptor.forClass(HttpUriRequest.class);
        verify(httpClient, times(4)).execute(sent.capture());
        for (HttpUriRequest request : sent.getAllValues()) {
            RequestConfig config = ((HttpRequestBase) request).getConfig();
            assertEquals(10000, config.getConnectTimeout(), request.getURI().toString());
            assertEquals(10000, config.getConnectionRequestTimeout(), request.getURI().toString());
            assertEquals(10000, config.getSocketTimeout(), request.getURI().toString());
        }
    }

    @Test
    void anEngineThatDoesNotAnswerGetsTheUnreachableError() throws Exception {
        when(httpClient.execute(any(HttpUriRequest.class))).thenThrow(new SocketTimeoutException("Read timed out"));

        for (Response response : List.of(
                resource.fetchAdaptiveMFAParameters("Bearer admin"),
                resource.updateAdaptiveMFAParameters("Bearer admin", new AdaptiveAuthConfig(List.of(), null)),
                resource.fetchScoringConfig("Bearer admin"),
                resource.updateScoringConfig("Bearer admin", new ScoringConfigDTO("weighted", null, List.of(0.3))))) {
            assertEquals(502, response.getStatus());
            assertEquals("AMFA engine unreachable: Read timed out", ((ErrorResponse) response.getEntity()).getError());
        }
    }
}
