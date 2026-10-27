/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.authenticator.authcontext;

import jakarta.ws.rs.core.MultivaluedHashMap;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.amfa.service.serviceaccount.ServiceAccountService;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.KeycloakSession;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.Answers;
import org.mockito.MockedStatic;

import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.keycloak.amfa.authenticator.authcontext.AuthContextAuthenticator.AUTH_CONTEXT_HASH;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The step keeps the engine's context hash on the login's own authentication
 * session, where Adaptive Authentication and the event details read it. It
 * must not also write the context to Keycloak's server-wide single-use store
 * under a fixed key: nothing reads it there, and that store is shared by
 * every realm and every cluster node.
 */
class AuthContextAuthenticatorTest {

    private MockedStatic<ServiceAccountService> serviceAccounts;
    private MockedStatic<SimpleHttp> http;
    private AuthenticationFlowContext context;
    private KeycloakSession flowSession;
    private AuthenticationSessionModel authenticationSession;
    private SimpleHttp.Response response;

    @BeforeEach
    void setUp() throws Exception {
        serviceAccounts = mockStatic(ServiceAccountService.class);
        serviceAccounts.when(() -> ServiceAccountService.getServiceAccountToken(any(), any(), anyString()))
                .thenReturn("token");
        SimpleHttp request = mock(SimpleHttp.class, Answers.RETURNS_SELF);
        response = mock(SimpleHttp.Response.class);
        when(request.asResponse()).thenReturn(response);
        http = mockStatic(SimpleHttp.class);
        http.when(() -> SimpleHttp.doPost(anyString(), any(KeycloakSession.class))).thenReturn(request);

        context = mock(AuthenticationFlowContext.class, Answers.RETURNS_DEEP_STUBS);
        flowSession = mock(KeycloakSession.class, Answers.RETURNS_DEEP_STUBS);
        authenticationSession = mock(AuthenticationSessionModel.class, Answers.RETURNS_DEEP_STUBS);
        when(context.getSession()).thenReturn(flowSession);
        when(context.getAuthenticationSession()).thenReturn(authenticationSession);
        when(context.getEvent().getEvent().getIpAddress()).thenReturn("203.0.113.9");
        MultivaluedHashMap<String, String> headers = new MultivaluedHashMap<>();
        headers.add("User-Agent", "Mozilla/5.0 (Macintosh)");
        when(context.getHttpRequest().getHttpHeaders().getRequestHeaders()).thenReturn(headers);
        when(context.getHttpRequest().getHttpHeaders().getAcceptableLanguages()).thenReturn(List.of(Locale.US));
        when(authenticationSession.getUserSessionNotes()).thenReturn(Map.of("screenResolution", "1920x1080"));
        when(authenticationSession.getClient().getClientId()).thenReturn("web");
        when(flowSession.getContext().getRealm().getAttribute(anyString())).thenReturn("http://engine.test");
    }

    @AfterEach
    void tearDown() {
        http.close();
        serviceAccounts.close();
    }

    private void authenticate() {
        new AuthContextAuthenticator(mock(KeycloakSession.class, Answers.RETURNS_DEEP_STUBS)).authenticate(context);
    }

    @Test
    void keepsTheHashOnTheLoginsOwnSessionOnly() throws Exception {
        when(response.getStatus()).thenReturn(200);
        when(response.asString()).thenReturn("{\"hash\":\"abc123\"}");

        authenticate();

        verify(authenticationSession).setAuthNote(AUTH_CONTEXT_HASH, "abc123");
        verify(flowSession, never()).singleUseObjects();
        verify(context).success();
    }

    @Test
    void anEngineErrorStoresNoHash() throws Exception {
        when(response.getStatus()).thenReturn(500);

        authenticate();

        verify(authenticationSession, never()).setAuthNote(eq(AUTH_CONTEXT_HASH), any());
        verify(flowSession, never()).singleUseObjects();
        verify(context).success();
    }
}
