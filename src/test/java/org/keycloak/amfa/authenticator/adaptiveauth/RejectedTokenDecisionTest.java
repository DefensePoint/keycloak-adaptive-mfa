/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.authenticator.adaptiveauth;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.amfa.authenticator.adaptiveauth.model.AdaptiveAuthResponse;
import org.keycloak.amfa.service.serviceaccount.ServiceAccountService;
import org.keycloak.amfa.util.AmfaHttp;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpRequest;
import org.keycloak.http.simple.SimpleHttpResponse;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.MockedStatic;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.when;

/**
 * The service account token is reused across logins until shortly before it
 * expires. If the engine rejects it (HTTP 401), it must not be reused for the
 * rest of its life, or every login until then would take the fallback.
 */
class RejectedTokenDecisionTest {

    private final RealmModel realm = mock(RealmModel.class);
    private final AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
    private final KeycloakSession session = mock(KeycloakSession.class);
    private final SimpleHttpResponse response = mock(SimpleHttpResponse.class);
    private MockedStatic<ServiceAccountService> serviceAccounts;
    private MockedStatic<AmfaHttp> amfaHttp;

    @BeforeEach
    void setUp() throws Exception {
        when(authSession.getRealm()).thenReturn(realm);
        when(realm.getName()).thenReturn("acme");
        when(realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_ENDPOINT)).thenReturn("http://engine.test");
        serviceAccounts = mockStatic(ServiceAccountService.class);
        serviceAccounts.when(() -> ServiceAccountService.getServiceAccountToken(any(), any(), anyString())).thenReturn("token");
        serviceAccounts.when(() -> ServiceAccountService.rejectsToken(anyInt())).thenCallRealMethod();

        SimpleHttp http = mock(SimpleHttp.class);
        SimpleHttpRequest request = mock(SimpleHttpRequest.class, RETURNS_SELF);
        when(http.doPost(anyString())).thenReturn(request);
        when(request.asResponse()).thenReturn(response);
        amfaHttp = mockStatic(AmfaHttp.class);
        amfaHttp.when(() -> AmfaHttp.create(any(), anyInt())).thenReturn(http);
    }

    @AfterEach
    void tearDown() {
        amfaHttp.close();
        serviceAccounts.close();
    }

    private void answer(int status, String body) throws Exception {
        when(response.getStatus()).thenReturn(status);
        when(response.asString()).thenReturn(body);
        when(response.asJson(AdaptiveAuthResponse.class)).thenReturn(new AdaptiveAuthResponse());
    }

    private void decide() {
        new AdaptiveAuthUtils().getUserAdaptiveAuthDecision(session, authSession, 3,
                "user-1", "web", "203.0.113.9", "ua", "en-US", "1920x1080", "acme", "default", "event-1", "");
    }

    @Test
    void aTokenTheEngineRejectsIsForgotten() throws Exception {
        answer(401, "{\"detail\":\"Invalid token\"}");

        decide();

        serviceAccounts.verify(() -> ServiceAccountService.forgetToken("token"));
    }

    @Test
    void aTokenTheEngineCannotVerifyIsForgotten() throws Exception {
        // The engine answers 403 for a token signed with a key it no longer finds,
        // as after a signing key rotation.
        answer(403, "{\"detail\":\"Unable to resolve signing key\"}");

        decide();

        serviceAccounts.verify(() -> ServiceAccountService.forgetToken("token"));
    }

    @Test
    void anotherErrorAnswerKeepsTheToken() throws Exception {
        answer(500, "{\"detail\":\"Internal Server Error\"}");

        decide();

        serviceAccounts.verify(() -> ServiceAccountService.forgetToken(anyString()), never());
    }

    @Test
    void anAnswerKeepsTheToken() throws Exception {
        answer(200, "{\"riskLevel\":1}");

        decide();

        serviceAccounts.verify(() -> ServiceAccountService.forgetToken(anyString()), never());
    }
}
