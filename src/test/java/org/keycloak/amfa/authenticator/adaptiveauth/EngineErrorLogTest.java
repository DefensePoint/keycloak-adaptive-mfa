/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.authenticator.adaptiveauth;

import org.jboss.logmanager.LogContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.amfa.service.serviceaccount.ServiceAccountService;
import org.keycloak.amfa.util.AmfaHttp;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpRequest;
import org.keycloak.http.simple.SimpleHttpResponse;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.MockedStatic;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * An error answer from the engine is one failed decision, so it is logged once:
 * the error starting with ADAPTIVE_AUTH_ENGINE_UNREACHABLE, carrying the status
 * and the engine's answer. The engine call used to log an unmarked error of its
 * own first, so each such failure gave two error lines.
 */
class EngineErrorLogTest {

    private final List<LogRecord> records = new ArrayList<>();
    private final Handler capture = new Handler() {
        @Override
        public void publish(LogRecord record) {
            records.add(record);
        }

        @Override
        public void flush() {
        }

        @Override
        public void close() {
        }
    };
    private final List<Logger> loggers = new ArrayList<>();
    private final List<Level> previousLevels = new ArrayList<>();

    private final RealmModel realm = mock(RealmModel.class);
    private final AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
    private final KeycloakSession session = mock(KeycloakSession.class);
    private MockedStatic<ServiceAccountService> serviceAccounts;
    private MockedStatic<AmfaHttp> amfaHttp;

    @BeforeEach
    void setUp() throws Exception {
        // slf4j logs through JBoss LogManager's own context, as in Keycloak.
        for (Class<?> type : List.of(AdaptiveAuthService.class, AdaptiveAuthUtils.class)) {
            Logger logger = LogContext.getLogContext().getLogger(type.getName());
            previousLevels.add(logger.getLevel());
            logger.setLevel(Level.ALL);
            logger.addHandler(capture);
            loggers.add(logger);
        }
        when(authSession.getRealm()).thenReturn(realm);
        when(realm.getName()).thenReturn("acme");
        when(realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_ENDPOINT)).thenReturn("http://engine.test");
        serviceAccounts = mockStatic(ServiceAccountService.class);
        serviceAccounts.when(() -> ServiceAccountService.getServiceAccountToken(any(), any(), anyString())).thenReturn("token");

        SimpleHttp http = mock(SimpleHttp.class);
        SimpleHttpRequest request = mock(SimpleHttpRequest.class, RETURNS_SELF);
        SimpleHttpResponse response = mock(SimpleHttpResponse.class);
        when(http.doPost(anyString())).thenReturn(request);
        when(request.asResponse()).thenReturn(response);
        when(response.getStatus()).thenReturn(403);
        when(response.asString()).thenReturn("{\"detail\":\"Token verification failed: InvalidAudienceError\"}");
        amfaHttp = mockStatic(AmfaHttp.class);
        amfaHttp.when(() -> AmfaHttp.create(any(), anyInt())).thenReturn(http);
    }

    @AfterEach
    void tearDown() {
        amfaHttp.close();
        serviceAccounts.close();
        for (int i = 0; i < loggers.size(); i++) {
            loggers.get(i).removeHandler(capture);
            loggers.get(i).setLevel(previousLevels.get(i));
        }
    }

    private List<LogRecord> errors() {
        return records.stream().filter(r -> r.getLevel().intValue() >= Level.SEVERE.intValue()).toList();
    }

    @Test
    void anErrorAnswerFromTheEngineIsLoggedOnceMarked() {
        AdaptiveAuthDecision decision = new AdaptiveAuthUtils().getUserAdaptiveAuthDecision(session, authSession, 3,
                "user-1", "web", "203.0.113.9", "ua", "en-US", "1920x1080", "acme", "default", "event-1", "");

        assertEquals(3, decision.getRiskLevel());
        List<LogRecord> errors = errors();
        assertEquals(1, errors.size(), errors.stream().map(LogRecord::getMessage).toList().toString());
        LogRecord marked = errors.get(0);
        assertTrue(marked.getMessage().startsWith("ADAPTIVE_AUTH_ENGINE_UNREACHABLE "), marked.getMessage());
        assertEquals("HTTP 403: {\"detail\":\"Token verification failed: InvalidAudienceError\"}",
                marked.getThrown().getMessage());
    }
}
