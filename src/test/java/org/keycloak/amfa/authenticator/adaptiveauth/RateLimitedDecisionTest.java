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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * A 429 from the engine is the engine refusing on purpose, not an outage. Taking
 * it as one gave the login the realm's fallback level: with a fallback of 1,
 * anyone with a user's password could pass MFA by logging in until the engine
 * rate-limited that user. A rate-limited login steps up instead, at the higher
 * of 3 and the fallback level, in either failure mode, and is reported as such.
 */
class RateLimitedDecisionTest {

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
    private final SimpleHttpResponse response = mock(SimpleHttpResponse.class);
    private MockedStatic<ServiceAccountService> serviceAccounts;
    private MockedStatic<AmfaHttp> amfaHttp;

    @BeforeEach
    void setUp() throws Exception {
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
        when(http.doPost(anyString())).thenReturn(request);
        when(request.asResponse()).thenReturn(response);
        answer(429, "{\"success\":false,\"message\":\"Rate limit exceeded\"}");
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

    private void answer(int status, String body) throws Exception {
        when(response.getStatus()).thenReturn(status);
        when(response.asString()).thenReturn(body);
    }

    private AdaptiveAuthDecision decide(int fallbackLevel) {
        return new AdaptiveAuthUtils().getUserAdaptiveAuthDecision(session, authSession, fallbackLevel,
                "user-1", "web", "203.0.113.9", "ua", "en-US", "1920x1080", "acme", "default", "event-1", "");
    }

    private List<LogRecord> at(Level level) {
        return records.stream().filter(r -> r.getLevel().intValue() == level.intValue()).toList();
    }

    @Test
    void aRateLimitedLoginStepsUpInsteadOfTakingAFallbackOfOne() {
        AdaptiveAuthDecision decision = decide(1);

        assertEquals(AdaptiveAuthUtils.HIGH_RISK_LEVEL, decision.getRiskLevel());
        assertEquals(AdaptiveAuthDecision.SOURCE_RATE_LIMITED, decision.getSource());
        assertFalse(decision.isFromFallback());
    }

    @Test
    void aStricterFallbackStillApplies() {
        assertEquals(AdaptiveAuthUtils.MAX_RISK_LEVEL, decide(AdaptiveAuthUtils.MAX_RISK_LEVEL).getRiskLevel());
    }

    @Test
    void mandatoryModeStepsUpRatherThanRefusing() {
        // A refusal would let anyone who can spend a user's /decision budget lock
        // that user out; the step-up keeps the login checked without that.
        when(realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_FAILURE_MODE)).thenReturn("mandatory");

        AdaptiveAuthDecision decision = decide(1);

        assertEquals(AdaptiveAuthUtils.HIGH_RISK_LEVEL, decision.getRiskLevel());
        assertEquals(AdaptiveAuthDecision.SOURCE_RATE_LIMITED, decision.getSource());
    }

    @Test
    void aRateLimitedLoginIsAWarningWithoutTheOutageMarker() {
        decide(1);

        assertEquals(List.of(), at(Level.SEVERE).stream().map(LogRecord::getMessage).toList());
        List<LogRecord> warnings = at(Level.WARNING);
        assertEquals(1, warnings.size(), warnings.stream().map(LogRecord::getMessage).toList().toString());
        assertFalse(warnings.get(0).getMessage().contains("ADAPTIVE_AUTH_ENGINE_UNREACHABLE"), warnings.get(0).getMessage());
        assertTrue(warnings.get(0).getMessage().contains("rate-limited"), warnings.get(0).getMessage());
    }

    @Test
    void anyOtherErrorAnswerIsStillAnOutage() throws Exception {
        answer(500, "{\"detail\":\"Internal Server Error\"}");

        AdaptiveAuthDecision decision = decide(1);

        assertEquals(1, decision.getRiskLevel());
        assertTrue(decision.isFromFallback());
        assertEquals(AdaptiveAuthDecision.SOURCE_FALLBACK, decision.getSource());
        assertEquals(1, at(Level.SEVERE).size());
        assertTrue(at(Level.SEVERE).get(0).getMessage().startsWith("ADAPTIVE_AUTH_ENGINE_UNREACHABLE "));
    }
}
