/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.authenticator.adaptiveauth;

import org.jboss.logmanager.LogContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.regex.Matcher;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

/**
 * The engine request's debug line carries values from the login request (the
 * User-Agent, the IP address), the client, the realm's settings and the engine's
 * own earlier answer. A CR or LF in any of them would start a forged log line.
 */
class AdaptiveAuthServiceTest {

    private static final String FORGED = "x\r\n2026-01-01 00:00:00,000 INFO  [org.keycloak] forged line";

    private final List<String> lines = new ArrayList<>();
    private final Handler capture = new Handler() {
        @Override
        public void publish(LogRecord record) {
            String message = record.getMessage();
            Object[] params = record.getParameters();
            if (params != null) {
                for (Object param : params) {
                    message = message.replaceFirst("\\{\\}", Matcher.quoteReplacement(String.valueOf(param)));
                }
            }
            lines.add(message);
        }

        @Override
        public void flush() {
        }

        @Override
        public void close() {
        }
    };
    private Logger logger;
    private Level previousLevel;

    @BeforeEach
    void captureTheServiceLog() {
        // slf4j logs through JBoss LogManager's own context, as in Keycloak.
        logger = LogContext.getLogContext().getLogger(AdaptiveAuthService.class.getName());
        previousLevel = logger.getLevel();
        logger.setLevel(Level.ALL);
        logger.addHandler(capture);
    }

    @AfterEach
    void restoreTheServiceLog() {
        logger.removeHandler(capture);
        logger.setLevel(previousLevel);
    }

    @Test
    void theEngineRequestLineCannotBeSplitByTheValuesItLogs() {
        AdaptiveAuthService service = new AdaptiveAuthService(mock(KeycloakSession.class));
        try {
            service.getAdaptiveAuthDecision("token", "http://engine.test/" + FORGED, "user-" + FORGED,
                    "client-" + FORGED, "203.0.113.7" + FORGED, "agent-" + FORGED, "en-US", "1920x1080",
                    "realm-" + FORGED, "group-" + FORGED, "event-id", "hash-" + FORGED);
        } catch (Exception | LinkageError e) {
            // The engine call itself cannot be made here; the line is logged before it.
        }

        List<String> requestLines = lines.stream().filter(l -> l.startsWith("getAdaptiveAuthDecision:")).toList();
        assertEquals(1, requestLines.size(), "the engine request was not logged: " + lines);
        String line = requestLines.get(0);
        assertFalse(line.contains("\n") || line.contains("\r"), "a logged value split the line: " + line);
        assertTrue(line.contains("agent-x"), "the User-Agent is no longer logged: " + line);
    }

    @Test
    void missingValuesAreLoggedWithoutFailingTheLogin() {
        // A login without the auth-context step has no hash, and other values can
        // be missing too. The sanitizing runs whatever the log level, so it must
        // not throw on them.
        AdaptiveAuthService service = new AdaptiveAuthService(mock(KeycloakSession.class));
        try {
            service.getAdaptiveAuthDecision("token", "http://engine.test", null, null, null, null, null, null,
                    null, null, null, null);
        } catch (Exception | LinkageError e) {
            // The engine call itself cannot be made here; the line is logged before it.
        }

        List<String> requestLines = lines.stream().filter(l -> l.startsWith("getAdaptiveAuthDecision:")).toList();
        // Logged at all means the sanitizing did not throw before it.
        assertEquals(1, requestLines.size(), "the engine request was not logged: " + lines);
        assertTrue(requestLines.get(0).contains("authContextHash=null"), requestLines.get(0));
    }
}
