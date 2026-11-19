/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.authenticator.adaptiveauth;

import org.jboss.logmanager.LogContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.RealmModel;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The fallback risk level is read on every login, so a realm with an unusable
 * {@code fallbackRisk} must not log a warning on every login: once per realm and
 * value is enough to tell the operator.
 */
class FallbackRiskWarningTest {

    private final List<String> warnings = new ArrayList<>();
    private final Handler capture = new Handler() {
        @Override
        public void publish(LogRecord record) {
            if (record.getLevel().intValue() >= Level.WARNING.intValue()) {
                warnings.add(record.getMessage());
            }
        }

        @Override
        public void flush() {
        }

        @Override
        public void close() {
        }
    };
    private Logger logger;

    @BeforeEach
    void captureTheLog() {
        // slf4j logs through JBoss LogManager's own context, as in Keycloak.
        logger = LogContext.getLogContext().getLogger(AdaptiveAuthUtils.class.getName());
        logger.addHandler(capture);
    }

    @AfterEach
    void restoreTheLog() {
        logger.removeHandler(capture);
    }

    /** A realm of its own per test: what was already warned about outlives a test. */
    private static RealmModel realm() {
        RealmModel realm = mock(RealmModel.class);
        String id = UUID.randomUUID().toString();
        when(realm.getId()).thenReturn(id);
        when(realm.getName()).thenReturn("realm-" + id);
        return realm;
    }

    private static void configure(RealmModel realm, String value) {
        when(realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_API_FALLBACK_RISK_LEVEL)).thenReturn(value);
    }

    private static void logins(RealmModel realm, int count) {
        for (int i = 0; i < count; i++) {
            assertEquals(AdaptiveAuthUtils.HIGH_RISK_LEVEL, AdaptiveAuthUtils.getFallbackRiskLevel(realm));
        }
    }

    @Test
    void aValueOutOfRangeIsWarnedAboutOnceNotOnEveryLogin() {
        RealmModel realm = realm();
        configure(realm, "7");

        logins(realm, 5);

        assertEquals(1, warnings.size(), warnings.toString());
    }

    @Test
    void aValueThatIsNotANumberIsWarnedAboutOnce() {
        RealmModel realm = realm();
        configure(realm, "high");

        logins(realm, 5);

        assertEquals(1, warnings.size(), warnings.toString());
    }

    @Test
    void aMissingValueIsWarnedAboutOnce() {
        RealmModel realm = realm();
        configure(realm, null);

        logins(realm, 5);

        assertEquals(1, warnings.size(), warnings.toString());
    }

    @Test
    void anotherBadValueInTheSameRealmIsWarnedAboutToo() {
        RealmModel realm = realm();
        configure(realm, "7");
        logins(realm, 3);
        configure(realm, "high");
        logins(realm, 3);

        assertEquals(2, warnings.size(), warnings.toString());
    }

    @Test
    void theSameBadValueInAnotherRealmIsWarnedAboutToo() {
        RealmModel first = realm();
        RealmModel second = realm();
        configure(first, "7");
        configure(second, "7");

        logins(first, 3);
        logins(second, 3);

        assertEquals(2, warnings.size(), warnings.toString());
    }

    @Test
    void aValueThatIsBrokenAgainAfterAFixIsWarnedAboutAgain() {
        RealmModel realm = realm();
        configure(realm, "7");
        logins(realm, 2);
        configure(realm, "2");
        assertEquals(2, AdaptiveAuthUtils.getFallbackRiskLevel(realm));
        configure(realm, "7");
        logins(realm, 2);

        assertEquals(2, warnings.size(), warnings.toString());
    }

    @Test
    void aValidValueIsNeverWarnedAbout() {
        RealmModel realm = realm();
        configure(realm, "2");

        for (int i = 0; i < 3; i++) {
            assertEquals(2, AdaptiveAuthUtils.getFallbackRiskLevel(realm));
        }

        assertEquals(0, warnings.size(), warnings.toString());
    }
}
