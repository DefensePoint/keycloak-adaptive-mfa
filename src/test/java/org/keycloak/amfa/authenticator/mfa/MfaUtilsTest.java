/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.authenticator.mfa;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.common.util.Time;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class MfaUtilsTest {

    @Mock
    private AuthenticationSessionModel authSession;

    private MfaUtils mfaUtils;

    /** Backing store that simulates auth notes. */
    private Map<String, String> notes;

    @BeforeEach
    void setUp() {
        mfaUtils = new MfaUtils();
        notes = new HashMap<>();

        lenient().doAnswer(inv -> {
            notes.put(inv.getArgument(0), inv.getArgument(1));
            return null;
        }).when(authSession).setAuthNote(anyString(), anyString());

        lenient().doAnswer(inv -> notes.get(inv.<String>getArgument(0)))
                .when(authSession).getAuthNote(anyString());

        lenient().doAnswer(inv -> {
            notes.remove(inv.<String>getArgument(0));
            return null;
        }).when(authSession).removeAuthNote(anyString());
    }

    @Test
    void generateCode_producesSixDigitString() {
        String code = mfaUtils.generateCode();
        assertNotNull(code);
        assertEquals(6, code.length());
        assertTrue(code.matches("\\d{6}"));
    }

    @Test
    void storeCode_andGetStoredCode_roundTrip() {
        mfaUtils.storeCode(authSession, "123456");
        assertEquals("123456", mfaUtils.getStoredCode(authSession));
    }

    @Test
    void storeCode_resetsAttemptCounter() {
        notes.put(MfaUtils.AUTH_NOTE_OTP_ATTEMPTS, "5");
        mfaUtils.storeCode(authSession, "999999");
        assertEquals(0, mfaUtils.getAttempts(authSession));
    }

    @Test
    void verifyCode_returnsTrueForMatch() {
        mfaUtils.storeCode(authSession, "123456");
        assertTrue(mfaUtils.verifyCode(authSession, "123456"));
    }

    @Test
    void verifyCode_returnsFalseForMismatch() {
        mfaUtils.storeCode(authSession, "123456");
        assertFalse(mfaUtils.verifyCode(authSession, "654321"));
    }

    @Test
    void verifyCode_returnsFalseWhenNoCodeStored() {
        assertFalse(mfaUtils.verifyCode(authSession, "123456"));
    }

    @Test
    void clearCode_removesAllNotes() {
        mfaUtils.storeCode(authSession, "123456");
        mfaUtils.clearCode(authSession);
        assertNull(mfaUtils.getStoredCode(authSession));
        assertEquals(0, mfaUtils.getAttempts(authSession));
    }

    @Test
    void incrementAttempts_incrementsAndReturnsCount() {
        mfaUtils.storeCode(authSession, "123456");
        assertEquals(1, mfaUtils.incrementAttempts(authSession));
        assertEquals(2, mfaUtils.incrementAttempts(authSession));
        assertEquals(3, mfaUtils.incrementAttempts(authSession));
    }

    @Test
    void getAttempts_returnsZeroWhenNoteIsNull() {
        assertEquals(0, mfaUtils.getAttempts(authSession));
    }

    @Test
    void getAttempts_returnsZeroForNonNumeric() {
        notes.put(MfaUtils.AUTH_NOTE_OTP_ATTEMPTS, "not-a-number");
        assertEquals(0, mfaUtils.getAttempts(authSession));
    }

    @Test
    void isExpired_returnsFalseWhenNoIssuedAtNote() {
        assertFalse(mfaUtils.isExpired(authSession, 300));
    }

    @Test
    void isExpired_returnsFalseWhenWithinTtl() {
        int now = Time.currentTime();
        notes.put(MfaUtils.AUTH_NOTE_OTP_ISSUED_AT, Long.toString(now));
        assertFalse(mfaUtils.isExpired(authSession, 300));
    }

    @Test
    void isExpired_returnsTrueWhenPastTtl() {
        int now = Time.currentTime();
        notes.put(MfaUtils.AUTH_NOTE_OTP_ISSUED_AT, Long.toString(now - 301));
        assertTrue(mfaUtils.isExpired(authSession, 300));
    }

    @Test
    void isExpired_returnsFalseForNonNumericIssuedAt() {
        notes.put(MfaUtils.AUTH_NOTE_OTP_ISSUED_AT, "garbage");
        assertFalse(mfaUtils.isExpired(authSession, 300));
    }
}
