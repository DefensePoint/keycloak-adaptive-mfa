/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.authenticator.mfa;

import org.keycloak.common.util.Time;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.security.SecureRandom;

public class MfaUtils {

    public static final String AUTH_NOTE_OTP_CODE = "amfa-otp-code";

    /**
     * How many wrong guesses the currently-issued code has received. Reset to
     * "0" every time a fresh code is stored (see {@link #storeCode}), so it
     * only ever counts guesses against the code that is actually live.
     */
    public static final String AUTH_NOTE_OTP_ATTEMPTS = "amfa-otp-attempts";

    /**
     * When the currently-issued code was stored, as epoch seconds
     * ({@link Time#currentTime()}). Used by {@link #isExpired} to give a code
     * a short lifetime regardless of how many guesses it has received.
     */
    public static final String AUTH_NOTE_OTP_ISSUED_AT = "amfa-otp-issued-at";

    private static final SecureRandom RANDOM = new SecureRandom();

    public String generateCode() {
        return String.format("%06d", RANDOM.nextInt(1_000_000));
    }

    /**
     * Store a freshly issued code, resetting its attempt counter and issue
     * time. Every path that hands the user a new code (a fresh challenge, a
     * resend, an expiry, or exhausting the attempt limit) goes through this,
     * so a new code always gets a clean budget rather than inheriting one
     * already partly spent.
     */
    public void storeCode(AuthenticationSessionModel authSession, String code) {
        authSession.setAuthNote(AUTH_NOTE_OTP_CODE, code);
        authSession.setAuthNote(AUTH_NOTE_OTP_ATTEMPTS, "0");
        authSession.setAuthNote(AUTH_NOTE_OTP_ISSUED_AT, Long.toString(Time.currentTime()));
    }

    public String getStoredCode(AuthenticationSessionModel authSession) {
        return authSession.getAuthNote(AUTH_NOTE_OTP_CODE);
    }

    public boolean verifyCode(AuthenticationSessionModel authSession, String enteredCode) {
        String stored = getStoredCode(authSession);
        return stored != null && stored.equals(enteredCode);
    }

    public void clearCode(AuthenticationSessionModel authSession) {
        authSession.removeAuthNote(AUTH_NOTE_OTP_CODE);
        authSession.removeAuthNote(AUTH_NOTE_OTP_ATTEMPTS);
        authSession.removeAuthNote(AUTH_NOTE_OTP_ISSUED_AT);
    }

    /**
     * Increment and return the number of wrong guesses made against the
     * currently-issued code.
     */
    public int incrementAttempts(AuthenticationSessionModel authSession) {
        int next = getAttempts(authSession) + 1;
        authSession.setAuthNote(AUTH_NOTE_OTP_ATTEMPTS, Integer.toString(next));
        return next;
    }

    public int getAttempts(AuthenticationSessionModel authSession) {
        String raw = authSession.getAuthNote(AUTH_NOTE_OTP_ATTEMPTS);
        if (raw == null) {
            return 0;
        }
        try {
            return Integer.parseInt(raw);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    /**
     * Whether the currently-issued code is older than {@code ttlSeconds}.
     * False if there is no issued-at note (nothing to expire), so this is
     * safe to call even when no code is currently live.
     */
    public boolean isExpired(AuthenticationSessionModel authSession, int ttlSeconds) {
        String raw = authSession.getAuthNote(AUTH_NOTE_OTP_ISSUED_AT);
        if (raw == null) {
            return false;
        }
        long issuedAt;
        try {
            issuedAt = Long.parseLong(raw);
        } catch (NumberFormatException e) {
            return false;
        }
        return Time.currentTime() - issuedAt > ttlSeconds;
    }
}
