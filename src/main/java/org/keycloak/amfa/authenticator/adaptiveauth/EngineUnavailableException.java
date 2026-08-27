/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.authenticator.adaptiveauth;

/**
 * Thrown by {@link AdaptiveAuthUtils#getUserAdaptiveAuthDecision} when the engine
 * could not be consulted (network failure, timeout, non-2xx response, or a TLS/
 * certificate error) AND the realm's {@code adaptiveAuthFailureMode} is {@code
 * mandatory}, meaning the caller must deny the login rather than proceed at any
 * risk level -- fallback or otherwise.
 *
 * <p>Unchecked, and deliberately never caught inside {@code AdaptiveAuthUtils}
 * itself: it is meant to unwind straight out to {@link AdaptiveAuthAuthenticator},
 * the one place authorized to decide how a denied login is reported back to
 * Keycloak.
 */
public class EngineUnavailableException extends RuntimeException {
    public EngineUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
