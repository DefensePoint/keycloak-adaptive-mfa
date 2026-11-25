/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.authenticator.adaptiveauth;

import java.io.IOException;

/**
 * The engine answered a decision request with 429: it is up, and refused this
 * user's request because of its rate limit. Kept apart from the other error
 * answers so the login steps up instead of taking the realm's fallback level.
 */
public class EngineRateLimitedException extends IOException {
    private static final long serialVersionUID = 1L;

    public EngineRateLimitedException(String message) {
        super(message);
    }
}
