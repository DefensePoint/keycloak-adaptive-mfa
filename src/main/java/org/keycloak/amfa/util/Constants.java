/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.util;

public class Constants {

    public static final String INVALID_CREDENTIALS = "The username or password is incorrect. Please try again.";

    /**
     * Realm attribute: may a user enrol a missing second factor during a step-up?
     *
     * <p>Off by default, and that default is the security-relevant part. Keycloak
     * treats "required action added" as satisfying the execution and defers the
     * action until after authentication, so enrolment does not challenge the user on
     * the login that triggered it. Enabling this means an account with no second
     * factor can pass a risk-elevated step-up by supplying an email address, with no
     * code entered. Convenient for self-service, but it is a hole in the control the
     * step-up exists to apply, so an operator has to ask for it.
     *
     * <p>Left off, a user with no usable factor is denied, and
     * {@code AmfaEmailAuthenticator.configuredFor} logs which user and why.
     */
    public static final String ALLOW_STEP_UP_ENROLMENT = "allowStepUpEnrolment";

    private Constants() {}
}
