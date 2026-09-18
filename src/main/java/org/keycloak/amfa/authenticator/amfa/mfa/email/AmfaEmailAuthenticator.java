/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.authenticator.amfa.mfa.email;

import lombok.extern.slf4j.Slf4j;
import org.keycloak.amfa.authenticator.mfa.MfaUtils;
import org.keycloak.amfa.authenticator.mfa.email.MfaEmailAuthenticator;
import org.keycloak.amfa.util.Constants;
import org.apache.commons.lang3.StringUtils;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

@Slf4j
public class AmfaEmailAuthenticator extends MfaEmailAuthenticator {

    public AmfaEmailAuthenticator(MfaUtils mfaUtils) {
        super(mfaUtils);
    }

    /**
     * Whether a code can actually be sent, which needs an address to send it to.
     *
     * <p>Logged when the answer is no. This is the only hook the flow engine calls on
     * that path, and until now an operator got no indication of the cause: the engine
     * recorded {@code invalid_user_credentials}, pointing at a password that had in
     * fact just been accepted. A risk-triggered step-up that cannot run is worth a
     * line in the log whatever the flow decides to do next.
     */
    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        boolean hasEmail = StringUtils.isNotBlank(user.getEmail());
        if (!hasEmail) {
            // The consequence differs by realm setting, so say which one applies rather
            // than describe an outcome that will not happen.
            String consequence = areRequiredActionsEnabled(session, realm)
                    ? "The user will be asked to supply one before continuing."
                    : "The login will be denied. Give the account an email address, enrol "
                      + "another factor, or set the realm attribute '"
                      + Constants.ALLOW_STEP_UP_ENROLMENT + "' to true to let users supply "
                      + "one during the step-up.";
            log.warn("Email step-up cannot run for user " + user.getId() + " in realm "
                    + realm.getName() + ": no email address on the account. " + consequence);
        }
        return hasEmail;
    }
}
