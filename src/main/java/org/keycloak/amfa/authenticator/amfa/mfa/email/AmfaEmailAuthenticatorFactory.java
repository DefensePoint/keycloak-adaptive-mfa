/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.authenticator.amfa.mfa.email;

import org.keycloak.amfa.authenticator.mfa.MfaUtils;
import org.keycloak.amfa.authenticator.mfa.email.MfaEmailAuthenticatorFactory;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;

public class AmfaEmailAuthenticatorFactory extends MfaEmailAuthenticatorFactory {
    private static final String PROVIDER_ID = "amfa-email";

    @Override
    public String getDisplayType() {
        return "AMFA Multi-Factor Authentication - Email";
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }


    @Override
    public Authenticator create(KeycloakSession session) {
        MfaUtils mfaUtils = new MfaUtils();
        return new AmfaEmailAuthenticator(mfaUtils);
    }
}
