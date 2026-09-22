/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.authenticator.amfa.mfa.totp;

import org.keycloak.amfa.authenticator.mfa.totp.MfaTOTPAuthenticatorFactory;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;

public class AmfaTOTPAuthenticatorFactory extends MfaTOTPAuthenticatorFactory {

    public static final String PROVIDER_ID = "amfa-totp";
    public static final AmfaTOTPAuthenticator SINGLETON = new AmfaTOTPAuthenticator();

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "AMFA Multi-Factor Authentication - TOTP";
    }
}
