/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.authenticator.screenresolution;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.UsernameFormFactory;
import org.keycloak.models.KeycloakSession;

public class ScreenResolutionAuthenticatorFactory extends UsernameFormFactory {

    public static final String PROVIDER_ID = "cookie-screen-resolution";
    public static final ScreenResolutionAuthenticator SINGLETON = new ScreenResolutionAuthenticator();

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
        return "Screen Resolution";
    }

    @Override
    public boolean isUserSetupAllowed() {
        return true;
    }
}
