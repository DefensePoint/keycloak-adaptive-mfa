/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.authenticator.mfa.totp;

import org.jboss.logging.Logger;
import org.keycloak.amfa.util.EventBuilderHelper;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.OTPCredentialProvider;
import org.keycloak.credential.OTPCredentialProviderFactory;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

public abstract class MfaTOTPAuthenticator implements Authenticator {

    private static final Logger log = Logger.getLogger(MfaTOTPAuthenticator.class);

    protected OTPCredentialProvider getCredentialProvider(KeycloakSession session) {
        return (OTPCredentialProvider) session.getProvider(CredentialProvider.class,
                OTPCredentialProviderFactory.PROVIDER_ID);
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        Response challenge = context.form().createLoginTotp();
        context.challenge(challenge);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        // The login TOTP form rendered by createLoginTotp() posts the code in
        // the "otp" field (Keycloak's base login-otp.ftl), not "totp".
        String totp = formData.getFirst("otp");

        if (totp == null || totp.isBlank()) {
            LoginFormsProvider form = context.form().setError("missingTotpMessage");
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                    form.createLoginTotp());
            return;
        }

        UserModel user = context.getUser();
        String credentialId = getCredentialProvider(context.getSession())
                .getDefaultCredential(context.getSession(), context.getRealm(), user)
                .getId();

        UserCredentialModel credential = new UserCredentialModel(credentialId,
                getCredentialProvider(context.getSession()).getType(), totp);

        if (user.credentialManager().isValid(credential)) {
            // See MfaEmailAuthenticator's identical call for the full
            // explanation: Keycloak rebuilds the EventBuilder per HTTP request,
            // so AdaptiveAuthAuthenticator's earlier-request details would
            // otherwise be lost from the LOGIN event whenever TOTP step-up is
            // required. Re-attaching from the (request-persistent) auth-session
            // notes here closes that.
            EventBuilderHelper.addExtraDetailsToEvent(context.getEvent(), context.getAuthenticationSession());
            context.success();
        } else {
            LoginFormsProvider form = context.form().setError("invalidTotpMessage");
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                    form.createLoginTotp());
        }
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return user.credentialManager().isConfiguredFor(getCredentialProvider(session).getType());
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        user.addRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
    }

    @Override
    public void close() {
    }
}
