/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.authenticator.mfa.totp;

import org.jboss.logging.Logger;
import org.keycloak.amfa.util.EventBuilderHelper;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.util.AuthenticatorUtils;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.OTPCredentialProvider;
import org.keycloak.credential.OTPCredentialProviderFactory;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

public abstract class MfaTOTPAuthenticator implements Authenticator {

    private static final Logger log = Logger.getLogger(MfaTOTPAuthenticator.class);

    /** The form field Keycloak's login-otp.ftl posts the picked device in. */
    private static final String SELECTED_CREDENTIAL_ID_FIELD = "selectedCredentialId";
    /** The page attribute login-otp.ftl marks the selected device by. */
    private static final String SELECTED_CREDENTIAL_ID_ATTRIBUTE = "selectedOtpCredentialId";

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
        // First, before the code is even read: an empty submit is a failed
        // login too, and must not extend the lockout either.
        UserModel user = context.getUser();
        if (denyIfLockedOut(context, user)) {
            return;
        }

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        // The login TOTP form rendered by createLoginTotp() posts the code in
        // the "otp" field (Keycloak's base login-otp.ftl), not "totp".
        String totp = formData.getFirst("otp");

        if (totp == null || totp.isBlank()) {
            EventBuilderHelper.recordError(context.getEvent(), context.getAuthenticationSession(),
                    user, Errors.INVALID_USER_CREDENTIALS);
            LoginFormsProvider form = context.form().setError("missingTotpMessage");
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                    form.createLoginTotp());
            return;
        }

        // The device the user picked on the page, as on Keycloak's own OTP
        // form (OTPFormAuthenticator): a user with several authenticator apps
        // chooses one, and the code is checked against that one. Only without
        // a choice is it the default device.
        String credentialId = formData.getFirst(SELECTED_CREDENTIAL_ID_FIELD);
        if (credentialId == null || credentialId.isEmpty()) {
            OTPCredentialModel defaultCredential = getCredentialProvider(context.getSession())
                    .getDefaultCredential(context.getSession(), context.getRealm(), user);
            credentialId = defaultCredential == null ? "" : defaultCredential.getId();
        }
        context.getEvent().detail(Details.SELECTED_CREDENTIAL_ID, credentialId);
        // Keeps that device selected when the page is shown again after a
        // wrong code.
        context.form().setAttribute(SELECTED_CREDENTIAL_ID_ATTRIBUTE, credentialId);

        // The picked ID comes from the form, so it may name another user's
        // device or none at all. Keycloak's check throws on such an ID (it
        // looks the credential up among this user's and dereferences what it
        // finds), which ended the login on an error page. It is refused like
        // a wrong code instead, and counts as one.
        String pickedId = credentialId;
        boolean ownDevice = user.credentialManager().getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE)
                .anyMatch(c -> pickedId.equals(c.getId()));

        UserCredentialModel credential = new UserCredentialModel(credentialId,
                getCredentialProvider(context.getSession()).getType(), totp);

        if (ownDevice && user.credentialManager().isValid(credential)) {
            // See MfaEmailAuthenticator's identical call for the full
            // explanation: Keycloak rebuilds the EventBuilder per HTTP request,
            // so AdaptiveAuthAuthenticator's earlier-request details would
            // otherwise be lost from the LOGIN event whenever TOTP step-up is
            // required. Re-attaching from the (request-persistent) auth-session
            // notes here closes that.
            EventBuilderHelper.addExtraDetailsToEvent(context.getEvent(), context.getAuthenticationSession());
            context.success();
        } else {
            // Recorded as Keycloak's own OTP form records a wrong code, so a
            // monitoring tool sees code guessing on this step too.
            EventBuilderHelper.recordError(context.getEvent(), context.getAuthenticationSession(),
                    user, Errors.INVALID_USER_CREDENTIALS);
            LoginFormsProvider form = context.form().setError("invalidTotpMessage");
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                    form.createLoginTotp());
        }
    }

    /**
     * Refuse a code, even the right one, while the realm's brute-force
     * protector has the account locked out. Without this a locked-out account
     * could keep guessing on this form, and the right code logged it in.
     *
     * <p>Mirrors Keycloak's own OTP form ({@code OTPFormAuthenticator}): the
     * same {@code *DisabledMessageTotp} messages, which read like a wrong code
     * and so do not reveal the lockout, and {@code forceChallenge()} rather
     * than a failure. The flow engine counts a FAILED or FAILURE_CHALLENGE
     * result as another failed login, so a failure here would extend the
     * lockout on every retry; MfaEmailAuthenticator's gate does the same.
     */
    private boolean denyIfLockedOut(AuthenticationFlowContext context, UserModel user) {
        String bruteForceError = AuthenticatorUtils.getDisabledByBruteForceEventError(context, user);
        if (bruteForceError == null) {
            return false;
        }
        EventBuilderHelper.recordError(context.getEvent(), context.getAuthenticationSession(), user, bruteForceError);
        String message = Errors.USER_TEMPORARILY_DISABLED.equals(bruteForceError)
                ? "accountTemporarilyDisabledMessageTotp"
                : "accountPermanentlyDisabledMessageTotp";
        context.forceChallenge(context.form().setError(message).createLoginTotp());
        return true;
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
