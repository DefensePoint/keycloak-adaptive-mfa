/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.authenticator.mfa.totp;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.amfa.authenticator.adaptiveauth.AdaptiveAuthAuthenticator;
import org.keycloak.amfa.util.EventBuilderHelper;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.OTPCredentialProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.services.managers.BruteForceProtector;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.Response;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class MfaTOTPAuthenticatorTest {

    @Mock private AuthenticationFlowContext context;
    @Mock private KeycloakSession session;
    @Mock private RealmModel realm;
    @Mock private UserModel user;
    @Mock private SubjectCredentialManager credentials;
    @Mock private BruteForceProtector protector;
    @Mock private HttpRequest request;
    @Mock private LoginFormsProvider form;
    @Mock private EventBuilder event;
    @Mock private AuthenticationSessionModel authSession;
    @Mock private OTPCredentialProvider otpProvider;
    @Mock private OTPCredentialModel otpCredential;
    @Mock private Response page;

    private MfaTOTPAuthenticator authenticator;

    @BeforeEach
    void setUp() {
        authenticator = new MfaTOTPAuthenticator() {
            @Override
            protected OTPCredentialProvider getCredentialProvider(KeycloakSession s) {
                return otpProvider;
            }
        };
        lenient().when(context.getSession()).thenReturn(session);
        lenient().when(context.getRealm()).thenReturn(realm);
        lenient().when(context.getUser()).thenReturn(user);
        lenient().when(context.getProtector()).thenReturn(protector);
        lenient().when(context.getHttpRequest()).thenReturn(request);
        lenient().when(context.form()).thenReturn(form);
        lenient().when(context.getEvent()).thenReturn(event);
        lenient().when(context.getAuthenticationSession()).thenReturn(authSession);
        lenient().when(form.setError(anyString())).thenReturn(form);
        lenient().when(form.createLoginTotp()).thenReturn(page);
        lenient().when(event.user(any(UserModel.class))).thenReturn(event);
        lenient().when(event.detail(anyString(), nullable(String.class))).thenReturn(event);
        lenient().when(authSession.getAuthNote(AdaptiveAuthAuthenticator.AUTH_NOTE)).thenReturn("3");
        lenient().when(authSession.getAuthNote(AdaptiveAuthAuthenticator.EVENT_ID_NOTE)).thenReturn("decision-1");
        lenient().when(user.credentialManager()).thenReturn(credentials);
        lenient().when(otpProvider.getDefaultCredential(session, realm, user)).thenReturn(otpCredential);
        lenient().when(otpProvider.getType()).thenReturn(OTPCredentialModel.TYPE);
        lenient().when(otpCredential.getId()).thenReturn("otp-1");
        // The user's own authenticator devices: the default one and a second.
        lenient().when(credentials.getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE))
                .thenAnswer(inv -> java.util.stream.Stream.of(stored("otp-1"), stored("otp-2")));
    }

    private void submit(String code, boolean valid) {
        MultivaluedHashMap<String, String> params = new MultivaluedHashMap<>();
        params.add("otp", code);
        // Lenient: a locked-out user is refused before the form is read.
        lenient().when(request.getDecodedFormParameters()).thenReturn(params);
        lenient().when(credentials.isValid(any(org.keycloak.credential.CredentialInput.class))).thenReturn(valid);
    }

    private void bruteForce(boolean on, boolean temporarilyDisabled, boolean permanentlyLockedOut) {
        lenient().when(realm.isBruteForceProtected()).thenReturn(on);
        lenient().when(protector.isTemporarilyDisabled(session, realm, user)).thenReturn(temporarilyDisabled);
        lenient().when(protector.isPermanentlyLockedOut(session, realm, user)).thenReturn(permanentlyLockedOut);
    }

    @Test
    void aTemporarilyLockedOutUserIsRefusedEvenWithTheRightCode() {
        bruteForce(true, true, false);
        submit("123456", true);

        authenticator.action(context);

        verify(context, never()).success();
        verify(credentials, never()).isValid(any(org.keycloak.credential.CredentialInput.class));
        verify(form).setError("accountTemporarilyDisabledMessageTotp");
        verify(event).error(Errors.USER_TEMPORARILY_DISABLED);
        // Not a FAILURE_CHALLENGE: Keycloak counts those as another failed
        // login, so each retry would extend the lockout.
        verify(context).forceChallenge(page);
        verify(context, never()).failureChallenge(any(), any());
    }

    @Test
    void aPermanentlyLockedOutUserIsRefusedEvenWithTheRightCode() {
        bruteForce(true, false, true);
        submit("123456", true);

        authenticator.action(context);

        verify(context, never()).success();
        verify(form).setError("accountPermanentlyDisabledMessageTotp");
        verify(event).error(Errors.USER_DISABLED);
        verify(context).forceChallenge(page);
    }

    @Test
    void aLockedOutUserSubmittingAnEmptyCodeIsRefusedWithoutAnotherFailedLogin() {
        bruteForce(true, true, false);
        submit("", false);

        authenticator.action(context);

        verify(context, never()).success();
        verify(form).setError("accountTemporarilyDisabledMessageTotp");
        verify(event).error(Errors.USER_TEMPORARILY_DISABLED);
        // The lockout is checked before the code is read, as Keycloak's own
        // OTP form does: an empty submit must not extend the lockout either.
        verify(request, never()).getDecodedFormParameters();
        verify(context).forceChallenge(page);
        verify(context, never()).failureChallenge(any(), any());
    }

    @Test
    void anEmptyCodeFromAUserWhoIsNotLockedOutIsAFailedLogin() {
        bruteForce(true, false, false);
        submit("", false);

        authenticator.action(context);

        verify(context, never()).success();
        verify(form).setError("missingTotpMessage");
        verify(context).failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, page);
    }

    @Test
    void aUserWhoIsNotLockedOutLogsInWithTheRightCode() {
        bruteForce(true, false, false);
        submit("123456", true);

        authenticator.action(context);

        verify(context).success();
        verify(context, never()).forceChallenge(any());
    }

    @Test
    void aWrongCodeIsAFailedLoginThatCountsTowardTheLockout() {
        bruteForce(true, false, false);
        submit("000000", false);

        authenticator.action(context);

        verify(context, never()).success();
        verify(form).setError("invalidTotpMessage");
        verify(context).failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, page);
    }

    @Test
    void withoutBruteForceProtectionTheRightCodeLogsIn() {
        bruteForce(false, false, false);
        submit("123456", true);

        authenticator.action(context);

        verify(context).success();
        verifyNoInteractions(protector);
    }

    /*
     * A user with more than one authenticator device picks one on the code
     * page, as on Keycloak's own OTP form. The code is checked against that
     * device; with no choice posted, against the default one.
     */

    private void submitFor(String code, String selectedCredentialId) {
        MultivaluedHashMap<String, String> params = new MultivaluedHashMap<>();
        params.add("otp", code);
        if (selectedCredentialId != null) {
            params.add("selectedCredentialId", selectedCredentialId);
        }
        lenient().when(request.getDecodedFormParameters()).thenReturn(params);
        lenient().when(form.setAttribute(anyString(), any())).thenReturn(form);
        lenient().when(event.detail(anyString(), anyString())).thenReturn(event);
    }

    private String checkedCredentialId() {
        ArgumentCaptor<CredentialInput> input = ArgumentCaptor.forClass(CredentialInput.class);
        verify(credentials).isValid(input.capture());
        return input.getValue().getCredentialId();
    }

    @Test
    void theCodeIsCheckedAgainstTheDeviceTheUserPicked() {
        bruteForce(false, false, false);
        submitFor("123456", "otp-2");
        when(credentials.isValid(any(CredentialInput.class))).thenReturn(true);

        authenticator.action(context);

        assertEquals("otp-2", checkedCredentialId());
        verify(context).success();
    }

    @Test
    void withoutAChoiceTheCodeIsCheckedAgainstTheDefaultDevice() {
        bruteForce(false, false, false);
        submitFor("123456", null);
        when(credentials.isValid(any(CredentialInput.class))).thenReturn(true);

        authenticator.action(context);

        assertEquals("otp-1", checkedCredentialId());
    }

    @Test
    void aWrongCodeKeepsThePickedDeviceSelectedAndRecordsIt() {
        bruteForce(false, false, false);
        submitFor("000000", "otp-2");
        when(credentials.isValid(any(CredentialInput.class))).thenReturn(false);

        authenticator.action(context);

        verify(form).setAttribute("selectedOtpCredentialId", "otp-2");
        verify(event).detail(Details.SELECTED_CREDENTIAL_ID, "otp-2");
        verify(context).failureChallenge(eq(AuthenticationFlowError.INVALID_CREDENTIALS), eq(page));
    }

    private static CredentialModel stored(String id) {
        CredentialModel model = new CredentialModel();
        model.setId(id);
        model.setType(OTPCredentialModel.TYPE);
        return model;
    }

    @Test
    void aPickedIdThatIsNotOneOfTheUsersDevicesIsAWrongCode() {
        // Another user's device, or no device at all: Keycloak's own check
        // throws on an ID that is not the user's, which ended the login on an
        // error page instead of the code page.
        bruteForce(false, false, false);
        submitFor("123456", "someone-elses-otp");

        authenticator.action(context);

        verify(credentials, never()).isValid(any(CredentialInput.class));
        verify(context, never()).success();
        verify(form).setError("invalidTotpMessage");
        verify(context).failureChallenge(eq(AuthenticationFlowError.INVALID_CREDENTIALS), eq(page));
    }

    /** The event of a failed attempt carries the login's AMFA details. */
    private void verifyAmfaDetails() {
        verify(event).detail(AdaptiveAuthAuthenticator.RISK_LEVEL, "3");
        verify(event).detail(EventBuilderHelper.AMFA_EVENT_ID_DETAIL, "decision-1");
    }

    @Test
    void aWrongCodeIsRecordedWithTheAmfaDetailsBeforeItIsCounted() {
        bruteForce(true, false, false);
        submit("000000", false);

        authenticator.action(context);

        verifyAmfaDetails();
        InOrder order = inOrder(event, context);
        order.verify(event).user(user);
        order.verify(event).error(Errors.INVALID_USER_CREDENTIALS);
        order.verify(context).failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, page);
    }

    @Test
    void anEmptyCodeIsRecordedLikeAWrongOne() {
        bruteForce(true, false, false);
        submit("", false);

        authenticator.action(context);

        verifyAmfaDetails();
        verify(event).error(Errors.INVALID_USER_CREDENTIALS);
    }

    @Test
    void aLockoutRefusalCarriesTheAmfaDetails() {
        bruteForce(true, true, false);
        submit("123456", true);

        authenticator.action(context);

        verifyAmfaDetails();
        verify(event).error(Errors.USER_TEMPORARILY_DISABLED);
    }

    @Test
    void theRightCodeRecordsNoError() {
        bruteForce(true, false, false);
        submit("123456", true);

        authenticator.action(context);

        verify(event, never()).error(anyString());
    }
}
