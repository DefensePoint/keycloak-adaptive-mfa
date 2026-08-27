/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.service;

import io.vavr.control.Either;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.models.AdminRoles;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;

public class Guards {
    private static final Logger logger = Logger.getLogger(Guards.class);

    private static final String REALMS_PATH_SEGMENT = "/realms/";

    /**
     * Authenticates and authorizes a realm-administrator request carrying a Keycloak
     * Bearer token in the Authorization header.
     *
     * <p>Verification mirrors what Keycloak's own admin REST endpoints do so it works
     * regardless of how the realm is administered:
     * <ol>
     *   <li>The token issuer selects the realm the token claims to come from (the
     *       "admin realm"): for a realm-local admin this is the current realm, for a
     *       master-console admin it is {@code master}.</li>
     *   <li>The token is cryptographically verified against that admin realm's signing
     *       keys (RS256 signature, expiry/not-before, active session). A bare
     *       {@code TokenVerifier.getToken()} only decodes and is never trusted for this.</li>
     *   <li>The authenticated user must hold the {@code manage-realm} admin role for the
     *       <em>target</em> realm (the realm resolved from the request path). This rejects
     *       both forged tokens and valid tokens whose subject is not an administrator of
     *       this realm.</li>
     * </ol>
     *
     * <p>The authorization check reproduces the logic of Keycloak's internal
     * {@code MgmtPermissions#hasOneAdminRole} using only model APIs available to deployed
     * providers, because the {@code ...resources.admin.permissions} package is not on the
     * provider runtime classpath.
     *
     * @return Right(token) when the caller is a verified administrator of the target
     *         realm, Left(error response) otherwise.
     */
    public static Either<Response, AccessToken> authenticateRealmAdminRequest(
            KeycloakSession session, String authorizationHeader) {

        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            return Either.left(errorResponse(Response.Status.UNAUTHORIZED,
                    "Missing or invalid Authorization header"));
        }

        String tokenString = authorizationHeader.substring(7).trim();
        RealmModel targetRealm = session.getContext().getRealm();

        // Decode (without trusting) only to discover which realm should verify the token.
        RealmModel adminRealm = resolveIssuerRealm(session, tokenString);
        if (adminRealm == null) {
            return Either.left(errorResponse(Response.Status.UNAUTHORIZED,
                    "Invalid or expired token"));
        }

        // Cryptographically verify signature/expiry/session against the issuing realm.
        // The signature provider resolves keys from the session context realm, so the
        // context must point at the admin realm for the duration of verification (this
        // is what Keycloak's own AdminRoot does). It is restored to the target realm
        // afterwards so the rest of the request handler is unaffected.
        AuthenticationManager.AuthResult authResult;
        session.getContext().setRealm(adminRealm);
        try {
            authResult = new AppAuthManager.BearerTokenAuthenticator(session)
                    .setRealm(adminRealm)
                    .setConnection(session.getContext().getConnection())
                    .setUriInfo(session.getContext().getUri())
                    .setHeaders(session.getContext().getRequestHeaders())
                    .setTokenString(tokenString)
                    .authenticate();
        } finally {
            session.getContext().setRealm(targetRealm);
        }

        if (authResult == null || authResult.getToken() == null || authResult.getUser() == null) {
            return Either.left(errorResponse(Response.Status.UNAUTHORIZED,
                    "Invalid or expired token"));
        }

        AccessToken token = authResult.getToken();

        // Authorize: the authenticated admin must be able to manage the target realm.
        if (!canManageRealm(adminRealm, targetRealm, authResult.getUser())) {
            logger.warnf("Rejected amfa-api request: subject '%s' (issuer realm '%s') cannot "
                    + "manage realm '%s'", token.getSubject(), adminRealm.getName(), targetRealm.getName());
            return Either.left(errorResponse(Response.Status.FORBIDDEN,
                    "Realm administrator privileges required"));
        }

        return Either.right(token);
    }

    /**
     * True when {@code adminUser} (authenticated in {@code adminRealm}) holds the
     * {@code manage-realm} admin role for {@code targetRealm}. Mirrors
     * {@code MgmtPermissions#hasOneAdminRole}: a master-realm admin is checked against the
     * target realm's master-admin client ({@code <realm>-realm}); a realm-local admin is
     * checked against that realm's {@code realm-management} client. Any other issuer realm
     * is denied.
     */
    private static boolean canManageRealm(RealmModel adminRealm, RealmModel targetRealm, UserModel adminUser) {
        ClientModel adminClient;
        if (adminRealm.getName().equals(Config.getAdminRealm())) {
            adminClient = targetRealm.getMasterAdminClient();
        } else if (adminRealm.equals(targetRealm)) {
            adminClient = targetRealm.getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID);
        } else {
            return false;
        }
        if (adminClient == null) {
            return false;
        }
        RoleModel manageRealm = adminClient.getRole(AdminRoles.MANAGE_REALM);
        return manageRealm != null && adminUser.hasRole(manageRealm);
    }

    /**
     * Reads the (untrusted) issuer claim from the token and resolves it to a local realm.
     * The result is only used to pick which realm's keys verify the token; the signature
     * check that follows is what establishes trust.
     */
    private static RealmModel resolveIssuerRealm(KeycloakSession session, String tokenString) {
        try {
            AccessToken decoded = TokenVerifier.create(tokenString, AccessToken.class).getToken();
            if (decoded == null || decoded.getIssuer() == null) {
                return null;
            }
            String issuer = decoded.getIssuer();
            int idx = issuer.lastIndexOf(REALMS_PATH_SEGMENT);
            if (idx < 0) {
                return null;
            }
            String realmName = issuer.substring(idx + REALMS_PATH_SEGMENT.length());
            if (realmName.isEmpty()) {
                return null;
            }
            return session.realms().getRealmByName(realmName);
        } catch (VerificationException e) {
            logger.debugf("Unable to decode bearer token: %s", e.getMessage());
            return null;
        }
    }

    private static Response errorResponse(Response.Status status, String message) {
        return Response.status(status)
                .entity("{\"error\":\"" + message + "\"}")
                .type(MediaType.APPLICATION_JSON)
                .build();
    }
}
