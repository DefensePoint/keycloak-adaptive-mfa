/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.service;

import org.keycloak.amfa.util.KeycloakUtils;
import io.vavr.control.Either;
import org.keycloak.models.*;

import java.util.Optional;
import java.util.stream.Stream;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class AmfaApiService {

    private final KeycloakSession session;

    public AmfaApiService(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Finds a User by userId in a Realm.
     *
     * @param userId userId
     * @return either user model or error message
     */
    public Either<String, UserModel> findUserByUserId(String userId, RealmModel realm) {
        // Check if a user with the same username exists
        Optional<UserModel> userOpt =
                Optional.ofNullable(session.users().getUserById((realm != null ? realm : session.getContext().getRealm()), userId));

        return userOpt.<Either<String, UserModel>>map(Either::right)
                .orElseGet(() -> Either.left("User not found in realm"));
    }

    /**
     * Finds a Realm by realmName in a Keycloak.
     *
     * @param realmName realmName
     * @return either realm model or error message
     */
    public Either<String, RealmModel> findRealmByName(String realmName) {
        Optional<RealmModel> userOpt =
                Optional.ofNullable(session.realms().getRealmByName(realmName));

        return userOpt.<Either<String, RealmModel>>map(Either::right)
                .orElseGet(() -> Either.left("Realm not found"));
    }

    public Either<String, ClientModel> findClientByClientId(String clientId) {

        // Check if a client with the same clientId exists
        Optional<ClientModel> clientOpt =
                Optional.ofNullable(session.getContext().getRealm().getClientByClientId(clientId));

        // Check if a client is enabled
        if(clientOpt.isPresent())
            clientOpt = Optional.ofNullable(clientOpt.get().isEnabled() ? clientOpt.get() : null);


        return clientOpt.<Either<String, ClientModel>>map(Either::right)
                .orElseGet(() -> Either.left("Client not found in realm or not enabled "));
    }

    public Either<String, IdentityProviderModel> findIdPByAlias(String idpAlias) {

        // Check if a client with the same clientId exists
        Optional<IdentityProviderModel> idpModel =
                Optional.ofNullable(session.getContext().getRealm().getIdentityProviderByAlias(idpAlias));

        // Check if a client is enabled
        if(idpModel.isPresent())
            idpModel = Optional.ofNullable(idpModel.get().isEnabled() ? idpModel.get() : null);


        return idpModel.<Either<String, IdentityProviderModel>>map(Either::right)
                .orElseGet(() -> Either.left("IdP not found in realm or not enabled "));
    }

    public Either<String, Stream<GroupModel>> getGroups() {
        RealmModel realm = session.realms().getRealmByName(session.getContext().getRealm().getName());
        if (realm != null) {
            return Either.right(realm.getGroupsStream());
        } else {
            return Either.left("Realm not found");
        }
    }

    public boolean isSsoUser(UserModel user) {
        return KeycloakUtils.getIdp(session.getContext().getRealm(), user.getUsername()) != null;
    }

}
