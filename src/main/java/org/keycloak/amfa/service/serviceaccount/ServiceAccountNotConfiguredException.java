/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.service.serviceaccount;

/**
 * The realm has no such service-account client, or the client has no secret,
 * so no token can be requested for it: the realm is not set up for AMFA.
 */
public class ServiceAccountNotConfiguredException extends IllegalStateException {

    public ServiceAccountNotConfiguredException(String message) {
        super(message);
    }
}
