/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.util;

import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import org.apache.commons.lang3.StringUtils;

public final class EmailUtils {

    private EmailUtils() {
    }

    public static String getEmailDomain(String email) {
        return  email.substring(email.indexOf("@") + 1).toLowerCase();
    }

    public static boolean isValidEmailAddress(String email) {
        if (StringUtils.isBlank(email)) return false;
        boolean result = true;
        try {
            InternetAddress emailAddr = new InternetAddress(email);
            emailAddr.validate();
        } catch (AddressException ex) {
            result = false;
        }
        return result;
    }
}
