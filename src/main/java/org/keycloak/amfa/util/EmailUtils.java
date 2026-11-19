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

    /**
     * The address as the email code page shows it. That page comes after the
     * password and before the second factor, so whoever has only the password
     * sees it: it names the mailbox without giving the address away.
     *
     * <p>The domain is kept, so the user knows which mailbox to look in. Of the
     * part before it, the first three characters are kept and the rest become one
     * {@code *} each, as point-iam masks it; a part of three characters or fewer
     * keeps only its first, and one of a single character keeps none.
     */
    public static String maskEmailAddress(String email) {
        if (email == null || email.isEmpty()) {
            return "";
        }
        int at = email.lastIndexOf('@');
        String local = at < 0 ? email : email.substring(0, at);
        String domain = at < 0 ? "" : email.substring(at);
        int keep = local.length() > 3 ? 3 : local.length() > 1 ? 1 : 0;
        return local.substring(0, keep) + "*".repeat(local.length() - keep) + domain;
    }
}
