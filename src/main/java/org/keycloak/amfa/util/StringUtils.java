/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.util;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class StringUtils {

    public static String extractDigits(final String in, final int length) {
        final Pattern p = Pattern.compile( "(\\d{" + length + "})" );
        final Matcher m = p.matcher( in );
        if ( m.find() ) {
            return m.group( 0 );
        }
        return "";
    }

    private StringUtils() {}
}
