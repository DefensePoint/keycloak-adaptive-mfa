/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class StringUtilsTest {

    @Test
    void extractDigits_returnsMatchingDigits() {
        assertEquals("1234", StringUtils.extractDigits("abc1234def", 4));
    }

    @Test
    void extractDigits_returnsEmptyWhenNoMatch() {
        assertEquals("", StringUtils.extractDigits("abcdef", 4));
    }

    @Test
    void extractDigits_returnsSixDigitCode() {
        assertEquals("123456", StringUtils.extractDigits("code: 123456 end", 6));
    }

    @Test
    void extractDigits_returnsFirstMatchWhenMultiple() {
        assertEquals("111", StringUtils.extractDigits("111 222", 3));
    }

    @Test
    void extractDigits_returnsEmptyForTooFewDigits() {
        assertEquals("", StringUtils.extractDigits("12", 3));
    }
}
