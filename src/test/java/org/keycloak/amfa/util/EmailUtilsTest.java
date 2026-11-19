/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class EmailUtilsTest {

    @Test
    void getEmailDomain_extractsDomainCorrectly() {
        assertEquals("example.com", EmailUtils.getEmailDomain("user@example.com"));
    }

    @Test
    void getEmailDomain_lowercasesDomain() {
        assertEquals("example.com", EmailUtils.getEmailDomain("user@EXAMPLE.COM"));
    }

    @Test
    void isValidEmailAddress_returnsTrueForValidEmail() {
        assertTrue(EmailUtils.isValidEmailAddress("test@example.com"));
    }

    @Test
    void isValidEmailAddress_returnsFalseForNull() {
        assertFalse(EmailUtils.isValidEmailAddress(null));
    }

    @Test
    void isValidEmailAddress_returnsFalseForBlank() {
        assertFalse(EmailUtils.isValidEmailAddress(""));
        assertFalse(EmailUtils.isValidEmailAddress("   "));
    }

    @Test
    void isValidEmailAddress_returnsFalseForInvalid() {
        assertFalse(EmailUtils.isValidEmailAddress("not-an-email"));
    }

    // --- maskEmailAddress: the address as the code page shows it ---

    @Test
    void maskEmailAddress_keepsTheFirstThreeCharactersAndTheDomain() {
        assertEquals("jon*****@example.com", EmailUtils.maskEmailAddress("jonathan@example.com"));
    }

    @Test
    void maskEmailAddress_masksAShortNameBeyondItsFirstCharacter() {
        assertEquals("b**@example.com", EmailUtils.maskEmailAddress("bob@example.com"));
        assertEquals("a*@example.com", EmailUtils.maskEmailAddress("al@example.com"));
        assertEquals("*@example.com", EmailUtils.maskEmailAddress("a@example.com"));
    }

    @Test
    void maskEmailAddress_masksUpToTheLastAt() {
        assertEquals("\"jo*******@example.com", EmailUtils.maskEmailAddress("\"john@doe\"@example.com"));
    }

    @Test
    void maskEmailAddress_masksAnAddressWithoutADomain() {
        assertEquals("loc**", EmailUtils.maskEmailAddress("local"));
    }

    @Test
    void maskEmailAddress_returnsEmptyForNoAddress() {
        assertEquals("", EmailUtils.maskEmailAddress(null));
        assertEquals("", EmailUtils.maskEmailAddress(""));
    }
}
