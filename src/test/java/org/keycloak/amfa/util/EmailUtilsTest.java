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
}
