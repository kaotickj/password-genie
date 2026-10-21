package com.kaotickj.passwordgenie;
import org.junit.Test;
import static org.junit.Assert.*;
import java.security.GeneralSecurityException;
import java.util.Base64;

public class VaultCryptoTest {
    // Generated with Python cryptography using fake credentials only.
    private static final String MASTER = "synthetic-🔐-master";
    private static final String SECRET = "  synthetic-秘密-password  ";
    private static final byte[] PYTHON_BLOB = Base64.getDecoder().decode("OjoxMjM0NTY3ODkwMTIzNDpnQUFBQUFCcTJOQlB4enUyejhYQ3gza2ZNQnlIYlBDZEtQY3JBU2ZEZmNJYldueUtxMjY5VWt5UU9fQmd4WjByelhKWHVsdEsxbW9uN0tqOEhfQ3ZZSmZoaldqRV9hSkNCZ0xfQjlYeHY0ek84SDhSWllxeVdnND0=");
    @Test public void pythonLegacyCompatibilityWithColonSaltAndUnicode() throws Exception {
        assertEquals(SECRET, VaultCrypto.decrypt(MASTER, PYTHON_BLOB));
    }
    @Test public void roundTrip() throws Exception {
        assertEquals(SECRET, VaultCrypto.decrypt(MASTER, VaultCrypto.encrypt(MASTER, SECRET)));
    }
    @Test public void wrongPasswordRejected() throws Exception {
        try { VaultCrypto.decrypt("wrong", PYTHON_BLOB); fail("Wrong password accepted"); }
        catch (GeneralSecurityException expected) {}
    }
    @Test public void tamperingRejected() throws Exception {
        byte[] blob = PYTHON_BLOB.clone(); blob[blob.length - 10] ^= 1;
        try { VaultCrypto.decrypt(MASTER, blob); fail("Tampered token accepted"); }
        catch (GeneralSecurityException expected) {}
    }
    @Test public void malformedRejected() throws Exception {
        try { VaultCrypto.decrypt(MASTER, new byte[10]); fail("Malformed token accepted"); }
        catch (GeneralSecurityException expected) {}
    }
    @Test public void digitGenerator() {
        String value = VaultCrypto.generate(64, false, true, false);
        assertTrue(value.matches("[0-9]{64}"));
    }
    @Test(expected=IllegalArgumentException.class) public void noCharacterTypesRejected() {
        VaultCrypto.generate(16, false, false, false);
    }
    @Test(expected=IllegalArgumentException.class) public void hugeLengthRejected() {
        VaultCrypto.generate(4097, true, true, true);
    }
}
