package com.kaotickj.passwordgenie;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/** Schema-1 compatibility using platform crypto. Authenticate before decrypting. */
public final class VaultCrypto {
    private static final SecureRandom RNG = new SecureRandom();
    private VaultCrypto() {}
    public static byte[] random(int length) {
        byte[] result = new byte[length]; RNG.nextBytes(result); return result;
    }
    public static byte[] derive(String master, byte[] salt) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(master.toCharArray(), salt, 100000, 256);
        try { return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded(); }
        finally { spec.clearPassword(); }
    }
    private static byte[] sign(byte[] key, byte[] data) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(Arrays.copyOfRange(key, 0, 16), "HmacSHA256"));
        return mac.doFinal(data);
    }
    public static byte[] encrypt(String master, String password) throws GeneralSecurityException {
        byte[] salt = random(16), key = derive(master, salt), iv = random(16);
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(Arrays.copyOfRange(key, 16, 32), "AES"), new IvParameterSpec(iv));
            byte[] encrypted = cipher.doFinal(password.getBytes(StandardCharsets.UTF_8));
            byte[] body = ByteBuffer.allocate(25 + encrypted.length).put((byte) 0x80)
                .putLong(System.currentTimeMillis() / 1000).put(iv).put(encrypted).array();
            byte[] signed = ByteBuffer.allocate(body.length + 32).put(body).put(sign(key, body)).array();
            byte[] token = Base64.getUrlEncoder().encode(signed);
            return ByteBuffer.allocate(17 + token.length).put(salt).put((byte) ':').put(token).array();
        } finally { Arrays.fill(key, (byte) 0); }
    }
    public static String decrypt(String master, byte[] blob) throws GeneralSecurityException {
        if (blob.length < 18 || blob[16] != ':') throw new GeneralSecurityException("Invalid credential format");
        byte[] key = derive(master, Arrays.copyOfRange(blob, 0, 16));
        try {
            byte[] token;
            try { token = Base64.getUrlDecoder().decode(Arrays.copyOfRange(blob, 17, blob.length)); }
            catch (IllegalArgumentException exc) { throw new GeneralSecurityException("Invalid token", exc); }
            if (token.length < 73 || token[0] != (byte) 0x80 || (token.length - 57) % 16 != 0)
                throw new GeneralSecurityException("Invalid token");
            byte[] body = Arrays.copyOfRange(token, 0, token.length - 32);
            if (!MessageDigest.isEqual(sign(key, body), Arrays.copyOfRange(token, token.length - 32, token.length)))
                throw new GeneralSecurityException("Invalid password or damaged credential");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(Arrays.copyOfRange(key, 16, 32), "AES"),
                new IvParameterSpec(Arrays.copyOfRange(token, 9, 25)));
            return new String(cipher.doFinal(Arrays.copyOfRange(token, 25, token.length - 32)), StandardCharsets.UTF_8);
        } finally { Arrays.fill(key, (byte) 0); }
    }
    public static String generate(int length, boolean letters, boolean digits, boolean punctuation) {
        if (length < 1 || length > 4096) throw new IllegalArgumentException("Length must be between 1 and 4096");
        String chars = (letters ? "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" : "")
            + (digits ? "0123456789" : "") + (punctuation ? "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~" : "");
        if (chars.isEmpty()) throw new IllegalArgumentException("Select at least one character type");
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < length; i++) result.append(chars.charAt(RNG.nextInt(chars.length())));
        return result.toString();
    }
}
