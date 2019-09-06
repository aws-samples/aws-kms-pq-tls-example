package com.example.crypto;

import software.amazon.awssdk.utils.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class RSAUtils {
    private static final Logger LOG = Logger.loggerFor(RSAUtils.class);
    private static final int RSA_PUBLIC_KEY_SIZE = 2048;
    public static RSAPublicKey decodeX509PublicKey(final byte[] publicKey) {
        final X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKey);
        try {
            final RSAPublicKey pk = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
            LOG.info(() -> String.format("Expected %d bit RSA key, got %d from KMS", RSA_PUBLIC_KEY_SIZE, pk.getModulus().bitLength()));
            return pk;
        } catch (final InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new CryptoException(e);
        }
    }

    public static byte[] encryptRSA(final RSAPublicKey publicKey, final byte[] plaintext) {
        try {
            final Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            final byte[] ciphertext = cipher.doFinal(plaintext);
            return ciphertext;
        } catch (final InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
                | IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoException(e);
        }
    }
}
