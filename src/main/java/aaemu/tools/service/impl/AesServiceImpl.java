package aaemu.tools.service.impl;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import aaemu.tools.service.AesService;

/**
 * @author Shannon
 */
public class AesServiceImpl implements AesService {
    public static final String ALGORITHM = "AES";
    public static final String TRANSFORMATION = "AES/ECB/NoPadding";

    private Cipher cipher;

    @Override
    public void setDecryptKey(byte[] key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key, ALGORITHM);
        cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
    }

    @Override
    public void setEncryptKey(byte[] key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key, ALGORITHM);
        cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    }

    @Override
    public byte[] decrypt(byte[] bytes, byte[] iv) throws Exception {
        xor(bytes, iv);

        return cipher.doFinal(bytes);
    }

    @Override
    public byte[] encrypt(byte[] bytes, byte[] iv) throws Exception {
        byte[] result = cipher.doFinal(bytes);
        xor(result, iv);

        return result;
    }

    private void xor(byte[] bytes, byte[] key) {
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) (bytes[i] ^ key[i]);
        }
    }
}
