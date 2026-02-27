package aaemu.tools.service;

/**
 * @author Shannon
 */
public interface AesService {

    void setDecryptKey(byte[] key) throws Exception;

    void setEncryptKey(byte[] key) throws Exception;

    byte[] decrypt(byte[] bytes, byte[] iv) throws Exception;

    byte[] encrypt(byte[] bytes, byte[] iv) throws Exception;
}
