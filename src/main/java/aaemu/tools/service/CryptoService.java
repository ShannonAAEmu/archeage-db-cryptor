package aaemu.tools.service;

import aaemu.tools.config.ConfigProperties;

/**
 * @author Shannon
 */
public interface CryptoService {

    byte[] decryptV2(ConfigProperties properties, byte[] encryptedData) throws Exception;

    byte[] encryptV2(ConfigProperties properties, byte[] decryptedData) throws Exception;

    byte[] decryptV3(ConfigProperties properties, byte[] encryptedData) throws Exception;

    byte[] encryptV3(ConfigProperties properties, byte[] decryptedData) throws Exception;
}
