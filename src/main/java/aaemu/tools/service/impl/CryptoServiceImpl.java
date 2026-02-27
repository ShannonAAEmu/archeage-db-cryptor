package aaemu.tools.service.impl;

import static aaemu.tools.util.ConstantsUtils.ZIP_BITFLAG;
import static aaemu.tools.util.ConstantsUtils.ZIP_COMPRESSION_METHOD;
import static aaemu.tools.util.ConstantsUtils.ZIP_HEADER;
import static aaemu.tools.util.ConstantsUtils.ZIP_OVERWRITE_HEADER_SIZE;
import static aaemu.tools.util.ConstantsUtils.ZIP_VERSION;
import static aaemu.tools.util.HexUtils.toBigInt;
import static aaemu.tools.util.HexUtils.toByteArray;
import static aaemu.tools.util.HexUtils.toHex;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import aaemu.tools.config.AesStepConfig;
import aaemu.tools.config.ConfigProperties;
import aaemu.tools.config.RsaStepConfig;
import aaemu.tools.service.AesService;
import aaemu.tools.service.CryptoService;
import lombok.RequiredArgsConstructor;

/**
 * @author Shannon
 */
@RequiredArgsConstructor
public class CryptoServiceImpl implements CryptoService {
    private final AesService aesService;

    @Override
    public byte[] decryptV2(ConfigProperties properties, byte[] encryptedData) throws Exception {
        byte[] bytes = decryptAesFirstStage(properties, encryptedData);

        return decryptAesSecondStage(properties, bytes, 0);
    }

    @Override
    public byte[] encryptV2(ConfigProperties properties, byte[] decryptedData) throws Exception {
        byte[] bytes = encryptAesFirstStage(properties, decryptedData, 0);

        return encryptAesSecondStage(properties, bytes);
    }

    @Override
    public byte[] decryptV3(ConfigProperties properties, byte[] encryptedData) throws Exception {
        byte[] bytes = decryptAesFirstStage(properties, encryptedData);

        RsaStepConfig rsa = properties.getRsa();
        int cipherBlockSize = rsa.getCLength();
        int rounds = rsa.getRounds();
        int totalCipherDataLength = cipherBlockSize * rounds;
        List<String> ciphers = readCiphers(cipherBlockSize, totalCipherDataLength, rounds, bytes);
        List<byte[]> decrypts = rsaDecrypt(ciphers, properties);

        List<Integer> blocksPoses = rsa.getBlocksPoses();
        int cipherOffset = bytes.length - totalCipherDataLength;

        for (int i = 0; i < decrypts.size(); i++) {
            byte[] mBytes = decrypts.get(i);
            int mPos = blocksPoses.get(i);

            System.arraycopy(mBytes, 0, bytes, mPos, mBytes.length);

            cipherOffset = cipherOffset + cipherBlockSize;
        }

        bytes = decryptAesSecondStage(properties, bytes, totalCipherDataLength);

        overwriteZipHeader(bytes);

        return bytes;
    }

    @Override
    public byte[] encryptV3(ConfigProperties properties, byte[] decryptedData) {
        // TODO

        return decryptedData;
    }

    public byte[] decryptAesFirstStage(ConfigProperties properties, byte[] encryptedData) throws Exception {
        AesStepConfig step = properties.getAesFirstStage();
        ByteBuffer dataBuffer = ByteBuffer.wrap(encryptedData);
        int length = dataBuffer.capacity();
        int offset = calculateOffset(length);

        return aesDecrypt(step, dataBuffer, offset, 0);
    }

    public byte[] decryptAesSecondStage(ConfigProperties properties, byte[] encryptedData, int skipLength) throws Exception {
        AesStepConfig step = properties.getAesSecondStage();
        ByteBuffer dataBuffer = ByteBuffer.wrap(encryptedData);
        int offset = 0;

        return aesDecrypt(step, dataBuffer, offset, skipLength);
    }

    public byte[] encryptAesFirstStage(ConfigProperties properties, byte[] decryptedData, int skipLength) throws Exception {
        AesStepConfig step = properties.getAesSecondStage();
        final ByteBuffer dataBuffer = ByteBuffer.wrap(decryptedData);
        int offset = 0;

        return aesEncrypt(step, dataBuffer, offset, skipLength);
    }

    public byte[] encryptAesSecondStage(ConfigProperties properties, byte[] decryptedData) throws Exception {
        AesStepConfig step = properties.getAesFirstStage();
        final ByteBuffer dataBuffer = ByteBuffer.wrap(decryptedData);
        int length = dataBuffer.capacity();
        int offset = calculateOffset(length);

        return aesEncrypt(step, dataBuffer, offset, 0);
    }

    private byte[] aesDecrypt(AesStepConfig step, ByteBuffer data, int offset, int skipLength) throws Exception {
        aesService.setDecryptKey(step.getAesKey());

        byte[] iv = step.getIv();
        final byte[] tempBlock = new byte[16];
        final int endOffset = data.capacity() - 15 - skipLength;

        while (offset < endOffset) {
            readData(data, offset, tempBlock);

            byte[] decryptedBlock = aesService.decrypt(tempBlock, iv);

            writeData(data, offset, decryptedBlock);

            iv = decryptedBlock;
            offset += 16;
        }

        return data.array();
    }

    private byte[] aesEncrypt(AesStepConfig step, ByteBuffer data, int offset, int skipLength) throws Exception {
        aesService.setEncryptKey(step.getAesKey());

        byte[] iv = step.getIv();
        final byte[] tempBlock = new byte[16];
        byte[] originalBlock;
        byte[] encryptedBlock;
        final int endOffset = data.capacity() - 15 - skipLength;

        while (offset < endOffset) {
            readData(data, offset, tempBlock);

            originalBlock = Arrays.copyOf(tempBlock, tempBlock.length);

            encryptedBlock = aesService.encrypt(tempBlock, iv);

            writeData(data, offset, encryptedBlock);

            iv = Arrays.copyOf(originalBlock, originalBlock.length);
            offset += 16;
        }

        return data.array();
    }

    private static void readData(ByteBuffer dataBuffer, int offset, byte[] block) {
        dataBuffer.get(offset, block, 0, block.length);
    }

    private static void writeData(ByteBuffer data, int offset, byte[] decryptedBlock) {
        data.put(offset, decryptedBlock, 0, decryptedBlock.length);
    }

    private static List<String> readCiphers(int cipherBlockSize, int totalCipherDataLength, int rounds, byte[] bytes) {
        byte[] cipherBytes = new byte[cipherBlockSize];
        int pos = bytes.length - totalCipherDataLength;
        List<String> ciphers = new ArrayList<>(rounds);

        for (int i = 0; i < rounds; i++) {
            System.arraycopy(bytes, pos, cipherBytes, 0, cipherBlockSize);
            ciphers.add(toHex(cipherBytes));
            pos += cipherBlockSize;
        }

        return ciphers;
    }

    private static List<byte[]> rsaDecrypt(List<String> ciphers, ConfigProperties properties) {
        RsaStepConfig rsa = properties.getRsa();

        if (properties.isAaFree()) {
            return rsaDecryptAaFree(ciphers, rsa);
        } else {
            return rsaDecryptCommon(ciphers, rsa);
        }
    }

    private static List<byte[]> rsaDecryptCommon(List<String> ciphers, RsaStepConfig rsa) {
        List<String> decrypts = new ArrayList<>(ciphers.size());
        List<byte[]> mBytes = new ArrayList<>(ciphers.size());

        for (String cHex : ciphers) {
            BigInteger c = toBigInt(cHex);
            BigInteger d = rsa.getD();
            BigInteger n = rsa.getN();

            BigInteger m = c.modPow(d, n);

            String mHex = toHex(m);
            decrypts.add(mHex);
        }

        for (String decrypt : decrypts) {
            mBytes.add(toByteArray(decrypt));
        }

        return mBytes;
    }

    private static List<byte[]> rsaDecryptAaFree(List<String> ciphers, RsaStepConfig rsa) {
        List<byte[]> mBytes = new ArrayList<>(ciphers.size());
        int mLength = rsa.getMLength();

        for (String cHex : ciphers) {
            cHex = cHex.substring(0, mLength * 2);
            mBytes.add(toByteArray(cHex));
        }

        return mBytes;
    }

    private static int calculateOffset(int length) {
        return 16 - (length % 16);
    }

    private static void overwriteZipHeader(byte[] bytes) {
        ByteBuffer zipHeaderBuffer = ByteBuffer.allocate(ZIP_OVERWRITE_HEADER_SIZE);

        zipHeaderBuffer.put(ZIP_HEADER);
        zipHeaderBuffer.put(ZIP_VERSION);
        zipHeaderBuffer.put(ZIP_BITFLAG);
        zipHeaderBuffer.put(ZIP_COMPRESSION_METHOD);

        byte[] zipHeader = zipHeaderBuffer.array();

        System.arraycopy(zipHeader, 0, bytes, 0, zipHeader.length);
    }
}
