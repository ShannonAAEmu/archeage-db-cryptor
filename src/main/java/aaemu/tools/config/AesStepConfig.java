package aaemu.tools.config;

import aaemu.tools.model.XLRandom;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

/**
 * @author Shannon
 */
@Data
public class AesStepConfig {
    private String keyConstant;
    private String ivConstant;
    private int keyBit;

    private byte[] aesKey;
    private byte[] iv;

    @JsonCreator
    public AesStepConfig(@JsonProperty("key_constant") String keyConstant, @JsonProperty("iv_constant") String ivConstant, @JsonProperty("key_bit") int keyBit) {
        this.keyConstant = keyConstant;
        this.ivConstant = ivConstant;
        this.keyBit = keyBit;

        this.aesKey = buildAesKey();
        this.iv = buildIv();
    }

    public void updateKey(int keySize) {
        int length = keySize / 8;

        aesKey = generateKey(keyConstant, length);
    }

    private byte[] buildAesKey() {
        int length = keyBit / 8;

        return generateKey(keyConstant, length);
    }

    private byte[] buildIv() {
        return generateKey(ivConstant, 16);
    }

    private byte[] generateKey(String constant, int length) {
        XLRandom xlRandom = new XLRandom(constant);
        byte[] bytes = new byte[length];
        xlRandom.generate(bytes, 0, length);

        return bytes;
    }
}
