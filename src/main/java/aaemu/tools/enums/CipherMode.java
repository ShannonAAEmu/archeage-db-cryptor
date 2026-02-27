package aaemu.tools.enums;

/**
 * @author Shannon
 */
public enum CipherMode {
    DECRYPT,
    ENCRYPT;

    public boolean isDecrypt() {
        return this.equals(DECRYPT);
    }
}
