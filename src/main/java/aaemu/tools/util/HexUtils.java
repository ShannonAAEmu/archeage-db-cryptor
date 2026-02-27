package aaemu.tools.util;

import java.math.BigInteger;
import java.util.HexFormat;

import lombok.experimental.UtilityClass;

/**
 * @author Shannon
 */
@UtilityClass
public class HexUtils {
    private static final HexFormat HEX_FORMAT = HexFormat.of();

    public static int toInt(String hex) {
        return Integer.parseInt(hex, 16);
    }

    public static long toLong(String hex) {
        return Long.parseLong(hex, 16);
    }

    public static BigInteger toBigInt(String hex) {
        StringBuilder reversed = new StringBuilder();

        for (int i = hex.length(); i > 0; i -= 2) {
            int start = Math.max(i - 2, 0);
            reversed.append(hex, start, i);
        }

        return new BigInteger(reversed.toString(), 16);
    }

    public static String toHex(byte[] bytes) {
        return HEX_FORMAT.formatHex(bytes).toUpperCase();
    }

    public static byte[] toByteArray(String hex) {
        return HEX_FORMAT.parseHex(hex);
    }

    public static String toHex(int value) {
        return Integer.toHexString(value).toUpperCase();
    }

    public static String toHex(BigInteger num) {
        String hex = num.toString(16).toUpperCase();

        if (hex.length() % 2 != 0) {
            hex = "0" + hex;
        }

        StringBuilder result = new StringBuilder();

        for (int i = hex.length(); i > 0; i -= 2) {
            result.append(hex, i - 2, i);
        }

        return result.toString();
    }
}
