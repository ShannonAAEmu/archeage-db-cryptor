package aaemu.tools.model;

import static aaemu.tools.util.ConstantsUtils.XL_COMMON_CONSTANT;
import static aaemu.tools.util.HexUtils.toLong;

/**
 * @author Shannon
 */
public class XLRandom {
    private long seedOne;
    private long seedTwo;

    private XLRandom(long seed) {
        this.seedOne = seed;
        this.seedTwo = seed ^ XL_COMMON_CONSTANT;
    }

    public XLRandom(String seed) {
        this(toLong(seed));
    }

    public long generate() {
        long seedOneLong = seedOne & 0xFFFFFFFFL;
        long shiftRight = seedOneLong >>> 16;
        long shiftLeft = (seedOne << 16) & 0xFFFFFFFFL;
        long tempSeed = (seedTwo & 0xFFFFFFFFL) + shiftRight + shiftLeft;
        tempSeed &= 0xFFFFFFFFL;
        seedOne = tempSeed;
        seedTwo += seedOne;
        seedTwo &= 0xFFFFFFFFL;

        return seedOne;
    }

    public void generate(byte[] buffer, int offset, int length) {
        if (length <= 0) {
            return;
        }

        int i = 0;

        while (i + 3 < length) {
            long randomValue = generate();
            buffer[offset + i] = (byte) (randomValue & 0xFF);
            buffer[offset + i + 1] = (byte) ((randomValue >> 8) & 0xFF);
            buffer[offset + i + 2] = (byte) ((randomValue >> 16) & 0xFF);
            buffer[offset + i + 3] = (byte) ((randomValue >> 24) & 0xFF);
            i += 4;
        }

        while (i < length) {
            buffer[offset + i] = (byte) (generate() & 0xFF);
            i++;
        }
    }
}
