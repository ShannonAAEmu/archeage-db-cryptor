package aaemu.tools.config;

import static aaemu.tools.util.HexUtils.toBigInt;
import static aaemu.tools.util.HexUtils.toInt;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import aaemu.tools.model.XLRandom;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

/**
 * @author Shannon
 */
@Data
public class RsaStepConfig {
    private BigInteger d;
    private BigInteger n;
    private int rounds;
    private int cLength;
    private int mLength;
    private List<Integer> blocksPoses;

    @JsonCreator
    public RsaStepConfig(@JsonProperty("d") String dHex,
                         @JsonProperty("n") String nHex,
                         @JsonProperty("constant") String constant,
                         @JsonProperty("rounds") int rounds,
                         @JsonProperty("c_length") String cLength,
                         @JsonProperty("m_length") String mLength) {
        this.d = toBigInt(dHex);
        this.n = toBigInt(nHex);
        this.rounds = rounds;
        this.cLength = toInt(cLength);
        this.mLength = toInt(mLength);

        this.blocksPoses = buildBlocksPoses(constant, rounds);
    }

    public int getRounds() {
        return blocksPoses.size();
    }

    private List<Integer> buildBlocksPoses(String constant, int rounds) {
        List<Integer> blocksPos = new ArrayList<>(rounds);

        XLRandom xlRandom = new XLRandom(constant);
        long currentPos = 0;

        for (int i = 0; i < rounds; i++) {
            long blockStart = currentPos;

            xlRandom.generate(new byte[mLength], 0, mLength);

            long offset = xlRandom.generate();
            offset = offset & 0xFFFFL;

            currentPos += offset + mLength;

            blocksPos.add((int) blockStart);
        }

        return blocksPos;
    }
}
