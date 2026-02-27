package aaemu.tools.config;

import static aaemu.tools.enums.CipherVersion.UNKNOWN;
import static aaemu.tools.enums.CipherVersion._2;
import static aaemu.tools.enums.CipherVersion._3;

import java.nio.file.Path;

import aaemu.tools.enums.CipherMode;
import aaemu.tools.enums.CipherVersion;
import ch.qos.logback.core.util.StringUtil;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Data;

/**
 * @author Shannon
 */
@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class ConfigProperties implements Comparable<ConfigProperties> {
    private String provider;
    private String version;
    private AesStepConfig aesFirstStage;
    private RsaStepConfig rsa;
    private AesStepConfig aesSecondStage;
    private CipherMode cipherMode;

    @JsonIgnore
    private Path path;

    public CipherVersion getCipherVersion() {
        if (StringUtil.isNullOrEmpty(version)) {
            return UNKNOWN;
        }

        String[] parts = version.split("\\.");
        int major = Integer.parseInt(parts[0]);
        int minor = Integer.parseInt(parts[1]);

        if (major == 2) {
            return _2;
        }

        if (major == 3 && minor == 0) {
            return _2;
        }

        if (major >= 3) {
            return _3;
        }

        return UNKNOWN;
    }

    public boolean isAaFree() {
        return provider.contains("Free") || provider.contains("free");
    }

    @Override
    public int compareTo(ConfigProperties other) {
        return compareVersions(this.version, other.getVersion());
    }

    private int compareVersions(String first, String second) {
        String[] parts1 = first.split("\\.");
        String[] parts2 = second.split("\\.");

        int length = Math.max(parts1.length, parts2.length);
        for (int i = 0; i < length; i++) {
            int num1 = i < parts1.length ? Integer.parseInt(parts1[i]) : 0;
            int num2 = i < parts2.length ? Integer.parseInt(parts2[i]) : 0;

            if (num1 != num2) {
                return Integer.compare(num1, num2);
            }
        }
        return 0;
    }
}
