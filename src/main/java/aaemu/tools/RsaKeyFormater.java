package aaemu.tools;

import java.io.IOException;
import java.util.List;

import aaemu.tools.service.FileService;
import lombok.RequiredArgsConstructor;

/**
 * @author Shannon
 */
@RequiredArgsConstructor
public class RsaKeyFormater {
    private final FileService fileService;

    public void formatRsaKeys(int hexLength) throws IOException {
        List<String> lines = fileService.readAllLines("rsa_data.txt");
        StringBuilder sb = new StringBuilder();
        String d = null;
        String n;

        for (String line : lines) {
            if (line.length() == 1) {
                d = sb.toString();
                sb.setLength(0);

                continue;
            }

            line = line.replaceAll("h", "").replaceAll("offset unk_", "");
            line = switch (hexLength) {
                case 2 -> String.format("%2s", line).replace(' ', '0');
                case 4 -> String.format("%4s", line).replace(' ', '0');
                case 6 -> String.format("%6s", line).replace(' ', '0');
                default -> String.format("%8s", line).replace(' ', '0');
            };

            if (line.length() > hexLength) {
                line = line.substring(1);
            }

            insertReversedByTwo(sb, line);
        }

        n = sb.toString();

        System.out.println("┌──────┬──────────────────────────────────────────────────────────────────┐");
        System.out.println("│ Type │                              Value                               │");
        System.out.println("├──────┼──────────────────────────────────────────────────────────────────┤");
        System.out.println("│  d   │ " + d);
        System.out.println("│  n   │ " + n);
        System.out.printf("└──────┴──────────────────────────────────────────────────────────────────┘%n");
    }

    public void insertReversedByTwo(StringBuilder sb, String hex) {
        if (hex == null || hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string must be even length: " + hex);
        }

        for (int i = hex.length() - 2; i >= 0; i -= 2) {
            sb.append(hex.charAt(i));
            sb.append(hex.charAt(i + 1));
        }
    }
}
