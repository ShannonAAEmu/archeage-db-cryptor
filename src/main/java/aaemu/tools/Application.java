package aaemu.tools;

import static aaemu.tools.enums.CipherMode.DECRYPT;
import static aaemu.tools.enums.CipherMode.ENCRYPT;
import static aaemu.tools.util.ConstantsUtils.DB_SQLITE;
import static aaemu.tools.util.ConstantsUtils.DB_SQLITE_NEW;
import static aaemu.tools.util.ConstantsUtils.DB_ZIP;
import static aaemu.tools.util.ConstantsUtils.GAME0PK_BYTES;
import static aaemu.tools.util.HexUtils.toHex;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Scanner;

import aaemu.tools.config.AesStepConfig;
import aaemu.tools.config.ConfigProperties;
import aaemu.tools.config.RsaStepConfig;
import aaemu.tools.enums.AesKeyBit;
import aaemu.tools.enums.CipherMode;
import aaemu.tools.enums.CipherVersion;
import aaemu.tools.service.AesService;
import aaemu.tools.service.CryptoService;
import aaemu.tools.service.FileService;
import aaemu.tools.service.impl.AesServiceImpl;
import aaemu.tools.service.impl.CryptoServiceImpl;
import aaemu.tools.service.impl.FileServiceImpl;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * @author Shannon
 */
public class Application {
    private static final ObjectMapper objectMapper = JsonMapper.builder().build();
    private static final FileService fileService = new FileServiceImpl(objectMapper);
    private static final AesService aesService = new AesServiceImpl();
    private static final CryptoService cryptoService = new CryptoServiceImpl(aesService);
    private static final RsaKeyFormater rsaKeyFormater = new RsaKeyFormater(fileService);

    public static void main(String[] args) throws IOException {
        try {
            printFunctionSelection();

            Scanner scanner = new Scanner(System.in);
            int selectedFunction = scanner.nextInt();

            switch (selectedFunction) {
                case 1 -> cipher(scanner);
                case 2 -> calculateKeysBit(scanner);
                case 3 -> rsaKeyFormater.formatRsaKeys(4);
            }

            System.out.println("\nPress any to exit");

            System.in.read(new byte[2]);
        } catch (Exception exception) {
            System.err.printf("%nError: %s%n%n", exception.fillInStackTrace());
            System.out.println("Press any to exit");

            System.in.read(new byte[2]);
            System.exit(0);
        }
    }

    private static void cipher(Scanner scanner) throws Exception {
        List<ConfigProperties> configProperties = fileService.readConfigPropertiesList();

        if (configProperties.isEmpty()) {
            System.out.println("No config properties found");

            return;
        }

        printConfigsInfo(configProperties);
        ConfigProperties properties = selectConfig(configProperties, scanner);
        CipherMode cipherMode = selectCipherMode(properties, scanner);

        if (cipherMode.isDecrypt()) {
            properties.setCipherMode(DECRYPT);
        } else {
            properties.setCipherMode(ENCRYPT);
        }

        start(properties);
    }

    private static void start(ConfigProperties properties) throws Exception {
        printConfigInfo(properties);
        printAesKeysInfo(properties);
        printRsaKeysInfo(properties);

        if (properties.getCipherMode().isDecrypt()) {
            byte[] decryptedData = decrypt(properties);
            fileService.writeFile(DB_ZIP, decryptedData);
        } else {
            byte[] encryptedData = encrypt(properties);
            fileService.writeFile(DB_SQLITE_NEW, encryptedData);
        }
    }

    private static byte[] decrypt(ConfigProperties properties) throws Exception {
        CipherVersion cipherVersion = properties.getCipherVersion();
        byte[] encryptedData = fileService.readFile(DB_SQLITE);

        return switch (cipherVersion) {
            case _2 -> cryptoService.decryptV2(properties, encryptedData);
            case _3 -> cryptoService.decryptV3(properties, encryptedData);
            case UNKNOWN -> new byte[0];
        };
    }

    private static byte[] encrypt(ConfigProperties properties) throws Exception {
        CipherVersion cipherVersion = properties.getCipherVersion();
        byte[] decryptedData = fileService.readFile(DB_ZIP);

        return switch (cipherVersion) {
            case _2 -> cryptoService.encryptV2(properties, decryptedData);
            case _3 -> cryptoService.encryptV3(properties, decryptedData);
            case UNKNOWN -> new byte[0];
        };
    }

    private static void calculateKeysBit(Scanner scanner) throws Exception {
        List<ConfigProperties> configProperties = fileService.readConfigPropertiesList();

        if (configProperties.isEmpty()) {
            System.out.println("No config properties found");

            return;
        }

        printConfigsInfo(configProperties);
        ConfigProperties properties = selectConfig(configProperties, scanner);
        properties.setCipherMode(DECRYPT);

        System.out.println("\n=== Analysis of AES key bit combinations ===");
        System.out.println("┌─────────────┬─────────────┬──────────┐");
        System.out.println("│ AES-1 (bit) │ AES-2 (bit) │  Result  │");
        System.out.println("├─────────────┼─────────────┼──────────┤");

        boolean found = false;
        int firstKeyBit = 0;
        int secondKeyBit = 0;

        for (AesKeyBit first : AesKeyBit.values()) {
            for (AesKeyBit second : AesKeyBit.values()) {
                properties.getAesFirstStage().updateKey(first.getBit());
                properties.getAesSecondStage().updateKey(second.getBit());
                String statusSymbol;

                try {
                    if (isValidKeysBit(properties)) {
                        statusSymbol = "+";
                        found = true;
                    } else {
                        statusSymbol = "-";
                    }
                } catch (Exception exception) {
                    statusSymbol = "!";
                }

                System.out.printf("│     %3d     │     %3d     │    %s     │%n", first.getBit(), second.getBit(), statusSymbol);

                if (found) {
                    firstKeyBit = first.getBit();
                    secondKeyBit = second.getBit();

                    break;
                }
            }

            if (found) {
                break;
            }
        }

        System.out.println("└─────────────┴─────────────┴──────────┘");

        if (!found) {
            System.out.println("Bit length of AES keys hasn't been detected");
            System.out.printf("Check config constants and %s%n", DB_SQLITE);

            return;
        }
        System.out.println("\n=== Overwrite config file ===");
        System.out.print(" Enter y/n: ");

        boolean overwrite = scanner.next().equalsIgnoreCase("y");

        if (overwrite) {
            overwriteJsonConfig(properties, firstKeyBit, secondKeyBit);
        }
    }

    private static boolean isValidKeysBit(ConfigProperties properties) throws Exception {
        byte[] decryptedData = decrypt(properties);

        if (decryptedData.length <= 30 + GAME0PK_BYTES.length) {
            return false;
        }
        byte[] copy = new byte[GAME0PK_BYTES.length];
        System.arraycopy(decryptedData, 30, copy, 0, copy.length);

        return Arrays.equals(copy, GAME0PK_BYTES);
    }

    private static void overwriteJsonConfig(ConfigProperties properties, int firstKeySize, int secondKeySize) throws IOException {
        ObjectNode jsonConfig = fileService.readJson(properties.getPath());
        ObjectNode aesStage = (ObjectNode) jsonConfig.get("aes_first_stage");
        aesStage.put("key_bit", firstKeySize);
        aesStage = (ObjectNode) jsonConfig.get("aes_second_stage");
        aesStage.put("key_bit", secondKeySize);

        fileService.writeFile(properties.getPath().toString(), jsonConfig.toPrettyString().getBytes());
    }

    private static void printFunctionSelection() {
        System.out.println("=== Select function ===");
        System.out.println("┌───┬────────────────────────┐");
        System.out.println("│ № │         Name           │");
        System.out.println("├───┼────────────────────────┤");
        System.out.println("│ 1 │ Cipher                 │");
        System.out.println("│ 2 │ Calculate AES keys bit │");
        System.out.println("│ 3 │ Format RSA keys        │");
        System.out.println("└───┴────────────────────────┘");
        System.out.print(" Enter №: ");
    }

    private static void printConfigsInfo(List<ConfigProperties> configProperties) {
        System.out.printf("%n=== Select version ===%n");
        System.out.println("┌─────┬─────────────────────────┐");
        System.out.println("│  №  │          Name           │");
        System.out.println("├─────┼─────────────────────────┤");

        for (int i = 0; i < configProperties.size(); i++) {
            ConfigProperties config = configProperties.get(i);

            String str = "│ %2d  │ %s v%s".formatted(i + 1, config.getProvider(), config.getVersion());

            System.out.printf(str + " ".repeat(32 - str.length()) + "│%n");
        }

        System.out.println("└─────┴─────────────────────────┘");
    }

    private static ConfigProperties selectConfig(List<ConfigProperties> configProperties, Scanner scanner) {
        System.out.print(" Enter №: ");

        int selectedNumber = scanner.nextInt() - 1;

        return configProperties.get(selectedNumber);
    }

    private static CipherMode selectCipherMode(ConfigProperties properties, Scanner scanner) throws Exception {
        System.out.printf("%n=== Select cipher mode ===%n");
        System.out.println("┌─────┬─────────┐");
        System.out.println("│  №  │  Mode   │");
        System.out.println("├─────┼─────────┤");
        System.out.println("│  1  │ DECRYPT │");

        boolean canEncrypt = false;

        if (properties.getCipherVersion().equals(CipherVersion._2)) {
            canEncrypt = true;

            System.out.println("│  2  │ ENCRYPT │");
        }

        System.out.println("└─────┴─────────┘");
        System.out.print(" Enter №: ");

        int selectedNumber = scanner.nextInt();

        if (canEncrypt) {
            return switch (selectedNumber) {
                case 1 -> DECRYPT;
                case 2 -> ENCRYPT;
                default -> throw new Exception("Invalid cipher mode");
            };
        }

        if (1 == selectedNumber) {
            return DECRYPT;
        } else {
            throw new Exception("Invalid cipher mode");
        }
    }

    private static void printConfigInfo(ConfigProperties properties) {
        String provider = properties.getProvider();
        String version = properties.getVersion();
        CipherMode cipherMode = properties.getCipherMode();

        System.out.printf("%n=== %s v%s (%s) ===%n", provider, version, cipherMode);
    }

    private static void printAesKeysInfo(ConfigProperties properties) {
        System.out.printf("%n==== AES ====%n");

        AesStepConfig aesStep = properties.getAesFirstStage();
        int keyBit = aesStep.getKeyBit();
        String key = toHex(aesStep.getAesKey());
        String iv = toHex(aesStep.getIv());

        printAesInfo(keyBit, key, iv);

        aesStep = properties.getAesSecondStage();
        keyBit = aesStep.getKeyBit();
        key = toHex(aesStep.getAesKey());
        iv = toHex(aesStep.getIv());

        printAesInfo(keyBit, key, iv);
    }

    private static void printAesInfo(int bit, String key, String iv) {
        System.out.println("┌────────────┬──────────────────────────────────────────────────────────────────┐");
        System.out.println("│    Type    │                              Value                               │");
        System.out.println("├────────────┼──────────────────────────────────────────────────────────────────┤");
        System.out.println("│  Bit " + "(%3d)".formatted(bit) + " │ " + key + " ".repeat(65 - key.length()) + "│");
        System.out.println("│  IV        │ " + iv + " ".repeat(65 - iv.length()) + "│");
        System.out.printf("└────────────┴──────────────────────────────────────────────────────────────────┘%n");
    }

    private static void printRsaKeysInfo(ConfigProperties properties) {
        RsaStepConfig rsaStep = properties.getRsa();

        if (Objects.isNull(rsaStep)) {
            return;
        }

        System.out.printf("%n==== RSA ====%n");

        BigInteger privateExponent = rsaStep.getD();
        BigInteger modulus = rsaStep.getN();
        String rounds = "%d".formatted(rsaStep.getRounds());
        String cLength = "%3d".formatted(rsaStep.getCLength());
        String mLength = "%3d".formatted(rsaStep.getMLength());

        System.out.println("┌────────────┬──────────────────────────────────────────────────────────────────┐");
        System.out.println("│    Type    │                              Value                               │");
        System.out.println("├────────────┼──────────────────────────────────────────────────────────────────┤");
        System.out.println("│ d          │ " + privateExponent);
        System.out.println("│ n          │ " + modulus);
        System.out.println("│ Rounds     │ " + rounds + " ".repeat(65 - rounds.length()) + "│");
        System.out.println("│ c length   │ " + cLength + " ".repeat(65 - cLength.length()) + "│");
        System.out.println("│ m length   │ " + mLength + " ".repeat(65 - mLength.length()) + "│");
        System.out.println("└────────────┴──────────────────────────────────────────────────────────────────┘");
    }
}
