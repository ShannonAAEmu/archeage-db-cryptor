package aaemu.tools.util;

import static aaemu.tools.util.HexUtils.toByteArray;

import lombok.experimental.UtilityClass;

/**
 * @author Shannon
 */
@UtilityClass
public class ConstantsUtils {
    public static final int XL_COMMON_CONSTANT = 0x49616E42;

    public static final byte[] ZIP_HEADER = toByteArray("504B0304");
    public static final byte[] ZIP_VERSION = toByteArray("1400");
    public static final byte[] ZIP_BITFLAG = toByteArray("0000");
    public static final byte[] ZIP_COMPRESSION_METHOD = toByteArray("0800");
    public static final int ZIP_OVERWRITE_HEADER_SIZE = ZIP_HEADER.length + ZIP_VERSION.length + ZIP_BITFLAG.length + ZIP_COMPRESSION_METHOD.length;
    public static final byte[] GAME0PK_BYTES = toByteArray("67616D6530");

    public static final String ROOT_FOLDER = System.getProperty("user.dir");
    public static final String CONFIG_PROPERTIES_FILE_NAME = "config.json";
    public static final String CONFIG_PROPERTIES_FILE_EXTENSION = "*.json";
    public static final String DB_SQLITE = "compact.sqlite";
    public static final String DB_SQLITE_NEW = "compact_new.sqlite";
    public static final String DB_ZIP = "compact.zip";
}
