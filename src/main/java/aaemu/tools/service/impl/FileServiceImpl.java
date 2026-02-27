package aaemu.tools.service.impl;

import static aaemu.tools.util.ConstantsUtils.CONFIG_PROPERTIES_FILE_EXTENSION;
import static aaemu.tools.util.ConstantsUtils.CONFIG_PROPERTIES_FILE_NAME;
import static aaemu.tools.util.ConstantsUtils.ROOT_FOLDER;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import aaemu.tools.config.ConfigProperties;
import aaemu.tools.service.FileService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.RequiredArgsConstructor;

/**
 * @author Shannon
 */
@RequiredArgsConstructor
public class FileServiceImpl implements FileService {
    private final ObjectMapper objectMapper;

    @Override
    public ConfigProperties readConfigProperties() throws IOException {
        byte[] bytes = read(CONFIG_PROPERTIES_FILE_NAME);

        return objectMapper.readValue(bytes, ConfigProperties.class);
    }

    @Override
    public List<ConfigProperties> readConfigPropertiesList() throws IOException {
        List<Path> jsonFiles = getAllJsonFiles();
        List<ConfigProperties> configs = new ArrayList<>();

        for (Path path : jsonFiles) {
            ConfigProperties config = objectMapper.readValue(path.toFile(), ConfigProperties.class);
            config.setPath(path);
            configs.add(config);
        }

        Collections.sort(configs);

        return configs;
    }

    @Override
    public byte[] readFile(String name) throws IOException {
        return read(name);
    }

    @Override
    public List<String> readAllLines(String name) throws IOException {
        Path filePath = buildFilePath(name);

        return Files.readAllLines(filePath);
    }

    @Override
    public void writeFile(String name, byte[] bytes) throws IOException {
        Path filePath = buildFilePath(name);
        Files.deleteIfExists(filePath);
        Files.write(filePath, bytes, StandardOpenOption.CREATE);
    }

    @Override
    public ObjectNode readJson(Path path) throws IOException {
        return objectMapper.readValue(path.toFile(), ObjectNode.class);
    }

    private static byte[] read(String name) throws IOException {
        Path filePath = buildFilePath(name);

        return Files.readAllBytes(filePath);
    }

    private static Path buildFilePath(String name) {
        if (name.contains(ROOT_FOLDER)) {
            return Paths.get(name);
        }

        String filePath = ROOT_FOLDER + FileSystems.getDefault().getSeparator() + name;

        return Paths.get(filePath);
    }

    private static List<Path> getAllJsonFiles() throws IOException {
        Path rootFolder = Path.of(ROOT_FOLDER);
        List<Path> jsonFiles = new ArrayList<>();

        try (DirectoryStream<Path> stream = Files.newDirectoryStream(rootFolder, CONFIG_PROPERTIES_FILE_EXTENSION)) {
            for (Path entry : stream) {
                if (Files.isRegularFile(entry)) {
                    jsonFiles.add(entry);
                }
            }
        }

        return jsonFiles;
    }
}
