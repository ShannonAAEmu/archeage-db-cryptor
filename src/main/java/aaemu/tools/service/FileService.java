package aaemu.tools.service;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

import aaemu.tools.config.ConfigProperties;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * @author Shannon
 */
public interface FileService {

    ConfigProperties readConfigProperties() throws IOException;

    List<ConfigProperties> readConfigPropertiesList() throws IOException;

    byte[] readFile(String name) throws IOException;

    List<String> readAllLines(String name) throws IOException;

    void writeFile(String name, byte[] bytes) throws IOException;

    ObjectNode readJson(Path path) throws IOException;
}
