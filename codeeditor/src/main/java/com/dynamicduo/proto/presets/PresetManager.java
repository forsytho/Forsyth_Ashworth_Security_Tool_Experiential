package com.dynamicduo.proto.presets;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.LinkedHashMap;
import java.util.stream.Stream;

public final class PresetManager {

    private PresetManager() {}

    public static final String PRESETS_DIR_NAME = "presets";

    public static void initialize(Path exportDir) throws IOException {
        Path presetsDir = exportDir.resolve(PRESETS_DIR_NAME);

        if (!Files.exists(presetsDir)) {
            Files.createDirectories(presetsDir);
        }
    }

    public static LinkedHashMap<String, Path> loadPresetMap(Path exportDir) throws IOException {
        Path presetsDir = exportDir.resolve(PRESETS_DIR_NAME);

        LinkedHashMap<String, Path> presets = new LinkedHashMap<>();

        if (!Files.exists(presetsDir)) {
            return presets;
        }

        try (Stream<Path> files = Files.list(presetsDir)) {
            files
                .filter(Files::isRegularFile)
                .filter(path -> path.toString().toLowerCase().endsWith(".txt"))
                .sorted()
                .forEach(path -> {
                    String displayName = toDisplayName(path.getFileName().toString());
                    presets.put(displayName, path);
                });
        }

        return presets;
    }

    public static String loadPresetText(Path presetFile) throws IOException {
        return Files.readString(presetFile, StandardCharsets.UTF_8);
    }

    private static String toDisplayName(String fileName) {
        String name = fileName;

        if (name.toLowerCase().endsWith(".txt")) {
            name = name.substring(0, name.length() - 4);
        }

        name = name.replace("_", " ")
                   .replace("-", " ");

        String[] words = name.split("\\s+");
        StringBuilder formatted = new StringBuilder();

        for (String word : words) {
            if (word.isBlank()) continue;

            formatted.append(Character.toUpperCase(word.charAt(0)))
                     .append(word.substring(1))
                     .append(" ");
        }

        return formatted.toString().trim();
    }
}