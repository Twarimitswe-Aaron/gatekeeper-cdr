package io.github.gatekeeper;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

public class NativeUtils {

    /**
     * Extracts and loads a native library from the JAR.
     * 
     * @param path The path to the library inside the JAR (e.g. "/native/linux/libgatekeeper_java.so")
     * @throws IOException
     */
    public static void loadLibraryFromJar(String path) throws IOException {
        if (path == null || !path.startsWith("/")) {
            throw new IllegalArgumentException("The path must be absolute (start with '/').");
        }

        String[] parts = path.split("/");
        String filename = (parts.length > 1) ? parts[parts.length - 1] : null;

        if (filename == null || filename.length() < 3) {
            throw new IllegalArgumentException("The filename has to be at least 3 characters long.");
        }

        // Create a temporary file to extract the library
        File temp = File.createTempFile(filename.split("\\.")[0] + "-", "." + filename.split("\\.")[1]);
        temp.deleteOnExit();

        try (InputStream is = NativeUtils.class.getResourceAsStream(path)) {
            if (is == null) {
                throw new FileNotFoundException("File " + path + " was not found inside JAR.");
            }
            Files.copy(is, temp.toPath(), StandardCopyOption.REPLACE_EXISTING);
        }

        System.load(temp.getAbsolutePath());
    }
}
