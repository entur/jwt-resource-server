package org.entur.jwt.junit5.impl;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.UUID;

public class AtomicFiles {

    private AtomicFiles() {
        // utility class
    }

    /**
     * Write a file via a unique temporary file in the same directory, so that concurrent readers
     * see either the previous or the new content, never partially written content.
     *
     * @param path    file to write
     * @param content file content
     * @throws IOException if the file could not be written
     */

    public static void write(Path path, String content) throws IOException {
        Path temporary = path.resolveSibling(path.getFileName() + "." + UUID.randomUUID() + ".tmp");
        try {
            Files.writeString(temporary, content, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
            try {
                Files.move(temporary, path, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temporary, path, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temporary);
        }
    }
}
