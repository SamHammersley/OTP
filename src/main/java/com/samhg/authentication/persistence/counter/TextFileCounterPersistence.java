package com.samhg.authentication.persistence.counter;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousFileChannel;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.nio.file.StandardOpenOption.*;

public final class TextFileCounterPersistence implements CounterPersistenceStrategy {

    private final Path path;

    public TextFileCounterPersistence(Path path) {
        this.path = path;
    }

    @Override
    public Long persist(CounterUpdate counterUpdate) {
        try (AsynchronousFileChannel channel = AsynchronousFileChannel.open(path, READ, WRITE)) {

            int fileSize = (int) channel.size();
            ByteBuffer readBuffer = ByteBuffer.allocate(fileSize);
            channel.read(readBuffer, 0);

            String[] linesArray = new String(readBuffer.array()).split("\n");
            Stream<String> lines = Arrays.stream(linesArray).parallel();

            Map<String, String> entries = lines
                    .filter(l -> l.matches("\\w+:\\w+"))
                    .map(l -> l.split(":"))
                    .collect(Collectors.toMap(l -> l[0], l -> l[1]));

            entries.compute(counterUpdate.getRequest().getIdentifier(),
                    (k, v) -> Long.toString(counterUpdate.getNewCounter()));

            String newFile = entries.entrySet()
                    .parallelStream()
                    .map(e -> e.getKey() + ":" + e.getValue() + "\n")
                    .reduce(String::concat)
                    .orElseThrow();

            ByteBuffer writeBuffer = ByteBuffer.wrap(newFile.getBytes());
            channel.write(writeBuffer, 0);

            return counterUpdate.getNewCounter();

        } catch (IOException e) {
            throw new RuntimeException("IO error occurred whilst accessing " + path.getFileName(), e);
        }
    }
}