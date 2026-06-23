# Gatekeeper CDR (Java)

This package provides native Java JNI bindings to the Gatekeeper CDR core, a zero-trust Content Disarm and Reconstruction engine. It sanitizes potentially malicious files by deeply inspecting and rebuilding them from raw pixel data, effectively stripping away any steganography, macros, or hidden exploits.

## Installation

Add the dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>io.github.twarimitswe-aaron</groupId>
    <artifactId>gatekeeper-cdr</artifactId>
    <version>0.4.0</version>
</dependency>
```

Or for Gradle:

```groovy
implementation 'io.github.twarimitswe-aaron:gatekeeper-cdr:0.4.0'
```

*(Note: This library relies on the `libgatekeeper_java.so` native binary. Ensure the binary is either bundled in your JAR or available on your `java.library.path`).*

## Usage

```java
import io.github.gatekeeper.GatekeeperCdr;
import io.github.gatekeeper.FileFormat;

import java.nio.file.Files;
import java.nio.file.Path;

public class Main {
    public static void main(String[] args) throws Exception {
        // 1. Read a suspicious file
        byte[] raw = Files.readAllBytes(Path.of("suspicious.jpg"));

        // 2. Detect the true format of the file without fully parsing it
        try {
            FileFormat fmt = GatekeeperCdr.sniffFormat(raw);
            System.out.println("Detected: " + fmt); // JPEG, PNG, etc.
        } catch (RuntimeException e) {
            System.err.println("Unknown or invalid format: " + e.getMessage());
        }

        // 3. Disarm the file (returns a clean byte array)
        try {
            byte[] clean = GatekeeperCdr.disarm(raw);
            Files.write(Path.of("clean.png"), clean);
            System.out.println("File successfully sanitized and saved as clean.png!");
        } catch (RuntimeException e) {
            System.err.println("Failed to sanitize file: " + e.getMessage());
        }
    }
}
```

## Security

If the file is malformed, structurally invalid, or contains an unknown format, Gatekeeper will intentionally throw a `RuntimeException` back to the JVM rather than attempting to process it. This default-deny stance ensures that only provably safe files make it into your application's storage.
