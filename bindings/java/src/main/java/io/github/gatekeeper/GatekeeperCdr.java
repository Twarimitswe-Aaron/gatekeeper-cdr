package io.github.gatekeeper;

public class GatekeeperCdr {
    
    static {
        try {
            // Check OS and Architecture here in a full implementation.
            // For now, load the Linux x64 binary bundled in the JAR.
            NativeUtils.loadLibraryFromJar("/native/linux/libgatekeeper_java.so");
        } catch (Exception e) {
            System.err.println("Failed to load native Gatekeeper library from JAR: " + e.getMessage());
            // Fallback for local development
            System.loadLibrary("gatekeeper_java");
        }
    }

    /**
     * Inspects the raw file bytes to determine its format without fully decoding it.
     * 
     * @param payload The raw file bytes to sniff
     * @return The detected FileFormat enum
     * @throws RuntimeException if the payload is invalid, empty, or an unknown format
     */
    public static native FileFormat sniffFormat(byte[] payload);

    /**
     * Sanitizes the input payload by stripping all metadata and potential exploits,
     * reconstructing a safe file from the raw pixel data.
     * 
     * @param payload The raw file bytes to disarm
     * @return A new byte array containing the safely reconstructed file
     * @throws RuntimeException if the payload cannot be parsed or sanitized
     */
    public static native byte[] disarm(byte[] payload);
}
