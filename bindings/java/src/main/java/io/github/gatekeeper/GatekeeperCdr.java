package io.github.gatekeeper;

public class GatekeeperCdr {
    
    static {
        // This will load libgatekeeper_java.so (Linux), gatekeeper_java.dll (Windows), or libgatekeeper_java.dylib (Mac)
        // Ensure that java.library.path is set correctly or the library is bundled in your jar.
        System.loadLibrary("gatekeeper_java");
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
